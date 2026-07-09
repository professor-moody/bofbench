package coff

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"bofbench/internal/capability"
)

const (
	MachineX86 = 0x014c
	MachineX64 = 0x8664

	sectionExecutable = 0x20000000
	sectionReadable   = 0x40000000
	sectionWritable   = 0x80000000
	sectionAlignMask  = 0x00f00000

	maxSections = 4096
	maxSymbols  = 1 << 20
)

type File struct {
	Path              string       `json:"path"`
	Size              int64        `json:"size"`
	SHA256            string       `json:"sha256"`
	Machine           string       `json:"machine"`
	MachineCode       uint16       `json:"machine_code"`
	Timestamp         uint32       `json:"timestamp"`
	NumberOfSections  int          `json:"number_of_sections"`
	SymbolTableOffset uint32       `json:"symbol_table_offset"`
	NumberOfSymbols   uint32       `json:"number_of_symbols"`
	Sections          []Section    `json:"sections"`
	Symbols           []Symbol     `json:"symbols"`
	Strings           []string     `json:"strings,omitempty"`
	LayoutValid       bool         `json:"layout_valid"`
	Diagnostics       []Diagnostic `json:"diagnostics,omitempty"`
}

type Section struct {
	Index                int          `json:"index"`
	Name                 string       `json:"name"`
	RawName              string       `json:"raw_name,omitempty"`
	Size                 uint32       `json:"size"`
	PointerToRawData     uint32       `json:"pointer_to_raw_data"`
	PointerToRelocations uint32       `json:"pointer_to_relocations"`
	NumberOfRelocations  uint16       `json:"number_of_relocations"`
	Characteristics      uint32       `json:"characteristics"`
	Data                 []byte       `json:"-"`
	Relocations          []Relocation `json:"relocations,omitempty"`
	Executable           bool         `json:"executable"`
	Readable             bool         `json:"readable"`
	Writable             bool         `json:"writable"`
	Uninitialized        bool         `json:"uninitialized"`
	Alignment            uint32       `json:"alignment,omitempty"`
}

type Symbol struct {
	Index         uint32 `json:"index"`
	Name          string `json:"name"`
	Value         uint32 `json:"value"`
	SectionNumber int16  `json:"section_number"`
	Type          uint16 `json:"type"`
	StorageClass  uint8  `json:"storage_class"`
	AuxSymbols    uint8  `json:"aux_symbols"`
	External      bool   `json:"external"`
}

type Diagnostic struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Detail   string `json:"detail"`
	Section  string `json:"section,omitempty"`
	Symbol   string `json:"symbol,omitempty"`
	Offset   uint64 `json:"offset,omitempty"`
}

type Relocation struct {
	Section          string `json:"section"`
	VirtualAddress   uint32 `json:"virtual_address"`
	SymbolTableIndex uint32 `json:"symbol_table_index"`
	Type             uint16 `json:"type"`
	TypeName         string `json:"type_name"`
	SymbolName       string `json:"symbol_name,omitempty"`
}

type MockRelocation struct {
	VirtualAddress uint32
	Symbol         string
	Type           uint16
}

func CreateMockObject(path, arch, entrypoint string, unresolved []string) error {
	return CreateMockObjectWithRelocations(path, arch, entrypoint, unresolved, nil)
}

func CreateMockObjectWithRelocations(path, arch, entrypoint string, unresolved []string, relocations []MockRelocation) error {
	if entrypoint == "" {
		entrypoint = "go"
	}
	machine := uint16(MachineX64)
	if arch == "x86" {
		machine = MachineX86
	}
	var buf bytes.Buffer
	sectionCount := uint16(1)
	symbols := []mockSymbol{{Name: entrypoint, SectionNumber: 1, External: true}}
	for _, sym := range unresolved {
		if sym == "" {
			continue
		}
		symbols = append(symbols, mockSymbol{Name: sym, SectionNumber: 0, External: true})
	}
	headerSize := 20
	sectionTableSize := int(sectionCount) * 40
	rawPtr := uint32(headerSize + sectionTableSize)
	rawData := make([]byte, 8)
	rawData[0] = 0xc3
	relocPtr := uint32(0)
	if len(relocations) > 0 {
		relocPtr = rawPtr + uint32(len(rawData))
	}
	symPtr := rawPtr + uint32(len(rawData)) + uint32(len(relocations)*10)
	stringTable := newStringTable()
	symbolIndexes := map[string]uint32{}
	for i, symbol := range symbols {
		if _, exists := symbolIndexes[symbol.Name]; !exists {
			symbolIndexes[symbol.Name] = uint32(i)
		}
	}
	for _, relocation := range relocations {
		if _, ok := symbolIndexes[relocation.Symbol]; !ok {
			return fmt.Errorf("mock relocation symbol %q is not declared", relocation.Symbol)
		}
	}

	writeU16(&buf, machine)
	writeU16(&buf, sectionCount)
	writeU32(&buf, 0)
	writeU32(&buf, symPtr)
	writeU32(&buf, uint32(len(symbols)))
	writeU16(&buf, 0)
	writeU16(&buf, 0)

	name := [8]byte{}
	copy(name[:], []byte(".text"))
	buf.Write(name[:])
	writeU32(&buf, 0)
	writeU32(&buf, 0)
	writeU32(&buf, uint32(len(rawData)))
	writeU32(&buf, rawPtr)
	writeU32(&buf, relocPtr)
	writeU32(&buf, 0)
	writeU16(&buf, uint16(len(relocations)))
	writeU16(&buf, 0)
	writeU32(&buf, 0x00000020|sectionExecutable|sectionReadable)
	buf.Write(rawData)
	for _, relocation := range relocations {
		writeU32(&buf, relocation.VirtualAddress)
		writeU32(&buf, symbolIndexes[relocation.Symbol])
		writeU16(&buf, relocation.Type)
	}

	for _, sym := range symbols {
		writeSymbol(&buf, sym, stringTable)
	}
	buf.Write(stringTable.bytes())

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func Inspect(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 20 {
		return nil, fmt.Errorf("file too small for COFF header")
	}
	sum := sha256.Sum256(b)
	machine := binary.LittleEndian.Uint16(b[0:2])
	sectionCount := binary.LittleEndian.Uint16(b[2:4])
	timestamp := binary.LittleEndian.Uint32(b[4:8])
	symPtr := binary.LittleEndian.Uint32(b[8:12])
	symCount := binary.LittleEndian.Uint32(b[12:16])
	optionalHeaderSize := binary.LittleEndian.Uint16(b[16:18])
	if optionalHeaderSize != 0 {
		return nil, fmt.Errorf("COFF object should not have optional header, got %d bytes", optionalHeaderSize)
	}
	machineName := machineString(machine)
	if machineName == "unknown" {
		return nil, fmt.Errorf("unsupported COFF machine 0x%x", machine)
	}
	file := &File{
		Path:              path,
		Size:              int64(len(b)),
		SHA256:            hex.EncodeToString(sum[:]),
		Machine:           machineName,
		MachineCode:       machine,
		Timestamp:         timestamp,
		NumberOfSections:  int(sectionCount),
		SymbolTableOffset: symPtr,
		NumberOfSymbols:   symCount,
		Strings:           ExtractStrings(b, 4),
		LayoutValid:       true,
	}
	addDiagnostic := func(diagnostic Diagnostic) {
		file.Diagnostics = append(file.Diagnostics, diagnostic)
		if diagnostic.Severity == "error" {
			file.LayoutValid = false
		}
	}
	if sectionCount == 0 {
		addDiagnostic(Diagnostic{Severity: "error", Code: "section_table_empty", Detail: "COFF object declares no sections"})
	}
	if int(sectionCount) > maxSections {
		addDiagnostic(Diagnostic{Severity: "error", Code: "section_count_limit", Detail: fmt.Sprintf("COFF object declares %d sections; parser limit is %d", sectionCount, maxSections)})
		return file, nil
	}
	sectionTableEnd := uint64(20) + uint64(sectionCount)*40
	if !rangeWithin(len(b), 20, uint64(sectionCount)*40) {
		addDiagnostic(Diagnostic{Severity: "error", Code: "section_table_range", Detail: "section table extends beyond the file", Offset: 20})
		return file, nil
	}
	file.Sections = make([]Section, 0, sectionCount)
	uninitializedFlag := capability.WindowsCOFF().SectionFlags.UninitializedData
	for i := 0; i < int(sectionCount); i++ {
		off := 20 + i*40
		rawNameBytes := b[off : off+8]
		rawName := strings.TrimRight(string(rawNameBytes), "\x00")
		size := binary.LittleEndian.Uint32(b[off+16 : off+20])
		rawPtr := binary.LittleEndian.Uint32(b[off+20 : off+24])
		relocPtr := binary.LittleEndian.Uint32(b[off+24 : off+28])
		numRelocs := binary.LittleEndian.Uint16(b[off+32 : off+34])
		ch := binary.LittleEndian.Uint32(b[off+36 : off+40])
		section := Section{
			Index:                i + 1,
			Name:                 rawName,
			RawName:              rawName,
			Size:                 size,
			PointerToRawData:     rawPtr,
			PointerToRelocations: relocPtr,
			NumberOfRelocations:  numRelocs,
			Characteristics:      ch,
			Executable:           ch&sectionExecutable != 0,
			Readable:             ch&sectionReadable != 0,
			Writable:             ch&sectionWritable != 0,
			Uninitialized:        ch&uninitializedFlag != 0,
			Alignment:            sectionAlignment(ch),
		}
		if rawName == "" {
			addDiagnostic(Diagnostic{Severity: "warning", Code: "section_name_empty", Detail: "section name is empty", Section: fmt.Sprintf("#%d", i+1), Offset: uint64(off)})
		}
		if ch&sectionAlignMask == sectionAlignMask {
			addDiagnostic(Diagnostic{Severity: "error", Code: "section_alignment_reserved", Detail: "section uses the reserved alignment encoding", Section: displaySection(section), Offset: uint64(off + 36)})
		}
		if size > 0 && !section.Uninitialized {
			switch {
			case rawPtr == 0:
				addDiagnostic(Diagnostic{Severity: "error", Code: "section_data_pointer", Detail: "non-empty section has a zero raw-data pointer", Section: displaySection(section)})
			case !rangeWithin(len(b), uint64(rawPtr), uint64(size)):
				addDiagnostic(Diagnostic{Severity: "error", Code: "section_data_range", Detail: "section raw data extends beyond the file", Section: displaySection(section), Offset: uint64(rawPtr)})
			case uint64(rawPtr) < sectionTableEnd:
				addDiagnostic(Diagnostic{Severity: "error", Code: "section_data_overlap_headers", Detail: "section raw data overlaps the COFF headers or section table", Section: displaySection(section), Offset: uint64(rawPtr)})
			default:
				section.Data = append([]byte(nil), b[rawPtr:rawPtr+size]...)
			}
		}
		if section.Uninitialized && rawPtr != 0 {
			addDiagnostic(Diagnostic{Severity: "warning", Code: "uninitialized_data_pointer", Detail: "uninitialized-data section has a non-zero raw-data pointer; loader will zero-fill it", Section: displaySection(section), Offset: uint64(rawPtr)})
		}
		if numRelocs > 0 {
			relocationBytes := uint64(numRelocs) * 10
			switch {
			case relocPtr == 0:
				addDiagnostic(Diagnostic{Severity: "error", Code: "relocation_table_pointer", Detail: "section declares relocations with a zero table pointer", Section: displaySection(section)})
			case !rangeWithin(len(b), uint64(relocPtr), relocationBytes):
				addDiagnostic(Diagnostic{Severity: "error", Code: "relocation_table_range", Detail: "relocation table extends beyond the file", Section: displaySection(section), Offset: uint64(relocPtr)})
			case uint64(relocPtr) < sectionTableEnd:
				addDiagnostic(Diagnostic{Severity: "error", Code: "relocation_table_overlap_headers", Detail: "relocation table overlaps the COFF headers or section table", Section: displaySection(section), Offset: uint64(relocPtr)})
			}
		}
		file.Sections = append(file.Sections, section)
	}

	var stringTable []byte
	symbolTableValid := true
	if symCount == 0 {
		addDiagnostic(Diagnostic{Severity: "warning", Code: "symbol_table_stripped", Detail: "object has no COFF symbol table; entrypoint and import discovery are unavailable"})
		symbolTableValid = false
	} else {
		symbolBytes := uint64(symCount) * 18
		switch {
		case symCount > maxSymbols:
			addDiagnostic(Diagnostic{Severity: "error", Code: "symbol_count_limit", Detail: fmt.Sprintf("COFF object declares %d symbol records; parser limit is %d", symCount, maxSymbols)})
			symbolTableValid = false
		case symPtr == 0:
			addDiagnostic(Diagnostic{Severity: "error", Code: "symbol_table_pointer", Detail: "object declares symbols with a zero symbol-table pointer"})
			symbolTableValid = false
		case !rangeWithin(len(b), uint64(symPtr), symbolBytes):
			addDiagnostic(Diagnostic{Severity: "error", Code: "symbol_table_range", Detail: "symbol table extends beyond the file", Offset: uint64(symPtr)})
			symbolTableValid = false
		case uint64(symPtr) < sectionTableEnd:
			addDiagnostic(Diagnostic{Severity: "error", Code: "symbol_table_overlap_headers", Detail: "symbol table overlaps the COFF headers or section table", Offset: uint64(symPtr)})
			symbolTableValid = false
		}
		if symbolTableValid {
			stringTableStart := uint64(symPtr) + symbolBytes
			if !rangeWithin(len(b), stringTableStart, 4) {
				addDiagnostic(Diagnostic{Severity: "warning", Code: "string_table_missing", Detail: "COFF string-table length is missing", Offset: stringTableStart})
			} else {
				total := uint64(binary.LittleEndian.Uint32(b[stringTableStart : stringTableStart+4]))
				switch {
				case total < 4:
					addDiagnostic(Diagnostic{Severity: "error", Code: "string_table_length", Detail: fmt.Sprintf("COFF string-table length is %d; minimum is 4", total), Offset: stringTableStart})
				case !rangeWithin(len(b), stringTableStart, total):
					addDiagnostic(Diagnostic{Severity: "error", Code: "string_table_range", Detail: "COFF string table extends beyond the file", Offset: stringTableStart})
				default:
					stringTable = b[stringTableStart : stringTableStart+total]
				}
			}
		}
	}

	for i := range file.Sections {
		resolved, diagnostic := resolveSectionName(file.Sections[i], stringTable)
		file.Sections[i].Name = resolved
		if diagnostic != nil {
			addDiagnostic(*diagnostic)
		}
	}
	seenSections := map[string]bool{}
	for _, section := range file.Sections {
		if section.Name != "" && seenSections[section.Name] {
			addDiagnostic(Diagnostic{Severity: "warning", Code: "section_name_duplicate", Detail: "multiple sections use the same resolved name", Section: section.Name})
		}
		seenSections[section.Name] = true
	}

	symbolNamesByIndex := map[uint32]string{}
	auxIndexes := map[uint32]bool{}
	if symbolTableValid {
		for i := uint32(0); i < symCount; {
			off := uint64(symPtr) + uint64(i)*18
			raw := b[off : off+18]
			name, nameDiagnostic := resolveSymbolName(raw[:8], stringTable)
			if nameDiagnostic != nil {
				nameDiagnostic.Offset = off
				addDiagnostic(*nameDiagnostic)
			}
			value := binary.LittleEndian.Uint32(raw[8:12])
			sectionNumber := int16(binary.LittleEndian.Uint16(raw[12:14]))
			symbolType := binary.LittleEndian.Uint16(raw[14:16])
			storageClass := raw[16]
			aux := raw[17]
			symbol := Symbol{Index: i, Name: name, Value: value, SectionNumber: sectionNumber, Type: symbolType, StorageClass: storageClass, AuxSymbols: aux, External: storageClass == 2 || storageClass == 105}
			file.Symbols = append(file.Symbols, symbol)
			symbolNamesByIndex[i] = name
			if uint64(i)+1+uint64(aux) > uint64(symCount) {
				addDiagnostic(Diagnostic{Severity: "error", Code: "aux_symbol_range", Detail: fmt.Sprintf("symbol declares %d auxiliary records beyond the symbol table", aux), Symbol: name, Offset: off})
				break
			}
			for ai := uint32(1); ai <= uint32(aux); ai++ {
				auxIndexes[i+ai] = true
			}
			if sectionNumber > int16(sectionCount) || sectionNumber < -2 {
				addDiagnostic(Diagnostic{Severity: "error", Code: "symbol_section_range", Detail: fmt.Sprintf("symbol refers to invalid section number %d", sectionNumber), Symbol: name, Offset: off + 12})
			} else if sectionNumber > 0 {
				section := file.Sections[sectionNumber-1]
				if value > section.Size {
					addDiagnostic(Diagnostic{Severity: "error", Code: "symbol_value_range", Detail: fmt.Sprintf("symbol value 0x%x exceeds section size 0x%x", value, section.Size), Section: section.Name, Symbol: name, Offset: off + 8})
				}
			}
			i += 1 + uint32(aux)
		}
	}

	for si := range file.Sections {
		section := &file.Sections[si]
		if section.NumberOfRelocations == 0 || section.PointerToRelocations == 0 || !rangeWithin(len(b), uint64(section.PointerToRelocations), uint64(section.NumberOfRelocations)*10) {
			continue
		}
		seenRelocations := map[string]bool{}
		for ri := 0; ri < int(section.NumberOfRelocations); ri++ {
			off := uint64(section.PointerToRelocations) + uint64(ri)*10
			symIdx := binary.LittleEndian.Uint32(b[off+4 : off+8])
			rel := Relocation{
				Section:          section.Name,
				VirtualAddress:   binary.LittleEndian.Uint32(b[off : off+4]),
				SymbolTableIndex: symIdx,
				Type:             binary.LittleEndian.Uint16(b[off+8 : off+10]),
			}
			rel.TypeName = RelocationTypeName(machineName, rel.Type)
			if name, ok := symbolNamesByIndex[symIdx]; ok {
				rel.SymbolName = name
			}
			switch {
			case symIdx >= symCount:
				addDiagnostic(Diagnostic{Severity: "error", Code: "relocation_symbol_range", Detail: fmt.Sprintf("relocation refers to symbol index %d but table has %d records", symIdx, symCount), Section: section.Name, Offset: off + 4})
			case auxIndexes[symIdx]:
				addDiagnostic(Diagnostic{Severity: "error", Code: "relocation_aux_symbol", Detail: "relocation refers to an auxiliary symbol record", Section: section.Name, Offset: off + 4})
			}
			width := relocationWidth(machineName, rel.Type)
			if width > 0 && (uint64(rel.VirtualAddress) > uint64(section.Size) || width > uint64(section.Size)-minUint64(uint64(rel.VirtualAddress), uint64(section.Size))) {
				addDiagnostic(Diagnostic{Severity: "error", Code: "relocation_offset_range", Detail: fmt.Sprintf("%s relocation at 0x%x needs %d bytes in a section of size 0x%x", rel.TypeName, rel.VirtualAddress, width, section.Size), Section: section.Name, Symbol: rel.SymbolName, Offset: off})
			}
			key := fmt.Sprintf("%x:%d:%x", rel.VirtualAddress, symIdx, rel.Type)
			if seenRelocations[key] {
				addDiagnostic(Diagnostic{Severity: "warning", Code: "relocation_duplicate", Detail: "duplicate relocation record", Section: section.Name, Symbol: rel.SymbolName, Offset: off})
			}
			seenRelocations[key] = true
			section.Relocations = append(section.Relocations, rel)
		}
	}
	return file, nil
}

func RelocationTypeName(machine string, typ uint16) string {
	if machine == "x64" {
		relocation, _ := capability.WindowsCOFF().RelocationByCode(typ)
		return relocation.Name
	}
	return fmt.Sprintf("0x%04x", typ)
}

func rangeWithin(total int, offset, size uint64) bool {
	return offset <= uint64(total) && size <= uint64(total)-offset
}

func sectionAlignment(characteristics uint32) uint32 {
	code := (characteristics & sectionAlignMask) >> 20
	if code == 0 || code >= 15 {
		return 0
	}
	return uint32(1) << (code - 1)
}

func displaySection(section Section) string {
	if section.Name != "" {
		return section.Name
	}
	return fmt.Sprintf("#%d", section.Index)
}

func resolveSectionName(section Section, stringTable []byte) (string, *Diagnostic) {
	raw := section.RawName
	if !strings.HasPrefix(raw, "/") || raw == "/" {
		return raw, nil
	}
	offset, err := strconv.ParseUint(strings.TrimPrefix(raw, "/"), 10, 32)
	if err != nil {
		return raw, &Diagnostic{Severity: "error", Code: "section_name_encoding", Detail: fmt.Sprintf("long section name %q does not contain a decimal string-table offset", raw), Section: displaySection(section), Offset: uint64(20 + (section.Index-1)*40)}
	}
	name, ok := stringAt(stringTable, uint32(offset))
	if !ok {
		return raw, &Diagnostic{Severity: "error", Code: "section_name_offset", Detail: fmt.Sprintf("long section name offset %d is outside the COFF string table", offset), Section: displaySection(section), Offset: uint64(20 + (section.Index-1)*40)}
	}
	return name, nil
}

func resolveSymbolName(raw, stringTable []byte) (string, *Diagnostic) {
	if len(raw) != 8 {
		return "", &Diagnostic{Severity: "error", Code: "symbol_name_record", Detail: "symbol name record is not 8 bytes"}
	}
	if binary.LittleEndian.Uint32(raw[:4]) == 0 {
		offset := binary.LittleEndian.Uint32(raw[4:])
		name, ok := stringAt(stringTable, offset)
		if !ok {
			return fmt.Sprintf("<bad-string-%d>", offset), &Diagnostic{Severity: "error", Code: "symbol_name_offset", Detail: fmt.Sprintf("symbol name offset %d is outside the COFF string table", offset)}
		}
		return name, nil
	}
	name := strings.TrimRight(string(raw), "\x00")
	if name == "" {
		return name, &Diagnostic{Severity: "warning", Code: "symbol_name_empty", Detail: "symbol name is empty"}
	}
	return name, nil
}

func stringAt(stringTable []byte, offset uint32) (string, bool) {
	if offset < 4 || uint64(offset) >= uint64(len(stringTable)) {
		return "", false
	}
	end := int(offset)
	for end < len(stringTable) && stringTable[end] != 0 {
		end++
	}
	if end == len(stringTable) {
		return "", false
	}
	return string(stringTable[offset:end]), true
}

func relocationWidth(machine string, typ uint16) uint64 {
	if machine == "x64" {
		switch typ {
		case 0x0000:
			return 0
		case 0x0001:
			return 8
		case 0x000b:
			return 2
		case 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000c:
			return 4
		default:
			return 1
		}
	}
	switch typ {
	case 0x0000:
		return 0
	case 0x0006, 0x0014:
		return 4
	default:
		return 1
	}
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func ExtractStrings(b []byte, min int) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) >= min {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			cur = append(cur, c)
			continue
		}
		flush()
	}
	flush()
	if len(out) > 200 {
		return out[:200]
	}
	return out
}

func machineString(machine uint16) string {
	switch machine {
	case MachineX64:
		return "x64"
	case MachineX86:
		return "x86"
	default:
		return "unknown"
	}
}

type mockSymbol struct {
	Name          string
	SectionNumber int16
	External      bool
}

type stringTable struct {
	data bytes.Buffer
	seen map[string]uint32
}

func newStringTable() *stringTable {
	st := &stringTable{seen: map[string]uint32{}}
	st.data.Write([]byte{0, 0, 0, 0})
	return st
}

func (st *stringTable) add(s string) uint32 {
	if off, ok := st.seen[s]; ok {
		return off
	}
	off := uint32(st.data.Len())
	st.data.WriteString(s)
	st.data.WriteByte(0)
	st.seen[s] = off
	return off
}

func (st *stringTable) bytes() []byte {
	b := st.data.Bytes()
	binary.LittleEndian.PutUint32(b[:4], uint32(len(b)))
	return b
}

func writeSymbol(buf *bytes.Buffer, sym mockSymbol, st *stringTable) {
	if len(sym.Name) <= 8 {
		name := [8]byte{}
		copy(name[:], []byte(sym.Name))
		buf.Write(name[:])
	} else {
		writeU32(buf, 0)
		writeU32(buf, st.add(sym.Name))
	}
	writeU32(buf, 0)
	writeU16(buf, uint16(sym.SectionNumber))
	writeU16(buf, 0x20)
	if sym.External {
		buf.WriteByte(2)
	} else {
		buf.WriteByte(3)
	}
	buf.WriteByte(0)
}

func writeU16(w io.Writer, v uint16) { _ = binary.Write(w, binary.LittleEndian, v) }
func writeU32(w io.Writer, v uint32) { _ = binary.Write(w, binary.LittleEndian, v) }
