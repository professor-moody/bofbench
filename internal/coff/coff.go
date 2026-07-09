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
	"strings"
)

const (
	MachineX86 = 0x014c
	MachineX64 = 0x8664

	sectionExecutable = 0x20000000
	sectionReadable   = 0x40000000
	sectionWritable   = 0x80000000
)

type File struct {
	Path             string    `json:"path"`
	Size             int64     `json:"size"`
	SHA256           string    `json:"sha256"`
	Machine          string    `json:"machine"`
	NumberOfSections int       `json:"number_of_sections"`
	Sections         []Section `json:"sections"`
	Symbols          []Symbol  `json:"symbols"`
	Strings          []string  `json:"strings,omitempty"`
}

type Section struct {
	Name                 string       `json:"name"`
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
}

type Symbol struct {
	Name          string `json:"name"`
	Value         uint32 `json:"value"`
	SectionNumber int16  `json:"section_number"`
	StorageClass  uint8  `json:"storage_class"`
	External      bool   `json:"external"`
}

type Relocation struct {
	Section          string `json:"section"`
	VirtualAddress   uint32 `json:"virtual_address"`
	SymbolTableIndex uint32 `json:"symbol_table_index"`
	Type             uint16 `json:"type"`
	TypeName         string `json:"type_name"`
	SymbolName       string `json:"symbol_name,omitempty"`
}

func CreateMockObject(path, arch, entrypoint string, unresolved []string) error {
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
	rawData := []byte{0xc3}
	symPtr := rawPtr + uint32(len(rawData))
	stringTable := newStringTable()

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
	writeU32(&buf, 0)
	writeU32(&buf, 0)
	writeU16(&buf, 0)
	writeU16(&buf, 0)
	writeU32(&buf, 0x00000020|sectionExecutable|sectionReadable)
	buf.Write(rawData)

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
	r := bytes.NewReader(b)
	machine := readU16(r)
	sectionCount := readU16(r)
	_ = readU32(r)
	symPtr := readU32(r)
	symCount := readU32(r)
	optionalHeaderSize := readU16(r)
	_ = readU16(r)
	if optionalHeaderSize != 0 {
		return nil, fmt.Errorf("COFF object should not have optional header, got %d bytes", optionalHeaderSize)
	}
	machineName := machineString(machine)
	if machineName == "unknown" {
		return nil, fmt.Errorf("unsupported COFF machine 0x%x", machine)
	}
	sections := make([]Section, 0, sectionCount)
	for i := 0; i < int(sectionCount); i++ {
		if r.Len() < 40 {
			return nil, fmt.Errorf("truncated section table")
		}
		rawName := make([]byte, 8)
		_, _ = io.ReadFull(r, rawName)
		name := strings.TrimRight(string(bytes.TrimRight(rawName, "\x00")), "\x00")
		_ = readU32(r)
		_ = readU32(r)
		size := readU32(r)
		rawPtr := readU32(r)
		relocPtr := readU32(r)
		_ = readU32(r)
		numRelocs := readU16(r)
		_ = readU16(r)
		ch := readU32(r)
		var data []byte
		if size > 0 && rawPtr > 0 && int(rawPtr+size) <= len(b) {
			data = append([]byte(nil), b[rawPtr:rawPtr+size]...)
		}
		sections = append(sections, Section{
			Name:                 name,
			Size:                 size,
			PointerToRawData:     rawPtr,
			PointerToRelocations: relocPtr,
			NumberOfRelocations:  numRelocs,
			Characteristics:      ch,
			Data:                 data,
			Executable:           ch&sectionExecutable != 0,
			Readable:             ch&sectionReadable != 0,
			Writable:             ch&sectionWritable != 0,
		})
	}
	if int(symPtr) > len(b) {
		return nil, fmt.Errorf("symbol table pointer is outside file")
	}
	stringTableStart := int(symPtr) + int(symCount)*18
	stringTable := []byte(nil)
	if stringTableStart+4 <= len(b) {
		total := int(binary.LittleEndian.Uint32(b[stringTableStart:]))
		if total >= 4 && stringTableStart+total <= len(b) {
			stringTable = b[stringTableStart : stringTableStart+total]
		}
	}
	var symbols []Symbol
	symbolNamesByIndex := map[int]string{}
	for i := 0; i < int(symCount); i++ {
		off := int(symPtr) + i*18
		if off+18 > len(b) {
			return nil, fmt.Errorf("truncated symbol table")
		}
		name := symbolName(b[off:off+8], stringTable)
		symbolNamesByIndex[i] = name
		value := binary.LittleEndian.Uint32(b[off+8 : off+12])
		sectionNumber := int16(binary.LittleEndian.Uint16(b[off+12 : off+14]))
		storageClass := b[off+16]
		aux := int(b[off+17])
		symbols = append(symbols, Symbol{
			Name:          name,
			Value:         value,
			SectionNumber: sectionNumber,
			StorageClass:  storageClass,
			External:      storageClass == 2,
		})
		i += aux
	}
	for si := range sections {
		section := &sections[si]
		for ri := 0; ri < int(section.NumberOfRelocations); ri++ {
			off := int(section.PointerToRelocations) + ri*10
			if off+10 > len(b) {
				return nil, fmt.Errorf("truncated relocation table for section %s", section.Name)
			}
			symIdx := binary.LittleEndian.Uint32(b[off+4 : off+8])
			rel := Relocation{
				Section:          section.Name,
				VirtualAddress:   binary.LittleEndian.Uint32(b[off : off+4]),
				SymbolTableIndex: symIdx,
				Type:             binary.LittleEndian.Uint16(b[off+8 : off+10]),
			}
			rel.TypeName = RelocationTypeName(machineName, rel.Type)
			if name, ok := symbolNamesByIndex[int(symIdx)]; ok {
				rel.SymbolName = name
			}
			section.Relocations = append(section.Relocations, rel)
		}
	}
	return &File{
		Path:             path,
		Size:             int64(len(b)),
		SHA256:           hex.EncodeToString(sum[:]),
		Machine:          machineName,
		NumberOfSections: int(sectionCount),
		Sections:         sections,
		Symbols:          symbols,
		Strings:          ExtractStrings(b, 4),
	}, nil
}

func RelocationTypeName(machine string, typ uint16) string {
	if machine == "x64" {
		switch typ {
		case 0x0000:
			return "ABSOLUTE"
		case 0x0001:
			return "ADDR64"
		case 0x0002:
			return "ADDR32"
		case 0x0003:
			return "ADDR32NB"
		case 0x0004:
			return "REL32"
		case 0x0005:
			return "REL32_1"
		case 0x0006:
			return "REL32_2"
		case 0x0007:
			return "REL32_3"
		case 0x0008:
			return "REL32_4"
		case 0x0009:
			return "REL32_5"
		case 0x000b:
			return "SECTION"
		case 0x000c:
			return "SECREL"
		default:
			return fmt.Sprintf("AMD64_0x%04x", typ)
		}
	}
	return fmt.Sprintf("0x%04x", typ)
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

func symbolName(raw []byte, st []byte) string {
	if len(raw) != 8 {
		return ""
	}
	if binary.LittleEndian.Uint32(raw[:4]) == 0 {
		off := int(binary.LittleEndian.Uint32(raw[4:]))
		if off >= 4 && off < len(st) {
			end := off
			for end < len(st) && st[end] != 0 {
				end++
			}
			return string(st[off:end])
		}
	}
	return strings.TrimRight(string(raw), "\x00")
}

func writeU16(w io.Writer, v uint16) { _ = binary.Write(w, binary.LittleEndian, v) }
func writeU32(w io.Writer, v uint32) { _ = binary.Write(w, binary.LittleEndian, v) }

func readU16(r io.Reader) uint16 {
	var v uint16
	_ = binary.Read(r, binary.LittleEndian, &v)
	return v
}

func readU32(r io.Reader) uint32 {
	var v uint32
	_ = binary.Read(r, binary.LittleEndian, &v)
	return v
}
