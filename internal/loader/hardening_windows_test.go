//go:build windows

package loader

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"bofbench/internal/coff"
)

type nativeCorpusCase struct {
	name      string
	data      []byte
	entry     string
	exitState string
	errorCode string
}

func TestNativeLoaderRejectsMalformedCorpusWithoutUnknownTermination(t *testing.T) {
	loaderPath := nativeLoaderTestPath(t)
	base := nativeTestObject(t, false)
	relocated := nativeTestObject(t, true)
	symbolOffset := binary.LittleEndian.Uint32(base[8:12])
	relocationOffset := binary.LittleEndian.Uint32(relocated[44:48])
	relocatedSymbolOffset := binary.LittleEndian.Uint32(relocated[8:12])

	cases := []nativeCorpusCase{
		{name: "truncated_header", data: append([]byte(nil), base[:12]...), exitState: "validation_error", errorCode: "header_range"},
		{name: "wrong_arch", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint16(value[0:2], coff.MachineX86) }), exitState: "bad_arch", errorCode: "unsupported_machine"},
		{name: "optional_header", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint16(value[16:18], 8) }), exitState: "bad_object", errorCode: "optional_header"},
		{name: "empty_sections", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint16(value[2:4], 0) }), exitState: "validation_error", errorCode: "section_table_empty"},
		{name: "section_count_limit", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint16(value[2:4], 4097) }), exitState: "validation_error", errorCode: "section_count_limit"},
		{name: "section_table_range", data: mutateNative(base[:20], func(value []byte) { binary.LittleEndian.PutUint16(value[2:4], 1) }), exitState: "validation_error", errorCode: "section_table_range"},
		{name: "section_data_pointer", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint32(value[40:44], 0) }), exitState: "validation_error", errorCode: "section_data_pointer"},
		{name: "section_data_range", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint32(value[40:44], uint32(len(value)-2)) }), exitState: "validation_error", errorCode: "section_data_range"},
		{name: "section_data_overlap", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint32(value[40:44], 20) }), exitState: "validation_error", errorCode: "section_data_overlap_headers"},
		{name: "section_data_missing", data: mutateNative(base, func(value []byte) {
			binary.LittleEndian.PutUint32(value[28:32], 8)
			binary.LittleEndian.PutUint32(value[36:40], 0)
		}), exitState: "validation_error", errorCode: "section_data_missing"},
		{name: "image_size_limit", data: mutateNative(base, func(value []byte) {
			binary.LittleEndian.PutUint32(value[36:40], ^uint32(0))
			binary.LittleEndian.PutUint32(value[56:60], binary.LittleEndian.Uint32(value[56:60])|0x80)
		}), exitState: "validation_error", errorCode: "image_size_limit"},
		{name: "relocation_pointer", data: mutateNative(relocated, func(value []byte) { binary.LittleEndian.PutUint32(value[44:48], 0) }), exitState: "validation_error", errorCode: "relocation_table_pointer"},
		{name: "relocation_range", data: mutateNative(relocated, func(value []byte) { binary.LittleEndian.PutUint32(value[44:48], uint32(len(value)-2)) }), exitState: "validation_error", errorCode: "relocation_table_range"},
		{name: "relocation_overlap", data: mutateNative(relocated, func(value []byte) { binary.LittleEndian.PutUint32(value[44:48], 20) }), exitState: "validation_error", errorCode: "relocation_table_overlap_headers"},
		{name: "symbol_count_limit", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint32(value[12:16], (1<<20)+1) }), exitState: "validation_error", errorCode: "symbol_count_limit"},
		{name: "symbol_pointer", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint32(value[8:12], 0) }), exitState: "validation_error", errorCode: "symbol_table_pointer"},
		{name: "symbol_range", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint32(value[8:12], uint32(len(value)-4)) }), exitState: "validation_error", errorCode: "symbol_table_range"},
		{name: "symbol_overlap", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint32(value[8:12], 20) }), exitState: "validation_error", errorCode: "symbol_table_overlap_headers"},
		{name: "string_length", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint32(value[symbolOffset+18:symbolOffset+22], 3) }), exitState: "validation_error", errorCode: "string_table_length"},
		{name: "string_range", data: mutateNative(base, func(value []byte) {
			binary.LittleEndian.PutUint32(value[symbolOffset+18:symbolOffset+22], uint32(len(value)))
		}), exitState: "validation_error", errorCode: "string_table_range"},
		{name: "symbol_name_offset", data: mutateNative(base, func(value []byte) {
			for index := 0; index < 8; index++ {
				value[int(symbolOffset)+index] = 0
			}
			binary.LittleEndian.PutUint32(value[symbolOffset+4:symbolOffset+8], 99)
		}), exitState: "validation_error", errorCode: "symbol_name_offset"},
		{name: "symbol_name_termination", data: unterminatedNativeSymbol(base, symbolOffset), exitState: "validation_error", errorCode: "symbol_name_termination"},
		{name: "aux_symbol_range", data: mutateNative(base, func(value []byte) { value[symbolOffset+17] = 1 }), exitState: "validation_error", errorCode: "aux_symbol_range"},
		{name: "symbol_section_range", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint16(value[symbolOffset+12:symbolOffset+14], 7) }), exitState: "validation_error", errorCode: "symbol_section_range"},
		{name: "symbol_value_range", data: mutateNative(base, func(value []byte) { binary.LittleEndian.PutUint32(value[symbolOffset+8:symbolOffset+12], 9) }), exitState: "validation_error", errorCode: "symbol_value_range"},
		{name: "relocation_symbol_range", data: mutateNative(relocated, func(value []byte) { binary.LittleEndian.PutUint32(value[relocationOffset+4:relocationOffset+8], 99) }), exitState: "validation_error", errorCode: "relocation_symbol_range"},
		{name: "relocation_aux_symbol", data: mutateNative(relocated, func(value []byte) { value[relocatedSymbolOffset+17] = 1 }), exitState: "validation_error", errorCode: "relocation_aux_symbol"},
		{name: "unsupported_relocation", data: mutateNative(relocated, func(value []byte) {
			binary.LittleEndian.PutUint16(value[relocationOffset+8:relocationOffset+10], 0xffff)
		}), exitState: "validation_error", errorCode: "unsupported_relocation"},
		{name: "relocation_offset_range", data: mutateNative(relocated, func(value []byte) { binary.LittleEndian.PutUint32(value[relocationOffset:relocationOffset+4], 99) }), exitState: "validation_error", errorCode: "relocation_offset_range"},
		{name: "entrypoint_nonexecutable", data: mutateNative(base, func(value []byte) {
			binary.LittleEndian.PutUint32(value[56:60], binary.LittleEndian.Uint32(value[56:60])&^uint32(0x20000000))
		}), entry: "go", exitState: "entry_invalid", errorCode: "entrypoint_section_nonexec"},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			entry := test.entry
			if entry == "" {
				entry = "__missing_entry__"
			}
			result := runNativeCorpusCase(t, loaderPath, test.data, entry)
			if result.ExitState != test.exitState || result.ErrorCode != test.errorCode {
				t.Fatalf("result = %+v, want exit=%s code=%s", result, test.exitState, test.errorCode)
			}
		})
	}

	t.Run("valid_sanity", func(t *testing.T) {
		result := runNativeCorpusCase(t, loaderPath, base, "go")
		if result.Status != "pass" || result.ExitState != "success" || result.Memory == nil || result.Memory.InitialProtection != "readwrite" || result.Memory.StubRegion.Protection != "execute_read" || result.Memory.WritableExecutableSections != 0 {
			t.Fatalf("valid object = %+v", result)
		}
		if len(result.Memory.Sections) != 1 || result.Memory.Sections[0].Protection != "execute_read" {
			t.Fatalf("valid object section memory = %+v", result.Memory)
		}
	})
}

func TestNativeLoaderMetadataMutationsHaveKnownTerminalState(t *testing.T) {
	loaderPath := nativeLoaderTestPath(t)
	base := nativeTestObject(t, false)
	limit := 60
	if len(base) < limit {
		limit = len(base)
	}
	for index := 0; index < limit; index++ {
		for variant, mask := range []byte{0x00, 0xff, 0x5a} {
			mutated := append([]byte(nil), base...)
			if variant == 2 {
				mutated[index] ^= mask
			} else {
				mutated[index] = mask
			}
			result := runNativeCorpusCase(t, loaderPath, mutated, "__missing_entry__")
			switch result.ExitState {
			case "validation_error", "bad_arch", "bad_object", "entry_missing", "relocation_error":
			default:
				t.Fatalf("mutation byte=%d variant=%d produced unknown terminal state: %+v", index, variant, result)
			}
			if result.Status != "fail" || result.ErrorCode == "" {
				t.Fatalf("mutation byte=%d variant=%d missing classified failure: %+v", index, variant, result)
			}
		}
	}
}

func TestLoaderRunClassifiesWindowsException(t *testing.T) {
	loaderPath := nativeLoaderTestPath(t)
	object := filepath.Join(t.TempDir(), "crash.o")
	data := nativeTestObject(t, false)
	rawOffset := binary.LittleEndian.Uint32(data[40:44])
	copy(data[rawOffset:rawOffset+6], []byte{0x31, 0xc0, 0xc6, 0x00, 0x01, 0xc3})
	if err := os.WriteFile(object, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOFBENCH_LOADER", loaderPath)
	result, err := Run(Request{Object: object, Entry: "go", TimeoutMS: 2000})
	if err == nil {
		t.Fatal("expected loader process exception")
	}
	if result.Status != "fail" || result.ExitState != "crash" || result.ErrorCode != "windows_exception" || result.Process == nil || result.Process.ExceptionCode != "0xc0000005" || result.Memory == nil || result.Memory.StubRegion.Protection != "execute_read" {
		t.Fatalf("crash classification = %+v err=%v", result, err)
	}
}

func TestLoaderRunClassifiesTimeout(t *testing.T) {
	loaderPath := nativeLoaderTestPath(t)
	object := filepath.Join(t.TempDir(), "timeout.o")
	data := nativeTestObject(t, false)
	rawOffset := binary.LittleEndian.Uint32(data[40:44])
	copy(data[rawOffset:rawOffset+2], []byte{0xeb, 0xfe})
	if err := os.WriteFile(object, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOFBENCH_LOADER", loaderPath)
	result, err := Run(Request{Object: object, Entry: "go", TimeoutMS: 100})
	if err == nil {
		t.Fatal("expected loader timeout")
	}
	if result.Status != "fail" || result.ExitState != "timeout" || result.ErrorCode != "loader_timeout" || result.Process == nil || result.Memory == nil || result.Memory.StubRegion.Protection != "execute_read" {
		t.Fatalf("timeout classification = %+v err=%v", result, err)
	}
}

func nativeLoaderTestPath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "native", "loader", "bofbench-loader.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("native loader is not built: %v", err)
	}
	return path
}

func nativeTestObject(t *testing.T, withRelocation bool) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.o")
	var err error
	if withRelocation {
		err = coff.CreateMockObjectWithRelocations(path, "x64", "go", []string{"BeaconPrintf"}, []coff.MockRelocation{{VirtualAddress: 0, Symbol: "BeaconPrintf", Type: 0x0004}})
	} else {
		err = coff.CreateMockObject(path, "x64", "go", nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mutateNative(seed []byte, mutate func([]byte)) []byte {
	value := append([]byte(nil), seed...)
	mutate(value)
	return value
}

func unterminatedNativeSymbol(seed []byte, symbolOffset uint32) []byte {
	value := append([]byte(nil), seed...)
	for index := 0; index < 8; index++ {
		value[int(symbolOffset)+index] = 0
	}
	binary.LittleEndian.PutUint32(value[symbolOffset+4:symbolOffset+8], 4)
	stringOffset := int(symbolOffset) + 18
	value = append(value, 'A', 'B')
	binary.LittleEndian.PutUint32(value[stringOffset:stringOffset+4], 6)
	return value
}

func runNativeCorpusCase(t *testing.T, loaderPath string, data []byte, entry string) Result {
	t.Helper()
	object := filepath.Join(t.TempDir(), "case.o")
	if err := os.WriteFile(object, data, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, loaderPath, "--object", object, "--entry", entry, "--arg-hex", "")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("native loader timed out: %v", ctx.Err())
	}
	var result Result
	_, decoded := decodeLoaderOutput(output, &result)
	if !decoded {
		t.Fatalf("native loader returned invalid protocol output (err=%v): %s", err, output)
	}
	if result.ExitState == "crash" || result.ExitState == "loader_error" || result.ExitState == "loader_protocol_error" {
		t.Fatalf("native loader terminated unexpectedly (err=%v): %+v", err, result)
	}
	return result
}
