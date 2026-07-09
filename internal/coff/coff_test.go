package coff

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestInspectMalformedCOFFDiagnostics(t *testing.T) {
	tests := []struct {
		name string
		code string
		make func(t *testing.T, path string)
	}{
		{
			name: "truncated section table",
			code: "section_table_range",
			make: func(t *testing.T, path string) {
				b := make([]byte, 20)
				binary.LittleEndian.PutUint16(b[0:2], MachineX64)
				binary.LittleEndian.PutUint16(b[2:4], 1)
				writeFixture(t, path, b)
			},
		},
		{
			name: "section data range",
			code: "section_data_range",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) { binary.LittleEndian.PutUint32(b[40:44], uint32(len(b)-2)) })
			},
		},
		{
			name: "section data overlaps headers",
			code: "section_data_overlap_headers",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) { binary.LittleEndian.PutUint32(b[40:44], 20) })
			},
		},
		{
			name: "initialized section missing data",
			code: "section_data_missing",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) {
					binary.LittleEndian.PutUint32(b[28:32], 8)
					binary.LittleEndian.PutUint32(b[36:40], 0)
				})
			},
		},
		{
			name: "mapped image limit",
			code: "image_size_limit",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) {
					binary.LittleEndian.PutUint32(b[36:40], ^uint32(0))
					binary.LittleEndian.PutUint32(b[56:60], binary.LittleEndian.Uint32(b[56:60])|0x80)
				})
			},
		},
		{
			name: "relocation count limit",
			code: "relocation_count_limit",
			make: func(t *testing.T, path string) {
				const sections = 17
				b := make([]byte, 20+sections*40)
				binary.LittleEndian.PutUint16(b[0:2], MachineX64)
				binary.LittleEndian.PutUint16(b[2:4], sections)
				for index := 0; index < sections; index++ {
					offset := 20 + index*40
					binary.LittleEndian.PutUint16(b[offset+32:offset+34], ^uint16(0))
				}
				writeFixture(t, path, b)
			},
		},
		{
			name: "reserved section alignment",
			code: "section_alignment_reserved",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) {
					characteristics := binary.LittleEndian.Uint32(b[56:60])
					binary.LittleEndian.PutUint32(b[56:60], characteristics|sectionAlignMask)
				})
			},
		},
		{
			name: "relocation table range",
			code: "relocation_table_range",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, []MockRelocation{{Symbol: "BeaconPrintf", Type: 0x0004}})
				mutateFixture(t, path, func(b []byte) { binary.LittleEndian.PutUint32(b[44:48], uint32(len(b)-2)) })
			},
		},
		{
			name: "symbol table range",
			code: "symbol_table_range",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) { binary.LittleEndian.PutUint32(b[8:12], uint32(len(b)-4)) })
			},
		},
		{
			name: "string table range",
			code: "string_table_range",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) {
					symbols := binary.LittleEndian.Uint32(b[12:16])
					start := binary.LittleEndian.Uint32(b[8:12]) + symbols*18
					binary.LittleEndian.PutUint32(b[start:start+4], uint32(len(b)))
				})
			},
		},
		{
			name: "aux symbol range",
			code: "aux_symbol_range",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) {
					start := binary.LittleEndian.Uint32(b[8:12])
					b[start+17] = 2
				})
			},
		},
		{
			name: "symbol section range",
			code: "symbol_section_range",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) {
					start := binary.LittleEndian.Uint32(b[8:12])
					binary.LittleEndian.PutUint16(b[start+12:start+14], 7)
				})
			},
		},
		{
			name: "symbol value range",
			code: "symbol_value_range",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) {
					start := binary.LittleEndian.Uint32(b[8:12])
					binary.LittleEndian.PutUint32(b[start+8:start+12], 99)
				})
			},
		},
		{
			name: "relocation symbol range",
			code: "relocation_symbol_range",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, []MockRelocation{{Symbol: "BeaconPrintf", Type: 0x0004}})
				mutateFixture(t, path, func(b []byte) {
					start := binary.LittleEndian.Uint32(b[44:48])
					binary.LittleEndian.PutUint32(b[start+4:start+8], 99)
				})
			},
		},
		{
			name: "relocation offset range",
			code: "relocation_offset_range",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, []MockRelocation{{Symbol: "BeaconPrintf", Type: 0x0004}})
				mutateFixture(t, path, func(b []byte) {
					start := binary.LittleEndian.Uint32(b[44:48])
					binary.LittleEndian.PutUint32(b[start:start+4], 99)
				})
			},
		},
		{
			name: "section name offset",
			code: "section_name_offset",
			make: func(t *testing.T, path string) {
				createMockFixture(t, path, nil)
				mutateFixture(t, path, func(b []byte) { copy(b[20:28], []byte("/999\x00\x00\x00\x00")) })
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fixture.o")
			test.make(t, path)
			file, err := Inspect(path)
			if err != nil {
				t.Fatal(err)
			}
			if file.LayoutValid || !hasDiagnostic(file.Diagnostics, test.code) {
				t.Fatalf("expected %s diagnostic: valid=%t diagnostics=%+v", test.code, file.LayoutValid, file.Diagnostics)
			}
		})
	}
}

func TestInspectRejectsFileAboveResourceLimitWithoutReadingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.o")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxCOFFFileSize + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(path); err == nil {
		t.Fatal("expected oversized COFF object rejection")
	}
}

func TestInspectStrippedAndLongSectionNames(t *testing.T) {
	t.Run("stripped", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "stripped.o")
		createMockFixture(t, path, nil)
		mutateFixture(t, path, func(b []byte) {
			binary.LittleEndian.PutUint32(b[8:12], 0)
			binary.LittleEndian.PutUint32(b[12:16], 0)
		})
		file, err := Inspect(path)
		if err != nil {
			t.Fatal(err)
		}
		if !file.LayoutValid || !hasDiagnostic(file.Diagnostics, "symbol_table_stripped") {
			t.Fatalf("stripped object diagnostics = %+v", file.Diagnostics)
		}
	})

	t.Run("long section", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "long-section.o")
		if err := CreateMockObject(path, "x64", "go", []string{"LongSectionName"}); err != nil {
			t.Fatal(err)
		}
		mutateFixture(t, path, func(b []byte) { copy(b[20:28], []byte("/4\x00\x00\x00\x00\x00\x00")) })
		file, err := Inspect(path)
		if err != nil {
			t.Fatal(err)
		}
		if !file.LayoutValid || len(file.Sections) != 1 || file.Sections[0].Name != "LongSectionName" {
			t.Fatalf("long section resolution = %+v diagnostics=%+v", file.Sections, file.Diagnostics)
		}
	})

	t.Run("unusual valid alignment", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "aligned.o")
		createMockFixture(t, path, nil)
		mutateFixture(t, path, func(b []byte) {
			characteristics := binary.LittleEndian.Uint32(b[56:60]) &^ sectionAlignMask
			binary.LittleEndian.PutUint32(b[56:60], characteristics|0x00e00000)
		})
		file, err := Inspect(path)
		if err != nil {
			t.Fatal(err)
		}
		if !file.LayoutValid || file.Sections[0].Alignment != 8192 {
			t.Fatalf("valid unusual alignment = %+v diagnostics=%+v", file.Sections[0], file.Diagnostics)
		}
	})
}

func createMockFixture(t *testing.T, path string, relocations []MockRelocation) {
	t.Helper()
	if err := CreateMockObjectWithRelocations(path, "x64", "go", []string{"BeaconPrintf"}, relocations); err != nil {
		t.Fatal(err)
	}
}

func mutateFixture(t *testing.T, path string, mutate func([]byte)) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutate(b)
	writeFixture(t, path, b)
}

func writeFixture(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasDiagnostic(diagnostics []Diagnostic, code string) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code {
			return true
		}
	}
	return false
}

func TestInspectMockObject(t *testing.T) {
	obj := filepath.Join(t.TempDir(), "demo.o")
	if err := CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(obj)
	if err != nil {
		t.Fatal(err)
	}
	if info.Machine != "x64" {
		t.Fatalf("machine = %s", info.Machine)
	}
	if len(info.Symbols) == 0 {
		t.Fatal("expected symbols")
	}
}

func TestInspectRelocationsFromRealCOFF(t *testing.T) {
	cc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("mingw compiler not available")
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "reloc.c")
	obj := filepath.Join(tmp, "reloc.o")
	if err := osWriteFile(src, []byte("extern void external_call(void); void go(void) { external_call(); }\n")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-c", src, "-o", obj)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile failed: %v\n%s", err, out)
	}
	info, err := Inspect(obj)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, section := range info.Sections {
		if len(section.Relocations) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected at least one relocation")
	}
}

func osWriteFile(path string, b []byte) error {
	return os.WriteFile(path, b, 0o644)
}

func FuzzInspectCOFFNeverPanics(f *testing.F) {
	seedPath := filepath.Join(f.TempDir(), "seed.o")
	if err := CreateMockObject(seedPath, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		f.Fatal(err)
	}
	valid, err := os.ReadFile(seedPath)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add(make([]byte, 20))
	f.Add(valid)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		path := filepath.Join(t.TempDir(), "fuzz.o")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = Inspect(path)
	})
}
