package coff

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

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
