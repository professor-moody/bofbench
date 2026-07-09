package capability

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsCOFFCatalogAndNormalization(t *testing.T) {
	catalog := WindowsCOFF()
	if catalog.CatalogVersion != "windows-coff-x64/v2" || catalog.Machine.Code != 0x8664 || catalog.SectionFlags.UninitializedData != 0x80 {
		t.Fatalf("catalog identity = %+v", catalog)
	}
	for _, name := range []string{"BeaconDataParse", "BeaconDataInt", "BeaconDataShort", "BeaconDataLength", "BeaconDataExtract", "BeaconPrintf", "BeaconOutput"} {
		if !catalog.SupportsBeaconAPI(name) || !catalog.SupportsBeaconAPI("__imp__"+name) {
			t.Fatalf("catalog does not support %s", name)
		}
	}
	if catalog.SupportsBeaconAPI("BeaconFormatAlloc") {
		t.Fatal("undeclared Beacon API reported supported")
	}
	if normalized, pointer := catalog.NormalizeImport("__imp__BeaconPrintf"); normalized != "BeaconPrintf" || !pointer {
		t.Fatalf("normalization = %q pointer=%t", normalized, pointer)
	}
	if relocation, declared := catalog.RelocationByCode(0x000c); !declared || relocation.Name != "SECREL" || relocation.Supported {
		t.Fatalf("SECREL capability = %+v declared=%t", relocation, declared)
	}
	if relocation, declared := catalog.RelocationByCode(0x0004); !declared || !relocation.Supported || relocation.Name != "REL32" {
		t.Fatalf("REL32 capability = %+v declared=%t", relocation, declared)
	}
}

func TestGeneratedNativeHeaderCHelpers(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler not available")
	}
	tmp := t.TempDir()
	source := filepath.Join(tmp, "capability_check.c")
	executable := filepath.Join(tmp, "capability_check")
	if strings.EqualFold(filepath.Ext(cc), ".exe") || filepath.Separator == '\\' {
		executable += ".exe"
	}
	body := `#include <stdint.h>
#include <string.h>
#include "capabilities.generated.h"
int main(void) {
    if (strcmp(bofbench_normalize_import("__imp__BeaconPrintf"), "BeaconPrintf") != 0) return 1;
    if (!bofbench_is_import_pointer_symbol("__imp__BeaconPrintf")) return 2;
    if (!bofbench_relocation_is_supported(REL_AMD64_REL32)) return 3;
    if (bofbench_relocation_is_supported(REL_AMD64_SECREL)) return 4;
    return 0;
}
`
	if err := os.WriteFile(source, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	include := filepath.Join("..", "..", "native", "loader")
	compile := exec.Command(cc, source, "-I", include, "-o", executable)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile generated C capability helper: %v\n%s", err, output)
	}
	if output, err := exec.Command(executable).CombinedOutput(); err != nil {
		t.Fatalf("run generated C capability helper: %v\n%s", err, output)
	}
}

func TestGeneratedNativeHeaderIsCurrent(t *testing.T) {
	want, err := NativeHeader(WindowsCOFF())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "native", "loader", "capabilities.generated.h")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is stale; run go generate ./internal/capability", path)
	}
	for _, text := range []string{"REL_AMD64_SECREL", "SECTION_CNT_UNINITIALIZED_DATA", "BOFBENCH_BEACON_API_LIST", "bofbench_normalize_import", "__imp__"} {
		if !strings.Contains(string(got), text) {
			t.Fatalf("generated header missing %q", text)
		}
	}
}
