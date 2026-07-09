package preflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bofbench/internal/coff"
	"bofbench/internal/evidence"
)

func TestRunArsenalCompatibilityMatrix(t *testing.T) {
	tmp := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	root := filepath.Join(tmp, "arsenal", "demo")
	fixtures := []struct {
		name       string
		unresolved []string
	}{
		{name: "blocked", unresolved: []string{"BeaconFormatAlloc"}},
		{name: "supported", unresolved: []string{"__imp__BeaconPrintf", "KERNEL32$VirtualAlloc"}},
		{name: "warning", unresolved: []string{"MissingExternal"}},
	}
	for _, fixture := range fixtures {
		object := filepath.Join(root, fixture.name, fixture.name+".x64.o")
		if err := coff.CreateMockObject(object, "x64", "go", fixture.unresolved); err != nil {
			t.Fatal(err)
		}
	}

	persisted, err := Run(Options{Path: root, Entrypoint: "go"})
	if err != nil {
		t.Fatal(err)
	}
	report := persisted.Report
	if report.Schema != evidence.SchemaPreflight || report.Status != "blocked" || report.Summary.Total != 3 || report.Summary.Compatible != 1 || report.Summary.RuntimeLookup != 1 || report.Summary.Blocked != 1 {
		t.Fatalf("report = %+v", report)
	}
	if report.RootFingerprint == nil || report.RootFingerprint.Files != 3 {
		t.Fatalf("root fingerprint = %+v", report.RootFingerprint)
	}
	if !report.HasProblems(false) || !report.HasProblems(true) {
		t.Fatalf("problem gate mismatch: %+v", report.Summary)
	}
	for _, path := range []string{persisted.JSONPath, persisted.MDPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing report %s: %v", path, err)
		}
	}
	text := Text(report)
	markdown := Markdown(report)
	for _, want := range []string{"supported", "compatible_runtime_lookup", "unsupported_beacon_api"} {
		if !strings.Contains(text, want) || !strings.Contains(markdown, want) {
			t.Fatalf("matrix output missing %q\ntext:\n%s\nmarkdown:\n%s", want, text, markdown)
		}
	}
}

func TestRunSelectionAndStrictWarning(t *testing.T) {
	tmp := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	root := filepath.Join(tmp, "arsenal", "demo")
	object := filepath.Join(root, "warning", "warning.x64.o")
	if err := coff.CreateMockObject(object, "x64", "go", []string{"MissingExternal"}); err != nil {
		t.Fatal(err)
	}
	persisted, err := Run(Options{Path: root, Select: "warning", Entrypoint: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Report.Status != "warn" || persisted.Report.Summary.Total != 1 || persisted.Report.HasProblems(false) || !persisted.Report.HasProblems(true) {
		t.Fatalf("strict warning gate = %+v", persisted.Report)
	}
}

func TestRunAllArchitectureAndArgumentDimensions(t *testing.T) {
	tmp := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	root := filepath.Join(tmp, "arsenal", "matrix")
	fixtures := []struct {
		name       string
		unresolved []string
		config     string
	}{
		{name: "configured", unresolved: []string{"BeaconDataParse"}, config: "entry = \"go\"\nargs = [\"z:target\"]\n"},
		{name: "required", unresolved: []string{"BeaconDataInt"}},
		{name: "noargs", unresolved: []string{"BeaconPrintf"}},
	}
	for _, fixture := range fixtures {
		dir := filepath.Join(root, fixture.name)
		if err := coff.CreateMockObject(filepath.Join(dir, fixture.name+".x64.o"), "x64", "go", fixture.unresolved); err != nil {
			t.Fatal(err)
		}
		if err := coff.CreateMockObject(filepath.Join(dir, fixture.name+".x86.o"), "x86", "_go@8", fixture.unresolved); err != nil {
			t.Fatal(err)
		}
		if fixture.config != "" {
			if err := os.WriteFile(filepath.Join(dir, "bofbench.toml"), []byte(fixture.config), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	persisted, err := Run(Options{Path: root, Arch: "all", Entrypoint: "go"})
	if err != nil {
		t.Fatal(err)
	}
	report := persisted.Report
	if report.Architecture != "all" || report.Status != "blocked" || report.Summary.Total != 6 || report.Summary.Compatible != 3 || report.Summary.Blocked != 3 {
		t.Fatalf("all-architecture report = %+v", report)
	}
	for key, want := range map[string]int{"x64": 3, "x86": 3} {
		if report.Summary.ByArchitecture[key] != want {
			t.Fatalf("architecture dimensions = %+v", report.Summary.ByArchitecture)
		}
	}
	if report.Summary.ByBlocker["unsupported_arch"] != 3 || len(report.Summary.ByBlocker) != 1 {
		t.Fatalf("blocker dimensions = %+v", report.Summary.ByBlocker)
	}
	for key, want := range map[string]int{"configured": 2, "required_unconfigured": 2, "none_observed": 2} {
		if report.Summary.ByArgumentNeed[key] != want {
			t.Fatalf("argument dimensions = %+v", report.Summary.ByArgumentNeed)
		}
	}
	for _, result := range report.Results {
		if result.Name == "configured" && result.ConfigFingerprint == nil {
			t.Fatalf("configured result missing config fingerprint: %+v", result)
		}
		if result.Arch == "x86" {
			if result.Entrypoint != "go" || !result.EntrypointOK || result.Status != "unsupported_arch" || result.Compatibility == nil || len(result.Compatibility.Blockers) != 1 {
				t.Fatalf("x86 result = %+v", result)
			}
		}
	}
	markdown := Markdown(report)
	text := Text(report)
	if !strings.Contains(markdown, "Architecture request: `all`") || !strings.Contains(text, "arch=[x64=3, x86=3]") {
		t.Fatalf("matrix architecture rendering missing\n%s\n%s", markdown, text)
	}
	for _, want := range []string{"unsupported_arch=3", "required_unconfigured=2"} {
		if !strings.Contains(markdown, want) || !strings.Contains(text, want) {
			t.Fatalf("matrix rendering missing %q\n%s\n%s", want, markdown, text)
		}
	}
	if _, err := Run(Options{Path: root, Arch: "arm64"}); err == nil {
		t.Fatal("expected invalid architecture error")
	}
}
