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
