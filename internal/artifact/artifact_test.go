package artifact

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"bofbench/internal/coff"
	"bofbench/internal/evidence"
)

func TestAnalyzeCOFF(t *testing.T) {
	obj := filepath.Join(t.TempDir(), "demo.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf", "KERNEL32$VirtualAlloc"}); err != nil {
		t.Fatal(err)
	}
	a, err := Analyze(obj, "go")
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != KindCOFF || a.Arch != "x64" || !a.EntrypointOK {
		t.Fatalf("unexpected analysis: %+v", a)
	}
	if a.Schema != evidence.SchemaAnalysis || a.SchemaVersion != evidence.ContractVersion || a.Tool.Name != "bofbench" || a.Host.OS == "" {
		t.Fatalf("analysis evidence header = %+v", a.Header)
	}
	if len(a.Unresolved) == 0 {
		t.Fatal("expected unresolved symbol")
	}
	if !hasImport(a, "KERNEL32$VirtualAlloc", "winapi") {
		t.Fatalf("expected KERNEL32 VirtualAlloc import: %+v", a.Imports)
	}
	if !hasFinding(a, "memory_api") {
		t.Fatalf("expected memory API finding: %+v", a.Findings)
	}
	if !hasImport(a, "BeaconPrintf", "beacon_api") {
		t.Fatalf("expected Beacon API import: %+v", a.Imports)
	}
	if len(a.Strings) == 0 {
		t.Fatal("expected visible string summary")
	}
	if a.Runtime.Runtime != "windows-coff" || a.Runtime.RequiredOS != "windows" || a.Runtime.RequiredArch != "amd64" {
		t.Fatalf("unexpected runtime compatibility: %+v", a.Runtime)
	}
	if a.LoaderCompatibility == nil || !a.LoaderCompatibility.Compatible || a.LoaderCompatibility.Status != "compatible" {
		t.Fatalf("unexpected loader compatibility: %+v", a.LoaderCompatibility)
	}
	if runtime.GOOS == "windows" && runtime.GOARCH == "amd64" {
		if !a.Runtime.CanRun || a.Runtime.Status != "runnable" {
			t.Fatalf("expected runnable on Windows amd64: %+v", a.Runtime)
		}
	} else if a.Runtime.CanRun || a.Runtime.Status != "requires_windows_amd64" {
		t.Fatalf("expected requires_windows_amd64 off Windows amd64: %+v", a.Runtime)
	}
	md := Markdown(a)
	if !strings.Contains(md, "## Runtime Compatibility") || !strings.Contains(md, "windows-coff") {
		t.Fatalf("markdown missing runtime compatibility:\n%s", md)
	}
	if !strings.Contains(md, "## Findings") || !strings.Contains(md, "## Imports") || !strings.Contains(md, "VirtualAlloc") {
		t.Fatalf("markdown missing richer analysis:\n%s", md)
	}
}

func TestAnalyzeCOFFLoaderPreflight(t *testing.T) {
	t.Run("unsupported Beacon API", func(t *testing.T) {
		obj := filepath.Join(t.TempDir(), "beacon.o")
		if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconFormatAlloc"}); err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(obj, "go")
		if err != nil {
			t.Fatal(err)
		}
		assertLoaderIssue(t, a, "unsupported_beacon_api")
		if a.Runtime.Status != "unsupported_beacon_api" || a.Runtime.CanRun {
			t.Fatalf("runtime should honor preflight blocker: %+v", a.Runtime)
		}
	})

	t.Run("unsupported relocation", func(t *testing.T) {
		obj := filepath.Join(t.TempDir(), "secrel.o")
		if err := coff.CreateMockObjectWithRelocations(obj, "x64", "go", []string{"BeaconPrintf"}, []coff.MockRelocation{{Symbol: "BeaconPrintf", Type: 0x000c}}); err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(obj, "go")
		if err != nil {
			t.Fatal(err)
		}
		assertLoaderIssue(t, a, "unsupported_relocation")
		if len(a.RelocationDetails) != 1 || a.RelocationDetails[0].Code == nil || *a.RelocationDetails[0].Code != 0x000c || a.RelocationDetails[0].Type != "SECREL" {
			t.Fatalf("relocation evidence = %+v", a.RelocationDetails)
		}
	})

	t.Run("unsupported architecture", func(t *testing.T) {
		obj := filepath.Join(t.TempDir(), "x86.o")
		if err := coff.CreateMockObject(obj, "x86", "go", nil); err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(obj, "go")
		if err != nil {
			t.Fatal(err)
		}
		assertLoaderIssue(t, a, "unsupported_arch")
	})

	t.Run("fallback lookup warning", func(t *testing.T) {
		obj := filepath.Join(t.TempDir(), "lookup.o")
		if err := coff.CreateMockObject(obj, "x64", "go", []string{"MissingExternal"}); err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(obj, "go")
		if err != nil {
			t.Fatal(err)
		}
		if a.LoaderCompatibility == nil || !a.LoaderCompatibility.Compatible || a.LoaderCompatibility.Status != "compatible_runtime_lookup" || len(a.LoaderCompatibility.Warnings) != 1 {
			t.Fatalf("loader compatibility = %+v", a.LoaderCompatibility)
		}
	})

	t.Run("long import pointer prefix", func(t *testing.T) {
		obj := filepath.Join(t.TempDir(), "pointer.o")
		if err := coff.CreateMockObject(obj, "x64", "go", []string{"__imp__BeaconPrintf"}); err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(obj, "go")
		if err != nil {
			t.Fatal(err)
		}
		if !hasImport(a, "__imp__BeaconPrintf", "beacon_api") || a.LoaderCompatibility == nil || !a.LoaderCompatibility.Compatible {
			t.Fatalf("pointer import analysis = imports=%+v compatibility=%+v", a.Imports, a.LoaderCompatibility)
		}
	})
}

func assertLoaderIssue(t *testing.T, a Analysis, category string) {
	t.Helper()
	if a.LoaderCompatibility == nil || a.LoaderCompatibility.Compatible {
		t.Fatalf("expected loader blocker %s: %+v", category, a.LoaderCompatibility)
	}
	for _, issue := range a.LoaderCompatibility.Blockers {
		if issue.Category == category {
			return
		}
	}
	t.Fatalf("missing loader blocker %s: %+v", category, a.LoaderCompatibility.Blockers)
}

func TestAnalyzeCOFFRelocationDetailsWhenCompilerAvailable(t *testing.T) {
	cc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("mingw compiler not available")
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "reloc.c")
	obj := filepath.Join(tmp, "reloc.o")
	if err := os.WriteFile(src, []byte("extern void external_call(void); void go(void) { external_call(); }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-c", src, "-o", obj)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile failed: %v\n%s", err, out)
	}
	a, err := Analyze(obj, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.RelocationDetails) == 0 {
		t.Fatalf("expected relocation details: %+v", a)
	}
	found := false
	for _, rel := range a.RelocationDetails {
		if strings.Contains(rel.Symbol, "external_call") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected relocation symbol external_call: %+v", a.RelocationDetails)
	}
	md := Markdown(a)
	if !strings.Contains(md, "## Relocation Detail") {
		t.Fatalf("markdown missing relocation detail:\n%s", md)
	}
}

func TestCompareAnalysis(t *testing.T) {
	baseline := Analysis{
		Path:         "old.o",
		Kind:         KindCOFF,
		Arch:         "x64",
		Entrypoint:   "go",
		EntrypointOK: true,
		Size:         100,
		SHA256:       "old",
		Relocations:  1,
		Imports:      []Import{{Symbol: "BeaconPrintf", Category: "beacon_api"}},
		Findings:     []Finding{{Severity: "info", Category: "string", Detail: "old", Evidence: "old"}},
		Sections:     []Section{{Name: ".text", Size: 10, Relocations: 1, Flags: "R-X"}},
	}
	current := baseline
	current.Path = "new.o"
	current.SHA256 = "new"
	current.Size = 120
	current.Relocations = 2
	current.Imports = append(current.Imports, Import{Symbol: "KERNEL32$VirtualAlloc", Category: "winapi", Library: "KERNEL32", API: "VirtualAlloc"})
	current.Findings = append(current.Findings, Finding{Severity: "review", Category: "memory_api", Detail: "memory allocation/protection API imported", Evidence: "KERNEL32$VirtualAlloc"})
	current.Sections = []Section{{Name: ".text", Size: 12, Relocations: 2, Flags: "R-X"}}
	diff := CompareAnalysis(baseline, current)
	if diff.Schema != evidence.SchemaAnalysisDiff || diff.SchemaVersion != evidence.ContractVersion {
		t.Fatalf("diff evidence header = %+v", diff.Header)
	}
	if !diff.Summary.HashChanged || diff.Summary.SizeDelta != 20 || diff.Summary.RelocationsDelta != 1 {
		t.Fatalf("unexpected diff summary: %+v", diff.Summary)
	}
	if diff.Summary.ImportsAdded != 1 || diff.Summary.FindingsAdded != 1 {
		t.Fatalf("expected added import/finding: %+v", diff.Summary)
	}
	if !strings.Contains(DiffMarkdown(diff), "Analysis Diff") {
		t.Fatal("diff markdown missing title")
	}
}

func TestLoadLegacyAnalysisWithoutEvidenceHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "analysis.json")
	if err := os.WriteFile(path, []byte(`{"path":"legacy.o","kind":"coff","size":1,"entrypoint_ok":false,"relocations":0,"generated_at":"2026-07-09T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := LoadAnalysis(path)
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Path != "legacy.o" || analysis.Kind != KindCOFF || analysis.Schema != "" || analysis.SchemaVersion != 0 {
		t.Fatalf("legacy analysis = %+v", analysis)
	}
}

func TestAnalyzeMissingEntrypointFinding(t *testing.T) {
	obj := filepath.Join(t.TempDir(), "demo.o")
	if err := coff.CreateMockObject(obj, "x64", "not_go", nil); err != nil {
		t.Fatal(err)
	}
	a, err := Analyze(obj, "go")
	if err != nil {
		t.Fatal(err)
	}
	if a.EntrypointOK {
		t.Fatalf("entrypoint unexpectedly present: %+v", a)
	}
	if !hasFinding(a, "entrypoint") {
		t.Fatalf("expected entrypoint finding: %+v", a.Findings)
	}
}

func TestClassifyStrings(t *testing.T) {
	got := classifyStrings([]string{
		"plain text",
		"https://example.test/path",
		"C:\\Windows\\Temp\\payload.bin",
		"cmd.exe /c whoami",
		"token=abc123",
		"10.0.0.5",
	})
	want := map[string]bool{
		"visible":     false,
		"url":         false,
		"path":        false,
		"command":     false,
		"secret_like": false,
		"ip_literal":  false,
	}
	for _, item := range got {
		if _, ok := want[item.Category]; ok {
			want[item.Category] = true
		}
	}
	for category, found := range want {
		if !found {
			t.Fatalf("missing string category %s in %#v", category, got)
		}
	}
}

func TestAnalyzeELFWhenCompilerAvailable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF fixture requires Linux compiler output")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available")
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "hello.c")
	obj := filepath.Join(tmp, "hello.o")
	if err := os.WriteFile(src, []byte("int go(void) { return 7; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-c", src, "-o", obj)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile failed: %v\n%s", err, out)
	}
	a, err := Analyze(obj, "go")
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != KindELF || !a.EntrypointOK {
		t.Fatalf("unexpected analysis: %+v", a)
	}
	if a.Runtime.Runtime != "linux-elf" || a.Runtime.Status != "runnable" {
		t.Fatalf("unexpected ELF runtime compatibility: %+v", a.Runtime)
	}
}

func TestAnalyzeMachOWhenAvailable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Mach-O fixture requires macOS compiler")
	}
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available")
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "hello.c")
	obj := filepath.Join(tmp, "hello.o")
	if err := os.WriteFile(src, []byte("int go(void) { return 7; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-c", src, "-o", obj)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile failed: %v\n%s", err, out)
	}
	a, err := Analyze(obj, "go")
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != KindMachO || !a.EntrypointOK {
		t.Fatalf("unexpected analysis: %+v", a)
	}
	if a.Runtime.Runtime != "darwin-macho" || a.Runtime.Status != "runnable" {
		t.Fatalf("unexpected Mach-O runtime compatibility: %+v", a.Runtime)
	}
}

func hasImport(a Analysis, symbol, category string) bool {
	for _, imp := range a.Imports {
		if imp.Symbol == symbol && imp.Category == category {
			return true
		}
	}
	return false
}

func hasFinding(a Analysis, category string) bool {
	for _, finding := range a.Findings {
		if finding.Category == category {
			return true
		}
	}
	return false
}
