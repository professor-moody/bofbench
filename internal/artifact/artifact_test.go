package artifact

import (
	"encoding/binary"
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
	if a.Kind != KindCOFF || a.Arch != "x64" || !a.EntrypointOK || !a.EntrypointExecutable {
		t.Fatalf("unexpected analysis: %+v", a)
	}
	if a.Schema != evidence.SchemaAnalysis || a.SchemaVersion != 3 || a.Tool.Name != "bofbench" || a.Host.OS == "" {
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
		if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconUseToken"}); err != nil {
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
		obj := filepath.Join(t.TempDir(), "unknown-relocation.o")
		if err := coff.CreateMockObjectWithRelocations(obj, "x64", "go", []string{"BeaconPrintf"}, []coff.MockRelocation{{Symbol: "BeaconPrintf", Type: 0x7777}}); err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(obj, "go")
		if err != nil {
			t.Fatal(err)
		}
		assertLoaderIssue(t, a, "unsupported_relocation")
		if len(a.RelocationDetails) != 1 || a.RelocationDetails[0].Code == nil || *a.RelocationDetails[0].Code != 0x7777 || a.RelocationDetails[0].Type != "AMD64_0x7777" {
			t.Fatalf("relocation evidence = %+v", a.RelocationDetails)
		}
	})

	t.Run("x86 helper architecture", func(t *testing.T) {
		obj := filepath.Join(t.TempDir(), "x86.o")
		if err := coff.CreateMockObject(obj, "x86", "go", nil); err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(obj, "go")
		if err != nil {
			t.Fatal(err)
		}
		if a.LoaderCompatibility == nil || !a.LoaderCompatibility.Compatible {
			t.Fatalf("x86 helper compatibility = %+v", a.LoaderCompatibility)
		}
	})

	t.Run("x86 decorated entrypoint", func(t *testing.T) {
		obj := filepath.Join(t.TempDir(), "x86-decorated.o")
		if err := coff.CreateMockObject(obj, "x86", "_go@8", nil); err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(obj, "go")
		if err != nil {
			t.Fatal(err)
		}
		if !a.EntrypointOK || a.EntrypointSymbol != "_go@8" {
			t.Fatalf("decorated entrypoint = %+v", a)
		}
		if a.LoaderCompatibility == nil || !a.LoaderCompatibility.Compatible {
			t.Fatalf("decorated x86 compatibility = %+v", a.LoaderCompatibility)
		}
		for _, blocker := range a.LoaderCompatibility.Blockers {
			if blocker.Category == "missing_entrypoint" {
				t.Fatalf("decorated entrypoint incorrectly missing: %+v", a.LoaderCompatibility)
			}
		}
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

	t.Run("non-executable entrypoint", func(t *testing.T) {
		obj := filepath.Join(t.TempDir(), "nonexec.o")
		if err := coff.CreateMockObject(obj, "x64", "go", nil); err != nil {
			t.Fatal(err)
		}
		value, err := os.ReadFile(obj)
		if err != nil {
			t.Fatal(err)
		}
		binary.LittleEndian.PutUint32(value[56:60], binary.LittleEndian.Uint32(value[56:60])&^uint32(0x20000000))
		if err := os.WriteFile(obj, value, 0o644); err != nil {
			t.Fatal(err)
		}
		a, err := Analyze(obj, "go")
		if err != nil {
			t.Fatal(err)
		}
		if !a.EntrypointOK || a.EntrypointExecutable {
			t.Fatalf("entrypoint evidence = found:%t executable:%t", a.EntrypointOK, a.EntrypointExecutable)
		}
		assertLoaderIssue(t, a, "entrypoint_nonexecutable")
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

func TestAnalyzeDebugCOFFAcceptsSectionRelativeRelocations(t *testing.T) {
	compiler, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("MinGW-w64 compiler not available")
	}
	tmp := t.TempDir()
	source := filepath.Join(tmp, "debug.c")
	object := filepath.Join(tmp, "debug.o")
	body := "__declspec(dllimport) void BeaconPrintf(int,const char*,...);\nvoid go(char *a,int l){(void)a;(void)l;BeaconPrintf(0,\"debug\");}\n"
	if err := os.WriteFile(source, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(compiler, "-g", "-O0", "-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile debug COFF: %v\n%s", err, output)
	}
	analysis, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, relocation := range analysis.RelocationDetails {
		if relocation.Type == "SECREL" || relocation.Type == "SECTION" {
			found = true
		}
	}
	if !found || analysis.LoaderCompatibility == nil || !analysis.LoaderCompatibility.Compatible {
		t.Fatalf("debug relocation support = found=%t compatibility=%+v", found, analysis.LoaderCompatibility)
	}
}

func TestEntrypointNormalization(t *testing.T) {
	for _, test := range []struct {
		symbol string
		arch   string
		want   bool
	}{
		{symbol: "go", arch: "x64", want: true},
		{symbol: "_go", arch: "x86", want: true},
		{symbol: "_go@8", arch: "x86", want: true},
		{symbol: "@go@8", arch: "x86", want: true},
		{symbol: "_go@bad", arch: "x86", want: false},
		{symbol: "_go", arch: "x64", want: false},
	} {
		if got := entrypointMatches(test.symbol, "go", test.arch); got != test.want {
			t.Fatalf("entrypointMatches(%q, go, %q)=%t want %t", test.symbol, test.arch, got, test.want)
		}
	}
}

func TestAnalyzeMalformedCOFFProducesStructuredEvidence(t *testing.T) {
	obj := filepath.Join(t.TempDir(), "malformed.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(b[40:44], uint32(len(b)-2))
	if err := os.WriteFile(obj, b, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := Analyze(obj, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.COFFDiagnostics) == 0 || a.COFFDiagnostics[0].Code != "section_data_range" {
		t.Fatalf("COFF diagnostics = %+v", a.COFFDiagnostics)
	}
	assertLoaderIssue(t, a, "malformed_object")
	if a.Runtime.Status != "malformed_object" || a.Runtime.CanRun || !hasFinding(a, "coff_layout") {
		t.Fatalf("malformed analysis = runtime=%+v findings=%+v", a.Runtime, a.Findings)
	}
	markdown := Markdown(a)
	for _, want := range []string{"## COFF Diagnostics", "section_data_range", "malformed_object"} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("malformed Markdown missing %q:\n%s", want, markdown)
		}
	}
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
	if a.Toolchain.Family != "mingw-gcc" || a.Toolchain.Confidence != "reported" {
		t.Fatalf("MinGW toolchain detection = %+v", a.Toolchain)
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

func TestAnalyzeMSVCCOFFWhenCompilerAvailable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("MSVC fixture requires Windows")
	}
	cl, err := exec.LookPath("cl")
	if err != nil {
		t.Skip("cl not available")
	}
	tmp := t.TempDir()
	src := filepath.Join(tmp, "msvc.c")
	obj := filepath.Join(tmp, "msvc.obj")
	if err := os.WriteFile(src, []byte("void go(char *args, int len) { (void)args; (void)len; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cl, "/nologo", "/c", src, "/Fo:"+obj)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cl is present but not configured for compilation: %v\n%s", err, out)
	}
	a, err := Analyze(obj, "go")
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != KindCOFF || !a.EntrypointOK || !a.EntrypointExecutable || (a.Toolchain.Family != "msvc-coff" && a.Toolchain.Family != "msvc") {
		t.Fatalf("MSVC analysis = kind=%s entry=%t toolchain=%+v diagnostics=%+v", a.Kind, a.EntrypointOK, a.Toolchain, a.COFFDiagnostics)
	}
}

func TestCompareAnalysis(t *testing.T) {
	baseline := Analysis{
		Path:                 "old.o",
		Kind:                 KindCOFF,
		Arch:                 "x64",
		Entrypoint:           "go",
		EntrypointOK:         true,
		EntrypointExecutable: true,
		Size:                 100,
		SHA256:               "old",
		Relocations:          1,
		Imports:              []Import{{Symbol: "BeaconPrintf", Category: "beacon_api"}},
		Capabilities:         []Capability{{ID: "identity_account_sid", Name: "Identity lookup", Confidence: "confirmed primitive", Effects: []string{"reads data"}}},
		Findings:             []Finding{{Severity: "info", Category: "string", Detail: "old", Evidence: "old"}},
		Sections:             []Section{{Name: ".text", Size: 10, Relocations: 1, Flags: "R-X"}},
	}
	current := baseline
	current.Path = "new.o"
	current.SHA256 = "new"
	current.Size = 120
	current.Relocations = 2
	current.Imports = append(current.Imports, Import{Symbol: "KERNEL32$VirtualAlloc", Category: "winapi", Library: "KERNEL32", API: "VirtualAlloc"})
	current.Capabilities = append(current.Capabilities, Capability{ID: "memory_operations", Name: "Memory operations", Confidence: "confirmed primitive", Effects: []string{"starts execution"}})
	current.BehaviorChains = []BehaviorChain{{ID: "process_injection_remote_thread", Name: "Remote-thread process injection", Function: "go", Confidence: "strong chain", Effects: []string{"starts execution"}, Steps: []BehaviorStep{{API: "openprocess"}, {API: "virtualallocex"}, {API: "writeprocessmemory"}, {API: "createremotethread"}}}}
	current.Findings = append(current.Findings, Finding{Severity: "review", Category: "memory_api", Detail: "memory allocation/protection API imported", Evidence: "KERNEL32$VirtualAlloc"})
	current.Sections = []Section{{Name: ".text", Size: 12, Relocations: 2, Flags: "R-X"}}
	diff := CompareAnalysis(baseline, current)
	if diff.Schema != evidence.SchemaAnalysisDiff || diff.SchemaVersion != evidence.ContractVersion {
		t.Fatalf("diff evidence header = %+v", diff.Header)
	}
	if !diff.Summary.HashChanged || diff.Summary.SizeDelta != 20 || diff.Summary.RelocationsDelta != 1 {
		t.Fatalf("unexpected diff summary: %+v", diff.Summary)
	}
	if diff.Summary.ImportsAdded != 1 || diff.Summary.FindingsAdded != 1 || diff.Summary.CapabilitiesAdded != 1 || diff.Summary.BehaviorChainsAdded != 1 {
		t.Fatalf("expected added import, capability, behavior chain, and finding: %+v", diff.Summary)
	}
	if !strings.Contains(DiffMarkdown(diff), "Analysis Diff") || !hasDiffChange(diff.Changes, "behavior", "added") {
		t.Fatal("diff markdown missing title")
	}
	current.EntrypointExecutable = false
	diff = CompareAnalysis(baseline, current)
	if !diff.Summary.EntrypointChanged || !hasDiffChange(diff.Changes, "entrypoint", "executable") {
		t.Fatalf("entrypoint protection change missing: %+v", diff)
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

func TestFindingSuppressionsPreserveEvidenceAndDiffState(t *testing.T) {
	obj := filepath.Join(t.TempDir(), "suppressed.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"KERNEL32$VirtualAlloc", "MissingExternal"}); err != nil {
		t.Fatal(err)
	}
	baseline, err := Analyze(obj, "go")
	if err != nil {
		t.Fatal(err)
	}
	current, err := AnalyzeWithOptions(obj, AnalysisOptions{Entrypoint: "go", Suppressions: []string{"memory_api", "external_symbol=Missing*"}})
	if err != nil {
		t.Fatal(err)
	}
	if current.FindingSummary.Suppressed != 2 || current.FindingSummary.Total != len(current.Findings) || len(current.Suppressions) != 2 {
		t.Fatalf("suppression summary = %+v rules=%+v findings=%+v", current.FindingSummary, current.Suppressions, current.Findings)
	}
	for _, category := range []string{"memory_api", "external_symbol"} {
		found := false
		for _, finding := range current.Findings {
			if finding.Category == category {
				found = true
				if !finding.Suppressed || finding.Suppression == "" || finding.Detail == "" || finding.Evidence == "" {
					t.Fatalf("suppressed finding lost raw evidence: %+v", finding)
				}
			}
		}
		if !found {
			t.Fatalf("missing suppressed category %s: %+v", category, current.Findings)
		}
	}
	diff := CompareAnalysis(baseline, current)
	if diff.Summary.ActiveFindingsDelta != -2 || diff.Summary.SuppressedFindingsDelta != 2 || diff.Summary.FindingsAdded != 2 || diff.Summary.FindingsRemoved != 2 {
		t.Fatalf("suppression diff = %+v changes=%+v", diff.Summary, diff.Changes)
	}
	if !strings.Contains(Markdown(current), "suppressed") || !strings.Contains(DiffMarkdown(diff), "Finding state") {
		t.Fatal("suppression state missing from Markdown evidence")
	}
	if _, err := AnalyzeWithOptions(obj, AnalysisOptions{Entrypoint: "go", Suppressions: []string{"memory_api=["}}); err == nil {
		t.Fatal("expected invalid suppression glob to fail")
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

func hasDiffChange(changes []DiffChange, category, change string) bool {
	for _, item := range changes {
		if item.Category == category && item.Change == change {
			return true
		}
	}
	return false
}
