package matrix

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"bofbench/internal/buildsys"
	"bofbench/internal/config"
	"bofbench/internal/evidence"
	runtimesvc "bofbench/internal/runtime"
)

func TestNormalizeOptionsBuildsStableMatrix(t *testing.T) {
	options := Options{Path: "fixture"}
	plan, err := normalizeOptions(&options)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 12 || options.Architecture != "all" || options.Execution != "auto" || options.Runtime != "windows-coff" {
		t.Fatalf("normalized options=%+v plan=%+v", options, plan)
	}
	if plan[0].Compiler != "mingw" || plan[0].Optimization != "debug" || plan[0].Architecture != "x64" || len(plan[0].CFlags) != 1 || plan[0].CFlags[0] != "-O0" {
		t.Fatalf("first matrix cell = %+v", plan[0])
	}
	last := plan[len(plan)-1]
	if last.Compiler != "msvc" || last.Optimization != "speed" || last.Architecture != "x86" || len(last.CFlags) != 1 || last.CFlags[0] != "/O2" {
		t.Fatalf("last matrix cell = %+v", last)
	}
}

func TestNormalizeOptionsRejectsUnknownDimensions(t *testing.T) {
	for _, options := range []Options{
		{Path: "fixture", Compilers: []string{"clang"}},
		{Path: "fixture", Optimizations: []string{"maximum"}},
		{Path: "fixture", Architecture: "arm64"},
		{Path: "fixture", Execution: "sometimes"},
	} {
		if _, err := normalizeOptions(&options); err == nil {
			t.Fatalf("expected invalid options to fail: %+v", options)
		}
	}
}

func TestSummarySeparatesExpectedSkipsAndFailures(t *testing.T) {
	summary := summarize([]Cell{
		{Compiler: "mingw", Optimization: "debug", Architecture: "x64", Status: cellPass, Classification: "runtime_pass"},
		{Compiler: "mingw", Optimization: "debug", Architecture: "x86", Status: cellExpected, Classification: "expected_unsupported_arch"},
		{Compiler: "msvc", Optimization: "debug", Architecture: "x64", Status: cellSkip, Classification: "compiler_unavailable"},
		{Compiler: "msvc", Optimization: "speed", Architecture: "x64", Status: cellFail, Classification: "runtime_failed"},
	})
	if summary.Total != 4 || summary.Passed != 1 || summary.Expected != 1 || summary.Skipped != 1 || summary.Failed != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.ByCompiler["msvc"].Failed != 1 || summary.ByClassification["expected_unsupported_arch"] != 1 {
		t.Fatalf("summary dimensions = %+v", summary)
	}
}

func TestValidateRunAppliesOutputAndExpectedTerminalContracts(t *testing.T) {
	cfg := config.Project{Expect: []string{"hello"}, Forbid: []string{"panic"}}
	if err := validateRun(cfg, runtimesvc.Result{Status: "pass", ExitState: "success", Output: []string{"hello matrix"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := validateRun(cfg, runtimesvc.Result{Status: "pass", ExitState: "success", Output: []string{"panic"}}, nil); err == nil {
		t.Fatal("expected output contract failure")
	}
	cfg = config.Project{ExpectedExit: "timeout", ExpectedStatus: "fail"}
	if err := validateRun(cfg, runtimesvc.Result{Status: "fail", ExitState: "timeout"}, os.ErrDeadlineExceeded); err != nil {
		t.Fatalf("expected terminal contract should pass: %v", err)
	}
}

func TestCompilerUnavailableClassification(t *testing.T) {
	build := buildsys.Result{Diagnostics: []buildsys.Diagnostic{{Code: "compiler_unavailable"}}}
	if !compilerUnavailable(build) {
		t.Fatal("compiler_unavailable diagnostic was not classified")
	}
	if compilerUnavailable(buildsys.Result{Diagnostics: []buildsys.Diagnostic{{Code: "compiler_error"}}}) {
		t.Fatal("ordinary compiler error was classified as unavailable")
	}
}

func TestResolveReplayArtifactBesideReport(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(root, "matrix.json")
	objects := filepath.Join(root, "objects")
	if err := os.MkdirAll(objects, 0o755); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(objects, "mingw-debug-x64.o")
	if err := os.WriteFile(artifactPath, []byte("object"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveReplayArtifact(reportPath, "mingw-debug-x64")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != artifactPath {
		t.Fatalf("resolved artifact = %s, want %s", resolved, artifactPath)
	}
}

func TestValidateReplayReportRejectsUnsafeOrIncompleteCells(t *testing.T) {
	validCell := Cell{
		ID:                  "mingw-debug-x64",
		Compiler:            "mingw",
		Optimization:        "debug",
		Architecture:        "x64",
		Artifact:            "objects/mingw-debug-x64.o",
		ArtifactFingerprint: &evidence.FileFingerprint{Size: 1, SHA256: strings.Repeat("0", 64)},
	}
	base := Report{
		Header:     evidence.New(evidence.SchemaCompilerMatrix, "matrix-source", ""),
		Entrypoint: "go",
		Runtime:    "windows-coff",
		Cells:      []Cell{validCell},
	}
	if err := validateReplayReport(base); err != nil {
		t.Fatalf("valid replay report rejected: %v", err)
	}
	invalidID := base
	invalidID.Cells = []Cell{validCell}
	invalidID.Cells[0].ID = "../escape"
	if err := validateReplayReport(invalidID); err == nil {
		t.Fatal("unsafe replay cell id was accepted")
	}
	duplicate := base
	duplicate.Cells = []Cell{validCell, validCell}
	if err := validateReplayReport(duplicate); err == nil {
		t.Fatal("duplicate replay cell was accepted")
	}
	missingFingerprint := base
	missingFingerprint.Cells = []Cell{validCell}
	missingFingerprint.Cells[0].ArtifactFingerprint = nil
	if err := validateReplayReport(missingFingerprint); err == nil {
		t.Fatal("artifact without fingerprint was accepted")
	}
}

func TestRunMinGWMatrixWhenAvailable(t *testing.T) {
	if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
		t.Skip("MinGW x64 compiler unavailable")
	}
	if _, err := exec.LookPath("i686-w64-mingw32-gcc"); err != nil {
		t.Skip("MinGW x86 compiler unavailable")
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(tmp, "fixture")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	source := "void BeaconPrintf(int, const char *, ...);\nvoid go(char *args, int len) { (void)args; (void)len; BeaconPrintf(0, \"matrix pass\"); }\n"
	if err := os.WriteFile(filepath.Join(project, "fixture.c"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "bofbench.toml"), []byte("name = \"fixture\"\nexpect = [\"matrix pass\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	persisted, err := Run(Options{
		Path:               project,
		Compilers:          []string{"mingw"},
		Optimizations:      []string{"debug", "speed"},
		Architecture:       "all",
		Execution:          "never",
		VerifyReproducible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Report.Status != "pass" || persisted.Report.Summary.Total != 4 || persisted.Report.Summary.Passed != 2 || persisted.Report.Summary.Expected != 2 || persisted.Report.Summary.Failed != 0 {
		t.Fatalf("matrix report = %+v", persisted.Report)
	}
	if len(persisted.Report.Contract.Expect) != 1 || persisted.Report.Contract.Expect[0] != "matrix pass" || persisted.Report.Contract.TimeoutMS != 5000 {
		t.Fatalf("embedded runtime contract = %+v", persisted.Report.Contract)
	}
	for _, cell := range persisted.Report.Cells {
		if cell.Artifact == "" || cell.ArtifactFingerprint == nil || cell.Build == nil || cell.BuildEvidence == "" || cell.BuildLog == "" || cell.Build.Reproducibility == nil || !cell.Build.Reproducibility.Reproducible {
			t.Fatalf("matrix cell evidence = %+v", cell)
		}
		if _, err := os.Stat(cell.BuildEvidence); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(cell.BuildLog); err != nil {
			t.Fatal(err)
		}
		if cell.Build.ParentRunID != persisted.Report.RunID {
			t.Fatalf("build lineage = %q, want %q", cell.Build.ParentRunID, persisted.Report.RunID)
		}
	}
	buildData, err := os.ReadFile(persisted.Report.Cells[0].Build.EvidencePath)
	if err != nil {
		t.Fatal(err)
	}
	var persistedBuild buildsys.Result
	if err := json.Unmarshal(buildData, &persistedBuild); err != nil {
		t.Fatal(err)
	}
	if persistedBuild.ParentRunID != persisted.Report.RunID {
		t.Fatalf("persisted build lineage = %q, want %q", persistedBuild.ParentRunID, persisted.Report.RunID)
	}
	if _, err := os.Stat(persisted.JSONPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(persisted.MDPath); err != nil {
		t.Fatal(err)
	}
}

func TestRunMSVCX86IsExpectedUnsupportedCombination(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(tmp, "fixture")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "fixture.c"), []byte("void go(char *args, int len) { (void)args; (void)len; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	persisted, err := Run(Options{
		Path:          project,
		Compilers:     []string{"msvc"},
		Optimizations: []string{"debug"},
		Architecture:  "x86",
		Execution:     "never",
	})
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Report.Status != "pass" || persisted.Report.Summary.Expected != 1 || len(persisted.Report.Cells) != 1 || persisted.Report.Cells[0].Classification != "unsupported_compiler_arch" || persisted.Report.Cells[0].RuntimeAttempted {
		t.Fatalf("MSVC/x86 classification = %+v", persisted.Report)
	}
}
