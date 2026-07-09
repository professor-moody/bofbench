package app

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"bofbench/internal/coff"
)

func TestCLIWorkspaceBuildInspectStage(t *testing.T) {
	requireMinGW(t)
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	runOK(t, tmp, bin, "new", "hello")
	runOK(t, tmp, bin, "build", filepath.Join("bofs", "hello"))
	inspect := runOK(t, tmp, bin, "inspect", filepath.Join("dist", "hello.x64.o"))
	if !strings.Contains(inspect, "entry \"go\": yes") {
		t.Fatalf("inspect did not confirm entrypoint:\n%s", inspect)
	}
	runOK(t, tmp, bin, "stage", filepath.Join("dist", "hello.x64.o"), "--target", "cobaltstrike", "--args", "z:hello", "i:3")
	mustExist(t, filepath.Join(tmp, "stage", "hello-cobaltstrike", "hello.cna"))
	mustExist(t, filepath.Join(tmp, "stage", "hello-cobaltstrike.zip"))
}

func TestCLIStageVerifyDirectoryZipAndFailure(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	obj := filepath.Join(tmp, "demo.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	runOK(t, tmp, bin, "stage", obj, "--target", "raw")
	directory := filepath.Join("stage", "demo-raw")
	archive := directory + ".zip"
	var verified struct {
		Schema string `json:"schema"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(runOK(t, tmp, bin, "stage", "verify", directory, "--format", "json")), &verified); err != nil {
		t.Fatal(err)
	}
	if verified.Schema != "bofbench.stage-verification" || verified.Status != "pass" {
		t.Fatalf("directory verification = %+v", verified)
	}
	zipText := runOK(t, tmp, bin, "stage", "verify", archive)
	if !strings.Contains(zipText, "Stage Package Verification: PASS") {
		t.Fatalf("unexpected ZIP verification output:\n%s", zipText)
	}
	if err := os.WriteFile(filepath.Join(tmp, directory, "objects", "demo.x64.o"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, tmp, bin, "stage", "verify", directory, "--format", "json")
	if err == nil || !strings.Contains(out, `"status": "fail"`) || !strings.Contains(out, "stage package verification failed") {
		t.Fatalf("tampered verification did not fail: err=%v\n%s", err, out)
	}
}

func TestCLINewTemplates(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	runOK(t, tmp, bin, "new", "pidcheck", "--template", "winapi")
	body, err := os.ReadFile(filepath.Join(tmp, "bofs", "pidcheck", "pidcheck.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "GetCurrentProcessId") {
		t.Fatalf("winapi template missing API call:\n%s", body)
	}

	runOK(t, tmp, bin, "new", "badlink", "--template", "unresolved")
	cfg, err := os.ReadFile(filepath.Join(tmp, "bofs", "badlink", "bofbench.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), `expect_exit = "relocation_error"`) {
		t.Fatalf("unresolved template missing expected exit:\n%s", cfg)
	}

	runOK(t, tmp, bin, "new", "echoer", "--template", "args")
	cfg, err = os.ReadFile(filepath.Join(tmp, "bofs", "echoer", "bofbench.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), "[profile.alt]") {
		t.Fatalf("args template missing alternate profile:\n%s", cfg)
	}
}

func TestCLIAnalyzeBaselineWritesDiff(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	obj := filepath.Join(tmp, "demo.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf", "KERNEL32$VirtualAlloc"}); err != nil {
		t.Fatal(err)
	}
	inspect := runOK(t, tmp, bin, "inspect", obj)
	if !strings.Contains(inspect, "runtime compatibility:") || !strings.Contains(inspect, "windows-coff") {
		t.Fatalf("inspect missing runtime compatibility:\n%s", inspect)
	}
	var first struct {
		Analysis struct {
			Schema        string `json:"schema"`
			SchemaVersion int    `json:"schema_version"`
			RunID         string `json:"run_id"`
		} `json:"analysis"`
		JSONPath string `json:"json_path"`
	}
	if err := json.Unmarshal([]byte(runOK(t, tmp, bin, "analyze", obj)), &first); err != nil {
		t.Fatal(err)
	}
	if first.JSONPath == "" || first.Analysis.Schema != "bofbench.analysis" || first.Analysis.SchemaVersion != 1 || first.Analysis.RunID == "" {
		t.Fatalf("missing versioned baseline analysis evidence: %+v", first)
	}
	var second struct {
		Diff *struct {
			Schema      string `json:"schema"`
			RunID       string `json:"run_id"`
			ParentRunID string `json:"parent_run_id"`
		} `json:"diff"`
		DiffJSON string `json:"diff_json_path"`
		DiffMD   string `json:"diff_md_path"`
	}
	if err := json.Unmarshal([]byte(runOK(t, tmp, bin, "analyze", obj, "--baseline", first.JSONPath)), &second); err != nil {
		t.Fatal(err)
	}
	if second.DiffJSON == "" || second.DiffMD == "" || second.Diff == nil || second.Diff.Schema != "bofbench.analysis-diff" || second.Diff.RunID == "" || second.Diff.ParentRunID == "" {
		t.Fatalf("missing diff paths: %+v", second)
	}
	mustExist(t, filepath.Join(tmp, second.DiffJSON))
	mustExist(t, filepath.Join(tmp, second.DiffMD))
	suppressed := runOK(t, tmp, bin, "analyze", obj, "--suppress", "memory_api")
	if !strings.Contains(suppressed, `"category": "memory_api"`) || !strings.Contains(suppressed, `"suppressed": true`) || !strings.Contains(suppressed, `"suppression": "memory_api"`) {
		t.Fatalf("CLI suppression did not preserve marked finding:\n%s", suppressed)
	}
}

func TestCLIRunRequiresWindowsOnNonWindows(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("non-Windows behavior only")
	}
	requireMinGW(t)
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	runOK(t, tmp, bin, "new", "hello")
	runOK(t, tmp, bin, "build", filepath.Join("bofs", "hello"))
	out, err := run(t, tmp, bin, "run", filepath.Join("dist", "hello.x64.o"), "--args", "z:hello", "i:3")
	if err == nil {
		t.Fatalf("run succeeded unexpectedly on non-Windows:\n%s", out)
	}
	if !strings.Contains(out, "requires Windows x64") {
		t.Fatalf("unexpected run output:\n%s", out)
	}
	if !strings.Contains(out, `"schema": "bofbench.run"`) || !strings.Contains(out, `"object_fingerprint"`) || !strings.Contains(out, `"run_id"`) {
		t.Fatalf("run failure missing evidence contract:\n%s", out)
	}
}

func TestCLIListTrustedSecLikeArsenal(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	arsenalDir := filepath.Join(tmp, "arsenal", "trustedsec-sa", "SA", "whoami")
	if err := os.MkdirAll(arsenalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(arsenalDir, "whoami.x64.o"), []byte("not-real-for-list"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runOK(t, tmp, bin, "list", filepath.Join("arsenal", "trustedsec-sa"))
	if !strings.Contains(out, "whoami") || !strings.Contains(out, "x64") {
		t.Fatalf("unexpected list output:\n%s", out)
	}
}

func TestCLIArsenalTestWritesReports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("report-only arsenal smoke avoids requiring native loader in test tempdir")
	}
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	arsenalDir := filepath.Join(tmp, "arsenal", "trustedsec-sa", "SA", "whoami")
	obj := filepath.Join(arsenalDir, "whoami.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", nil); err != nil {
		t.Fatal(err)
	}
	out := runOK(t, tmp, bin, "test", filepath.Join("arsenal", "trustedsec-sa"), "--select", "whoami")
	if !strings.Contains(out, "reports:") {
		t.Fatalf("missing report line:\n%s", out)
	}
	matches, err := filepath.Glob(filepath.Join(tmp, "runs", "*test-arsenal-trustedsec-sa", "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one result.json, got %d", len(matches))
	}
	b, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"status": "analyze_pass"`) {
		t.Fatalf("unexpected report:\n%s", b)
	}
	if !strings.Contains(string(b), `"schema": "bofbench.arsenal-test"`) || !strings.Contains(string(b), `"parent_run_id"`) {
		t.Fatalf("arsenal report missing evidence lineage:\n%s", b)
	}
}

func TestCLIPreflightArsenalGateAndReports(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	root := filepath.Join(tmp, "arsenal", "demo")
	if err := coff.CreateMockObject(filepath.Join(root, "supported", "supported.x64.o"), "x64", "go", []string{"__imp__BeaconPrintf", "KERNEL32$VirtualAlloc"}); err != nil {
		t.Fatal(err)
	}
	if err := coff.CreateMockObject(filepath.Join(root, "blocked", "blocked.x64.o"), "x64", "go", []string{"BeaconFormatAlloc"}); err != nil {
		t.Fatal(err)
	}
	var passed struct {
		Report struct {
			Schema  string `json:"schema"`
			Status  string `json:"status"`
			Summary struct {
				Compatible int `json:"compatible"`
				Total      int `json:"total"`
			} `json:"summary"`
		} `json:"report"`
		JSONPath string `json:"json_path"`
		MDPath   string `json:"md_path"`
	}
	jsonOutput := runOK(t, tmp, bin, "preflight", filepath.Join("arsenal", "demo"), "--select", "supported", "--format", "json")
	if err := json.Unmarshal([]byte(jsonOutput), &passed); err != nil {
		t.Fatal(err)
	}
	if passed.Report.Schema != "bofbench.preflight" || passed.Report.Status != "pass" || passed.Report.Summary.Compatible != 1 || passed.Report.Summary.Total != 1 || passed.JSONPath == "" || passed.MDPath == "" {
		t.Fatalf("preflight JSON = %+v", passed)
	}
	mustExist(t, filepath.Join(tmp, passed.JSONPath))
	mustExist(t, filepath.Join(tmp, passed.MDPath))

	blocked, err := run(t, tmp, bin, "preflight", filepath.Join("arsenal", "demo"), "--select", "blocked")
	if err == nil || !strings.Contains(blocked, "unsupported_beacon_api") || !strings.Contains(blocked, "loader preflight gate failed") || !strings.Contains(blocked, "reports:") {
		t.Fatalf("blocked preflight did not fail with evidence: err=%v\n%s", err, blocked)
	}
}

func TestCLIVersionJSON(t *testing.T) {
	bin := buildTestBinary(t)
	out := runOK(t, t.TempDir(), bin, "version", "--format", "json")
	var report struct {
		Schema        string `json:"schema"`
		SchemaVersion int    `json:"schema_version"`
		Tool          struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tool"`
		Host struct {
			OS   string `json:"os"`
			Arch string `json:"arch"`
		} `json:"host"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != "bofbench.version" || report.SchemaVersion != 1 || report.Tool.Name != "bofbench" || report.Tool.Version == "" || report.Host.OS == "" || report.Host.Arch == "" {
		t.Fatalf("version evidence = %+v", report)
	}
}

func TestCLILabSmokePrint(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	out := runOK(t, tmp, bin, "lab", "smoke", "--print", "--repo-root", `C:\bofbench`, "--select", "whoami,env", "--timeout", "7000", "--skip-fetch")
	for _, want := range []string{"windows-lab-smoke.ps1", "-RepoRoot", `C:\bofbench`, "-Select", "whoami,env", "-TimeoutMS", "7000", "-BofbenchExe", "bofbench-lab.exe", "-SkipFetch"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestCLILabSummaryLatest(t *testing.T) {
	bin := buildTestBinary(t)
	tmp := t.TempDir()
	runDir := filepath.Join(tmp, "runs", "20260709-180000-lab-smoke")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
  "generated_at": "2026-07-09T18:00:00Z",
  "repo_root": "C:\\bofbench",
  "selection": "whoami,env",
  "timeout_ms": 5000,
  "status": "pass",
  "steps": [
    {"name": "go test", "status": "pass", "started_at": "2026-07-09T18:00:00Z", "duration_ms": 123, "error": null}
  ]
}`
	if err := os.WriteFile(filepath.Join(runDir, "lab-smoke.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	out := runOK(t, tmp, bin, "lab", "summary")
	for _, want := range []string{"Lab Smoke Summary", "Status: `pass`", "`go test`", "`123ms`"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	jsonOut := runOK(t, tmp, bin, "lab", "summary", filepath.Join("runs", "20260709-180000-lab-smoke", "lab-smoke.json"), "--format", "json")
	if !strings.Contains(jsonOut, `"status": "pass"`) || !strings.Contains(jsonOut, `"path":`) {
		t.Fatalf("unexpected json summary:\n%s", jsonOut)
	}
}

func buildTestBinary(t *testing.T) string {
	t.Helper()
	repo := filepath.Clean("../..")
	bin := filepath.Join(t.TempDir(), executableName("bofbench"))
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/bofbench")
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func executableName(name string) string {
	if os.PathSeparator == '\\' {
		return name + ".exe"
	}
	return name
}

func requireMinGW(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
		if os.PathSeparator == '\\' {
			if _, clErr := exec.LookPath("cl"); clErr == nil {
				return
			}
		}
		t.Skip("x86_64-w64-mingw32-gcc or cl not available")
	}
}

func runOK(t *testing.T, dir, bin string, args ...string) string {
	t.Helper()
	out, err := run(t, dir, bin, args...)
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
	return out
}

func run(t *testing.T, dir, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s missing: %v", path, err)
	}
}
