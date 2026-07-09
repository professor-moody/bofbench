package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bofbench/internal/evidence"
)

func TestSmokeArgs(t *testing.T) {
	opts := SmokeOptions{
		RepoRoot:    `C:\bofbench`,
		Select:      "whoami,env",
		TimeoutMS:   7000,
		BofbenchExe: `work\bin\bofbench-lab.exe`,
		SkipFetch:   true,
		Script:      `C:\bofbench\scripts\windows-lab-smoke.ps1`,
		Shell:       "pwsh",
	}
	args := SmokeArgs(opts)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"pwsh",
		"-ExecutionPolicy Bypass",
		`C:\bofbench\scripts\windows-lab-smoke.ps1`,
		`-RepoRoot C:\bofbench`,
		"-Select whoami,env",
		"-TimeoutMS 7000",
		`-BofbenchExe work\bin\bofbench-lab.exe`,
		"-SkipFetch",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %q", want, joined)
		}
	}
}

func TestDefaultSmokeOptionsKeepsWindowsPaths(t *testing.T) {
	opts := DefaultSmokeOptions(`C:\bofbench`)
	if opts.Script != `C:\bofbench\scripts\windows-lab-smoke.ps1` {
		t.Fatalf("script path = %q", opts.Script)
	}
	if opts.BofbenchExe != `work\bin\bofbench-lab.exe` {
		t.Fatalf("runner path = %q", opts.BofbenchExe)
	}
}

func TestLatestSummaryAndLoad(t *testing.T) {
	tmp := t.TempDir()
	oldPath := writeSummary(t, tmp, "20260709-010101-lab-smoke", "fail")
	newPath := writeSummary(t, tmp, "20260709-020202-lab-smoke", "pass")
	oldTime := time.Now().Add(-time.Hour)
	newTime := time.Now()
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	latest, err := LatestSummaryPath(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if latest != newPath {
		t.Fatalf("latest = %s want %s", latest, newPath)
	}
	summary, err := LoadSummary(latest)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != "pass" || summary.Path != latest || len(summary.Steps) != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestTextSummary(t *testing.T) {
	summary := Summary{
		Header:      evidence.New(evidence.SchemaLabSmoke, "20260709-180000-lab-smoke", ""),
		Path:        "runs/demo/lab-smoke.json",
		GeneratedAt: "2026-07-09T18:00:00Z",
		RepoRoot:    `C:\bofbench`,
		Selection:   "whoami,env",
		TimeoutMS:   5000,
		Status:      "pass",
		Steps: []Step{
			{Name: "go test", Status: "pass", DurationMS: 123},
		},
		Environment: LabEnvironment{OSVersion: "Windows 11", OSArchitecture: "X64", BofbenchSHA256: "toolhash", LoaderSHA256: "loaderhash"},
	}
	text := Text(summary)
	for _, want := range []string{"Lab Smoke Summary", "Schema: `bofbench.lab-smoke`", "Run ID: `20260709-180000-lab-smoke`", "Status: `pass`", "Windows 11", "toolhash", "loaderhash", "`go test`", "`123ms`"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in:\n%s", want, text)
		}
	}
}

func writeSummary(t *testing.T, root, name, status string) string {
	t.Helper()
	dir := filepath.Join(root, "runs", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lab-smoke.json")
	body := `{
  "generated_at": "2026-07-09T18:00:00Z",
  "repo_root": "C:\\bofbench",
  "selection": "whoami,env",
  "timeout_ms": 5000,
  "status": "` + status + `",
  "steps": [
    {"name": "go test", "status": "` + status + `", "started_at": "2026-07-09T18:00:00Z", "duration_ms": 123, "error": null}
  ]
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
