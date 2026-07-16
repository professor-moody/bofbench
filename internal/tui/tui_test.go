package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bofbench/internal/arsenal"
)

func TestFilteredRunsByStatusAndRuntime(t *testing.T) {
	m := model{
		runs: []runEntry{
			{Status: "pass", Runtime: "windows-coff"},
			{Status: "fail", Runtime: "windows-coff"},
			{Status: "pass", Runtime: "linux-elf"},
		},
		statusFilter:  2, // fail
		runtimeFilter: 2, // windows-coff
	}
	got := m.filteredRuns()
	if len(got) != 1 || got[0].Status != "fail" || got[0].Runtime != "windows-coff" {
		t.Fatalf("unexpected filtered runs: %#v", got)
	}
}

func TestFilteredRunsBySelectedArtifact(t *testing.T) {
	m := model{
		arsenal: []arsenal.Entry{
			{Name: "whoami", X64: "arsenal/trustedsec-sa/SA/whoami/whoami.x64.o"},
			{Name: "ipconfig", X64: "arsenal/trustedsec-sa/SA/ipconfig/ipconfig.x64.o"},
		},
		arsenalCursor: 1,
		runs: []runEntry{
			{Status: "pass", Runtime: "windows-coff", Artifact: "arsenal/trustedsec-sa/SA/whoami/whoami.x64.o"},
			{Status: "pass", Runtime: "windows-coff", Artifact: "arsenal/trustedsec-sa/SA/ipconfig/ipconfig.x64.o"},
		},
		artifactFilter: true,
	}
	got := m.filteredRuns()
	if len(got) != 1 || !strings.Contains(got[0].Artifact, "ipconfig.x64.o") {
		t.Fatalf("unexpected artifact-filtered runs: %#v", got)
	}
}

func TestArsenalDetailIncludesCommandPreviews(t *testing.T) {
	m := model{arsenalRoot: "arsenal/trustedsec-sa"}
	entry := arsenal.Entry{
		Name: "whoami",
		Path: "arsenal/trustedsec-sa/SA/whoami",
		X64:  "arsenal/trustedsec-sa/SA/whoami/whoami.x64.o",
	}
	view := m.renderArsenalDetail(entry)
	for _, want := range []string{
		"bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o",
		"bofbench test arsenal/trustedsec-sa --select whoami --runtime windows-coff",
		"bofbench export arsenal/trustedsec-sa/SA/whoami/whoami.x64.o --for raw",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q in:\n%s", want, view)
		}
	}
}

func TestActionTabsProduceDirectBOFBenchCommands(t *testing.T) {
	m := model{projects: []string{"bofs/fieldcheck"}, viaCursor: 2}
	checks := []struct {
		tab  int
		want string
	}{
		{tab: 0, want: "build bofs/fieldcheck"},
		{tab: 1, want: "analyze bofs/fieldcheck"},
		{tab: 3, want: "run bofs/fieldcheck --via sliver"},
	}
	for _, check := range checks {
		m.tab = check.tab
		if got := strings.Join(m.currentCommand(), " "); got != check.want {
			t.Fatalf("tab %d command = %q, want %q", check.tab, got, check.want)
		}
	}
}

func TestReadRunEntryParsesEventsAndFindings(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "runs", "demo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
  "object": "dist/demo.x64.o",
  "kind": "coff",
  "runtime": "windows-coff",
  "status": "fail",
  "exit_state": "output_contract_failed",
  "events": [
    {"type": "artifact", "time_ms": 0, "status": "detected", "message": "kind=coff"},
    {"type": "api_event", "time_ms": 5, "status": "fail", "message": "missing output"}
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "result.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run := readRunEntry(dir, time.Now())
	if run.Status != "fail" || run.Runtime != "windows-coff" || run.Artifact != "dist/demo.x64.o" {
		t.Fatalf("unexpected run: %#v", run)
	}
	if len(run.Events) != 2 || run.Events[1].Type != "api_event" {
		t.Fatalf("events not parsed: %#v", run.Events)
	}
}

func TestReadOperationReceiptParsesParallelLanes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runs", "parallel")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{
  "schema": "bofbench.operation-receipt",
  "schema_version": 5,
  "status": "completed",
  "actual_path": ["matrix"],
  "expanded_path": ["matrix", "matrix/rpc", "matrix/com", "matrix/$join"],
  "max_observed_concurrency": 2,
  "steps": [{
    "id": "matrix",
    "state": "completed",
    "parallel": {
      "state": "completed",
      "branches": [
        {"id": "rpc", "state": "completed", "started_at": "2026-07-16T14:00:00Z"},
        {"id": "com", "state": "completed", "child_receipt": "runs/child/operation.json", "child_cleanup_state": "completed"}
      ]
    }
  }]
}`
	if err := os.WriteFile(filepath.Join(dir, "operation.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run := readRunEntry(dir, time.Now())
	if run.MaxConcurrency != 2 || len(run.ParallelLanes) != 2 || !strings.Contains(run.ParallelLanes[0], "matrix/rpc=completed") {
		t.Fatalf("parallel lanes were not parsed: %#v", run)
	}
	view := renderRunDetail(run)
	if !strings.Contains(view, "max concurrency: 2") || !strings.Contains(view, "matrix/com=completed") {
		t.Fatalf("parallel detail was not rendered:\n%s", view)
	}
}

func TestRunDetailRendersEventsAndFollowup(t *testing.T) {
	run := runEntry{
		Path:      "runs/demo",
		Report:    "runs/demo/result.json",
		Status:    "pass",
		Runtime:   "windows-coff",
		Kind:      "coff",
		ExitState: "success",
		Artifact:  "dist/demo.x64.o",
		Events: []eventEntry{
			{Type: "load", Status: "pass", Message: "loader=native/loader/bofbench-loader.exe"},
			{Type: "beacon_output", Status: "line", Message: "hello"},
		},
	}
	view := renderRunDetail(run)
	for _, want := range []string{"Events", "beacon_output", "bofbench inspect dist/demo.x64.o"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q in:\n%s", want, view)
		}
	}
}
