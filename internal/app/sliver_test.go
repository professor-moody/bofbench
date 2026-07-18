package app

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"bofbench/internal/runtimeadapter"
)

func TestSliverExtensionCommandLineUsesNamedFlags(t *testing.T) {
	extension := sliverExtension{CommandName: "survey"}
	extension.Arguments = append(extension.Arguments,
		struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Optional bool   `json:"optional"`
		}{Name: "process_filter", Type: "string", Optional: true},
		struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Optional bool   `json:"optional"`
		}{Name: "result_limit", Type: "int", Optional: true},
	)

	got, err := sliverExtensionCommandLine("survey", extension, []string{"lsass", "5"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `survey -- --process_filter lsass --result_limit 5`; got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
}

func TestSliverExtensionCommandLineQuotesValues(t *testing.T) {
	extension := sliverExtension{}
	extension.Arguments = append(extension.Arguments, struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Optional bool   `json:"optional"`
	}{Name: "command", Type: "string"})

	got, err := sliverExtensionCommandLine("run_bof", extension, []string{`whoami /all`})
	if err != nil {
		t.Fatal(err)
	}
	if want := `run_bof -- --command "whoami /all"`; got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
}

func TestSliverExtensionCommandLineQuotesWindowsPaths(t *testing.T) {
	extension := sliverExtension{}
	extension.Arguments = append(extension.Arguments, struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Optional bool   `json:"optional"`
	}{Name: "blob_path", Type: "wstring"})
	got, err := sliverExtensionCommandLine("dpapi", extension, []string{`C:\bofbench\fixture.bin`})
	if err != nil {
		t.Fatal(err)
	}
	if want := `dpapi -- --blob_path "C:\\bofbench\\fixture.bin"`; got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
}

func TestConciseSliverLinesAcceptsAnyStructuredPackOutput(t *testing.T) {
	output := "[*] Successfully executed\n[credential-list] target=BOFBench-LiveProof secret_bytes=48\n[wmi-query] property=Name value=DEVBOX\n"
	lines := conciseSliverLines(output, "ignored")
	if len(lines) != 2 || lines[0] != "[credential-list] target=BOFBench-LiveProof secret_bytes=48" || lines[1] != "[wmi-query] property=Name value=DEVBOX" {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestDiscoverSliverConfigsPrefersExplicitConfig(t *testing.T) {
	home := t.TempDir()
	configs := filepath.Join(home, "configs")
	if err := os.MkdirAll(configs, 0o700); err != nil {
		t.Fatal(err)
	}
	discovered := filepath.Join(configs, "automatic.cfg")
	explicit := filepath.Join(t.TempDir(), "operator.cfg")
	for _, path := range []string{discovered, explicit} {
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SLIVER_CLIENT_HOME", home)
	t.Setenv("BOFBENCH_SLIVER_CONFIG", explicit)

	got := discoverSliverConfigs()
	if len(got) != 2 || got[0] != explicit || got[1] != discovered {
		t.Fatalf("configs = %#v, want explicit config first", got)
	}
}

func TestSliverClientSelectionUsesExplicitProfileIndex(t *testing.T) {
	home := t.TempDir()
	configs := filepath.Join(home, "configs")
	if err := os.MkdirAll(configs, 0o700); err != nil {
		t.Fatal(err)
	}
	var selected string
	for _, name := range []string{"a.cfg", "b.cfg", "c.cfg"} {
		path := filepath.Join(configs, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if name == "b.cfg" {
			selected = path
		}
	}
	t.Setenv("SLIVER_CLIENT_HOME", home)
	t.Setenv("BOFBENCH_SLIVER_CONFIG", selected)
	if got := sliverClientSelection(); got != "2" {
		t.Fatalf("selection = %q, want 2", got)
	}
}

func TestSliverFetchedTaskState(t *testing.T) {
	for state, line := range map[string]string{
		"completed": "State: completed",
		"failed":    "Task State FAILED",
		"canceled":  "state=canceled",
		"pending":   "State pending",
		"sent":      "State: sent",
		"running":   "task state running",
	} {
		if got := sliverFetchedTaskState([]string{line}); got != state {
			t.Fatalf("state for %q = %q, want %q", line, got, state)
		}
	}
}

func TestRefreshSliverRuntimeReceiptFromPersistedTaskOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a temporary POSIX Sliver client fixture")
	}
	client := filepath.Join(t.TempDir(), "sliver-client")
	script := "#!/bin/sh\nprintf '%s\\n' 'Task ID: deadbeef' 'State: completed' '[named-pipe-transact] status=complete response_sha256=abc'\n"
	if err := os.WriteFile(client, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	receipt := runtimeadapter.Receipt{
		Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion,
		Runtime: "sliver", Status: "incomplete", ExecutionState: "submitted",
		Session: "0123abcd", TaskID: "deadbeef", OutputClassification: "partial",
	}
	refreshed, err := refreshSliverRuntimeReceipt(context.Background(), receipt, sliverOptions{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.ExecutionState != "completed" || !refreshed.OutputComplete || refreshed.OutputClassification != "complete" || !refreshed.FinalChunk {
		t.Fatalf("refreshed receipt = %+v", refreshed)
	}
	if refreshed.CompletionSource != "sliver-task-store" || len(refreshed.OutputChunks) != 1 || !refreshed.OutputChunks[0].Final {
		t.Fatalf("refresh metadata = %+v", refreshed)
	}
}
