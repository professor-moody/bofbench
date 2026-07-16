package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bofbench/internal/runtimeadapter"
)

func TestLoadRuntimeTaskReceiptsFiltersAndSorts(t *testing.T) {
	root := t.TempDir()
	writeTask := func(dir, runtimeName, profile, taskID, state string, complete bool, at time.Time) {
		t.Helper()
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		receipt := runtimeadapter.Receipt{Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion, Runtime: runtimeName, Profile: profile, TaskID: taskID, ExecutionState: state, OutputComplete: complete, CompletedAt: at.UTC().Format(time.RFC3339Nano)}
		data, _ := json.Marshal(receipt)
		if err := os.WriteFile(filepath.Join(path, "result.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeTask("old", "sliver", "devbox", "aaaa1111", "submitted", false, time.Unix(1, 0))
	writeTask("new", "sliver", "devbox", "bbbb2222", "completed", true, time.Unix(2, 0))
	writeTask("other", "cobaltstrike", "", "cccc3333", "submitted", false, time.Unix(3, 0))

	tasks, err := loadRuntimeTaskReceipts(root, "sliver", "devbox")
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 2 || tasks[0].Receipt.TaskID != "bbbb2222" || !runtimeTaskTerminal(tasks[0].Receipt.ExecutionState) {
		t.Fatalf("tasks = %+v", tasks)
	}
	found, err := findRuntimeTaskReceipt(root, "aaaa1111", "sliver", "devbox")
	if err != nil || found.Receipt.ExecutionState != "submitted" || runtimeTaskTerminal(found.Receipt.ExecutionState) {
		t.Fatalf("found = %+v err=%v", found, err)
	}
}

func TestRuntimeTaskStateTransitions(t *testing.T) {
	receipt := runtimeadapter.Receipt{}
	runtimeadapter.AddTransition(&receipt, "submitted", "queued", time.Unix(1, 0))
	runtimeadapter.AddTransition(&receipt, "completed", "done", time.Unix(2, 0))
	if len(receipt.StateTransitions) != 2 || receipt.StateTransitions[1].State != "completed" {
		t.Fatalf("transitions = %+v", receipt.StateTransitions)
	}
}

func TestRuntimeTaskTerminalAcceptsBothCanceledSpellings(t *testing.T) {
	for _, state := range []string{"completed", "failed", "canceled", "cancelled", "timeout"} {
		if !runtimeTaskTerminal(state) {
			t.Fatalf("%q should be terminal", state)
		}
	}
	for _, state := range []string{"submitted", "running", ""} {
		if runtimeTaskTerminal(state) {
			t.Fatalf("%q should remain refreshable", state)
		}
	}
}
