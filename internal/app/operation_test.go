package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	operationsvc "bofbench/internal/operation"
	packsvc "bofbench/internal/pack"
)

func TestResolveOperationInputsValidatesTypesAndDuplicates(t *testing.T) {
	document := operationsvc.Document{Inputs: []operationsvc.Input{{Name: "pid", Type: "int", Required: true}}}
	if _, err := resolveOperationInputs(document, []string{"pid=not-a-number"}, nil, false); err == nil {
		t.Fatal("invalid integer input was accepted")
	}
	if _, err := resolveOperationInputs(document, []string{"pid=1", "pid=2"}, nil, false); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
	resolved, err := resolveOperationInputs(document, []string{"pid=1234"}, nil, false)
	if err != nil || resolved["pid"] != "1234" {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
}

func TestOperationCancelLeavesTerminalReceiptTerminal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operation.json")
	receipt := operationsvc.Receipt{
		Schema: operationsvc.ReceiptSchema, SchemaVersion: operationsvc.ReceiptSchemaVersion,
		Operation: "builtin/test", Status: "completed",
	}
	if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := operationCancelCommand(&output, func() (*operationsvc.Registry, error) {
		t.Fatal("registry should not be loaded without cleanup")
		return nil, nil
	})
	command.SetArgs([]string{path})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	updated, err := operationsvc.LoadReceipt(path)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Status != "completed" || updated.CancellationState != "" {
		t.Fatalf("terminal receipt changed: %+v", updated)
	}
	if !strings.Contains(output.String(), "cancellation_not_needed") {
		t.Fatalf("output = %q", output.String())
	}
}

func TestWaitForOperationTasksToSettle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operation.json")
	receipt := operationsvc.Receipt{
		Schema: operationsvc.ReceiptSchema, SchemaVersion: operationsvc.ReceiptSchemaVersion,
		Operation: "builtin/test", Status: "canceled",
		Steps: []operationsvc.StepReceipt{{ID: "watch", State: "canceled"}},
	}
	if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
		t.Fatal(err)
	}
	settled, err := waitForOperationTasksToSettle(t.Context(), path, time.Second)
	if err != nil || settled.Status != "canceled" {
		t.Fatalf("settled=%+v err=%v", settled, err)
	}
}

func TestWaitForOperationTasksDoesNotTreatTerminalLabelAsSettled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operation.json")
	receipt := operationsvc.Receipt{
		Schema: operationsvc.ReceiptSchema, SchemaVersion: operationsvc.ReceiptSchemaVersion,
		Operation: "builtin/test", Status: "canceled",
		Steps: []operationsvc.StepReceipt{{ID: "watch", State: "ready"}},
	}
	if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := waitForOperationTasksToSettle(t.Context(), path, 25*time.Millisecond); err == nil {
		t.Fatal("terminal operation with an active runtime task was treated as settled")
	}
}

func TestSensitiveInputIsRequiredOnlyWhenReferencedAgain(t *testing.T) {
	document := operationsvc.Document{Inputs: []operationsvc.Input{{Name: "payload", Type: "file", Sensitive: true}, {Name: "pid", Type: "int"}}}
	receipt := operationsvc.Receipt{RedactedInputs: []string{"payload"}}
	inputs := map[string]string{"payload": "", "pid": "7"}
	if err := requireReferencedSensitiveInputs(document, receipt, inputs, map[string]string{"target_pid": "$input.pid"}); err != nil {
		t.Fatalf("completed-step secret was requested again: %v", err)
	}
	if err := requireReferencedSensitiveInputs(document, receipt, inputs, map[string]string{"payload": "$input.payload"}); err == nil || !strings.Contains(err.Error(), "resupply") {
		t.Fatalf("expected secret resupply error, got %v", err)
	}
}

func TestPinnedOperationPacksIncludeCleanup(t *testing.T) {
	packs, err := packsvc.Load(packsvc.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	document := operationsvc.Document{Steps: []operationsvc.Step{{ID: "one", Pack: "host-discovery", Cleanup: &operationsvc.Cleanup{Pack: "host-discovery"}}}}
	item := operationsvc.Resolved{Document: document, Qualified: "test/one", SHA256: operationsvc.Fingerprint(document)}
	registry, err := operationsvc.Load(operationsvc.LoadOptions{PackRegistry: packs})
	if err != nil {
		t.Fatal(err)
	}
	receipt := operationsvc.NewReceipt(item, registry, "operation.json", "lab", "devbox", "", "x64", "auto", nil)
	if err := validatePinnedOperation(item, &receipt, registry); err != nil {
		t.Fatal(err)
	}
	receipt.Steps[0].CleanupSHA256 = "changed"
	if err := validatePinnedOperation(item, &receipt, registry); err == nil || !strings.Contains(err.Error(), "cleanup pack") {
		t.Fatalf("expected cleanup hash rejection, got %v", err)
	}
}

func TestOperationInputSensitivityFlowsToPackArgument(t *testing.T) {
	document := operationsvc.Document{Inputs: []operationsvc.Input{{Name: "payload", Type: "file", Sensitive: true}, {Name: "pid", Type: "int"}}}
	got := operationArgumentSensitivity(document, map[string]string{"content": "$input.payload", "endpoint": "https://${input.payload}@example.invalid/", "target_pid": "$input.pid", "literal": "value"})
	if !got["content"] || got["target_pid"] || got["literal"] {
		t.Fatalf("unexpected sensitivity mapping: %#v", got)
	}
	if !got["endpoint"] {
		t.Fatalf("templated sensitive input did not mark argument sensitive: %#v", got)
	}
}

func TestNormalizeOperationPackArgumentsLoadsFileInputsForByteArguments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	document := packsvc.Document{Arguments: []packsvc.Argument{{Name: "payload", Type: "bytes"}, {Name: "path", Type: "wstring"}}}
	got := normalizeOperationPackArguments(document, map[string]string{"payload": path, "path": path})
	if got["payload"] != "@"+path {
		t.Fatalf("byte payload was not normalized as a file: %q", got["payload"])
	}
	if got["path"] != path {
		t.Fatalf("non-byte argument changed: %q", got["path"])
	}
	got = normalizeOperationPackArguments(document, map[string]string{"payload": "@file:" + path})
	if got["payload"] != "@"+path {
		t.Fatalf("@file byte payload was not normalized: %q", got["payload"])
	}
}

func TestOperationFanOutProofCountsResolvedBranches(t *testing.T) {
	receipt := operationsvc.Receipt{Steps: []operationsvc.StepReceipt{{ID: "targets", FanOut: &operationsvc.FanOutReceipt{Branches: []operationsvc.FanOutBranchReceipt{{ID: "target-01"}, {ID: "target-02"}}}}}}
	counts := operationFanOutCounts(receipt)
	if err := matchOperationProofFanOut(map[string]int{"targets": 2}, counts); err != nil {
		t.Fatal(err)
	}
	if err := matchOperationProofFanOut(map[string]int{"targets": 3}, counts); err == nil {
		t.Fatal("mismatched fan-out count passed")
	}
}
