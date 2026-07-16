package app

import (
	"strings"
	"testing"

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
	got := operationArgumentSensitivity(document, map[string]string{"content": "$input.payload", "target_pid": "$input.pid", "literal": "value"})
	if !got["content"] || got["target_pid"] || got["literal"] {
		t.Fatalf("unexpected sensitivity mapping: %#v", got)
	}
}
