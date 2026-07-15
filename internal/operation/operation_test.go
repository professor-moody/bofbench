package operation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	packsvc "bofbench/internal/pack"
	"bofbench/internal/runtimeadapter"
)

func TestValidateReferencesRequireEarlierCaptures(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 1, ID: "bad", Version: "1.0.0", Title: "Bad", Summary: "Bad reference", Tier: "public", Inputs: []Input{{Name: "pid", Type: "int", Required: true}}, Steps: []Step{
		{ID: "read", Pack: "host-discovery", Arguments: map[string]string{"value": "$capture.later"}},
		{ID: "later", Pack: "host-discovery", Captures: map[string]Capture{"later": {Tag: "host", Field: "name"}}},
	}}
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "forward capture") {
		t.Fatalf("expected forward capture rejection, got %v", err)
	}
}

func TestCaptureOutputUsesTagAndField(t *testing.T) {
	values, err := CaptureOutput([]string{"noise", "[map] status=complete remote_base=0x7ff0 bytes=1"}, map[string]Capture{"base": {Tag: "map", Field: "remote_base"}, "size": {Tag: "map", Field: "bytes"}})
	if err != nil {
		t.Fatal(err)
	}
	if values["base"] != "0x7ff0" || values["size"] != "1" {
		t.Fatalf("unexpected captures: %#v", values)
	}
}

func TestReceiptRedactsSensitiveInputsAndPinsHashes(t *testing.T) {
	packs, err := packsvc.Load(packsvc.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	document := Document{Schema: Schema, SchemaVersion: 1, ID: "one", Version: "1.0.0", Title: "One", Summary: "One step", Tier: "public", Inputs: []Input{{Name: "pid", Type: "int", Required: true}, {Name: "secret", Type: "string", Sensitive: true}}, Steps: []Step{{ID: "host", Pack: "host-discovery"}}}
	item := Resolved{Document: document, Catalog: "test", Qualified: "test/one", SHA256: Fingerprint(document)}
	receipt := NewReceipt(item, packs, filepath.Join(t.TempDir(), "operation.json"), "lab", "devbox", "", "x64", "mingw", map[string]string{"pid": "7", "secret": "do-not-store"})
	if receipt.Inputs["secret"] != "" || len(receipt.RedactedInputs) != 1 || receipt.RedactedInputs[0] != "secret" {
		t.Fatalf("sensitive input persisted: %#v", receipt)
	}
	if receipt.Steps[0].PackSHA256 == "" {
		t.Fatal("pack hash was not pinned")
	}
	if err := SaveReceipt(receipt.Path, &receipt); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(receipt.Path)
	if strings.Contains(string(data), "do-not-store") {
		t.Fatal("secret appeared in receipt")
	}
}

func TestProjectOperationCollidesWithBuiltinByQualifiedName(t *testing.T) {
	project := t.TempDir()
	root := filepath.Join(project, ".bofbench", "operations", "process-triage")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"schema":"bofbench.operation","schema_version":1,"id":"process-triage","version":"2.0.0","title":"Local triage","summary":"Project-local triage","tier":"public","steps":[{"id":"host","pack":"host-discovery"}]}`
	if err := os.WriteFile(filepath.Join(root, "operation.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	packs, err := packsvc.Load(packsvc.LoadOptions{Project: project})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := Load(LoadOptions{Project: project, PackRegistry: packs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve("process-triage"); err == nil || !strings.Contains(err.Error(), "multiple catalogs") {
		t.Fatalf("expected qualified collision, got %v", err)
	}
	if _, err := registry.Resolve("project/process-triage"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveValueSupportsInputCaptureStepAndTopology(t *testing.T) {
	inputs := map[string]string{"pid": "12"}
	captures := map[string]string{"base": "0x1000"}
	topology := map[string]string{"target.computer_name": "DEVBOX"}
	for reference, want := range map[string]string{"$input.pid": "12", "$capture.base": "0x1000", "$step.map.base": "0x1000", "$topology.target.computer_name": "DEVBOX", "literal": "literal"} {
		got, err := ResolveValue(reference, inputs, captures, topology)
		if err != nil || got != want {
			t.Fatalf("%s: got %q err=%v", reference, got, err)
		}
	}
}

func TestTopologyRolesRequireResolvedComputers(t *testing.T) {
	if err := ValidateTopologyRoles([]string{"execution", "target"}, map[string]string{"execution.computer_name": "DEVBOX"}); err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatalf("expected missing target role, got %v", err)
	}
	if err := ValidateTopologyRoles([]string{"execution", "target"}, map[string]string{"execution.computer_name": "DEVBOX", "target.computer_name": "TARGET"}); err != nil {
		t.Fatal(err)
	}
}

func TestResumeAndCleanupOrdering(t *testing.T) {
	document := Document{Steps: []Step{{ID: "one", Cleanup: &Cleanup{Pack: "first"}}, {ID: "two", Cleanup: &Cleanup{Pack: "second"}}, {ID: "three"}}}
	receipt := Receipt{Steps: []StepReceipt{{ID: "one", State: "completed"}, {ID: "two", State: "completed"}, {ID: "three", State: "incomplete"}}}
	if got := RunnableStepIndexes(receipt); len(got) != 1 || got[0] != 2 {
		t.Fatalf("unexpected resume indexes: %#v", got)
	}
	if got := CleanupStepIndexes(document, receipt); len(got) != 2 || got[0] != 1 || got[1] != 0 {
		t.Fatalf("cleanup was not reversed: %#v", got)
	}
	receipt.Steps[1].CleanupState = "completed"
	if got := CleanupStepIndexes(document, receipt); len(got) != 1 || got[0] != 0 {
		t.Fatalf("completed cleanup was not skipped: %#v", got)
	}
}

func TestRuntimeClassificationRequiresCompleteOutput(t *testing.T) {
	cases := []struct {
		state    string
		complete bool
		failed   bool
		want     string
	}{{"completed", true, false, "completed"}, {"submitted", false, false, "incomplete"}, {"running", false, false, "incomplete"}, {"failed", true, false, "failed"}, {"timeout", false, false, "failed"}}
	for _, test := range cases {
		got, _ := ClassifyExecution(test.state, test.complete, test.failed)
		if got != test.want {
			t.Fatalf("state=%s complete=%t failed=%t: got %s want %s", test.state, test.complete, test.failed, got, test.want)
		}
	}
}

func TestStepQualifiedCaptureMustBelongToNamedStep(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 1, ID: "wrong-owner", Version: "1.0.0", Title: "Wrong owner", Summary: "Reject a mismatched step capture", Tier: "public", Steps: []Step{
		{ID: "first", Pack: "host-discovery", Captures: map[string]Capture{"host_name": {Tag: "host", Field: "name"}}},
		{ID: "second", Pack: "host-discovery", Arguments: map[string]string{"value": "$step.second.host_name"}},
	}}
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "step capture") {
		t.Fatalf("expected capture owner rejection, got %v", err)
	}
}

func TestReceiptPinsCleanupPackHash(t *testing.T) {
	packs, err := packsvc.Load(packsvc.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	document := Document{Schema: Schema, SchemaVersion: 1, ID: "cleanup", Version: "1.0.0", Title: "Cleanup", Summary: "Pins action and cleanup", Tier: "public", Steps: []Step{{ID: "action", Pack: "host-discovery", Cleanup: &Cleanup{Pack: "host-discovery"}}}}
	item := Resolved{Document: document, Catalog: "test", Qualified: "test/cleanup", SHA256: Fingerprint(document)}
	receipt := NewReceipt(item, packs, filepath.Join(t.TempDir(), "operation.json"), "lab", "devbox", "", "x64", "auto", nil)
	if receipt.Steps[0].CleanupPack != "host-discovery" || receipt.Steps[0].CleanupSHA256 == "" {
		t.Fatalf("cleanup hash was not pinned: %#v", receipt.Steps[0])
	}
}

func TestRefreshRuntimeReceiptUsesCompletedExternalTask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	current := runtimeadapter.Receipt{Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion, Runtime: "cobaltstrike", ExecutionState: "submitted", ReceiptPath: path, ObjectSHA256: "same"}
	updated := current
	updated.ExecutionState, updated.OutputComplete, updated.Status = "completed", true, "pass"
	updated.Output = []string{"[done] status=complete value=7"}
	data, _ := json.Marshal(updated)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := RefreshRuntimeReceipt(current)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExecutionState != "completed" || !got.OutputComplete || got.ObjectSHA256 != "same" {
		t.Fatalf("unexpected refreshed receipt: %#v", got)
	}
}

func TestTopologyValueSyntax(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 1, ID: "topology", Version: "1.0.0", Title: "Topology", Summary: "Validate topology input", Tier: "public", Inputs: []Input{{Name: "host", Type: "wstring", TopologyValue: "unknown.computer_name"}}, Steps: []Step{{ID: "host", Pack: "host-discovery"}}}
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "invalid topology value") {
		t.Fatalf("expected invalid topology value, got %v", err)
	}
}
