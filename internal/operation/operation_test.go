package operation

import (
	"crypto/sha256"
	"encoding/hex"
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
	registry := &Registry{items: map[string]Resolved{}, unqualified: map[string][]string{}, packRegistry: packs}
	receipt := NewReceipt(item, registry, filepath.Join(t.TempDir(), "operation.json"), "lab", "devbox", "", "x64", "mingw", map[string]string{"pid": "7", "secret": "do-not-store"})
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
	registry := &Registry{items: map[string]Resolved{}, unqualified: map[string][]string{}, packRegistry: packs}
	receipt := NewReceipt(item, registry, filepath.Join(t.TempDir(), "operation.json"), "lab", "devbox", "", "x64", "auto", nil)
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

func TestSchemaVersionSixDAGValidatesDependenciesAndAncestorCaptures(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 6, Execution: "dag", ID: "dag", Version: "1.0.0", Title: "DAG", Summary: "Dependency-aware execution", Tier: "internal", Steps: []Step{
		{ID: "discover", Pack: "host-discovery", Expect: &packsvc.ProofExpectation{Tag: "host", Fields: map[string]string{"status": "complete"}}, Captures: map[string]Capture{"host_name": {Tag: "host", Field: "name"}}},
		{ID: "independent", Pack: "host-discovery", Expect: &packsvc.ProofExpectation{Tag: "host", Fields: map[string]string{"status": "complete"}}},
		{ID: "consume", Pack: "host-discovery", DependsOn: []string{"discover"}, Arguments: map[string]string{"value": "$capture.host_name"}, Expect: &packsvc.ProofExpectation{Tag: "done", Fields: map[string]string{"host": "$step.discover.host_name"}}},
	}}
	if err := validate(document); err != nil {
		t.Fatalf("valid dag rejected: %v", err)
	}
	document.Steps[2].DependsOn = []string{"independent"}
	if err := validate(document); err == nil || (!strings.Contains(err.Error(), "transitive") && !strings.Contains(err.Error(), "forward capture")) {
		t.Fatalf("sibling capture should be rejected, got %v", err)
	}
}

func TestSchemaVersionSixDAGRejectsCyclesAndLinearFeatures(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 6, Execution: "dag", ID: "cycle", Version: "1.0.0", Title: "Cycle", Summary: "Reject a cycle", Tier: "internal", Steps: []Step{
		{ID: "one", Pack: "host-discovery", DependsOn: []string{"two"}, Expect: &packsvc.ProofExpectation{Tag: "one"}},
		{ID: "two", Pack: "host-discovery", DependsOn: []string{"one"}, Expect: &packsvc.ProofExpectation{Tag: "two"}},
	}}
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected cycle rejection, got %v", err)
	}
	document.Steps[0].DependsOn = nil
	document.Steps[1].Outcomes = []Outcome{{ID: "bad", Expect: packsvc.ProofExpectation{Tag: "two"}, Next: "$complete"}}
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "ordered outcomes") {
		t.Fatalf("expected outcome rejection, got %v", err)
	}
}

func TestSchemaVersionSevenBackgroundReadiness(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 7, Execution: "dag", ID: "async", Version: "1.0.0", Title: "Async", Summary: "Readiness-aware execution", Tier: "internal", Steps: []Step{
		{
			ID: "watch", Pack: "host-discovery", Mode: "background", TimeoutMS: 120000,
			Ready:         &packsvc.ProofExpectation{Tag: "watch", Fields: map[string]string{"status": "ready"}},
			Expect:        &packsvc.ProofExpectation{Tag: "watch", Fields: map[string]string{"status": "complete"}},
			ReadyCaptures: map[string]Capture{"watch_id": {Tag: "watch", Field: "id"}},
		},
		{
			ID: "trigger", Pack: "identity", DependsOnReady: []string{"watch"},
			Arguments: map[string]string{"watch_id": "$capture.watch_id"},
			Expect:    &packsvc.ProofExpectation{Tag: "identity", Fields: map[string]string{"status": "complete"}},
		},
	}}
	if err := validate(document); err != nil {
		t.Fatalf("valid background dag rejected: %v", err)
	}
	receipt := Receipt{Steps: []StepReceipt{{ID: "watch", State: "ready", Mode: "background"}, {ID: "trigger", State: "pending"}}}
	ready, err := ReadyDAGSteps(document, receipt)
	if err != nil || len(ready) != 2 || ready[0] != 0 || ready[1] != 1 {
		t.Fatalf("ready background step did not release dependent: ready=%v err=%v", ready, err)
	}
}

func TestSchemaVersionSevenRejectsInvalidReadiness(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 7, Execution: "dag", ID: "async-bad", Version: "1.0.0", Title: "Async", Summary: "Reject invalid readiness", Tier: "internal", Steps: []Step{
		{ID: "watch", Pack: "host-discovery", Mode: "background", Expect: &packsvc.ProofExpectation{Tag: "watch"}},
		{ID: "trigger", Pack: "identity", DependsOnReady: []string{"watch"}, Expect: &packsvc.ProofExpectation{Tag: "identity"}},
	}}
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "requires schema v7, ready, and timeout_ms") {
		t.Fatalf("missing readiness contract was not rejected: %v", err)
	}
	document.Steps[0].Ready = &packsvc.ProofExpectation{Tag: "watch"}
	document.Steps[0].TimeoutMS = 1000
	document.Steps[0].Mode = "foreground"
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "foreground mode") {
		t.Fatalf("foreground readiness was not rejected: %v", err)
	}
}

func TestDAGReadyWavesBlockingAndCleanupOrder(t *testing.T) {
	document := Document{Execution: "dag", Steps: []Step{
		{ID: "root-a", Cleanup: &Cleanup{Pack: "a"}},
		{ID: "root-b", Cleanup: &Cleanup{Pack: "b"}},
		{ID: "join", DependsOn: []string{"root-a", "root-b"}, Cleanup: &Cleanup{Pack: "join"}},
	}}
	receipt := Receipt{Steps: []StepReceipt{
		{ID: "root-a", State: "pending"},
		{ID: "root-b", State: "pending"},
		{ID: "join", State: "pending"},
	}}
	ready, err := ReadyDAGSteps(document, receipt)
	if err != nil || len(ready) != 2 || ready[0] != 0 || ready[1] != 1 {
		t.Fatalf("unexpected root wave: %v err=%v", ready, err)
	}
	receipt.Steps[0].State, receipt.Steps[1].State = "completed", "completed"
	ready, err = ReadyDAGSteps(document, receipt)
	if err != nil || len(ready) != 1 || ready[0] != 2 {
		t.Fatalf("unexpected join wave: %v err=%v", ready, err)
	}
	receipt.Steps[2].State = "completed"
	if got := CleanupStepIndexes(document, receipt); len(got) != 3 || got[0] != 2 || got[1] != 1 || got[2] != 0 {
		t.Fatalf("cleanup was not reverse-topological: %v", got)
	}
	receipt.Steps[0].State, receipt.Steps[1].State, receipt.Steps[2].State = "failed", "pending", "pending"
	BlockDAGDescendants(document, &receipt, []string{"root-a"})
	if receipt.Steps[2].State != "blocked" || receipt.Steps[1].State != "pending" {
		t.Fatalf("unexpected blocking: %#v", receipt.Steps)
	}
}

func TestTopologyValueSyntax(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 1, ID: "topology", Version: "1.0.0", Title: "Topology", Summary: "Validate topology input", Tier: "public", Inputs: []Input{{Name: "host", Type: "wstring", TopologyValue: "unknown.computer_name"}}, Steps: []Step{{ID: "host", Pack: "host-discovery"}}}
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "invalid topology value") {
		t.Fatalf("expected invalid topology value, got %v", err)
	}
}

func TestSchemaVersionTwoRequiresStepContracts(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 2, ID: "no-contract", Version: "1.0.0", Title: "No contract", Summary: "Missing expected output", Tier: "public", Steps: []Step{{ID: "host", Pack: "host-discovery"}}}
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "requires expect") {
		t.Fatalf("expected v2 contract rejection, got %v", err)
	}
	document.SchemaVersion = 1
	if err := validate(document); err != nil {
		t.Fatalf("schema v1 compatibility failed: %v", err)
	}
}

func TestExpectationRejectsCompletedRuntimeWithFailedStructuredStatus(t *testing.T) {
	expect := &packsvc.ProofExpectation{Tag: "allocate", Fields: map[string]string{"status": "complete", "base": "*"}}
	if _, _, err := EvaluateExpectation([]string{"[allocate] status=failed base=0x1000"}, expect, nil, nil, nil); err == nil {
		t.Fatal("completed runtime output with status=failed satisfied the step contract")
	}
	fields, payload, err := EvaluateExpectation([]string{"[allocate] status=complete base=0x1000"}, expect, nil, nil, nil)
	if err != nil || payload || len(fields) != 2 {
		t.Fatalf("valid contract failed: fields=%v payload=%t err=%v", fields, payload, err)
	}
}

func TestExpectationResolvesReferencesAndVerifiesPayload(t *testing.T) {
	data := []byte("atomic-operation-payload")
	sum := sha256.Sum256(data)
	expect := &packsvc.ProofExpectation{Tag: "read", Fields: map[string]string{"status": "complete", "pid": "$input.pid", "address": "$capture.base"}, Payload: &packsvc.ProofPayloadExpectation{Tag: "read-data", Field: "hex", Encoding: "hex", SHA256: "$input.sha256"}}
	lines := []string{"[read] status=complete pid=42 address=0x2000", "[read-data] offset=0 hex=" + hex.EncodeToString(data[:10]), "[read-data] offset=10 hex=" + hex.EncodeToString(data[10:])}
	_, verified, err := EvaluateExpectation(lines, expect, map[string]string{"pid": "42", "sha256": hex.EncodeToString(sum[:])}, map[string]string{"base": "0x2000"}, nil)
	if err != nil || !verified {
		t.Fatalf("payload contract failed: verified=%t err=%v", verified, err)
	}
}

func TestLoadReceiptMigratesVersionOneContractState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operation.json")
	legacy := Receipt{Schema: ReceiptSchema, SchemaVersion: 1, Status: "completed", Steps: []StepReceipt{{ID: "one", State: "completed"}, {ID: "two", State: "pending"}}}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadReceipt(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SchemaVersion != ReceiptSchemaVersion || loaded.Steps[0].ContractState != "legacy" || loaded.Steps[1].ContractState != "" || len(loaded.ActualPath) != 1 {
		t.Fatalf("unexpected migrated receipt: %#v", loaded)
	}
}

func TestSchemaVersionThreeRoutesForwardAndRejectsCycles(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 3, ID: "adaptive", Version: "1.0.0", Title: "Adaptive", Summary: "Route a completed result", Tier: "internal", Steps: []Step{
		{ID: "map", Pack: "host-discovery", Outcomes: []Outcome{{ID: "mapped", Expect: packsvc.ProofExpectation{Tag: "map", Fields: map[string]string{"status": "complete"}}, Next: "start"}, {ID: "fallback", Expect: packsvc.ProofExpectation{Tag: "map", Fields: map[string]string{"status": "failed"}}, Next: "allocate"}}},
		{ID: "start", Pack: "host-discovery", Expect: &packsvc.ProofExpectation{Tag: "start", Fields: map[string]string{"status": "complete"}}},
		{ID: "allocate", Pack: "host-discovery", Expect: &packsvc.ProofExpectation{Tag: "allocate", Fields: map[string]string{"status": "complete"}}},
	}}
	if err := validate(document); err != nil {
		t.Fatal(err)
	}
	document.Steps[0].Outcomes[0].Next = "map"
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "later step") {
		t.Fatalf("expected backward route rejection, got %v", err)
	}
}

func TestResultRoutePinsPathAndSkipsUnvisitedSteps(t *testing.T) {
	document := Document{Steps: []Step{{ID: "map"}, {ID: "start"}, {ID: "allocate"}, {ID: "write"}}}
	receipt := Receipt{Steps: []StepReceipt{{ID: "map", State: "completed", NextStep: "allocate"}, {ID: "start", State: "pending"}, {ID: "allocate", State: "pending"}, {ID: "write", State: "pending"}}}
	if err := ApplyRoute(document, &receipt, 0); err != nil {
		t.Fatal(err)
	}
	if len(receipt.ActualPath) != 1 || receipt.ActualPath[0] != "map" || receipt.Steps[1].State != "skipped" || len(receipt.SkippedSteps) != 1 {
		t.Fatalf("route was not persisted: %#v", receipt)
	}
	index, ok, err := NextRunnableStep(document, receipt)
	if err != nil || !ok || index != 2 {
		t.Fatalf("next=%d ok=%t err=%v", index, ok, err)
	}
}

func TestFailedSelectedStepCannotBeRetriedByResume(t *testing.T) {
	document := Document{Steps: []Step{{ID: "map"}, {ID: "allocate"}}}
	receipt := Receipt{
		ActualPath: []string{"map"},
		Steps: []StepReceipt{
			{ID: "map", State: "completed", NextStep: "allocate"},
			{ID: "allocate", State: "failed"},
		},
	}
	if _, ok, err := NextRunnableStep(document, receipt); err == nil || ok || !strings.Contains(err.Error(), "cannot be resumed") {
		t.Fatalf("expected failed route to remain terminal, ok=%t err=%v", ok, err)
	}
}

func TestOutcomesAreOrderedAndRuntimeResultSelectsOne(t *testing.T) {
	outcomes := []Outcome{
		{ID: "mapped", Expect: packsvc.ProofExpectation{Tag: "map", Fields: map[string]string{"status": "complete"}}, Next: "start"},
		{ID: "fallback", Expect: packsvc.ProofExpectation{Tag: "map", Fields: map[string]string{"status": "failed"}}, Next: "allocate"},
	}
	selected, fields, _, err := EvaluateOutcomes([]string{"[map] status=failed error=5"}, outcomes, nil, nil, nil)
	if err != nil || selected.ID != "fallback" || selected.Next != "allocate" || len(fields) != 1 {
		t.Fatalf("selected=%#v fields=%v err=%v", selected, fields, err)
	}
	if _, _, _, err := EvaluateOutcomes([]string{"[map] status=unknown"}, outcomes, nil, nil, nil); err == nil {
		t.Fatal("unmatched result selected a route")
	}
}

func TestGraphRendersMermaidAndJSON(t *testing.T) {
	document := Document{ID: "adaptive", Steps: []Step{{ID: "map", Pack: "section", Outcomes: []Outcome{{ID: "mapped", Next: "$complete"}, {ID: "fallback", Next: "allocate"}}}, {ID: "allocate", Pack: "memory"}}}
	mermaid, err := Graph(document, "mermaid")
	if err != nil || !strings.Contains(mermaid, "mapped") || !strings.Contains(mermaid, "step_allocate") {
		t.Fatalf("mermaid=%q err=%v", mermaid, err)
	}
	body, err := Graph(document, "json")
	if err != nil || !strings.Contains(body, `"schema": "bofbench.operation-graph"`) || !strings.Contains(body, `"outcome": "fallback"`) {
		t.Fatalf("json=%q err=%v", body, err)
	}
}

func TestSchemaVersionFourRequiresExactlyOneStepTarget(t *testing.T) {
	document := Document{Schema: Schema, SchemaVersion: 4, ID: "parent", Version: "1.0.0", Title: "Parent", Summary: "Nested operation", Tier: "internal", Steps: []Step{{ID: "child", Pack: "host-discovery", Operation: "process-triage", Expect: &packsvc.ProofExpectation{Tag: "operation", Fields: map[string]string{"status": "complete"}}}}}
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected pack/operation exclusivity rejection, got %v", err)
	}
	document.Steps[0].Pack = ""
	if err := validate(document); err != nil {
		t.Fatalf("valid child operation step failed: %v", err)
	}
}

func TestNestedOperationsPinDependenciesExportCapturesAndExpandGraph(t *testing.T) {
	project := t.TempDir()
	writeOperation := func(id, body string) {
		t.Helper()
		root := filepath.Join(project, ".bofbench", "operations", id)
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "operation.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeOperation("child", `{"schema":"bofbench.operation","schema_version":4,"id":"child","version":"1.0.0","title":"Child","summary":"Child operation","tier":"internal","steps":[{"id":"host","pack":"host-discovery","expect":{"tag":"host","fields":{"name":"*"}},"captures":{"host_name":{"tag":"host","field":"name"}}}]}`)
	writeOperation("parent", `{"schema":"bofbench.operation","schema_version":4,"id":"parent","version":"1.0.0","title":"Parent","summary":"Parent operation","tier":"internal","steps":[{"id":"nested","operation":"child","expect":{"tag":"operation","fields":{"status":"complete"}},"captures":{"exported_host":{"capture":"host_name"}}}]}`)
	packs, err := packsvc.Load(packsvc.LoadOptions{Project: project})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := Load(LoadOptions{Project: project, PackRegistry: packs})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := registry.Resolve("project/parent")
	if err != nil {
		t.Fatal(err)
	}
	dependencies := registry.DependencyHashes(parent)
	if dependencies["operation:project/parent"] == "" || dependencies["operation:project/child"] == "" || dependencies["pack:builtin/host-discovery"] == "" {
		t.Fatalf("transitive dependency closure was incomplete: %#v", dependencies)
	}
	childReceipt := Receipt{Captures: map[string]string{"host_name": "DEVBOX"}}
	captured, err := CaptureChildOutput(childReceipt, parent.Document.Steps[0].Captures)
	if err != nil || captured["exported_host"] != "DEVBOX" {
		t.Fatalf("child capture export failed: %#v err=%v", captured, err)
	}
	graph, err := registry.Graph(parent, "json", true)
	if err != nil || !strings.Contains(graph, `"id": "nested/host"`) {
		t.Fatalf("expanded graph omitted child node: %s err=%v", graph, err)
	}
}

func TestNestedOperationRegistryRejectsIndirectCycles(t *testing.T) {
	project := t.TempDir()
	for id, child := range map[string]string{"a": "b", "b": "a"} {
		root := filepath.Join(project, ".bofbench", "operations", id)
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatal(err)
		}
		body := `{"schema":"bofbench.operation","schema_version":4,"id":"` + id + `","version":"1.0.0","title":"Cycle","summary":"Cycle test","tier":"internal","steps":[{"id":"child","operation":"` + child + `","expect":{"tag":"operation","fields":{"status":"complete"}}}]}`
		if err := os.WriteFile(filepath.Join(root, "operation.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	packs, err := packsvc.Load(packsvc.LoadOptions{Project: project})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(LoadOptions{Project: project, PackRegistry: packs}); err == nil || !strings.Contains(err.Error(), "operation call cycle") {
		t.Fatalf("expected indirect cycle rejection, got %v", err)
	}
}

func TestSchemaVersionFiveValidatesParallelGroupsAndExports(t *testing.T) {
	expect := func(tag string) *packsvc.ProofExpectation {
		return &packsvc.ProofExpectation{Tag: tag, Fields: map[string]string{"status": "complete"}}
	}
	document := Document{
		Schema: Schema, SchemaVersion: 5, ID: "parallel", Version: "1.0.0",
		Title: "Parallel", Summary: "Parallel validation", Tier: "internal",
		Steps: []Step{{
			ID: "fanout",
			Parallel: &Parallel{
				Join: "all",
				Branches: []ParallelBranch{
					{ID: "left", Pack: "host-discovery", Expect: expect("left"), Captures: map[string]Capture{"value": {Tag: "left", Field: "value"}}},
					{ID: "right", Pack: "host-discovery", Expect: expect("right")},
				},
				Exports: map[string]string{"selected": "$branch.left.value"},
			},
		}},
	}
	if err := validate(document); err != nil {
		t.Fatalf("valid parallel operation failed: %v", err)
	}
	document.Steps[0].Pack = "host-discovery"
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected step target exclusivity rejection, got %v", err)
	}
	document.Steps[0].Pack = ""
	document.Steps[0].Parallel.Join = "any"
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "join must be all") {
		t.Fatalf("expected join rejection, got %v", err)
	}
	document.Steps[0].Parallel.Join = "all"
	document.Steps[0].Parallel.Exports["selected"] = "$branch.right.missing"
	if err := validate(document); err == nil || !strings.Contains(err.Error(), "unknown branch capture") {
		t.Fatalf("expected export rejection, got %v", err)
	}
}

func TestParallelReceiptPinsBranchesAndRecordsExpandedPath(t *testing.T) {
	packs, err := packsvc.Load(packsvc.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	document := Document{
		Schema: Schema, SchemaVersion: 5, ID: "parallel-receipt", Version: "1.0.0",
		Title: "Parallel Receipt", Summary: "Pin parallel dependencies", Tier: "public",
		Steps: []Step{{
			ID: "fanout",
			Parallel: &Parallel{Join: "all", Branches: []ParallelBranch{
				{ID: "left", Pack: "host-discovery", Expect: &packsvc.ProofExpectation{Tag: "host", Fields: map[string]string{"status": "complete"}}},
				{ID: "right", Pack: "identity", Expect: &packsvc.ProofExpectation{Tag: "identity", Fields: map[string]string{"status": "complete"}}},
			}},
		}},
	}
	item := Resolved{Document: document, Catalog: "test", Qualified: "test/parallel-receipt", SHA256: Fingerprint(document)}
	registry := &Registry{items: map[string]Resolved{}, unqualified: map[string][]string{}, packRegistry: packs}
	receipt := NewReceipt(item, registry, filepath.Join(t.TempDir(), "operation.json"), "lab", "devbox", "", "x64", "mingw", nil)
	if receipt.SchemaVersion != ReceiptSchemaVersion || receipt.Steps[0].Parallel == nil || len(receipt.Steps[0].Parallel.Branches) != 2 {
		t.Fatalf("parallel receipt was not initialized: %#v", receipt)
	}
	for _, branch := range receipt.Steps[0].Parallel.Branches {
		if branch.PackSHA256 == "" {
			t.Fatalf("parallel branch hash was not pinned: %#v", branch)
		}
		branch.State = "completed"
	}
	RecordParallelPath(&receipt, "fanout", *receipt.Steps[0].Parallel)
	want := []string{"fanout", "fanout/left", "fanout/right", "fanout/$join"}
	if strings.Join(receipt.ExpandedPath, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected expanded parallel path: %#v", receipt.ExpandedPath)
	}
	graph, err := Graph(document, "json")
	if err != nil || !strings.Contains(graph, `"id": "fanout/$join"`) || !strings.Contains(graph, `"outcome": "fork"`) || !strings.Contains(graph, `"outcome": "join"`) {
		t.Fatalf("parallel graph omitted fork/join nodes: %s err=%v", graph, err)
	}
}

func TestParallelCleanupDetectsCompletedStatefulBranches(t *testing.T) {
	document := Document{Steps: []Step{{
		ID: "fanout",
		Parallel: &Parallel{Join: "all", Branches: []ParallelBranch{
			{ID: "left", Pack: "host-discovery", Cleanup: &Cleanup{Pack: "host-discovery"}},
			{ID: "right", Pack: "identity"},
		}},
	}}}
	receipt := Receipt{Steps: []StepReceipt{{
		ID: "fanout", State: "completed",
		Parallel: &ParallelReceipt{State: "completed", Branches: []StepReceipt{
			{ID: "left", State: "completed"},
			{ID: "right", State: "completed"},
		}},
	}}}
	indexes := CleanupStepIndexes(document, receipt)
	if len(indexes) != 1 || indexes[0] != 0 {
		t.Fatalf("parallel cleanup step was not selected: %#v", indexes)
	}
	receipt.Steps[0].Parallel.Branches[0].CleanupState = "completed"
	if indexes := CleanupStepIndexes(document, receipt); len(indexes) != 0 {
		t.Fatalf("completed parallel cleanup was selected again: %#v", indexes)
	}
}
