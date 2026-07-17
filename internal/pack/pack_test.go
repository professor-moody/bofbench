package pack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryAppliesBuiltinAndExternalPacks(t *testing.T) {
	t.Setenv("BOFBENCH_CONFIG_HOME", t.TempDir())
	project := newProject(t)
	catalog := t.TempDir()
	packRoot := filepath.Join(catalog, "operator-note")
	if err := os.MkdirAll(packRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := Document{
		Schema: Schema, SchemaVersion: 1, ID: "operator-note", Version: "1.0.0", Title: "Operator Note", Summary: "Print a parameter-ready pack marker", Tier: "internal",
		Capabilities: []string{"operator marker"}, Effects: []string{"reads data"}, Platforms: []string{"windows"}, Architecture: []string{"x64"}, Privilege: "user", Network: "none",
		Arguments: []Argument{{Name: "message", Type: "string", Required: true}}, Source: Source{HeaderFragments: []string{"operator.h"}, Calls: []string{"bofbench_pack_operator_note()"}},
		ExpectedAnalysis: []string{"operator marker"}, OutputFields: []string{"message"}, TargetSupport: []string{"native", "sliver"},
	}
	writeTestJSON(t, filepath.Join(packRoot, "pack.json"), manifest)
	if err := os.WriteFile(filepath.Join(packRoot, "operator.h"), []byte(`static void bofbench_pack_operator_note(void) { BeaconPrintf(CALLBACK_OUTPUT, "[operator-note] status=ready"); }`), 0o644); err != nil {
		t.Fatal(err)
	}
	registry, err := Load(LoadOptions{Project: project, ExtraCatalogs: []string{catalog}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := registry.Apply(project, []string{"host-discovery", filepath.Base(catalog) + "/operator-note"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Added) != 2 || result.LockPath == "" {
		t.Fatalf("apply result = %+v", result)
	}
	source, err := os.ReadFile(filepath.Join(project, "demo.c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bofbench_feature_host();", "bofbench_pack_operator_note();"} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("source missing %q:\n%s", want, source)
		}
	}
	lock, _, err := LoadLock(project)
	if err != nil || len(lock.Packs) != 2 || lock.Packs[1].SHA256 == "" {
		t.Fatalf("lock=%+v err=%v", lock, err)
	}
	if lock.Packs[1].CatalogRoot == "" {
		t.Fatalf("external catalog root was not locked: %+v", lock.Packs[1])
	}
	reopened, err := Load(LoadOptions{Project: project})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Resolve(filepath.Base(catalog) + "/operator-note"); err != nil {
		t.Fatalf("project could not rediscover its locked explicit catalog: %v", err)
	}
	second, err := registry.Apply(project, []string{"host-discovery", filepath.Base(catalog) + "/operator-note"})
	if err != nil || len(second.Added) != 0 || len(second.Existing) != 2 {
		t.Fatalf("second=%+v err=%v", second, err)
	}
}

func TestPackValidationRejectsTraversalAndUnknownFields(t *testing.T) {
	root := t.TempDir()
	manifest := `{"schema":"bofbench.pack","schema_version":1,"id":"bad","version":"1","title":"Bad","summary":"Bad","tier":"internal","capabilities":["x"],"effects":["reads data"],"platforms":["windows"],"architecture":["x64"],"privilege":"user","network":"none","source":{"header_fragments":["../bad.h"]},"target_support":["native"]}`
	path := filepath.Join(root, "pack.json")
	if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateFile(path); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("traversal error = %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSuffix(manifest, "}")+`,"mystery":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateFile(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestPackSchemaV1CompatibilityAndV2Contracts(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pack.h"), []byte("static void pack(void) {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := Document{
		Schema: Schema, SchemaVersion: 1, ID: "versioned", Version: "1.0.0", Title: "Versioned", Summary: "Schema compatibility", Tier: "public",
		Capabilities: []string{"inventory"}, Effects: []string{"reads data"}, Platforms: []string{"windows"}, Architecture: []string{"x64"}, Privilege: "user", Network: "none",
		Arguments: []Argument{{Name: "limit", Type: "int"}}, Source: Source{HeaderFragments: []string{"pack.h"}}, TargetSupport: []string{"native"},
	}
	path := filepath.Join(root, "pack.json")
	writeTestJSON(t, path, base)
	if _, err := ValidateFile(path); err != nil {
		t.Fatalf("schema v1 must remain readable: %v", err)
	}
	base.AnalysisSignatures = []AnalysisSignature{{ID: "inventory", Name: "Inventory", Summary: "Read inventory", Steps: []AnalysisStep{{Action: "enumerate", APIs: []string{"EnumThings"}}}, Effects: []string{"reads data"}}}
	writeTestJSON(t, path, base)
	if _, err := ValidateFile(path); err == nil || !strings.Contains(err.Error(), "require schema version 2") {
		t.Fatalf("schema v1 accepted v2 fields: %v", err)
	}
	base.SchemaVersion = 2
	base.ProofCases = []ProofCase{{ID: "bounded", Via: []string{"lab"}, Arguments: map[string]string{"limit": "10"}, Expect: ProofExpectation{Tag: "versioned", Fields: map[string]string{"status": "complete"}}}}
	writeTestJSON(t, path, base)
	if _, err := ValidateFile(path); err != nil {
		t.Fatalf("schema v2 contract rejected: %v", err)
	}
	base.ProofCases[0].Arguments["limit"] = "prefix-$UNKNOWN"
	writeTestJSON(t, path, base)
	if _, err := ValidateFile(path); err == nil || !strings.Contains(err.Error(), "$UNKNOWN") {
		t.Fatalf("embedded unsupported proof placeholder accepted: %v", err)
	}
}

func TestPackSchemaV3SensitiveCleanupAndProofContracts(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pack.h"), []byte("static void pack(void) {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	document := Document{
		Schema: Schema, SchemaVersion: 2, ID: "sensitive", Version: "1.0.0", Title: "Sensitive", Summary: "Schema v3 contract", Tier: "internal",
		Capabilities: []string{"exact secret read"}, Effects: []string{"accesses credential material"}, Platforms: []string{"windows"}, Architecture: []string{"x64"}, Privilege: "user", Network: "none",
		Arguments: []Argument{{Name: "password", Type: "wstring", Required: true, Sensitive: true}, {Name: "output_path", Type: "wstring", Required: true}},
		Source:    Source{HeaderFragments: []string{"pack.h"}}, OutputFields: []string{"hex", "status"}, SensitiveOutputFields: []string{"hex"},
		CleanupPack: "file-remove", CleanupArguments: map[string]string{"path": "$arg.output_path"}, TargetSupport: []string{"lab"},
		ProofCases: []ProofCase{{ID: "exact", Via: []string{"lab"}, Arguments: map[string]string{"password": "$PROOF_SECRET", "output_path": "$TEMP\\proof.pfx"}, Expect: ProofExpectation{Tag: "sensitive", Fields: map[string]string{"status": "complete"}, Payload: &ProofPayloadExpectation{Tag: "sensitive-data", Field: "hex", Encoding: "hex", SHA256: "$CANARY_SHA256"}}, Cleanup: true, StateChecks: []ProofStateCheck{{Phase: "after_cleanup", Kind: "pfx", Expect: "absent", Parameters: map[string]string{"path": "$TEMP\\proof.pfx", "password": "$PROOF_SECRET", "thumbprint": "$CERT_THUMBPRINT"}}}}},
	}
	path := filepath.Join(root, "pack.json")
	writeTestJSON(t, path, document)
	if _, err := ValidateFile(path); err == nil || !strings.Contains(err.Error(), "require schema version 3") {
		t.Fatalf("schema v2 accepted v3 fields: %v", err)
	}
	document.SchemaVersion = 3
	writeTestJSON(t, path, document)
	if _, err := ValidateFile(path); err != nil {
		t.Fatalf("schema v3 contract rejected: %v", err)
	}
	document.SensitiveOutputFields = []string{"undeclared"}
	writeTestJSON(t, path, document)
	if _, err := ValidateFile(path); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("undeclared sensitive output accepted: %v", err)
	}
}

func TestPackSchemaV4TopologyRolesCapturesAndStateChecks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pack.h"), []byte("static void pack(void) {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	document := Document{
		Schema: Schema, SchemaVersion: 3, ID: "topology-proof", Version: "1.0.0", Title: "Topology Proof", Summary: "Schema v4 contract", Tier: "internal",
		Capabilities: []string{"exact-host proof"}, Effects: []string{"reaches a supplied host"}, Platforms: []string{"windows"}, Architecture: []string{"x64"}, Privilege: "user", Network: "explicit host",
		Arguments: []Argument{{Name: "target_host", Type: "wstring", TopologyValue: "target.computer_name"}}, Source: Source{HeaderFragments: []string{"pack.h"}}, OutputFields: []string{"pid", "status"}, TargetSupport: []string{"lab"},
		ProofCases: []ProofCase{{
			ID: "cross-host", Via: []string{"lab"}, Roles: []string{"execution", "target"}, Arguments: map[string]string{},
			Expect:      ProofExpectation{Tag: "topology-proof", Fields: map[string]string{"status": "complete"}},
			Captures:    map[string]ProofCapture{"$SPAWNED_PID": {Tag: "topology-proof", Field: "pid"}},
			StateChecks: []ProofStateCheck{{Phase: "after_cleanup", Kind: "process", Expect: "absent", Role: "target", Parameters: map[string]string{"pid": "$SPAWNED_PID", "image": "cmd.exe", "marker": "BOFBench-$RUN_ID"}}},
		}},
	}
	path := filepath.Join(root, "pack.json")
	writeTestJSON(t, path, document)
	if _, err := ValidateFile(path); err == nil || !strings.Contains(err.Error(), "require schema version 4") {
		t.Fatalf("schema v3 accepted v4 fields: %v", err)
	}
	document.SchemaVersion = 4
	writeTestJSON(t, path, document)
	if _, err := ValidateFile(path); err != nil {
		t.Fatalf("schema v4 contract rejected: %v", err)
	}
	document.ProofCases[0].StateChecks[0].Role = "directory_server"
	writeTestJSON(t, path, document)
	if _, err := ValidateFile(path); err == nil || !strings.Contains(err.Error(), "invalid role") {
		t.Fatalf("invalid state-check role accepted: %v", err)
	}
}

func TestPackSchemaV5DelegatedOperationProof(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pack.h"), []byte("static void pack(void) {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	document := Document{
		Schema: Schema, SchemaVersion: 4, ID: "delegated", Version: "1.0.0", Title: "Delegated", Summary: "Schema v5 delegated proof", Tier: "internal",
		Capabilities: []string{"wait for a change"}, Effects: []string{"reads state"}, Platforms: []string{"windows"}, Architecture: []string{"x64"}, Privilege: "user", Network: "none",
		Arguments: []Argument{{Name: "path", Type: "wstring"}}, Source: Source{HeaderFragments: []string{"pack.h"}}, TargetSupport: []string{"lab"},
		ProofCases: []ProofCase{{ID: "operation", Via: []string{"lab"}, OperationProof: &OperationProof{Operation: "internal/change-observe", Step: "watch", Phase: "action", Inputs: map[string]string{"path": "$TEMP\\watch"}}}},
	}
	path := filepath.Join(root, "pack.json")
	writeTestJSON(t, path, document)
	if _, err := ValidateFile(path); err == nil || !strings.Contains(err.Error(), "require schema version 5") {
		t.Fatalf("schema v4 accepted delegated proof: %v", err)
	}
	document.SchemaVersion = 5
	writeTestJSON(t, path, document)
	if _, err := ValidateFile(path); err != nil {
		t.Fatalf("schema v5 delegated proof rejected: %v", err)
	}
}

func TestPackSchemaV6RuntimeComparisonContracts(t *testing.T) {
	document := Document{
		Schema: Schema, SchemaVersion: 6, ID: "runtime-comparison", Version: "1.0.0",
		Title: "Runtime comparison", Summary: "Compare stable fields", Tier: "public",
		Capabilities: []string{"reports a host"}, Effects: []string{"reads data"}, Platforms: []string{"windows"},
		Architecture: []string{"x64"}, Privilege: "user", Network: "none", Source: Source{Features: []string{"host"}},
		OutputFields: []string{"status", "host", "pid"}, TargetSupport: []string{"native", "sliver"},
		ComparisonContracts: []ComparisonContract{{Tag: "host", Fields: []ComparisonField{{Name: "status", Behavior: "exact"}, {Name: "host", Behavior: "normalized", Normalizer: "hostname"}, {Name: "pid", Behavior: "presence"}}}},
	}
	if err := validate(document, ""); err != nil {
		t.Fatalf("schema v6 contract should validate: %v", err)
	}
	document.SchemaVersion = 5
	if err := validate(document, ""); err == nil || !strings.Contains(err.Error(), "schema version 6") {
		t.Fatalf("schema v5 accepted comparison contract: %v", err)
	}
	document.SchemaVersion = 6
	document.ComparisonContracts[0].Fields[1].Normalizer = "unknown"
	if err := validate(document, ""); err == nil || !strings.Contains(err.Error(), "supported normalizer") {
		t.Fatalf("invalid normalizer accepted: %v", err)
	}
}

func TestConfiguredCatalogLifecycle(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("BOFBENCH_CONFIG_HOME", configRoot)
	catalog := t.TempDir()
	packRoot := filepath.Join(catalog, "one")
	if err := os.MkdirAll(packRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := Document{Schema: Schema, SchemaVersion: 1, ID: "one", Version: "1", Title: "One", Summary: "One", Tier: "public", Capabilities: []string{"one"}, Effects: []string{"reads data"}, Platforms: []string{"windows"}, Architecture: []string{"x64"}, Privilege: "user", Network: "none", Source: Source{Features: []string{"host"}}, TargetSupport: []string{"native"}}
	writeTestJSON(t, filepath.Join(packRoot, "pack.json"), manifest)
	ref, err := AddCatalog(catalog, "local")
	if err != nil || ref.Name != "local" {
		t.Fatalf("add=%+v err=%v", ref, err)
	}
	registry, err := Load(LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if item, err := registry.Resolve("local/one"); err != nil || item.Document.ID != "one" {
		t.Fatalf("resolve=%+v err=%v", item, err)
	}
	if err := RemoveCatalog("local"); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryRejectsMissingCleanupCompanion(t *testing.T) {
	t.Setenv("BOFBENCH_CONFIG_HOME", t.TempDir())
	catalog := t.TempDir()
	root := filepath.Join(catalog, "stateful")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := Document{Schema: Schema, SchemaVersion: 2, ID: "stateful", Version: "1", Title: "Stateful", Summary: "Stateful test", Tier: "internal", Capabilities: []string{"state"}, Effects: []string{"writes state"}, Platforms: []string{"windows"}, Architecture: []string{"x64"}, Privilege: "user", Network: "none", Source: Source{HeaderFragments: []string{"pack.h"}}, CleanupPack: "missing-cleanup", TargetSupport: []string{"native"}}
	writeTestJSON(t, filepath.Join(root, "pack.json"), manifest)
	if err := os.WriteFile(filepath.Join(root, "pack.h"), []byte("static void pack(void) {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(LoadOptions{ExtraCatalogs: []string{catalog}}); err == nil || !strings.Contains(err.Error(), "missing-cleanup") {
		t.Fatalf("missing cleanup reference accepted: %v", err)
	}
}

func newProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	source := `#include "beacon.h"
/* bofbench:feature-includes */
void go(char *args, int len) { (void)args; (void)len;
    /* bofbench:feature-calls */
}
`
	if err := os.WriteFile(filepath.Join(root, "demo.c"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
