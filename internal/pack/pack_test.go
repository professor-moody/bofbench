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
