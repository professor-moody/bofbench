package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	packsvc "bofbench/internal/pack"
)

func TestPrepareCleanupProjectLeavesActionProjectUnchanged(t *testing.T) {
	tmp := t.TempDir()
	project := filepath.Join(tmp, "action")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	tpl, err := templateFor("hello", "action")
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"action.c": tpl.Source, "beacon.h": tpl.Header, "bofbench.toml": tpl.Config, "README.md": tpl.Readme} {
		if err := os.WriteFile(filepath.Join(project, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	registry, err := packsvc.Load(packsvc.LoadOptions{Project: project})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Apply(project, []string{"active-actions"}); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(project, "action.c"))
	if err != nil {
		t.Fatal(err)
	}
	cleanupProject, packs, remove, err := prepareCleanupProject(project)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if strings.Join(packs, ",") != "builtin/active-cleanup" {
		t.Fatalf("cleanup packs = %v", packs)
	}
	cleanupSource, err := os.ReadFile(filepath.Join(cleanupProject, "cleanup.c"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cleanupSource), "bofbench_feature_lab_cleanup") {
		t.Fatalf("cleanup source missing companion:\n%s", cleanupSource)
	}
	current, err := os.ReadFile(filepath.Join(project, "action.c"))
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatal("cleanup preparation changed the action project")
	}
}

func TestCleanupNamedArgumentsPrefersExplicitMapping(t *testing.T) {
	tmp := t.TempDir()
	project, cleanupProject := filepath.Join(tmp, "action"), filepath.Join(tmp, "cleanup")
	for _, path := range []string{project, cleanupProject} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeLock := func(path string, lock packsvc.Lock) {
		t.Helper()
		data, err := json.Marshal(lock)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, packsvc.LockName), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeLock(project, packsvc.Lock{
		Schema: packsvc.LockSchema, SchemaVersion: packsvc.LockSchemaVersion,
		Packs: []packsvc.LockRecord{{
			ID: "event-log-export", Cleanup: "file-remove",
			CleanupArguments: map[string]string{"path": "$arg.output_path"},
		}},
	})
	writeLock(cleanupProject, packsvc.Lock{
		Schema: packsvc.LockSchema, SchemaVersion: packsvc.LockSchemaVersion,
		Packs: []packsvc.LockRecord{{
			ID: "file-remove", Arguments: []packsvc.Argument{{Name: "path", Type: "wstring", Required: true}},
		}},
	})
	got := cleanupNamedArguments(project, cleanupProject, []string{
		"path=System",
		"output_path=C:\\bofbench\\proof\\events.evtx",
	})
	if len(got) != 1 || got[0] != `path=C:\bofbench\proof\events.evtx` {
		t.Fatalf("cleanup arguments = %#v", got)
	}
}
