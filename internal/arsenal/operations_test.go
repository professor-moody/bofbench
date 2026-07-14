package arsenal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bofbench/internal/coff"
	"bofbench/internal/evidence"
)

func TestInventorySearchLockAndDiff(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tmp, "arsenal", "demo")
	createArsenalObject(t, root, "hello", []string{"BeaconPrintf", "KERNEL32$GetCurrentProcessId"})
	createArsenalObject(t, root, "argparse", []string{"BeaconDataParse", "BeaconDataInt", "BeaconPrintf"})
	createArsenalObject(t, root, "tokencheck", []string{"ADVAPI32$OpenProcessToken", "ADVAPI32$GetTokenInformation", "BeaconPrintf"})

	inventory, err := BuildInventory(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Status != "pass" || inventory.Summary.Entries != 3 || inventory.Summary.X64Objects != 3 || inventory.Summary.Compatible != 3 || inventory.Summary.NeedsArguments != 1 {
		t.Fatalf("inventory = %+v entries=%+v", inventory.Summary, inventory.Entries)
	}
	searched, err := BuildInventory(root, "BeaconDataParse")
	if err != nil {
		t.Fatal(err)
	}
	if len(searched.Entries) != 1 || searched.Entries[0].Name != "argparse" {
		t.Fatalf("search entries = %+v", searched.Entries)
	}
	capabilitySearch, err := BuildInventoryWithFilters(root, InventoryFilters{Can: "token", Effect: "reads data", WorksWith: "sliver", Requires: "current user"})
	if err != nil {
		t.Fatal(err)
	}
	if len(capabilitySearch.Entries) != 1 || capabilitySearch.Entries[0].Name != "tokencheck" || len(capabilitySearch.Entries[0].Capabilities) == 0 {
		t.Fatalf("capability filters = %+v", capabilitySearch.Entries)
	}
	persisted, err := PersistInventory(searched)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{persisted.JSONPath, persisted.MarkdownPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}

	baseline, err := CreateLock(root)
	if err != nil {
		t.Fatal(err)
	}
	written, lockPath, err := WriteLock(root, baseline)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RootFingerprint.SHA256 != written.RootFingerprint.SHA256 || len(loaded.Entries) != 3 {
		t.Fatalf("loaded lock = %+v", loaded)
	}
	sourcePath := filepath.Join(root, "SA", "hello", "hello.c")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte(strings.ReplaceAll(string(source), "\n", "\r\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := CreateLock(root)
	if err != nil {
		t.Fatal(err)
	}
	if diff := CompareLocks(lockPath, root, loaded, current); diff.Status != "same" || diff.SourceChanged || loaded.RootFingerprint.SHA256 != current.RootFingerprint.SHA256 {
		t.Fatalf("unchanged diff = %+v", diff)
	}

	object := filepath.Join(root, "SA", "hello", "hello.x64.o")
	f, err := os.OpenFile(object, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("changed")); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	changed, err := CreateLock(root)
	if err != nil {
		t.Fatal(err)
	}
	diff, err := PersistLockDiff(CompareLocks(lockPath, root, loaded, changed))
	if err != nil {
		t.Fatal(err)
	}
	if diff.Status != "changed" || diff.SourceChanged || len(diff.Changed) != 1 || diff.Changed[0].Key != "hello/x64" {
		t.Fatalf("changed diff = %+v", diff)
	}
	if text := LockDiffText(diff); !strings.Contains(text, "added=0 removed=0 changed=1") {
		t.Fatalf("diff text = %s", text)
	}
}

func TestComparePreflightRegressionEvidence(t *testing.T) {
	tmp := t.TempDir()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	baseline := writeRegressionEvidence(t, tmp, "baseline.json", evidence.SchemaPreflight, []map[string]any{
		{"name": "stable", "arch": "x64", "status": "compatible", "sha256": "sha-stable", "relocations": 3, "argument_need": "none"},
		{"name": "lookup", "arch": "x64", "status": "compatible_runtime_lookup", "sha256": "sha-lookup", "relocations": 2, "argument_need": "required"},
		{"name": "removed", "arch": "x64", "status": "compatible", "sha256": "sha-removed", "relocations": 1, "argument_need": "none"},
	})

	same, err := CompareRegressionEvidence(baseline, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if same.Status != "pass" || same.Summary.Unchanged != 3 || len(same.Changes) != 0 {
		t.Fatalf("same report = %+v", same)
	}

	hashChanged := writeRegressionEvidence(t, tmp, "hash-changed.json", evidence.SchemaPreflight, []map[string]any{
		{"name": "stable", "arch": "x64", "status": "compatible", "sha256": "new-sha", "relocations": 3, "argument_need": "none"},
		{"name": "lookup", "arch": "x64", "status": "compatible_runtime_lookup", "sha256": "sha-lookup", "relocations": 2, "argument_need": "required"},
		{"name": "removed", "arch": "x64", "status": "compatible", "sha256": "sha-removed", "relocations": 1, "argument_need": "none"},
	})
	hashReport, err := CompareRegressionEvidence(baseline, hashChanged)
	if err != nil {
		t.Fatal(err)
	}
	if hashReport.Status != "pass_with_changes" || hashReport.Summary.Changed != 1 || hashReport.Summary.Regressions != 0 || len(hashReport.Changes) != 1 || hashReport.Changes[0].Classification != "changed" {
		t.Fatalf("hash report = %+v", hashReport)
	}

	current := writeRegressionEvidence(t, tmp, "current.json", evidence.SchemaPreflight, []map[string]any{
		{"name": "stable", "arch": "x64", "status": "unsupported_beacon_api", "sha256": "sha-stable", "relocations": 3, "argument_need": "none"},
		{"name": "lookup", "arch": "x64", "status": "compatible", "sha256": "sha-lookup", "relocations": 2, "argument_need": "required"},
		{"name": "new-bad", "arch": "x64", "status": "unsupported_relocation", "sha256": "sha-bad", "relocations": 4, "argument_need": "none"},
		{"name": "new-good", "arch": "x64", "status": "compatible", "sha256": "sha-good", "relocations": 1, "argument_need": "none"},
	})
	report, err := CompareRegressionEvidence(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "fail" || report.Summary.Added != 2 || report.Summary.Removed != 1 || report.Summary.Improved != 1 || report.Summary.Regressions != 3 {
		t.Fatalf("regression report = %+v", report)
	}
	persisted, err := PersistRegression(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{persisted.EvidencePath, persisted.MarkdownPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	if text := RegressionText(persisted); !strings.Contains(text, "regressions=3") || !strings.Contains(text, "added_regression") {
		t.Fatalf("regression text = %s", text)
	}
}

func TestCompareArsenalTestRegressionEvidence(t *testing.T) {
	tmp := t.TempDir()
	baseline := writeRegressionEvidence(t, tmp, "test-baseline.json", evidence.SchemaArsenalTest, []map[string]any{
		{"name": "survey", "status": "pass", "phase": "run", "analysis": map[string]any{"arch": "x64", "sha256": "sha-survey"}, "run": map[string]any{"exit_state": "completed"}},
		{"name": "recovered", "status": "fail", "phase": "build", "error": "compile failed"},
	})
	current := writeRegressionEvidence(t, tmp, "test-current.json", evidence.SchemaArsenalTest, []map[string]any{
		{"name": "survey", "status": "fail", "phase": "run", "error": "access violation", "analysis": map[string]any{"arch": "x64", "sha256": "sha-survey"}, "run": map[string]any{"exit_state": "exception"}},
		{"name": "recovered", "status": "pass", "phase": "run", "analysis": map[string]any{"arch": "x64", "sha256": "sha-recovered"}, "run": map[string]any{"exit_state": "completed"}},
	})
	report, err := CompareRegressionEvidence(baseline, current)
	if err != nil {
		t.Fatal(err)
	}
	if report.EvidenceType != evidence.SchemaArsenalTest || report.Status != "fail" || report.Summary.Regressions != 1 || report.Summary.Improved != 1 || len(report.Changes) != 2 {
		t.Fatalf("test regression report = %+v", report)
	}
}

func writeRegressionEvidence(t *testing.T, root, name, schema string, results []map[string]any) string {
	t.Helper()
	data, err := json.MarshalIndent(map[string]any{
		"schema":         schema,
		"schema_version": evidence.ContractVersion,
		"results":        results,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func createArsenalObject(t *testing.T, root, name string, imports []string) {
	t.Helper()
	dir := filepath.Join(root, "SA", name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".c"), []byte("void go(char *args, int len) {(void)args;(void)len;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := coff.CreateMockObject(filepath.Join(dir, name+".x64.o"), "x64", "go", imports); err != nil {
		t.Fatal(err)
	}
}
