package buildsys

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"bofbench/internal/evidence"
)

func TestFindCSourceIgnoresAppleDoubleFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.c"), []byte("void go(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "._hello.c"), []byte("metadata"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := findCSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "hello.c" {
		t.Fatalf("source = %s", got)
	}
}

func TestBuildCopiedObjectWritesVersionedEvidence(t *testing.T) {
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(tmp, "demo.o")
	if err := os.WriteFile(object, []byte("object"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Build(object, "x64")
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != evidence.SchemaBuild || result.SchemaVersion != evidence.ContractVersion || result.RunID == "" || result.ObjectFingerprint == nil {
		t.Fatalf("build evidence = %+v", result)
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(result.LogPath), "build.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted Result
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.RunID != result.RunID || persisted.ObjectFingerprint == nil || persisted.ObjectFingerprint.SHA256 != result.ObjectFingerprint.SHA256 {
		t.Fatalf("persisted build evidence = %+v", persisted)
	}
}
