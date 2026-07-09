package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewHeaderAndFingerprint(t *testing.T) {
	header := New(SchemaRun, "run-1", "parent-1")
	if header.Schema != SchemaRun || header.SchemaVersion != ContractVersion || header.RunID != "run-1" || header.ParentRunID != "parent-1" {
		t.Fatalf("header = %+v", header)
	}
	if header.Tool.Name != "bofbench" || header.Tool.Version == "" || header.Host.OS == "" || header.Host.Arch == "" || header.Host.GoVersion == "" {
		t.Fatalf("header metadata = %+v", header)
	}
	path := filepath.Join(t.TempDir(), "artifact.o")
	if err := os.WriteFile(path, []byte("object"), 0o644); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := FingerprintFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.Path != path || fingerprint.Size != 6 || fingerprint.SHA256 != "2958d416d08aa5a472d7b509036cb7eafd542add84527e66a145ea64cb4cdc75" {
		t.Fatalf("fingerprint = %+v", fingerprint)
	}
}

func TestFingerprintTreeIsStableAndExcludesMetadata(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.o"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "b.o"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := FingerprintTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.json"), []byte("metadata"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "._a.o"), []byte("appledouble"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".DS_Store"), []byte("finder"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := FingerprintTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.Files != 2 || first.Bytes != 6 || first.SHA256 == "" {
		t.Fatalf("tree fingerprints differ: first=%+v second=%+v", first, second)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "b.o"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := FingerprintTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if third.SHA256 == first.SHA256 {
		t.Fatalf("tree fingerprint did not change: %+v", third)
	}
}
