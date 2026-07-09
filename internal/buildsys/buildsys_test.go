package buildsys

import (
	"os"
	"path/filepath"
	"testing"
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
