package runlog

import (
	"os"
	"testing"
)

func TestNewDirIsUniqueWithinOneSecond(t *testing.T) {
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	first, err := NewDir("analysis-demo")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDir("analysis-demo")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || ID(first) == "" || ID(second) == "" {
		t.Fatalf("run directories are not unique: %q %q", first, second)
	}
}
