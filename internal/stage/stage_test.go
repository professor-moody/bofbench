package stage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bofbench/internal/argpack"
	"bofbench/internal/coff"
)

func TestStageTargets(t *testing.T) {
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(tmp, "hello.x64.o")
	if err := os.WriteFile(obj, []byte("object"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []argpack.Item{{Kind: "z", Value: "hello"}, {Kind: "i", Value: "3"}}
	for _, target := range []string{"cobaltstrike", "sliver", "raw"} {
		res, err := Stage(obj, target, "go", args)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(res.Output + ".zip"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(res.Output, "manifest.json")); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile(filepath.Join("stage", "hello-cobaltstrike", "hello.cna"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "beacon_inline_execute") || !strings.Contains(string(script), "bof_pack") {
		t.Fatalf("unexpected cna:\n%s", script)
	}
	if _, err := os.Stat(filepath.Join("stage", "hello-raw", "reports", "analysis.json")); err != nil {
		t.Fatal(err)
	}
}

func TestStageIncludesAnalysisAndLatestReport(t *testing.T) {
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(tmp, "hello.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join("runs", "20260709-000000-run-hello")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "result.json"), []byte(`{"status":"pass"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "result.md"), []byte("# Run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Stage(obj, "raw", "go", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(res.Output, "reports", "analysis.json"),
		filepath.Join(res.Output, "reports", "analysis.md"),
		filepath.Join(res.Output, "reports", "latest-result.json"),
		filepath.Join(res.Output, "reports", "latest-result.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	var manifest Manifest
	b, err := os.ReadFile(filepath.Join(res.Output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Analysis == "" || len(manifest.LatestReport) != 2 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}
