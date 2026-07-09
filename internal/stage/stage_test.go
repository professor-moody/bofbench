package stage

import (
	"archive/zip"
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
	if manifest.Schema != ManifestSchema || manifest.SchemaVersion != ManifestSchemaVersion || len(manifest.Files) == 0 {
		t.Fatalf("manifest contract missing: %+v", manifest)
	}
}

func TestVerifyGeneratedTargetsAsDirectoryAndZip(t *testing.T) {
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
	args := []argpack.Item{{Kind: "z", Value: "hello"}, {Kind: "i", Value: "3"}}
	for _, target := range []string{"cobaltstrike", "sliver", "raw"} {
		t.Run(target, func(t *testing.T) {
			result, err := Stage(obj, target, "go", args)
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []string{result.Output, result.Output + ".zip"} {
				verification := Verify(input)
				if !verification.Passed() || verification.Status != "pass" {
					t.Fatalf("verification failed for %s:\n%s", input, verification.Text())
				}
				if verification.Schema != VerificationSchema || verification.SchemaVersion != VerificationSchemaVersion {
					t.Fatalf("verification schema = %q/%d", verification.Schema, verification.SchemaVersion)
				}
			}
		})
	}
}

func TestVerifyDetectsTamperingAndExtraFiles(t *testing.T) {
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(tmp, "hello.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", nil); err != nil {
		t.Fatal(err)
	}
	result, err := Stage(obj, "raw", "go", nil)
	if err != nil {
		t.Fatal(err)
	}
	stagedObject := filepath.Join(result.Output, "objects", filepath.Base(obj))
	if err := os.WriteFile(stagedObject, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(result.Output, "unexpected.txt"), []byte("extra"), 0o644); err != nil {
		t.Fatal(err)
	}
	verification := Verify(result.Output)
	if verification.Passed() || verification.Status != "fail" {
		t.Fatalf("tampered package passed:\n%s", verification.Text())
	}
	if !hasVerificationFailure(verification, "file.integrity", "objects/hello.x64.o") {
		t.Fatalf("object integrity failure missing:\n%s", verification.Text())
	}
	if !hasVerificationFailure(verification, "package.extra_file", "unexpected.txt") {
		t.Fatalf("extra-file failure missing:\n%s", verification.Text())
	}
}

func TestVerifyRejectsLegacyManifestSchema(t *testing.T) {
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(tmp, "hello.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", nil); err != nil {
		t.Fatal(err)
	}
	result, err := Stage(obj, "raw", "go", nil)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(result.Output, "manifest.json")
	var manifest Manifest
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Schema = ""
	manifest.SchemaVersion = 0
	data, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	verification := Verify(result.Output)
	if !hasVerificationFailure(verification, "manifest.schema", "manifest.json") {
		t.Fatalf("legacy schema failure missing:\n%s", verification.Text())
	}
}

func TestVerifyRejectsUnsafeZipInventory(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "unsafe.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, name := range []string{"../manifest.json", "README.md"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("data")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	verification := Verify(zipPath)
	if verification.Passed() || !hasVerificationFailure(verification, "package.entry", "../manifest.json") {
		t.Fatalf("unsafe ZIP inventory was not rejected:\n%s", verification.Text())
	}
}

func hasVerificationFailure(verification Verification, name, path string) bool {
	for _, check := range verification.Checks {
		if check.Status == "fail" && check.Name == name && check.Path == path {
			return true
		}
	}
	return false
}
