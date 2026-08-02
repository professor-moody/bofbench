package stage

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/bofbench/internal/argpack"
	"github.com/professor-moody/bofbench/internal/coff"
	"github.com/professor-moody/bofbench/internal/evidence"
	"github.com/professor-moody/bofbench/internal/recipe"
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
		if !res.Verified || len(res.Verification) != 2 {
			t.Fatalf("stage was not self-verified: %+v", res)
		}
	}
	script, err := os.ReadFile(filepath.Join("stage", "hello-cobaltstrike", "hello.cna"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), "beacon_inline_execute") || !strings.Contains(string(script), "bof_pack") || !strings.Contains(string(script), "beacon_command_register") {
		t.Fatalf("unexpected cna:\n%s", script)
	}
	var extension SliverExtension
	extensionData, err := os.ReadFile(filepath.Join("stage", "hello-sliver", "extension.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(extensionData, &extension); err != nil {
		t.Fatal(err)
	}
	if extension.DependsOn != "coff-loader" || extension.CommandName != "hello" || len(extension.Files) != 1 || extension.Files[0].Path != "hello.x64.o" || len(extension.Arguments) != 2 {
		t.Fatalf("unexpected Sliver extension: %+v", extension)
	}
	if _, err := os.Stat(filepath.Join("stage", "hello-raw", "reports", "analysis.json")); err != nil {
		t.Fatal(err)
	}
}

func TestStagePreservesPackArgumentNames(t *testing.T) {
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(tmp, "token.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	result, err := StageWithOptions(Options{
		Object: obj, Target: "sliver", Entrypoint: "go",
		Arguments:        []argpack.Item{{Kind: "i", Value: "1234"}, {Kind: "Z", Value: "whoami"}},
		ArgumentNames:    []string{"source_pid", "command"},
		ArgumentOptional: []bool{false, false},
	})
	if err != nil {
		t.Fatal(err)
	}
	var extension SliverExtension
	data, err := os.ReadFile(filepath.Join(result.Output, "extension.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &extension); err != nil {
		t.Fatal(err)
	}
	if len(extension.Arguments) != 2 || extension.Arguments[0].Name != "source_pid" || extension.Arguments[1].Name != "command" {
		t.Fatalf("argument names were not preserved: %+v", extension.Arguments)
	}
}

func TestSliverExtensionUsesX86Architecture(t *testing.T) {
	manifest := Manifest{Object: "dist/example.x86.o", Name: "example", Entrypoint: "go"}
	manifest.TargetContract.CommandName = "example"
	extension := sliverExtension(manifest, "example.x86.o")
	if len(extension.Files) != 1 || extension.Files[0].Arch != "386" {
		t.Fatalf("x86 extension files = %+v", extension.Files)
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
	if manifest.Schema != ManifestSchema || manifest.SchemaVersion != ManifestSchemaVersion || manifest.RunID == "" || manifest.Tool.Name != "bofbench" || manifest.Host.OS == "" || len(manifest.Files) == 0 {
		t.Fatalf("manifest contract missing: %+v", manifest)
	}
	if manifest.ArgumentContract == "" || manifest.ObjectFingerprint.SHA256 == "" || manifest.PackedArguments.SHA256 == "" || manifest.TargetContract.Invoke == "" {
		t.Fatalf("handoff contract missing: %+v", manifest)
	}
}

func TestStageWithValidatedRecipeAndDevelopmentEvidence(t *testing.T) {
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(tmp, "survey.x64.o")
	if err := coff.CreateMockObject(obj, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	document, ok := recipe.Builtin("full-survey")
	if !ok {
		t.Fatal("full-survey recipe missing")
	}
	validation := recipe.Validate("bofbench.recipe.json", document, document.Features)
	if validation.Status != "pass" {
		t.Fatalf("validation = %+v", validation)
	}
	if err := os.WriteFile("dev.json", []byte(`{"schema":"bofbench.dev","schema_version":1,"status":"pass"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := StageWithOptions(Options{
		Object: obj, Target: "raw", Entrypoint: "go", SourceInput: "bofs/survey", Project: "bofs/survey",
		Recipe: &document, RecipeValidation: &validation,
		Evidence: []EvidenceInput{{Kind: "developer_json", Path: "dev.json", Destination: "reports/dev.json"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.Verification[0].Status != "pass" || result.Verification[1].Status != "pass" {
		t.Fatalf("verification = %+v", result.Verification)
	}
	var manifest Manifest
	data, err := os.ReadFile(filepath.Join(result.Output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Operations.Status != "complete" || manifest.Operations.Recipe != "full-survey" || len(manifest.Evidence) != 1 || manifest.Evidence[0].Path != "reports/dev.json" {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestCobaltStrikeBinaryArgumentReadsOperatorFile(t *testing.T) {
	manifest := Manifest{
		Name: "binary-demo", StagedObject: "objects/binary-demo.x64.o", Entrypoint: "go",
		Arguments:      []argpack.Item{{Kind: "b", Value: "SGVsbG8="}},
		Operations:     OperationalContract{Privilege: "user", Network: "none", Impact: "read_only"},
		TargetContract: TargetContract{CommandName: "binary_demo", Invoke: "binary_demo payload.bin"},
	}
	script := cobaltStrike(manifest)
	for _, want := range []string{"openf($2)", "$arg1_data = readb", `bof_pack($1, "b", $arg1_data)`} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
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
				if !verification.Passed() || verification.Status != "pass_with_warnings" || verification.Summary.Warnings != 1 {
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

func TestVerifyAcceptsLegacyV1PackageWithWarning(t *testing.T) {
	tmp := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(tmp, "legacy.x64.o")
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
	manifest.SchemaVersion = 1
	manifest.SourceInput = ""
	manifest.Project = ""
	manifest.Profile = ""
	manifest.ObjectFingerprint = evidence.FileFingerprint{}
	manifest.PackedArguments = PackedArguments{}
	manifest.ArgumentContract = ""
	manifest.Operations = OperationalContract{}
	manifest.Recipe = ""
	manifest.RecipeValidation = ""
	manifest.TargetContract = TargetContract{}
	manifest.Evidence = nil
	argumentPath := filepath.Join(result.Output, "reports", "arguments.json")
	if err := os.Remove(argumentPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(result.Output, "operator-notes.md"), []byte(legacyRawNotes(manifest.Object, manifest.Entrypoint, manifest.Arguments)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(result.Output, "README.md"), []byte(legacyStageReadme(manifest.Target, manifest.Object, manifest.Entrypoint, manifest.Arguments, manifest.GeneratedAt)), 0o644); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, record := range manifest.Files {
		if record.Path != "reports/arguments.json" {
			paths = append(paths, record.Path)
		}
	}
	manifest.Files, err = manifestFileRecords(result.Output, paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	verification := Verify(result.Output)
	if !verification.Passed() || verification.Status != "pass_with_warnings" || !hasVerificationWarning(verification, "manifest.schema", "manifest.json") {
		t.Fatalf("legacy package did not pass with warning:\n%s", verification.Text())
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

func hasVerificationWarning(verification Verification, name, path string) bool {
	for _, check := range verification.Checks {
		if check.Status == "warn" && check.Name == name && check.Path == path {
			return true
		}
	}
	return false
}
