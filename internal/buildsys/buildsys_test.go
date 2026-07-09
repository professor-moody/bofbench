package buildsys

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	result, err := BuildWithOptions(object, Options{Arch: "x64", VerifyReproducible: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != evidence.SchemaBuild || result.SchemaVersion != evidence.ContractVersion || result.RunID == "" || result.ObjectFingerprint == nil || result.SourceFingerprint == nil {
		t.Fatalf("build evidence = %+v", result)
	}
	if result.Reproducibility == nil || !result.Reproducibility.Checked || !result.Reproducibility.Reproducible {
		t.Fatalf("copy reproducibility = %+v", result.Reproducibility)
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

func TestBuildPersistsStrictConfigurationFailures(t *testing.T) {
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(tmp, "broken")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "payload.c"), []byte("void go(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "bofbench.toml"), []byte("compiler = \"unknown\"\nmystery = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Build(project, "x64")
	if err == nil {
		t.Fatal("expected configuration failure")
	}
	if result.RunID == "" || result.Status != "error" || result.ConfigFingerprint == nil || result.SourceTreeFingerprint == nil {
		t.Fatalf("failed build evidence = %+v", result)
	}
	if len(result.Diagnostics) != 2 || result.Diagnostics[0].Tool != "config" || result.Diagnostics[0].Line != 1 {
		t.Fatalf("configuration diagnostics = %+v", result.Diagnostics)
	}
	data, readErr := os.ReadFile(result.EvidencePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	var persisted Result
	if unmarshalErr := json.Unmarshal(data, &persisted); unmarshalErr != nil {
		t.Fatal(unmarshalErr)
	}
	if persisted.Error == "" || len(persisted.Diagnostics) != 2 || persisted.Duration == "" {
		t.Fatalf("persisted failure = %+v", persisted)
	}
}

func TestBuildExplicitCompilerRecordsProvenanceAndReproducibility(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX fake compiler")
	}
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(binDir, "x86_64-w64-mingw32-gcc")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "fake-mingw 1.0"
  exit 0
fi
out=""
previous=""
for argument in "$@"; do
  if [ "$previous" = "-o" ]; then out="$argument"; fi
  previous="$argument"
done
printf 'stable-object' > "$out"
`
	if err := os.WriteFile(compiler, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	project := filepath.Join(tmp, "demo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "demo.c"), []byte("void go(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "bofbench.toml"), []byte("compiler = \"msvc\"\ncflags = [\"-DTEST=1\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := BuildWithOptions(project, Options{Arch: "x64", Compiler: "mingw", VerifyReproducible: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Compiler.Profile != "mingw" || result.Compiler.SelectedBy != "cli" || result.Compiler.Version != "fake-mingw 1.0" || result.Compiler.Path == "" || result.Compiler.SHA256 == "" {
		t.Fatalf("compiler provenance = %+v", result.Compiler)
	}
	if result.Reproducibility == nil || !result.Reproducibility.Reproducible || result.Reproducibility.Method != "double_compile" {
		t.Fatalf("reproducibility = %+v", result.Reproducibility)
	}
	command := strings.Join(result.Command, " ")
	if !strings.Contains(command, "-frandom-seed=") || !strings.Contains(command, "-ffile-prefix-map=") || !strings.Contains(command, "-DTEST=1") {
		t.Fatalf("deterministic command = %s", command)
	}
	if result.Environment["SOURCE_DATE_EPOCH"] != "0" || result.ObjectFingerprint == nil || result.Status != "built" {
		t.Fatalf("build result = %+v", result)
	}
}

func TestBuildParsesCompilerFailureAndPersistsExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX fake compiler")
	}
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(binDir, "x86_64-w64-mingw32-gcc")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "fake-mingw failure"; exit 0; fi
echo "payload.c:7:3: error: unknown symbol" >&2
exit 1
`
	if err := os.WriteFile(compiler, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	project := filepath.Join(tmp, "failure")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "payload.c"), []byte("void go(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := BuildWithOptions(project, Options{Arch: "x64", Compiler: "mingw"})
	if err == nil {
		t.Fatal("expected compiler failure")
	}
	if result.ExitCode == nil || *result.ExitCode != 1 || len(result.Diagnostics) != 1 {
		t.Fatalf("failure evidence = %+v", result)
	}
	diagnostic := result.Diagnostics[0]
	if diagnostic.Severity != "error" || diagnostic.File != "payload.c" || diagnostic.Line != 7 || diagnostic.Column != 3 || diagnostic.Message != "unknown symbol" {
		t.Fatalf("parsed diagnostic = %+v", diagnostic)
	}
	if _, statErr := os.Stat(result.EvidencePath); statErr != nil {
		t.Fatal(statErr)
	}
}

func TestBuildRejectsNonReproducibleOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX fake compiler")
	}
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	compiler := filepath.Join(binDir, "x86_64-w64-mingw32-gcc")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "fake-mingw unstable"; exit 0; fi
out=""
previous=""
for argument in "$@"; do
  if [ "$previous" = "-o" ]; then out="$argument"; fi
  previous="$argument"
done
state="$0.state"
if [ -f "$state" ]; then
  printf 'second-object' > "$out"
else
  printf 'first-object' > "$out"
  : > "$state"
fi
`
	if err := os.WriteFile(compiler, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	project := filepath.Join(tmp, "unstable")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "payload.c"), []byte("void go(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := BuildWithOptions(project, Options{Arch: "x64", Compiler: "mingw", VerifyReproducible: true})
	if err == nil {
		t.Fatal("expected reproducibility failure")
	}
	if result.Status != "non_reproducible" || result.Reproducibility == nil || result.Reproducibility.Reproducible {
		t.Fatalf("reproducibility failure = %+v", result)
	}
	if result.Reproducibility.First.SHA256 == result.Reproducibility.Second.SHA256 {
		t.Fatalf("artifact hashes should differ: %+v", result.Reproducibility)
	}
	found := false
	for _, diagnostic := range result.Diagnostics {
		found = found || diagnostic.Code == "non_reproducible"
	}
	if !found {
		t.Fatalf("missing non_reproducible diagnostic: %+v", result.Diagnostics)
	}
}

func TestParseMSVCDiagnostic(t *testing.T) {
	diagnostics := parseCompilerDiagnostics(`C:\src\payload.c(12,5): error C2065: 'value': undeclared identifier`, "msvc")
	if len(diagnostics) != 1 {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
	got := diagnostics[0]
	if got.Tool != "msvc" || got.Code != "C2065" || got.Line != 12 || got.Column != 5 || !strings.Contains(got.Message, "undeclared") {
		t.Fatalf("diagnostic = %+v", got)
	}
}

func TestMSVCDeterministicCommandMapsWorkspacePaths(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "bofs", "demo", "payload.c")
	output := filepath.Join(root, "dist", "demo.x64.o")
	command := compileCommand("msvc", "x64", "cl", source, output, filepath.Dir(source), nil, true, "seed")
	joined := strings.Join(command, " ")
	for _, flag := range []string{"/Brepro", "/experimental:deterministic", "/pathmap:" + root + "=."} {
		if !strings.Contains(joined, flag) {
			t.Fatalf("MSVC command missing %q: %s", flag, joined)
		}
	}
}

func TestRealMinGWReproducibleBuildWhenAvailable(t *testing.T) {
	if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err != nil {
		t.Skip("MinGW x64 compiler unavailable")
	}
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(tmp, "real")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "payload.c"), []byte("void go(char *args, int len) { (void)args; (void)len; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := BuildWithOptions(project, Options{Arch: "x64", Compiler: "mingw", VerifyReproducible: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reproducibility == nil || !result.Reproducibility.Reproducible || result.Compiler.SHA256 == "" || result.Compiler.SelectedBy != "cli" {
		t.Fatalf("real compiler evidence = %+v", result)
	}
}

func TestBuildPreservesSafeConfiguredObjectName(t *testing.T) {
	wd, _ := os.Getwd()
	tmp := t.TempDir()
	defer os.Chdir(wd)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(tmp, "source")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "bofbench.toml"), []byte("name = \"under_score\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(project, "payload.o")
	if err := os.WriteFile(object, []byte("object"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Build(object, "x64")
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "under_score" || result.Object != filepath.Join("dist", "under_score.x64.o") {
		t.Fatalf("configured output = %+v", result)
	}
}
