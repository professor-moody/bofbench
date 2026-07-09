package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"bofbench/internal/artifact"
	"bofbench/internal/coff"
	"bofbench/internal/evidence"
)

func TestSelectRuntime(t *testing.T) {
	cases := map[artifact.Kind]string{
		artifact.KindCOFF:  "windows-coff",
		artifact.KindELF:   "linux-elf",
		artifact.KindMachO: "darwin-macho",
	}
	for kind, want := range cases {
		if got := SelectRuntime(kind); got != want {
			t.Fatalf("SelectRuntime(%s)=%s want %s", kind, got, want)
		}
	}
}

func TestLinuxELFRequiresLinux(t *testing.T) {
	if goruntime.GOOS == "linux" {
		t.Skip("non-Linux behavior only")
	}
	path := filepath.Join(t.TempDir(), "demo.o")
	if err := os.WriteFile(path, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Request{Path: path, Runtime: "linux-elf"})
	if err == nil {
		t.Fatal("expected error")
	}
	if res.ExitState != "requires_linux" {
		t.Fatalf("expected requires_linux: %+v", res)
	}
	if res.Schema != evidence.SchemaRun || res.SchemaVersion != evidence.ContractVersion || res.ObjectFingerprint == nil || res.ObjectFingerprint.SHA256 == "" {
		t.Fatalf("runtime evidence = %+v", res)
	}
}

func TestMachORequiresDarwin(t *testing.T) {
	if goruntime.GOOS == "darwin" {
		t.Skip("non-macOS behavior only")
	}
	path := filepath.Join(t.TempDir(), "demo.o")
	if err := os.WriteFile(path, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Request{Path: path, Runtime: "darwin-macho"})
	if err == nil {
		t.Fatal("expected error")
	}
	if res.ExitState != "requires_darwin" {
		t.Fatalf("expected requires_darwin: %+v", res)
	}
	requireEvents(t, res, "artifact", "arg_pack", "load", "beacon_error", "exit")
}

func TestWrongRuntimeResultHasNormalizedEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "demo.o")
	if err := os.WriteFile(path, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Request{Path: path, Runtime: "windows-coff", Tokens: []string{"z:hello"}, ArgHex: "0500000068656c6c6f00"})
	if err == nil {
		t.Fatal("expected error")
	}
	if res.ExitState != "wrong_artifact" {
		t.Fatalf("expected wrong_artifact: %+v", res)
	}
	requireEvents(t, res, "artifact", "arg_pack", "load", "beacon_error", "exit")
}

func TestWindowsCOFFRuntimeEnforcesLoaderPreflight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocked.o")
	if err := coff.CreateMockObject(path, "x64", "go", []string{"BeaconFormatAlloc"}); err != nil {
		t.Fatal(err)
	}
	res, err := Run(Request{Path: path, Runtime: "windows-coff", Entry: "go"})
	if err == nil {
		t.Fatal("expected preflight failure")
	}
	if res.Status != "fail" || res.ExitState != "preflight_blocked" || res.LoaderCompatibility == nil || res.LoaderCompatibility.Compatible {
		t.Fatalf("runtime preflight = %+v", res)
	}
	if !strings.Contains(strings.Join(res.Errors, "\n"), "unsupported_beacon_api") {
		t.Fatalf("runtime preflight errors = %+v", res.Errors)
	}
	requireEvents(t, res, "artifact", "arg_pack", "preflight", "load", "beacon_error", "exit")
}

func TestDarwinMachORunner(t *testing.T) {
	if goruntime.GOOS != "darwin" {
		t.Skip("Mach-O runner requires macOS")
	}
	obj := compileNativeObject(t)
	res, err := Run(Request{
		Path:      obj,
		Runtime:   "darwin-macho",
		Entry:     "go",
		Tokens:    []string{"z:hello"},
		TimeoutMS: 5000,
	})
	if err != nil {
		t.Fatalf("run failed: %v\n%+v", err, res)
	}
	if res.Status != "pass" || res.ExitState != "success" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Output, "\n"), "native:1:hello") {
		t.Fatalf("missing native output: %+v", res.Output)
	}
	requireEvents(t, res, "artifact", "arg_pack", "load", "entry_call", "beacon_output", "exit")
}

func TestLinuxELFRunner(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("ELF runner requires Linux")
	}
	obj := compileNativeObject(t)
	res, err := Run(Request{
		Path:      obj,
		Runtime:   "linux-elf",
		Entry:     "go",
		Tokens:    []string{"z:hello"},
		TimeoutMS: 5000,
	})
	if err != nil {
		t.Fatalf("run failed: %v\n%+v", err, res)
	}
	if res.Status != "pass" || res.ExitState != "success" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !strings.Contains(strings.Join(res.Output, "\n"), "native:1:hello") {
		t.Fatalf("missing native output: %+v", res.Output)
	}
	requireEvents(t, res, "artifact", "arg_pack", "load", "entry_call", "beacon_output", "exit")
}

func compileNativeObject(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("cc not available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "native.c")
	obj := filepath.Join(dir, "native.o")
	body := `#include <stdio.h>
void go(int argc, char **argv) {
    printf("native:%d:%s\n", argc, argc > 0 ? argv[0] : "none");
}
`
	if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cc, "-c", src, "-o", obj)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compile fixture: %v\n%s", err, out)
	}
	return obj
}

func requireEvents(t *testing.T, res Result, want ...string) {
	t.Helper()
	seen := make(map[string]bool)
	for _, event := range res.Events {
		if event.Type == "" {
			t.Fatalf("empty event type in %+v", res.Events)
		}
		seen[event.Type] = true
	}
	for _, eventType := range want {
		if !seen[eventType] {
			t.Fatalf("missing event %q in %+v", eventType, res.Events)
		}
	}
}
