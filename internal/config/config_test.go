package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadForTinyConfig(t *testing.T) {
	dir := t.TempDir()
	body := `name = "demo"
entry = "go"
compiler = "mingw"
cflags = ["-DVALUE=a,b", "-DSECRET=#kept"] # inline comment
deterministic = true
args = ["z:hello", "i:7"]
expect = ["hello"]
forbid = ["panic"]
timeout_ms = 900
expect_exit = "success"

[profile.smoke]
args = ["z:profile", "i:9"]
expect = ["profile"]
forbid = []
timeout_ms = 1200
`
	if err := os.WriteFile(filepath.Join(dir, "bofbench.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload.c"), []byte("void go(char *args, int len) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, path, err := LoadFor(filepath.Join(dir, "payload.c"))
	if err != nil {
		t.Fatal(err)
	}
	if path == "" || cfg.Name != "demo" || cfg.Entrypoint != "go" || cfg.Compiler != "mingw" || !cfg.CompilerSet || !cfg.Deterministic || cfg.TimeoutMS != 900 {
		t.Fatalf("unexpected config: %+v path=%s", cfg, path)
	}
	if len(cfg.CFlags) != 2 || cfg.CFlags[0] != "-DVALUE=a,b" || cfg.CFlags[1] != "-DSECRET=#kept" {
		t.Fatalf("cflags = %#v", cfg.CFlags)
	}
	if len(cfg.Args) != 2 || cfg.Args[0] != "z:hello" {
		t.Fatalf("args = %#v", cfg.Args)
	}
	if len(cfg.Expect) != 1 || cfg.Expect[0] != "hello" {
		t.Fatalf("expect = %#v", cfg.Expect)
	}
	if len(cfg.Forbid) != 1 || cfg.Forbid[0] != "panic" {
		t.Fatalf("forbid = %#v", cfg.Forbid)
	}
	if cfg.ExpectedExit != "success" {
		t.Fatalf("expected exit = %q", cfg.ExpectedExit)
	}
	profiled, err := ApplyProfile(cfg, "smoke")
	if err != nil {
		t.Fatal(err)
	}
	if profiled.TimeoutMS != 1200 || len(profiled.Args) != 2 || profiled.Args[0] != "z:profile" {
		t.Fatalf("profile not applied: %+v", profiled)
	}
	if len(profiled.Forbid) != 0 {
		t.Fatalf("profile should allow empty forbid override: %#v", profiled.Forbid)
	}
	if _, err := ApplyProfile(cfg, "missing"); err == nil {
		t.Fatal("expected missing profile error")
	}
}

func TestLoadForRejectsInvalidConfigurationWithLineDiagnostics(t *testing.T) {
	dir := t.TempDir()
	body := `name = "demo"
entry = "go"
entrypoint = "again"
compiler = "mystery"
timeout_ms = -1
args = ["ok", broken]
unknown = "value"
[unsupported]
value = "bad"
`
	if err := os.WriteFile(filepath.Join(dir, "bofbench.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, path, err := LoadFor(dir)
	if err == nil {
		t.Fatal("expected strict configuration error")
	}
	var configErr *Error
	if !errors.As(err, &configErr) {
		t.Fatalf("error type = %T: %v", err, err)
	}
	if configErr.Path != path || len(configErr.Diagnostics) != 7 {
		t.Fatalf("configuration diagnostics = %+v", configErr)
	}
	want := map[string]bool{
		"duplicate_key":         false,
		"invalid_value":         false,
		"invalid_syntax":        false,
		"unknown_key":           false,
		"unknown_section":       false,
		"invalid_section_value": false,
	}
	for _, diagnostic := range configErr.Diagnostics {
		if diagnostic.Line <= 0 || diagnostic.Detail == "" {
			t.Fatalf("incomplete diagnostic: %+v", diagnostic)
		}
		if _, exists := want[diagnostic.Code]; exists {
			want[diagnostic.Code] = true
		}
	}
	for code, found := range want {
		if !found {
			t.Fatalf("missing diagnostic %s in %+v", code, configErr.Diagnostics)
		}
	}
	if !strings.Contains(err.Error(), "bofbench.toml:3") || !strings.Contains(err.Error(), "7 configuration error") {
		t.Fatalf("error summary = %q", err)
	}
}

func TestLoadForMissingConfigUsesDeterministicAutoDefaults(t *testing.T) {
	cfg, path, err := LoadFor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if path != "" || cfg.Compiler != "auto" || cfg.CompilerSet || !cfg.Deterministic || cfg.Entrypoint != "go" || cfg.TimeoutMS != 5000 {
		t.Fatalf("defaults = %+v path=%q", cfg, path)
	}
}

func TestLoadForRejectsUnsafeProjectName(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bofbench.toml"), []byte("name = \"../outside\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadFor(dir)
	var configErr *Error
	if !errors.As(err, &configErr) || len(configErr.Diagnostics) != 1 || configErr.Diagnostics[0].Code != "invalid_value" {
		t.Fatalf("unsafe name error = %#v", err)
	}
}
