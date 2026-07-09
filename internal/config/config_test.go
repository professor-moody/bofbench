package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadForTinyConfig(t *testing.T) {
	dir := t.TempDir()
	body := `name = "demo"
entry = "go"
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
	if path == "" || cfg.Name != "demo" || cfg.Entrypoint != "go" || cfg.TimeoutMS != 900 {
		t.Fatalf("unexpected config: %+v path=%s", cfg, path)
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
