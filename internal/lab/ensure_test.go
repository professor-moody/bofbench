package lab

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/professor-moody/bofbench/internal/evidence"
)

func TestRemoteVersionMatchesReleaseAndRejectsUnknownDevelopmentBuilds(t *testing.T) {
	oldVersion, oldCommit := evidence.Version, evidence.Commit
	t.Cleanup(func() { evidence.Version, evidence.Commit = oldVersion, oldCommit })
	evidence.Version, evidence.Commit = "1.2.3", "abc123"
	raw, _ := json.Marshal(map[string]any{"tool": map[string]any{"version": "1.2.3", "commit": "abc123"}})
	if !remoteVersionMatches(raw) {
		t.Fatal("matching release should be current")
	}
	evidence.Commit = "unknown"
	if remoteVersionMatches(raw) {
		t.Fatal("unknown development commit must use hash-aware bootstrap")
	}
}

func TestRuntimeLoaderHashesMustMatchBothArchitectures(t *testing.T) {
	repository := t.TempDir()
	loaderDirectory := filepath.Join(repository, "native", "loader")
	if err := os.MkdirAll(loaderDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	x64 := filepath.Join(loaderDirectory, "bofbench-loader.exe")
	x86 := filepath.Join(loaderDirectory, "bofbench-loader-x86.exe")
	if err := os.WriteFile(x64, []byte("x64"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(x86, []byte("x86"), 0o600); err != nil {
		t.Fatal(err)
	}
	x64Fingerprint, _ := evidence.FingerprintFile(x64)
	x86Fingerprint, _ := evidence.FingerprintFile(x86)
	status := RemoteStatusReport{RuntimeHashes: map[string]string{
		"bofbench-loader.exe": x64Fingerprint.SHA256, "bofbench-loader-x86.exe": x86Fingerprint.SHA256,
	}}
	if !runtimeLoaderHashesMatch(status, BootstrapOptions{Repository: repository}) {
		t.Fatal("matching x64/x86 loader hashes should be current")
	}
	status.RuntimeHashes["bofbench-loader-x86.exe"] = "stale"
	if runtimeLoaderHashesMatch(status, BootstrapOptions{Repository: repository}) {
		t.Fatal("stale x86 loader must trigger bootstrap")
	}
}

func TestEnsureRuntimeRejectsUnknownModeAndAllowsNever(t *testing.T) {
	if _, err := EnsureRuntime(t.Context(), "sometimes", BootstrapOptions{}); err == nil {
		t.Fatal("expected invalid bootstrap mode")
	}
	result, err := EnsureRuntime(t.Context(), "never", BootstrapOptions{})
	if err != nil || result.Action != "skipped" {
		t.Fatalf("never result = %+v, %v", result, err)
	}
}
