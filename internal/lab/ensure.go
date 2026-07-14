package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bofbench/internal/evidence"
)

type EnsureResult struct {
	Mode      string              `json:"mode"`
	Action    string              `json:"action"`
	Status    *RemoteStatusReport `json:"status,omitempty"`
	Bootstrap *BootstrapReport    `json:"bootstrap,omitempty"`
}

// EnsureRuntime implements --bootstrap auto|always|never. Auto is quiet when
// the remote runtime reports the same built BOFBench version and otherwise
// delegates to the hash-aware, idempotent bootstrap.
func EnsureRuntime(ctx context.Context, mode string, opts BootstrapOptions) (EnsureResult, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "auto"
	}
	if mode != "auto" && mode != "always" && mode != "never" {
		return EnsureResult{}, fmt.Errorf("bootstrap mode must be auto, always, or never")
	}
	result := EnsureResult{Mode: mode, Action: "skipped"}
	if mode == "never" {
		return result, nil
	}
	profile := NormalizeProfile(opts.Profile)
	remote, resolveErr := ResolveRemoteOptions(ctx, opts.ProfileName, profile)
	if resolveErr != nil {
		return result, resolveErr
	}
	if mode == "auto" {
		status, err := RemoteStatus(ctx, remote)
		result.Status = &status
		if err == nil && remoteVersionMatches(status.Version) && runtimeLoaderHashesMatch(status, opts) {
			result.Action = "ready"
			return result, nil
		}
	}
	opts.Force = mode == "always"
	report, err := Bootstrap(ctx, opts)
	result.Action = "bootstrapped"
	result.Bootstrap = &report
	return result, err
}

func runtimeLoaderHashesMatch(status RemoteStatusReport, opts BootstrapOptions) bool {
	repository := opts.Repository
	if repository == "" {
		var err error
		repository, err = os.Getwd()
		if err != nil {
			return false
		}
	}
	paths := map[string]string{
		"bofbench-loader.exe":     opts.LoaderX64,
		"bofbench-loader-x86.exe": opts.LoaderX86,
	}
	if paths["bofbench-loader.exe"] == "" {
		paths["bofbench-loader.exe"] = filepath.Join(repository, "native", "loader", "bofbench-loader.exe")
	}
	if paths["bofbench-loader-x86.exe"] == "" {
		paths["bofbench-loader-x86.exe"] = filepath.Join(repository, "native", "loader", "bofbench-loader-x86.exe")
	}
	for name, path := range paths {
		remoteHash := strings.TrimSpace(status.RuntimeHashes[name])
		if remoteHash == "" {
			return false
		}
		fingerprint, err := evidence.FingerprintFile(path)
		if err != nil || !strings.EqualFold(remoteHash, fingerprint.SHA256) {
			return false
		}
	}
	return true
}

func remoteVersionMatches(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var remote struct {
		Tool evidence.ToolInfo `json:"tool"`
	}
	if json.Unmarshal(raw, &remote) != nil {
		return false
	}
	local := evidence.CurrentTool()
	if local.Version == "" || remote.Tool.Version != local.Version {
		return false
	}
	// Development binaries deliberately re-check hashes because "unknown"
	// cannot prove that two builds contain the same code.
	if local.Commit == "" || local.Commit == "unknown" || remote.Tool.Commit == "" || remote.Tool.Commit == "unknown" {
		return false
	}
	return remote.Tool.Commit == local.Commit
}
