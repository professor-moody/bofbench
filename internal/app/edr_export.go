package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bofbench/internal/argpack"
)

const windowsArtifactBundleSchema = "windows.artifact-bundle/v1"

type edrArtifact struct {
	ID, Path, SHA256, Kind string
}
type edrMode struct {
	Name, Kind, ArtifactID, LoaderID, Export string
	Arguments                                []string
	Command                                  []string
}
type edrBundle struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name"`
	Architecture  string `json:"architecture"`
	Artifacts     []struct {
		ID     string `json:"id"`
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Kind   string `json:"kind"`
	} `json:"artifacts"`
	ExecutionModes []struct {
		Name       string   `json:"name"`
		Kind       string   `json:"kind"`
		ArtifactID string   `json:"artifact_id"`
		LoaderID   string   `json:"loader_id,omitempty"`
		Export     string   `json:"export,omitempty"`
		Arguments  []string `json:"arguments,omitempty"`
		Command    []string `json:"command"`
	} `json:"execution_modes"`
	Effect struct {
		Type     string `json:"type"`
		Path     string `json:"path"`
		Contains string `json:"contains"`
	} `json:"effect"`
	Cleanup struct {
		Command      []string `json:"command"`
		VerifyAbsent string   `json:"verify_absent"`
	} `json:"cleanup"`
	DeadlineSeconds int               `json:"deadline_seconds"`
	Provenance      map[string]string `json:"provenance"`
	Replay          map[string]any    `json:"replay"`
}

func exportEDRBundle(input string, argumentTokens []string, argumentsExplicit bool, entry, profile, compiler, arch, runtimeName string, verifyReproducible, skipRun bool) (string, error) {
	if strings.ToLower(strings.TrimSpace(arch)) != "x64" {
		return "", fmt.Errorf("EDR Lab export supports x64 BOFs")
	}
	options, err := prepareStageOptions(stageInputOptions{Input: input, Target: "raw", Entrypoint: entry, ArgumentTokens: argumentTokens, ArgumentsExplicit: argumentsExplicit, Profile: profile, Compiler: compiler, Arch: arch, Runtime: runtimeName, VerifyReproducible: verifyReproducible, SkipRun: skipRun})
	if err != nil {
		return "", err
	}
	loader, err := findEDRLoader()
	if err != nil {
		return "", err
	}
	packed, err := argpack.PackItems(options.Arguments)
	if err != nil {
		return "", err
	}
	packedDigest := sha256.Sum256(packed)
	name := filepath.Base(filepath.Clean(input))
	name = strings.TrimSuffix(name, filepath.Ext(name))
	root := filepath.Join("export", safeName(name)+"-edrlab")
	if err := os.RemoveAll(root); err != nil {
		return "", err
	}
	artifactsDir := filepath.Join(root, "artifacts")
	if err := os.MkdirAll(artifactsDir, 0o700); err != nil {
		return "", err
	}
	objectName := filepath.Base(options.Object)
	objectPath := filepath.Join(artifactsDir, objectName)
	loaderPath := filepath.Join(artifactsDir, "bofbench-loader.exe")
	runnerPath := filepath.Join(artifactsDir, "bofbench-edr-runner.ps1")
	if err := copyEDRFile(options.Object, objectPath); err != nil {
		return "", err
	}
	if err := copyEDRFile(loader, loaderPath); err != nil {
		return "", err
	}
	if err := os.WriteFile(runnerPath, []byte(edrRunnerPowerShell), 0o600); err != nil {
		return "", err
	}
	objectHash, _ := edrFileHash(objectPath)
	loaderHash, _ := edrFileHash(loaderPath)
	runnerHash, _ := edrFileHash(runnerPath)
	bundle := edrBundle{SchemaVersion: windowsArtifactBundleSchema, Name: name, Architecture: "x64", DeadlineSeconds: 120, Provenance: map[string]string{"producer": "bofbench", "object_sha256": objectHash, "loader_sha256": loaderHash, "packed_arguments_sha256": "sha256:" + hex.EncodeToString(packedDigest[:])}, Replay: map[string]any{"entrypoint": options.Entrypoint, "argument_types": edrArgumentTypes(options.Arguments), "generated_at": time.Now().UTC().Format(time.RFC3339Nano)}}
	for _, artifact := range []edrArtifact{{"bof", "artifacts/" + objectName, objectHash, "coff"}, {"loader", "artifacts/bofbench-loader.exe", loaderHash, "exe"}, {"runner", "artifacts/bofbench-edr-runner.ps1", runnerHash, "data"}} {
		bundle.Artifacts = append(bundle.Artifacts, struct {
			ID     string `json:"id"`
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Kind   string `json:"kind"`
		}{artifact.ID, artifact.Path, artifact.SHA256, artifact.Kind})
	}
	command := []string{"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", `{{run_dir}}\bofbench-edr-runner.ps1`, "-Loader", "{{loader}}", "-Object", "{{artifact}}", "-Entry", options.Entrypoint, "-ArgHex", hex.EncodeToString(packed), "-Effect", `{{run_dir}}\bofbench-effect.json`, "-RunID", "{{run_id}}"}
	bundle.ExecutionModes = append(bundle.ExecutionModes, struct {
		Name       string   `json:"name"`
		Kind       string   `json:"kind"`
		ArtifactID string   `json:"artifact_id"`
		LoaderID   string   `json:"loader_id,omitempty"`
		Export     string   `json:"export,omitempty"`
		Arguments  []string `json:"arguments,omitempty"`
		Command    []string `json:"command"`
	}{"bof-native-loader", "coff-native-loader", "bof", "loader", options.Entrypoint, edrArgumentTypes(options.Arguments), command})
	bundle.Effect.Type, bundle.Effect.Path, bundle.Effect.Contains = "file_contains", `{{run_dir}}\bofbench-effect.json`, `{{run_id}}`
	bundle.Cleanup.Command = []string{"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", `Remove-Item -Force -LiteralPath $args[0] -ErrorAction SilentlyContinue`, `{{run_dir}}\bofbench-effect.json`}
	bundle.Cleanup.VerifyAbsent = `{{run_dir}}\bofbench-effect.json`
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", err
	}
	bundlePath := filepath.Join(root, "windows-artifact-bundle.json")
	if err := os.WriteFile(bundlePath, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	return bundlePath, nil
}

func findEDRLoader() (string, error) {
	candidates := []string{strings.TrimSpace(os.Getenv("BOFBENCH_LOADER")), filepath.Join("native", "loader", "bofbench-loader.exe")}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "bofbench-loader.exe"))
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		absolute, _ := filepath.Abs(candidate)
		if info, err := os.Stat(absolute); err == nil && info.Mode().IsRegular() {
			return absolute, nil
		}
	}
	return "", fmt.Errorf("x64 bofbench-loader.exe is unavailable; set BOFBENCH_LOADER or run from the BOFBench repository")
}

func copyEDRFile(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0o600)
}
func edrFileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func edrArgumentTypes(items []argpack.Item) []string {
	result := make([]string, len(items))
	for index, item := range items {
		result[index] = item.Kind
	}
	return result
}

const edrRunnerPowerShell = `param(
  [Parameter(Mandatory=$true)][string]$Loader,
  [Parameter(Mandatory=$true)][string]$Object,
  [Parameter(Mandatory=$true)][string]$Entry,
  [Parameter(Mandatory=$true)][string]$ArgHex,
  [Parameter(Mandatory=$true)][string]$Effect,
  [Parameter(Mandatory=$true)][string]$RunID
)
$ErrorActionPreference = 'Stop'
$raw = & $Loader --object $Object --entry $Entry --arg-hex $ArgHex | Out-String
$result = $raw | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $result.status -ne 'pass') { exit 3 }
$record = [ordered]@{schema='bofbench.edr-effect/v1';run_id=$RunID;object=$result.object;entry=$result.entry;status=$result.status;exit_state=$result.exit_state}
$record | ConvertTo-Json -Compress | Set-Content -NoNewline -Encoding UTF8 -LiteralPath $Effect
exit 0
`
