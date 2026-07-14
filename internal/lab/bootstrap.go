package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"bofbench/internal/evidence"
	"bofbench/internal/runlog"
)

type BootstrapOptions struct {
	Config        Config
	ConfigPath    string
	Repository    string
	Executable    string
	LoaderX64     string
	LoaderX86     string
	BuildTools    string
	IncludeSliver bool
}

type LabCapabilities struct {
	Compile         bool   `json:"compile"`
	Compiler        string `json:"compiler,omitempty"`
	NativeX64       bool   `json:"native_x64"`
	NativeX86       bool   `json:"native_x86"`
	Sliver          bool   `json:"sliver"`
	Debugging       bool   `json:"debugging"`
	SnapshotSupport bool   `json:"snapshot_support"`
}

type BootstrapReport struct {
	evidence.Header
	Operation       string           `json:"operation"`
	Status          string           `json:"status"`
	Provider        string           `json:"provider"`
	Host            string           `json:"host"`
	RemoteRoot      string           `json:"remote_root"`
	Executable      string           `json:"executable"`
	Capabilities    LabCapabilities  `json:"capabilities"`
	Files           []string         `json:"files"`
	TransportEvents []TransportEvent `json:"transport_events,omitempty"`
	StartedAt       string           `json:"started_at"`
	CompletedAt     string           `json:"completed_at"`
	DurationMS      int64            `json:"duration_ms"`
	Error           string           `json:"error,omitempty"`
	EvidencePath    string           `json:"evidence_path"`
}

func Bootstrap(ctx context.Context, opts BootstrapOptions) (BootstrapReport, error) {
	start := time.Now()
	config := opts.Config
	if err := ValidateConfig(config); err != nil {
		return BootstrapReport{}, err
	}
	if config.Provider != "existing" {
		return BootstrapReport{}, fmt.Errorf("run 'bofbench lab up' before bootstrap for the %s provider", config.Provider)
	}
	if config.Transport != "ssh" {
		return BootstrapReport{}, fmt.Errorf("existing-VM bootstrap currently requires SSH transport; WinRM is used by the Vagrant provider")
	}
	runDir, err := runlog.NewDir("lab-bootstrap")
	if err != nil {
		return BootstrapReport{}, err
	}
	report := BootstrapReport{Header: evidence.New("bofbench.lab-bootstrap", runlog.ID(runDir), ""), Operation: "bootstrap", Status: "fail", Provider: config.Provider, Host: config.Host, RemoteRoot: config.RemoteRoot, Executable: config.Executable, StartedAt: start.UTC().Format(time.RFC3339Nano), EvidencePath: filepath.Join(runDir, "bootstrap.json")}
	finish := func(operationErr error) (BootstrapReport, error) {
		if operationErr != nil {
			report.Error = operationErr.Error()
		} else {
			report.Status = "pass"
		}
		report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		report.DurationMS = time.Since(start).Milliseconds()
		data, marshalErr := json.MarshalIndent(report, "", "  ")
		if marshalErr == nil {
			marshalErr = os.WriteFile(report.EvidencePath, append(data, '\n'), 0o600)
		}
		if operationErr == nil && marshalErr != nil {
			operationErr = marshalErr
		}
		return report, operationErr
	}
	repository := opts.Repository
	if repository == "" {
		var err error
		repository, err = os.Getwd()
		if err != nil {
			return finish(err)
		}
	}
	executable := opts.Executable
	removeExecutable := false
	if executable == "" {
		executable, err = buildWindowsCLI(ctx, repository)
		if err != nil {
			return finish(err)
		}
		removeExecutable = true
	}
	if removeExecutable {
		defer os.RemoveAll(filepath.Dir(executable))
	}
	loader := opts.LoaderX64
	if loader == "" {
		loader = filepath.Join(repository, "native", "loader", "bofbench-loader.exe")
	}
	loaderX86 := opts.LoaderX86
	if loaderX86 == "" {
		loaderX86 = filepath.Join(repository, "native", "loader", "bofbench-loader-x86.exe")
	}
	for _, file := range []string{executable, loader, loaderX86} {
		if info, statErr := os.Stat(file); statErr != nil || info.IsDir() {
			if statErr == nil {
				statErr = fmt.Errorf("is a directory")
			}
			return finish(fmt.Errorf("bootstrap file %s: %w", file, statErr))
		}
	}
	remote := config.RemoteOptions()
	remoteLoader := windowsJoin(config.RemoteRoot, "native", "loader", "bofbench-loader.exe")
	remoteLoaderX86 := windowsJoin(config.RemoteRoot, "native", "loader", "bofbench-loader-x86.exe")
	directories := []string{config.RemoteRoot, windowsDir(config.Executable), windowsDir(remoteLoader), windowsJoin(config.RemoteRoot, "work", "projects"), windowsJoin(config.RemoteRoot, "runs")}
	quoted := make([]string, 0, len(directories))
	for _, directory := range directories {
		quoted = append(quoted, powerShellQuote(directory))
	}
	eventStart := time.Now()
	_, stderr, err := executeRemoteTransport(ctx, remote.SSH, remote.Host, "$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force -Path "+strings.Join(quoted, ",")+" | Out-Null")
	report.TransportEvents = append(report.TransportEvents, transportEvent("ssh-prepare", eventStart, err, string(stderr)))
	if err != nil {
		return finish(err)
	}
	for _, transfer := range []struct{ Local, Remote, Name string }{{executable, config.Executable, "bofbench.exe"}, {loader, remoteLoader, "bofbench-loader.exe"}, {loaderX86, remoteLoaderX86, "bofbench-loader-x86.exe"}} {
		eventStart = time.Now()
		_, stderr, err = executeRemoteTransport(ctx, remote.SCP, transfer.Local, remoteSpec(remote.Host, transfer.Remote))
		report.TransportEvents = append(report.TransportEvents, transportEvent("scp-"+transfer.Name, eventStart, err, string(stderr)))
		if err != nil {
			return finish(err)
		}
		report.Files = append(report.Files, transfer.Remote)
	}
	payloadScript := fmt.Sprintf(`$ErrorActionPreference='Stop'; $compiler=if(Get-Command cl.exe -ErrorAction SilentlyContinue){'msvc'}elseif(Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue){'mingw'}else{''}; [ordered]@{compile=($compiler -ne '');compiler=$compiler;native_x64=(Test-Path %s);native_x86=(Test-Path %s);sliver=((Get-Command sliver-client.exe -ErrorAction SilentlyContinue) -ne $null);debugging=(((Get-Command cdb.exe -ErrorAction SilentlyContinue) -ne $null) -or ((Get-Command windbg.exe -ErrorAction SilentlyContinue) -ne $null));snapshot_support=$false} | ConvertTo-Json -Compress`, powerShellQuote(remoteLoader), powerShellQuote(windowsJoin(config.RemoteRoot, "native", "loader", "bofbench-loader-x86.exe")))
	eventStart = time.Now()
	stdout, stderr, err := executeRemoteTransport(ctx, remote.SSH, remote.Host, payloadScript)
	report.TransportEvents = append(report.TransportEvents, transportEvent("ssh-capabilities", eventStart, err, string(stderr)))
	if err != nil {
		return finish(err)
	}
	if err := json.Unmarshal(stdout, &report.Capabilities); err != nil {
		return finish(fmt.Errorf("decode bootstrapped lab capabilities: %w", err))
	}
	report.Capabilities.SnapshotSupport = config.Provider == "vagrant"
	if !report.Capabilities.NativeX64 {
		return finish(fmt.Errorf("x64 loader was not observable after deployment"))
	}
	return finish(nil)
}

func buildWindowsCLI(ctx context.Context, repository string) (string, error) {
	directory, err := os.MkdirTemp("", "bofbench-windows-cli-*")
	if err != nil {
		return "", err
	}
	output := filepath.Join(directory, "bofbench.exe")
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", output, "./cmd/bofbench")
	command.Dir = repository
	command.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if combined, err := command.CombinedOutput(); err != nil {
		os.RemoveAll(directory)
		return "", fmt.Errorf("build Windows BOFBench CLI: %w\n%s", err, combined)
	}
	return output, nil
}

func windowsDir(path string) string {
	index := strings.LastIndexAny(path, `\/`)
	if index <= 0 {
		return path
	}
	return path[:index]
}

func BootstrapText(report BootstrapReport) string {
	return fmt.Sprintf("Windows lab bootstrap %s\nhost        %s\ncompile     %t %s\nnative x64  %t\nnative x86  %t\nsliver      %t\ndebugging   %t\nsnapshots   %t\nreports     %s\n", strings.ToUpper(report.Status), report.Host, report.Capabilities.Compile, report.Capabilities.Compiler, report.Capabilities.NativeX64, report.Capabilities.NativeX86, report.Capabilities.Sliver, report.Capabilities.Debugging, report.Capabilities.SnapshotSupport, report.EvidencePath)
}
