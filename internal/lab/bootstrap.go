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
	ProfileName   string
	Profile       Profile
	Config        Config
	ConfigPath    string
	Repository    string
	Executable    string
	LoaderX64     string
	LoaderX86     string
	BuildTools    string
	IncludeSliver bool
	Force         bool
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
	Profile         string           `json:"profile,omitempty"`
	Host            string           `json:"host"`
	RemoteRoot      string           `json:"remote_root"`
	Executable      string           `json:"executable"`
	Capabilities    LabCapabilities  `json:"capabilities"`
	Files           []string         `json:"files"`
	Deployed        []string         `json:"deployed,omitempty"`
	Unchanged       []string         `json:"unchanged,omitempty"`
	System          BootstrapSystem  `json:"system"`
	TransportEvents []TransportEvent `json:"transport_events,omitempty"`
	StartedAt       string           `json:"started_at"`
	CompletedAt     string           `json:"completed_at"`
	DurationMS      int64            `json:"duration_ms"`
	Error           string           `json:"error,omitempty"`
	EvidencePath    string           `json:"evidence_path"`
}

type BootstrapSystem struct {
	ComputerName   string          `json:"computer_name,omitempty"`
	WindowsVersion string          `json:"windows_version,omitempty"`
	Architecture   string          `json:"architecture,omitempty"`
	Elevated       bool            `json:"elevated"`
	DiskFreeBytes  int64           `json:"disk_free_bytes,omitempty"`
	BOFBench       json.RawMessage `json:"bofbench_version,omitempty"`
}

func Bootstrap(ctx context.Context, opts BootstrapOptions) (BootstrapReport, error) {
	start := time.Now()
	config := opts.Config
	remote := RemoteOptions{}
	if opts.ProfileName != "" {
		opts.Profile = NormalizeProfile(opts.Profile)
		if err := ValidateProfile(opts.Profile); err != nil {
			return BootstrapReport{}, err
		}
		config = opts.Profile.LegacyConfig()
		var resolveErr error
		remote, resolveErr = ResolveRemoteOptions(ctx, opts.ProfileName, opts.Profile)
		if resolveErr != nil {
			return BootstrapReport{}, resolveErr
		}
	} else {
		if err := ValidateConfig(config); err != nil {
			return BootstrapReport{}, err
		}
		remote = config.RemoteOptions()
	}
	runDir, err := runlog.NewDir("lab-bootstrap")
	if err != nil {
		return BootstrapReport{}, err
	}
	report := BootstrapReport{Header: evidence.New("bofbench.lab-bootstrap", runlog.ID(runDir), ""), Operation: "bootstrap", Status: "fail", Provider: config.Provider, Profile: opts.ProfileName, Host: remote.Host, RemoteRoot: remote.RemoteRoot, Executable: remote.Executable, StartedAt: start.UTC().Format(time.RFC3339Nano), EvidencePath: filepath.Join(runDir, "bootstrap.json")}
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
	remoteLoader := windowsJoin(config.RemoteRoot, "native", "loader", "bofbench-loader.exe")
	remoteLoaderX86 := windowsJoin(config.RemoteRoot, "native", "loader", "bofbench-loader-x86.exe")
	directories := []string{config.RemoteRoot, windowsDir(config.Executable), windowsDir(remoteLoader), windowsJoin(config.RemoteRoot, "work", "projects"), windowsJoin(config.RemoteRoot, "runs")}
	quoted := make([]string, 0, len(directories))
	for _, directory := range directories {
		quoted = append(quoted, powerShellQuote(directory))
	}
	eventStart := time.Now()
	_, stderr, err := remoteExecute(ctx, remote, "$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force -Path "+strings.Join(quoted, ",")+" | Out-Null")
	report.TransportEvents = append(report.TransportEvents, transportEvent(remote.Transport+"-prepare", eventStart, err, string(stderr)))
	if err != nil {
		return finish(err)
	}
	transfers := []struct{ Local, Remote, Name string }{{executable, config.Executable, "bofbench.exe"}, {loader, remoteLoader, "bofbench-loader.exe"}, {loaderX86, remoteLoaderX86, "bofbench-loader-x86.exe"}}
	hashStatements := make([]string, 0, len(transfers))
	localHashes := map[string]string{}
	for _, transfer := range transfers {
		fingerprint, fingerprintErr := evidence.FingerprintFile(transfer.Local)
		if fingerprintErr != nil {
			return finish(fingerprintErr)
		}
		localHashes[transfer.Name] = fingerprint.SHA256
		hashStatements = append(hashStatements, fmt.Sprintf(`%s=$(if(Test-Path %s){(Get-FileHash -Algorithm SHA256 -LiteralPath %s).Hash.ToLower()}else{''})`, powerShellQuote(transfer.Name), powerShellQuote(transfer.Remote), powerShellQuote(transfer.Remote)))
	}
	remoteHashes := map[string]string{}
	hashScript := `$ErrorActionPreference='Stop'; [ordered]@{` + strings.Join(hashStatements, ";") + `} | ConvertTo-Json -Compress`
	eventStart = time.Now()
	stdout, stderr, hashErr := remoteExecute(ctx, remote, hashScript)
	report.TransportEvents = append(report.TransportEvents, transportEvent(remote.Transport+"-hashes", eventStart, hashErr, string(stderr)))
	if hashErr != nil {
		return finish(hashErr)
	}
	var remoteHashPayload map[string]any
	if err := json.Unmarshal(stdout, &remoteHashPayload); err != nil {
		return finish(fmt.Errorf("decode remote runtime hashes: %w", err))
	}
	for name, value := range remoteHashPayload {
		if hash, ok := value.(string); ok {
			remoteHashes[name] = hash
		}
	}
	for _, transfer := range transfers {
		report.Files = append(report.Files, transfer.Remote)
		if !opts.Force && strings.EqualFold(remoteHashes[transfer.Name], localHashes[transfer.Name]) {
			report.Unchanged = append(report.Unchanged, transfer.Remote)
			continue
		}
		eventStart = time.Now()
		_, stderr, err = remoteUploadFile(ctx, remote, transfer.Local, transfer.Remote)
		report.TransportEvents = append(report.TransportEvents, transportEvent(remote.Transport+"-"+transfer.Name, eventStart, err, string(stderr)))
		if err != nil {
			return finish(err)
		}
		report.Deployed = append(report.Deployed, transfer.Remote)
	}
	systemScript := fmt.Sprintf(`$ErrorActionPreference='Stop'; $identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($identity); $drive=Get-Item %s; $version=$null; if(Test-Path %s){$version=(& %s version --format json | ConvertFrom-Json)}; [ordered]@{computer_name=$env:COMPUTERNAME;windows_version=[Environment]::OSVersion.Version.ToString();architecture=$env:PROCESSOR_ARCHITECTURE;elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);disk_free_bytes=$drive.PSDrive.Free;bofbench_version=$version} | ConvertTo-Json -Depth 8 -Compress`, powerShellQuote(config.RemoteRoot), powerShellQuote(config.Executable), powerShellQuote(config.Executable))
	eventStart = time.Now()
	stdout, stderr, err = remoteExecute(ctx, remote, systemScript)
	report.TransportEvents = append(report.TransportEvents, transportEvent(remote.Transport+"-system", eventStart, err, string(stderr)))
	if err != nil {
		return finish(err)
	}
	if err := json.Unmarshal(stdout, &report.System); err != nil {
		return finish(fmt.Errorf("decode bootstrapped Windows system probe: %w", err))
	}
	payloadScript := fmt.Sprintf(`$ErrorActionPreference='Stop'; $compiler=if(Get-Command cl.exe -ErrorAction SilentlyContinue){'msvc'}elseif(Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue){'mingw'}else{''}; [ordered]@{compile=($compiler -ne '');compiler=$compiler;native_x64=(Test-Path %s);native_x86=(Test-Path %s);sliver=((Get-Command sliver-client.exe -ErrorAction SilentlyContinue) -ne $null);debugging=(((Get-Command cdb.exe -ErrorAction SilentlyContinue) -ne $null) -or ((Get-Command windbg.exe -ErrorAction SilentlyContinue) -ne $null));snapshot_support=$false} | ConvertTo-Json -Compress`, powerShellQuote(remoteLoader), powerShellQuote(windowsJoin(config.RemoteRoot, "native", "loader", "bofbench-loader-x86.exe")))
	eventStart = time.Now()
	stdout, stderr, err = remoteExecute(ctx, remote, payloadScript)
	report.TransportEvents = append(report.TransportEvents, transportEvent(remote.Transport+"-capabilities", eventStart, err, string(stderr)))
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
	return fmt.Sprintf("Windows lab bootstrap %s\nprofile     %s\nhost        %s (%s %s)\nelevated    %t\ndisk free   %d\ncompile     %t %s\nnative x64  %t\nnative x86  %t\nsliver      %t\ndebugging   %t\nsnapshots   %t\ndeployed    %d\nunchanged   %d\nreports     %s\n", strings.ToUpper(report.Status), report.Profile, report.System.ComputerName, report.System.WindowsVersion, report.System.Architecture, report.System.Elevated, report.System.DiskFreeBytes, report.Capabilities.Compile, report.Capabilities.Compiler, report.Capabilities.NativeX64, report.Capabilities.NativeX86, report.Capabilities.Sliver, report.Capabilities.Debugging, report.Capabilities.SnapshotSupport, len(report.Deployed), len(report.Unchanged), report.EvidencePath)
}
