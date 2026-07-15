package lab

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"bofbench/internal/buildsys"
	"bofbench/internal/evidence"
	"bofbench/internal/runlog"
	runtimesvc "bofbench/internal/runtime"
	"bofbench/internal/runtimeadapter"
)

type RemoteOptions struct {
	ProfileName     string
	Transport       string
	Host            string
	User            string
	Port            int
	IdentityFile    string
	KnownHosts      string
	WinRMHTTPS      bool
	WinRMPassword   string
	BuildMode       string
	SnapshotSupport bool
	RemoteRoot      string
	Executable      string
	SSH             string
	SCP             string
}

type RemoteStatusReport struct {
	evidence.Header
	Operation       string            `json:"operation"`
	Status          string            `json:"status"`
	Profile         string            `json:"profile,omitempty"`
	Host            string            `json:"host"`
	RemoteRoot      string            `json:"remote_root"`
	Executable      string            `json:"executable"`
	ComputerName    string            `json:"computer_name,omitempty"`
	PowerShell      string            `json:"powershell,omitempty"`
	LoaderReady     bool              `json:"loader_ready"`
	ExecutableReady bool              `json:"executable_ready"`
	Capabilities    LabCapabilities   `json:"capabilities"`
	System          BootstrapSystem   `json:"system"`
	RuntimeHashes   map[string]string `json:"runtime_hashes,omitempty"`
	Version         json.RawMessage   `json:"version,omitempty"`
	Doctor          json.RawMessage   `json:"doctor,omitempty"`
	StartedAt       string            `json:"started_at"`
	CompletedAt     string            `json:"completed_at"`
	DurationMS      int64             `json:"duration_ms"`
	Error           string            `json:"error,omitempty"`
	TransportError  string            `json:"transport_error,omitempty"`
	EvidencePath    string            `json:"evidence_path"`
}

type RemoteSyncReport struct {
	evidence.Header
	Operation       string                   `json:"operation"`
	Status          string                   `json:"status"`
	Profile         string                   `json:"profile,omitempty"`
	Host            string                   `json:"host"`
	RemoteRoot      string                   `json:"remote_root"`
	Project         string                   `json:"project"`
	RemoteProject   string                   `json:"remote_project"`
	SourceTree      evidence.TreeFingerprint `json:"source_tree"`
	StartedAt       string                   `json:"started_at"`
	CompletedAt     string                   `json:"completed_at"`
	DurationMS      int64                    `json:"duration_ms"`
	Error           string                   `json:"error,omitempty"`
	EvidencePath    string                   `json:"evidence_path"`
	TransportEvents []TransportEvent         `json:"transport_events"`
}

type RemoteRunOptions struct {
	RemoteOptions
	Compiler               string
	Arch                   string
	Runtime                string
	Profile                string
	NoSync                 bool
	Args                   []string
	BuildMode              string
	TimeoutMS              int
	SensitiveArguments     []bool
	SensitiveArgumentNames []string
	SensitiveOutputFields  []string
	SensitiveValues        []string
	Interactive            bool
}

type RemoteRunReport struct {
	evidence.Header
	Operation       string                  `json:"operation"`
	Status          string                  `json:"status"`
	LabProfile      string                  `json:"lab_profile,omitempty"`
	Host            string                  `json:"host"`
	RemoteRoot      string                  `json:"remote_root"`
	Project         string                  `json:"project"`
	RemoteProject   string                  `json:"remote_project"`
	Compiler        string                  `json:"compiler"`
	Arch            string                  `json:"arch"`
	Runtime         string                  `json:"runtime"`
	Profile         string                  `json:"profile,omitempty"`
	BuildMode       string                  `json:"build_mode"`
	TimeoutMS       int                     `json:"timeout_ms"`
	Arguments       []string                `json:"arguments,omitempty"`
	StartedAt       string                  `json:"started_at"`
	CompletedAt     string                  `json:"completed_at"`
	DurationMS      int64                   `json:"duration_ms"`
	RemoteDev       *RemoteDevReport        `json:"remote_dev,omitempty"`
	LocalBuild      *buildsys.Result        `json:"local_build,omitempty"`
	RemoteResult    *runtimesvc.Result      `json:"remote_result,omitempty"`
	RemoteRunPath   string                  `json:"remote_run_path,omitempty"`
	RemoteComputer  string                  `json:"remote_computer,omitempty"`
	Receipt         *runtimeadapter.Receipt `json:"receipt,omitempty"`
	RemoteStderr    string                  `json:"remote_stderr,omitempty"`
	Collected       []CollectedFile         `json:"collected,omitempty"`
	TransportEvents []TransportEvent        `json:"transport_events"`
	Error           string                  `json:"error,omitempty"`
	EvidencePath    string                  `json:"evidence_path"`
	MarkdownPath    string                  `json:"markdown_path"`
}

type RemoteDevReport struct {
	evidence.Header
	Status           string `json:"status"`
	EvidencePath     string `json:"evidence_path"`
	MarkdownPath     string `json:"markdown_path"`
	SourceJSONPath   string `json:"source_json_path,omitempty"`
	SourceMDPath     string `json:"source_md_path,omitempty"`
	AnalysisJSONPath string `json:"analysis_json_path,omitempty"`
	AnalysisMDPath   string `json:"analysis_md_path,omitempty"`
	Build            struct {
		Object       string `json:"object"`
		EvidencePath string `json:"evidence_path"`
		LogPath      string `json:"log_path"`
	} `json:"build"`
	Run          *runtimesvc.Result `json:"run,omitempty"`
	RuntimeState string             `json:"runtime_state"`
	Error        string             `json:"error,omitempty"`
}

type RemoteCollectReport struct {
	evidence.Header
	Operation       string                   `json:"operation"`
	Status          string                   `json:"status"`
	Profile         string                   `json:"profile,omitempty"`
	Host            string                   `json:"host"`
	RemoteRoot      string                   `json:"remote_root"`
	RemoteRunID     string                   `json:"remote_run_id"`
	LocalPath       string                   `json:"local_path"`
	Fingerprint     evidence.TreeFingerprint `json:"fingerprint"`
	StartedAt       string                   `json:"started_at"`
	CompletedAt     string                   `json:"completed_at"`
	DurationMS      int64                    `json:"duration_ms"`
	Error           string                   `json:"error,omitempty"`
	EvidencePath    string                   `json:"evidence_path"`
	TransportEvents []TransportEvent         `json:"transport_events"`
}

type RemoteResetReport struct {
	evidence.Header
	Operation       string           `json:"operation"`
	Status          string           `json:"status"`
	Profile         string           `json:"profile,omitempty"`
	Host            string           `json:"host"`
	RemoteRoot      string           `json:"remote_root"`
	Scope           string           `json:"scope"`
	Removed         []string         `json:"removed"`
	StartedAt       string           `json:"started_at"`
	CompletedAt     string           `json:"completed_at"`
	DurationMS      int64            `json:"duration_ms"`
	Error           string           `json:"error,omitempty"`
	EvidencePath    string           `json:"evidence_path"`
	TransportEvents []TransportEvent `json:"transport_events"`
}

type TransportEvent struct {
	Type       string `json:"type"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	Detail     string `json:"detail,omitempty"`
	Error      string `json:"error,omitempty"`
}

type CollectedFile struct {
	RemotePath string `json:"remote_path"`
	LocalPath  string `json:"local_path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
}

type remoteStatusPayload struct {
	ComputerName    string          `json:"computer_name"`
	PowerShell      string          `json:"powershell"`
	ExecutableReady bool            `json:"executable_ready"`
	LoaderReady     bool            `json:"loader_ready"`
	LoaderX86Ready  bool            `json:"loader_x86_ready"`
	Compiler        string          `json:"compiler"`
	Sliver          bool            `json:"sliver"`
	Debugging       bool            `json:"debugging"`
	WindowsVersion  string          `json:"windows_version"`
	Architecture    string          `json:"architecture"`
	Elevated        bool            `json:"elevated"`
	DiskFreeBytes   int64           `json:"disk_free_bytes"`
	ExecutableHash  string          `json:"executable_sha256"`
	LoaderX64Hash   string          `json:"loader_x64_sha256"`
	LoaderX86Hash   string          `json:"loader_x86_sha256"`
	Version         json.RawMessage `json:"version"`
	Doctor          json.RawMessage `json:"doctor"`
}

type transportFunc func(context.Context, string, ...string) ([]byte, []byte, error)

var executeRemoteTransport transportFunc = runTransport

var safeRemoteName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func DefaultRemoteOptions() RemoteOptions {
	host := strings.TrimSpace(os.Getenv("BOFBENCH_LAB_HOST"))
	root := strings.TrimSpace(os.Getenv("BOFBENCH_LAB_ROOT"))
	if root == "" {
		root = `C:\bofbench`
	}
	executable := strings.TrimSpace(os.Getenv("BOFBENCH_LAB_EXE"))
	if executable == "" {
		executable = windowsJoin(root, "work", "bin", "bofbench.exe")
	}
	return RemoteOptions{Transport: "ssh", Host: host, Port: 22, RemoteRoot: root, Executable: executable, SSH: "ssh", SCP: "scp"}
}

func RemoteOptionsFromProfile(name string, profile Profile) RemoteOptions {
	profile = NormalizeProfile(profile)
	return RemoteOptions{
		ProfileName: name, Transport: profile.Transport, Host: profile.Host, User: profile.User,
		Port: profile.Port, IdentityFile: expandUserPath(profile.IdentityFile), KnownHosts: expandUserPath(profile.KnownHosts),
		WinRMHTTPS: profile.WinRMHTTPS, WinRMPassword: os.Getenv(WinRMPasswordEnvironment(name)), BuildMode: profile.BuildMode, SnapshotSupport: profile.Provider == "vagrant",
		RemoteRoot: profile.RemoteRoot, Executable: windowsJoin(profile.RemoteRoot, "work", "bin", "bofbench.exe"),
		SSH: "ssh", SCP: "scp",
	}
}

func RemoteStatus(ctx context.Context, opts RemoteOptions) (RemoteStatusReport, error) {
	start := time.Now()
	opts, err := normalizeRemoteOptions(opts)
	if err != nil {
		return RemoteStatusReport{}, err
	}
	runDir, err := runlog.NewDir("lab-status")
	if err != nil {
		return RemoteStatusReport{}, err
	}
	report := RemoteStatusReport{
		Header: evidence.New(evidence.SchemaLabRemoteStatus, runlog.ID(runDir), ""), Operation: "status", Status: "fail",
		Profile: opts.ProfileName, Host: opts.Host, RemoteRoot: opts.RemoteRoot, Executable: opts.Executable, StartedAt: start.UTC().Format(time.RFC3339Nano),
		EvidencePath: filepath.Join(runDir, "status.json"),
	}
	loaderX64 := windowsJoin(opts.RemoteRoot, "native", "loader", "bofbench-loader.exe")
	loaderX86 := windowsJoin(opts.RemoteRoot, "native", "loader", "bofbench-loader-x86.exe")
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; $exeReady=Test-Path %s; $loaderReady=Test-Path %s; $loaderX86Ready=Test-Path %s; $version=$null; if($exeReady){$version=(& %s version --format json | ConvertFrom-Json)}; $compiler=if(Get-Command cl.exe -ErrorAction SilentlyContinue){'msvc'}elseif(Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue){'mingw'}else{''}; $identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=New-Object Security.Principal.WindowsPrincipal($identity); $root=Get-Item %s -ErrorAction SilentlyContinue; [ordered]@{computer_name=$env:COMPUTERNAME;powershell=$PSVersionTable.PSVersion.ToString();windows_version=[Environment]::OSVersion.Version.ToString();architecture=$env:PROCESSOR_ARCHITECTURE;elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);disk_free_bytes=if($root){$root.PSDrive.Free}else{0};executable_ready=$exeReady;loader_ready=$loaderReady;loader_x86_ready=$loaderX86Ready;executable_sha256=if($exeReady){(Get-FileHash -Algorithm SHA256 -LiteralPath %s).Hash.ToLower()}else{''};loader_x64_sha256=if($loaderReady){(Get-FileHash -Algorithm SHA256 -LiteralPath %s).Hash.ToLower()}else{''};loader_x86_sha256=if($loaderX86Ready){(Get-FileHash -Algorithm SHA256 -LiteralPath %s).Hash.ToLower()}else{''};compiler=$compiler;sliver=((Get-Command sliver-client.exe -ErrorAction SilentlyContinue) -ne $null);debugging=(((Get-Command cdb.exe -ErrorAction SilentlyContinue) -ne $null) -or ((Get-Command windbg.exe -ErrorAction SilentlyContinue) -ne $null));version=$version} | ConvertTo-Json -Depth 12 -Compress`,
		powerShellQuote(opts.Executable), powerShellQuote(loaderX64), powerShellQuote(loaderX86), powerShellQuote(opts.Executable), powerShellQuote(opts.RemoteRoot), powerShellQuote(opts.Executable), powerShellQuote(loaderX64), powerShellQuote(loaderX86))
	stdout, stderr, runErr := remoteExecute(ctx, opts, script)
	if runErr != nil {
		report.TransportError = boundedText(string(stderr), 4096)
		report.Error = runErr.Error()
	} else {
		var payload remoteStatusPayload
		if err := json.Unmarshal(stdout, &payload); err != nil {
			runErr = fmt.Errorf("decode remote status: %w", err)
			report.Error = runErr.Error()
		} else {
			report.ComputerName = payload.ComputerName
			report.PowerShell = payload.PowerShell
			report.LoaderReady = payload.LoaderReady
			report.ExecutableReady = payload.ExecutableReady || (payload.LoaderReady && len(payload.Version) > 0)
			report.Version = payload.Version
			report.Doctor = payload.Doctor
			report.RuntimeHashes = map[string]string{"bofbench.exe": payload.ExecutableHash, "bofbench-loader.exe": payload.LoaderX64Hash, "bofbench-loader-x86.exe": payload.LoaderX86Hash}
			report.Capabilities = LabCapabilities{Compile: payload.Compiler != "", Compiler: payload.Compiler, NativeX64: payload.LoaderReady, NativeX86: payload.LoaderX86Ready, Sliver: payload.Sliver, Debugging: payload.Debugging, SnapshotSupport: opts.SnapshotSupport}
			report.System = BootstrapSystem{ComputerName: payload.ComputerName, WindowsVersion: payload.WindowsVersion, Architecture: payload.Architecture, Elevated: payload.Elevated, DiskFreeBytes: payload.DiskFreeBytes, BOFBench: payload.Version}
			if report.ExecutableReady && payload.LoaderReady && payload.LoaderX86Ready {
				report.Status = "pass"
			} else {
				runErr = errors.New("remote BOFBench runtime is missing; run 'bofbench lab bootstrap'")
				report.Error = runErr.Error()
			}
		}
	}
	finishRemoteStatus(&report, start)
	if persistErr := writeRemoteJSON(report.EvidencePath, report); persistErr != nil && runErr == nil {
		runErr = persistErr
	}
	return report, runErr
}

func RemoteSync(ctx context.Context, project string, opts RemoteOptions) (RemoteSyncReport, error) {
	start := time.Now()
	opts, err := normalizeRemoteOptions(opts)
	if err != nil {
		return RemoteSyncReport{}, err
	}
	runDir, err := runlog.NewDir("lab-sync-" + remoteSafeName(project))
	if err != nil {
		return RemoteSyncReport{}, err
	}
	report := RemoteSyncReport{
		Header: evidence.New(evidence.SchemaLabRemoteSync, runlog.ID(runDir), ""), Operation: "sync", Status: "fail",
		Profile: opts.ProfileName, Host: opts.Host, RemoteRoot: opts.RemoteRoot, Project: project, StartedAt: start.UTC().Format(time.RFC3339Nano),
		EvidencePath: filepath.Join(runDir, "sync.json"),
	}
	remoteProject, fingerprint, events, syncErr := syncRemoteProject(ctx, project, opts, "")
	report.RemoteProject = remoteProject
	report.SourceTree = fingerprint
	report.TransportEvents = events
	if syncErr != nil {
		report.Error = syncErr.Error()
	} else {
		report.Status = "pass"
	}
	finishRemoteSync(&report, start)
	if persistErr := writeRemoteJSON(report.EvidencePath, report); persistErr != nil && syncErr == nil {
		syncErr = persistErr
	}
	return report, syncErr
}

func RemoteRun(ctx context.Context, project string, opts RemoteRunOptions) (RemoteRunReport, error) {
	start := time.Now()
	remoteOpts, err := normalizeRemoteOptions(opts.RemoteOptions)
	if err != nil {
		return RemoteRunReport{}, err
	}
	opts.RemoteOptions = remoteOpts
	enforceBuildMode := opts.BuildMode != "" || opts.RemoteOptions.BuildMode != ""
	if opts.BuildMode == "" {
		opts.BuildMode = opts.RemoteOptions.BuildMode
	}
	if opts.BuildMode == "" {
		// Direct callers from the version-1 API retain remote-build behavior.
		// Named profiles always provide their explicit auto/local/remote mode.
		opts.BuildMode = "remote"
	}
	if opts.BuildMode != "auto" && opts.BuildMode != "local" && opts.BuildMode != "remote" {
		return RemoteRunReport{}, fmt.Errorf("build mode must be auto, local, or remote")
	}
	if opts.Compiler == "" {
		opts.Compiler = "msvc"
	}
	if opts.Arch == "" {
		opts.Arch = "x64"
	}
	if opts.Arch != "x64" && opts.Arch != "x86" {
		return RemoteRunReport{}, fmt.Errorf("lab architecture must be x64 or x86")
	}
	if opts.Runtime == "" {
		opts.Runtime = "windows-coff"
	}
	if opts.TimeoutMS <= 0 {
		opts.TimeoutMS = 5000
	}
	runDir, err := runlog.NewDir("lab-run-" + remoteSafeName(project))
	if err != nil {
		return RemoteRunReport{}, err
	}
	report := RemoteRunReport{
		Header: evidence.New(evidence.SchemaLabRemoteRun, runlog.ID(runDir), ""), Operation: "run", Status: "fail",
		LabProfile: opts.ProfileName, Host: opts.Host, RemoteRoot: opts.RemoteRoot, Project: project, Compiler: opts.Compiler, Arch: opts.Arch, Runtime: opts.Runtime, Profile: opts.Profile, BuildMode: opts.BuildMode, TimeoutMS: opts.TimeoutMS, Arguments: append([]string(nil), opts.Args...),
		StartedAt: start.UTC().Format(time.RFC3339Nano), EvidencePath: filepath.Join(runDir, "lab-run.json"), MarkdownPath: filepath.Join(runDir, "lab-run.md"),
	}
	report.Arguments = redactRemoteArgumentTokens(report.Arguments, opts.SensitiveArguments)
	identityStart := time.Now()
	if computer, identityErr := detectRemoteComputer(ctx, opts.RemoteOptions); identityErr == nil {
		report.RemoteComputer = computer
		report.TransportEvents = append(report.TransportEvents, transportEvent(opts.Transport+"-identity", identityStart, nil, ""))
	} else {
		report.TransportEvents = append(report.TransportEvents, transportEvent(opts.Transport+"-identity", identityStart, identityErr, ""))
	}
	var runErr error
	if opts.BuildMode == "auto" {
		remoteCompiler, compilerErr := detectRemoteCompiler(ctx, opts.RemoteOptions, opts.Arch)
		if compilerErr == nil && remoteCompiler != "" {
			opts.BuildMode = "remote"
			report.BuildMode = "remote"
		} else {
			opts.BuildMode = "local"
			report.BuildMode = "local"
		}
	}
	if opts.BuildMode == "remote" && enforceBuildMode {
		remoteCompiler, compilerErr := detectRemoteCompiler(ctx, opts.RemoteOptions, opts.Arch)
		if compilerErr != nil {
			return report, compilerErr
		}
		if remoteCompiler == "" {
			return report, fmt.Errorf("lab profile %q requires remote compilation but no MinGW or MSVC compiler is available", opts.ProfileName)
		}
	}
	if opts.BuildMode == "local" {
		runErr = runLocallyBuiltObject(ctx, runDir, project, &report, opts)
		if runErr != nil {
			report.Error = runErr.Error()
		}
		finishRemoteRun(&report, start)
		persisted := redactRemoteRunReport(report, opts)
		persistRemoteRuntimeReceipt(&persisted, runDir, runErr, opts.SensitiveArgumentNames, opts.SensitiveOutputFields)
		report.Receipt = persisted.Receipt
		if persistErr := writeRemoteJSON(report.EvidencePath, persisted); persistErr != nil && runErr == nil {
			runErr = persistErr
		}
		if persistErr := os.WriteFile(report.MarkdownPath, []byte(RemoteRunMarkdown(persisted)), 0o644); persistErr != nil && runErr == nil {
			runErr = persistErr
		}
		return report, runErr
	}
	if opts.NoSync {
		projectsRoot := windowsJoin(opts.RemoteRoot, "work", "projects")
		if opts.ProfileName != "" {
			projectsRoot = windowsJoin(projectsRoot, remoteProfileSegment(opts.ProfileName))
		}
		report.RemoteProject = windowsJoin(projectsRoot, remoteSafeName(project))
	} else {
		remoteProject, _, events, syncErr := syncRemoteProject(ctx, project, opts.RemoteOptions, report.RunID)
		report.RemoteProject = remoteProject
		report.TransportEvents = append(report.TransportEvents, events...)
		if syncErr != nil {
			runErr = syncErr
			report.Error = syncErr.Error()
		}
	}
	if runErr == nil {
		remoteWorkspace := windowsJoin(opts.RemoteRoot, "runs", remoteProfileSegment(opts.ProfileName), report.RunID)
		report.RemoteRunPath = remoteWorkspace
		eventStart := time.Now()
		_, stderr, prepareErr := remoteExecute(ctx, opts.RemoteOptions, fmt.Sprintf(`New-Item -ItemType Directory -Force -Path %s | Out-Null`, powerShellQuote(remoteWorkspace)))
		report.TransportEvents = append(report.TransportEvents, transportEvent(opts.Transport+"-prepare-run", eventStart, prepareErr, string(stderr)))
		if prepareErr != nil {
			runErr = prepareErr
		}
	}
	if runErr == nil {
		args := []string{"dev", report.RemoteProject, "--compiler", opts.Compiler, "--arch", opts.Arch, "--runtime", opts.Runtime, "--format", "json"}
		if opts.Profile != "" {
			args = append(args, "--profile", opts.Profile)
		}
		for _, token := range opts.Args {
			args = append(args, "--arg-token", token)
		}
		for index, sensitive := range opts.SensitiveArguments {
			if sensitive {
				args = append(args, "--sensitive-arg-index", strconv.Itoa(index))
			}
		}
		for _, field := range opts.SensitiveOutputFields {
			args = append(args, "--sensitive-output-field", field)
		}
		quotedArgs := make([]string, 0, len(args))
		for _, arg := range args {
			quotedArgs = append(quotedArgs, powerShellQuote(arg))
		}
		loaderX64 := windowsJoin(opts.RemoteRoot, "native", "loader", "bofbench-loader.exe")
		loaderX86 := windowsJoin(opts.RemoteRoot, "native", "loader", "bofbench-loader-x86.exe")
		script := fmt.Sprintf(`$ErrorActionPreference='Continue'; Set-Location %s; $env:BOFBENCH_LOADER=%s; $env:BOFBENCH_LOADER_X86=%s; & %s %s`, powerShellQuote(report.RemoteRunPath), powerShellQuote(loaderX64), powerShellQuote(loaderX86), powerShellQuote(opts.Executable), strings.Join(quotedArgs, " "))
		if opts.Interactive {
			script = interactiveExecutionScript(report, opts, quotedArgs, loaderX64, loaderX86)
		}
		eventStart := time.Now()
		stdout, stderr, devErr := remoteExecute(ctx, opts.RemoteOptions, script)
		report.TransportEvents = append(report.TransportEvents, transportEvent(opts.Transport+"-dev", eventStart, devErr, string(stderr)))
		report.RemoteStderr = boundedText(string(stderr), 8192)
		var remoteDev RemoteDevReport
		if decodeErr := json.Unmarshal(stdout, &remoteDev); decodeErr != nil {
			runErr = fmt.Errorf("decode remote dev report: %w", decodeErr)
		} else {
			report.RemoteDev = &remoteDev
			evidenceOptions := opts.RemoteOptions
			evidenceOptions.RemoteRoot = report.RemoteRunPath
			collected, events, collectErr := collectDevEvidence(ctx, runDir, remoteDev, evidenceOptions)
			report.Collected = collected
			report.TransportEvents = append(report.TransportEvents, events...)
			if collectErr != nil {
				runErr = collectErr
			} else if devErr != nil || remoteDev.Status != "pass" {
				runErr = fmt.Errorf("remote developer loop failed: %s", emptyRemote(remoteDev.Error, remoteDev.Status))
			} else {
				report.Status = "pass"
			}
		}
		if runErr == nil && devErr != nil {
			runErr = devErr
		}
	}
	if runErr != nil {
		report.Error = runErr.Error()
	}
	finishRemoteRun(&report, start)
	persisted := redactRemoteRunReport(report, opts)
	persistRemoteRuntimeReceipt(&persisted, runDir, runErr, opts.SensitiveArgumentNames, opts.SensitiveOutputFields)
	report.Receipt = persisted.Receipt
	if persistErr := writeRemoteJSON(report.EvidencePath, persisted); persistErr != nil && runErr == nil {
		runErr = persistErr
	}
	if persistErr := os.WriteFile(report.MarkdownPath, []byte(RemoteRunMarkdown(persisted)), 0o644); persistErr != nil && runErr == nil {
		runErr = persistErr
	}
	return report, runErr
}

func interactiveExecutionScript(report RemoteRunReport, opts RemoteRunOptions, quotedArgs []string, loaderX64, loaderX86 string) string {
	outputPath := windowsJoin(report.RemoteRunPath, "interactive-session-output.json")
	exitPath := windowsJoin(report.RemoteRunPath, "interactive-session-exit.txt")
	inner := fmt.Sprintf(`$ErrorActionPreference='Continue'; Set-Location %s; $env:BOFBENCH_LOADER=%s; $env:BOFBENCH_LOADER_X86=%s; $text=(& %s %s 2>&1 | Out-String); $code=$LASTEXITCODE; [IO.File]::WriteAllText(%s,$text,(New-Object Text.UTF8Encoding($false))); [IO.File]::WriteAllText(%s,[string]$code,(New-Object Text.UTF8Encoding($false)))`, powerShellQuote(report.RemoteRunPath), powerShellQuote(loaderX64), powerShellQuote(loaderX86), powerShellQuote(opts.Executable), strings.Join(quotedArgs, " "), powerShellQuote(outputPath), powerShellQuote(exitPath))
	encoded := encodePowerShellCommand(inner)
	taskName := "BOFBench-Interactive-" + report.RunID
	return fmt.Sprintf(`$ErrorActionPreference='Stop'; $task=%s; $output=%s; $exitFile=%s; $exitCode=1; $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument %s -WorkingDirectory %s; $principal=New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME+'\'+$env:USERNAME) -LogonType Interactive -RunLevel Highest; try { Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force | Out-Null; Start-ScheduledTask -TaskName $task; $deadline=(Get-Date).AddSeconds(90); do { Start-Sleep -Milliseconds 250; $state=(Get-ScheduledTask -TaskName $task).State } while($state -eq 'Running' -and (Get-Date) -lt $deadline); if($state -eq 'Running'){ Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue; throw 'interactive execution timed out' }; if(-not (Test-Path -LiteralPath $output)){ throw 'interactive execution produced no output' }; [Console]::Out.Write([IO.File]::ReadAllText($output)); if(Test-Path -LiteralPath $exitFile){ $exitCode=[int]([IO.File]::ReadAllText($exitFile).Trim()) } } finally { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $output,$exitFile -Force -ErrorAction SilentlyContinue }; exit $exitCode`, powerShellQuote(taskName), powerShellQuote(outputPath), powerShellQuote(exitPath), powerShellQuote("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "+encoded), powerShellQuote(report.RemoteRunPath))
}

func encodePowerShellCommand(script string) string {
	units := utf16.Encode([]rune(script))
	data := make([]byte, len(units)*2)
	for index, unit := range units {
		data[index*2] = byte(unit)
		data[index*2+1] = byte(unit >> 8)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func detectRemoteComputer(ctx context.Context, opts RemoteOptions) (string, error) {
	stdout, stderr, err := remoteExecute(ctx, opts, `Write-Output $env:COMPUTERNAME`)
	if err != nil {
		return "", fmt.Errorf("identify remote computer: %w: %s", err, boundedText(string(stderr), 1024))
	}
	computer := strings.TrimSpace(string(stdout))
	if computer == "" {
		return "", fmt.Errorf("remote computer name was empty")
	}
	return computer, nil
}

func persistRemoteRuntimeReceipt(report *RemoteRunReport, runDir string, operationErr error, sensitiveArguments, sensitiveFields []string) {
	result := report.RemoteResult
	if result == nil && report.RemoteDev != nil {
		result = report.RemoteDev.Run
	}
	receipt := runtimeadapter.Receipt{
		Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion,
		Runtime: "lab", Status: report.Status, ExecutionState: "failed", Profile: report.LabProfile,
		Transport: reportTransport(report), RemoteHost: report.Host, RemoteComputer: report.RemoteComputer,
		StartedAt: report.StartedAt, CompletedAt: report.CompletedAt, DurationMS: report.DurationMS,
		ReceiptPath: filepath.Join(runDir, "result.json"), Arguments: runtimeArgumentTypes(report.Arguments), TimeoutMS: report.TimeoutMS,
		SensitiveArguments: append([]string(nil), sensitiveArguments...), RedactedOutputFields: append([]string(nil), sensitiveFields...),
	}
	if result != nil {
		receipt.Object = result.Object
		if result.ObjectFingerprint != nil {
			receipt.ObjectSHA256 = result.ObjectFingerprint.SHA256
		}
		receipt.Entrypoint = result.Entry
		receipt.Output = cleanReceiptOutput(result.Output)
		receipt.ExitState = result.ExitState
		receipt.TimedOut = result.ExitState == "timeout"
		if result.Status == "pass" && operationErr == nil {
			receipt.ExecutionState = "completed"
			receipt.OutputComplete = true
		} else if receipt.TimedOut {
			receipt.ExecutionState = "timeout"
		}
		if result.LoaderProcess != nil {
			receipt.ExitCode = result.LoaderProcess.ExitCode
		}
	}
	if operationErr != nil {
		receipt.Error = operationErr.Error()
		if receipt.Status == "" || receipt.Status == "pass" {
			receipt.Status = "fail"
		}
	}
	if receipt.Status == "" {
		receipt.Status = "fail"
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err == nil {
		err = os.WriteFile(receipt.ReceiptPath, append(data, '\n'), 0o600)
	}
	if err == nil {
		report.Receipt = &receipt
	}
}

func redactRemoteArgumentTokens(tokens []string, sensitive []bool) []string {
	result := append([]string(nil), tokens...)
	for index := range result {
		if index >= len(sensitive) || !sensitive[index] {
			continue
		}
		if kind, _, ok := strings.Cut(result[index], ":"); ok {
			result[index] = kind + ":<redacted>"
		} else {
			result[index] = "<redacted>"
		}
	}
	return result
}

func redactRemoteRunReport(report RemoteRunReport, opts RemoteRunOptions) RemoteRunReport {
	persisted := report
	persisted.Arguments = redactRemoteArgumentTokens(report.Arguments, opts.SensitiveArguments)
	persisted.Error = redactRemoteLines([]string{report.Error}, nil, opts.SensitiveValues)[0]
	persisted.RemoteStderr = redactRemoteLines([]string{report.RemoteStderr}, nil, opts.SensitiveValues)[0]
	if report.RemoteResult != nil {
		result := redactRemoteRuntimeResult(*report.RemoteResult, opts.SensitiveOutputFields, opts.SensitiveValues)
		persisted.RemoteResult = &result
	}
	if report.RemoteDev != nil {
		dev := *report.RemoteDev
		dev.Error = redactRemoteLines([]string{dev.Error}, nil, opts.SensitiveValues)[0]
		if report.RemoteDev.Run != nil {
			result := redactRemoteRuntimeResult(*report.RemoteDev.Run, opts.SensitiveOutputFields, opts.SensitiveValues)
			dev.Run = &result
		}
		persisted.RemoteDev = &dev
	}
	return persisted
}

func redactRemoteRuntimeResult(result runtimesvc.Result, fields, secrets []string) runtimesvc.Result {
	result.Output = redactRemoteLines(result.Output, fields, secrets)
	result.Errors = redactRemoteLines(result.Errors, nil, secrets)
	result.Events = append([]runtimesvc.Event(nil), result.Events...)
	for index := range result.Events {
		result.Events[index].Message = redactRemoteLines([]string{result.Events[index].Message}, fields, secrets)[0]
	}
	if result.LoaderProcess != nil {
		process := *result.LoaderProcess
		process.Stdout = redactRemoteLines(process.Stdout, fields, secrets)
		process.Stderr = redactRemoteLines(process.Stderr, nil, secrets)
		result.LoaderProcess = &process
	}
	return result
}

func redactRemoteLines(lines, fields, secrets []string) []string {
	result := make([]string, len(lines))
	for index, line := range lines {
		for _, secret := range secrets {
			if secret != "" {
				line = strings.ReplaceAll(line, secret, "<redacted>")
			}
		}
		for _, field := range fields {
			needle := field + "="
			for start := 0; start < len(line); {
				position := strings.Index(line[start:], needle)
				if position < 0 {
					break
				}
				position += start
				end := position + len(needle)
				for end < len(line) && !strings.ContainsRune(" \t\r\n", rune(line[end])) {
					end++
				}
				line = line[:position+len(needle)] + "<redacted>" + line[end:]
				start = position + len(needle) + len("<redacted>")
			}
		}
		result[index] = line
	}
	return result
}

func cleanReceiptOutput(lines []string) []string {
	clean := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			clean = append(clean, line)
		}
	}
	return clean
}

func reportTransport(report *RemoteRunReport) string {
	for _, event := range report.TransportEvents {
		if index := strings.IndexByte(event.Type, '-'); index > 0 {
			return event.Type[:index]
		}
	}
	return ""
}

func runtimeArgumentTypes(tokens []string) []string {
	types := make([]string, 0, len(tokens))
	for _, token := range tokens {
		kind := token
		if index := strings.IndexByte(token, ':'); index > 0 {
			kind = token[:index]
		}
		types = append(types, kind)
	}
	return types
}

func detectRemoteCompiler(ctx context.Context, opts RemoteOptions, arch string) (string, error) {
	script := remoteCompilerProbeScript(arch)
	stdout, stderr, err := remoteExecute(ctx, opts, script)
	if err != nil {
		return "", fmt.Errorf("probe remote compiler: %w: %s", err, boundedText(string(stderr), 1024))
	}
	return strings.TrimSpace(string(stdout)), nil
}

func remoteCompilerProbeScript(arch string) string {
	if arch == "x86" {
		return `$compiler=if(Get-Command i686-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue){'mingw'}else{''}; Write-Output $compiler`
	}
	return `$compiler=if(Get-Command cl.exe -ErrorAction SilentlyContinue){'msvc'}elseif(Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue){'mingw'}else{''}; Write-Output $compiler`
}

func runLocallyBuiltObject(ctx context.Context, runDir, project string, report *RemoteRunReport, opts RemoteRunOptions) error {
	compiler := opts.Compiler
	if compiler == "" || compiler == "msvc" {
		compiler = "auto"
	}
	build, err := buildsys.BuildWithOptions(project, buildsys.Options{Arch: opts.Arch, Compiler: compiler, ParentRunID: report.RunID})
	report.LocalBuild = &build
	if err != nil {
		return err
	}
	remoteRun := windowsJoin(opts.RemoteRoot, "runs", remoteProfileSegment(opts.ProfileName), report.RunID)
	remoteObject := windowsJoin(remoteRun, filepath.Base(build.Object))
	report.RemoteRunPath = remoteRun
	report.RemoteProject = remoteObject
	eventStart := time.Now()
	_, stderr, err := remoteExecute(ctx, opts.RemoteOptions, fmt.Sprintf(`New-Item -ItemType Directory -Force -Path %s | Out-Null`, powerShellQuote(remoteRun)))
	report.TransportEvents = append(report.TransportEvents, transportEvent(opts.Transport+"-prepare-object", eventStart, err, string(stderr)))
	if err != nil {
		return err
	}
	eventStart = time.Now()
	_, stderr, err = remoteUploadFile(ctx, opts.RemoteOptions, build.Object, remoteObject)
	report.TransportEvents = append(report.TransportEvents, transportEvent(opts.Transport+"-object", eventStart, err, string(stderr)))
	if err != nil {
		return err
	}
	arguments := []string{"run", remoteObject, "--runtime", "windows-coff", "--entry", "go", "--timeout", fmt.Sprintf("%d", opts.TimeoutMS), "--args"}
	arguments = append(arguments, opts.Args...)
	quoted := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		quoted = append(quoted, powerShellQuote(argument))
	}
	remoteResultPath := windowsJoin(remoteRun, "result.json")
	remoteStderrPath := windowsJoin(remoteRun, "stderr.txt")
	loaderX64 := windowsJoin(opts.RemoteRoot, "native", "loader", "bofbench-loader.exe")
	loaderX86 := windowsJoin(opts.RemoteRoot, "native", "loader", "bofbench-loader-x86.exe")
	script := fmt.Sprintf(`$ErrorActionPreference='Continue'; $env:BOFBENCH_LOADER=%s; $env:BOFBENCH_LOADER_X86=%s; & %s %s 1> %s 2> %s; $exit=$LASTEXITCODE; $output=Get-Content -LiteralPath %s -Raw; $errors=if(Test-Path %s){Get-Content -LiteralPath %s -Raw}else{''}; Write-Output $output; if($errors){[Console]::Error.Write($errors)}; exit $exit`, powerShellQuote(loaderX64), powerShellQuote(loaderX86), powerShellQuote(opts.Executable), strings.Join(quoted, " "), powerShellQuote(remoteResultPath), powerShellQuote(remoteStderrPath), powerShellQuote(remoteResultPath), powerShellQuote(remoteStderrPath), powerShellQuote(remoteStderrPath))
	eventStart = time.Now()
	stdout, stderr, executeErr := remoteExecute(ctx, opts.RemoteOptions, script)
	report.TransportEvents = append(report.TransportEvents, transportEvent(opts.Transport+"-run-object", eventStart, executeErr, string(stderr)))
	report.RemoteStderr = boundedText(string(stderr), 8192)
	var result runtimesvc.Result
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(stdout))), &result); err != nil {
		if executeErr != nil {
			return fmt.Errorf("remote object execution failed: %w: %s", executeErr, boundedText(string(stderr), 4096))
		}
		return fmt.Errorf("decode remote runtime result: %w", err)
	}
	report.RemoteResult = &result
	localResult := filepath.Join(runDir, "remote-result.json")
	if err := os.WriteFile(localResult, append(bytes.TrimSpace(stdout), '\n'), 0o600); err == nil {
		if fingerprint, fingerprintErr := evidence.FingerprintFile(localResult); fingerprintErr == nil {
			report.Collected = append(report.Collected, CollectedFile{RemotePath: remoteResultPath, LocalPath: localResult, Size: fingerprint.Size, SHA256: fingerprint.SHA256})
		}
	}
	if executeErr != nil || result.Status != "pass" {
		return fmt.Errorf("remote object run failed: %s", emptyRemote(result.ExitState, result.Status))
	}
	report.Status = "pass"
	return nil
}

func RemoteCollect(ctx context.Context, remoteRunID string, opts RemoteOptions) (RemoteCollectReport, error) {
	start := time.Now()
	opts, err := normalizeRemoteOptions(opts)
	if err != nil {
		return RemoteCollectReport{}, err
	}
	if !safeRemoteName.MatchString(remoteRunID) {
		return RemoteCollectReport{}, fmt.Errorf("invalid remote run id %q", remoteRunID)
	}
	runDir, err := runlog.NewDir("lab-collect-" + remoteRunID)
	if err != nil {
		return RemoteCollectReport{}, err
	}
	localPath := filepath.Join(runDir, "remote-run")
	report := RemoteCollectReport{
		Header: evidence.New(evidence.SchemaLabRemoteCollect, runlog.ID(runDir), ""), Operation: "collect", Status: "fail",
		Profile: opts.ProfileName, Host: opts.Host, RemoteRoot: opts.RemoteRoot, RemoteRunID: remoteRunID, LocalPath: localPath,
		StartedAt: start.UTC().Format(time.RFC3339Nano), EvidencePath: filepath.Join(runDir, "collect.json"),
	}
	remotePath := windowsJoin(opts.RemoteRoot, "runs")
	if opts.ProfileName != "" {
		remotePath = windowsJoin(remotePath, remoteProfileSegment(opts.ProfileName))
	}
	remotePath = windowsJoin(remotePath, remoteRunID)
	eventStart := time.Now()
	_, stderr, collectErr := remoteDownloadDirectory(ctx, opts, remotePath, localPath)
	report.TransportEvents = append(report.TransportEvents, transportEvent(opts.Transport+"-run", eventStart, collectErr, string(stderr)))
	if collectErr == nil {
		report.Fingerprint, collectErr = evidence.FingerprintTree(localPath)
	}
	if collectErr != nil {
		report.Error = collectErr.Error()
	} else {
		report.Status = "pass"
	}
	finishRemoteCollect(&report, start)
	if persistErr := writeRemoteJSON(report.EvidencePath, report); persistErr != nil && collectErr == nil {
		collectErr = persistErr
	}
	return report, collectErr
}

func RemoteReset(ctx context.Context, scope string, opts RemoteOptions) (RemoteResetReport, error) {
	start := time.Now()
	opts, err := normalizeRemoteOptions(opts)
	if err != nil {
		return RemoteResetReport{}, err
	}
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" {
		scope = "managed"
	}
	projectsRoot := windowsJoin(opts.RemoteRoot, "work", "projects")
	syncRoot := windowsJoin(opts.RemoteRoot, "work", "sync")
	runsRoot := windowsJoin(opts.RemoteRoot, "runs")
	if opts.ProfileName != "" {
		segment := remoteProfileSegment(opts.ProfileName)
		projectsRoot = windowsJoin(projectsRoot, segment)
		syncRoot = windowsJoin(syncRoot, segment)
		runsRoot = windowsJoin(runsRoot, segment)
	}
	paths := []string{projectsRoot, syncRoot}
	switch scope {
	case "managed":
	case "artifacts":
		if opts.ProfileName != "" {
			paths = append(paths, runsRoot)
		} else {
			paths = append(paths, windowsJoin(opts.RemoteRoot, "dist"), windowsJoin(opts.RemoteRoot, "stage"))
		}
	case "runs":
		if opts.ProfileName != "" {
			paths = append(paths, runsRoot)
		} else {
			paths = append(paths, windowsJoin(opts.RemoteRoot, "dist"), windowsJoin(opts.RemoteRoot, "stage"), runsRoot)
		}
	default:
		return RemoteResetReport{}, fmt.Errorf("reset scope must be managed, artifacts, or runs")
	}
	runDir, err := runlog.NewDir("lab-reset-" + scope)
	if err != nil {
		return RemoteResetReport{}, err
	}
	report := RemoteResetReport{
		Header: evidence.New(evidence.SchemaLabRemoteReset, runlog.ID(runDir), ""), Operation: "reset", Status: "fail",
		Profile: opts.ProfileName, Host: opts.Host, RemoteRoot: opts.RemoteRoot, Scope: scope, Removed: paths, StartedAt: start.UTC().Format(time.RFC3339Nano),
		EvidencePath: filepath.Join(runDir, "reset.json"),
	}
	var statements []string
	for _, path := range paths {
		statements = append(statements, fmt.Sprintf(`if(Test-Path %s){Remove-Item -LiteralPath %s -Recurse -Force}`, powerShellQuote(path), powerShellQuote(path)))
	}
	statements = append(statements, fmt.Sprintf(`New-Item -ItemType Directory -Force -Path %s,%s | Out-Null`, powerShellQuote(projectsRoot), powerShellQuote(syncRoot)))
	eventStart := time.Now()
	_, stderr, resetErr := remoteExecute(ctx, opts, strings.Join(statements, "; "))
	report.TransportEvents = append(report.TransportEvents, transportEvent(opts.Transport+"-reset", eventStart, resetErr, string(stderr)))
	if resetErr != nil {
		report.Error = resetErr.Error()
	} else {
		report.Status = "pass"
	}
	finishRemoteReset(&report, start)
	if persistErr := writeRemoteJSON(report.EvidencePath, report); persistErr != nil && resetErr == nil {
		resetErr = persistErr
	}
	return report, resetErr
}

func RemoteStatusText(report RemoteStatusReport) string {
	return fmt.Sprintf("Windows lab %s\nprofile   %s\nhost      %s\ncomputer  %s (%s %s)\nroot      %s\nbuild     remote=%t %s local=%t\nrun       x64=%t x86=%t sliver=%t debug=%t snapshots=%t\nreports   %s\n", strings.ToUpper(report.Status), report.Profile, report.Host, report.ComputerName, report.System.WindowsVersion, report.System.Architecture, report.RemoteRoot, report.Capabilities.Compile, report.Capabilities.Compiler, report.LoaderReady, report.Capabilities.NativeX64, report.Capabilities.NativeX86, report.Capabilities.Sliver, report.Capabilities.Debugging, report.Capabilities.SnapshotSupport, report.EvidencePath)
}

func RemoteSyncText(report RemoteSyncReport) string {
	return fmt.Sprintf("Windows lab sync %s\nproject   %s\nremote    %s:%s\nsource    files=%d bytes=%d sha256=%s\nreports   %s\n", strings.ToUpper(report.Status), report.Project, report.Host, report.RemoteProject, report.SourceTree.Files, report.SourceTree.Bytes, report.SourceTree.SHA256, report.EvidencePath)
}

func RemoteRunText(report RemoteRunReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Windows lab run %s\n", strings.ToUpper(report.Status))
	fmt.Fprintf(&b, "profile   %s\nproject   %s\nremote    %s:%s\nbuild     %s\n", report.LabProfile, report.Project, report.Host, report.RemoteProject, report.BuildMode)
	if report.RemoteDev != nil {
		fmt.Fprintf(&b, "dev       %s runtime=%s run=%s\n", report.RemoteDev.Status, report.RemoteDev.RuntimeState, report.RemoteDev.RunID)
		if report.RemoteDev.Run != nil {
			for _, line := range conciseObservedLines(report.RemoteDev.Run.Output, 12) {
				fmt.Fprintf(&b, "observed  %s\n", line)
			}
		}
	}
	if report.RemoteResult != nil {
		for _, line := range conciseObservedLines(report.RemoteResult.Output, 12) {
			fmt.Fprintf(&b, "observed  %s\n", line)
		}
	}
	fmt.Fprintf(&b, "evidence  %d file(s)\n", len(report.Collected))
	for _, file := range report.Collected {
		fmt.Fprintf(&b, "          %s\n", file.LocalPath)
	}
	if report.Error != "" {
		fmt.Fprintf(&b, "error     %s\n", report.Error)
	}
	fmt.Fprintf(&b, "reports   %s\n", report.EvidencePath)
	return b.String()
}

func conciseObservedLines(lines []string, limit int) []string {
	result := make([]string, 0, limit)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, line)
		if len(result) == limit {
			break
		}
	}
	return result
}

func RemoteRunMarkdown(report RemoteRunReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Windows Lab Run: %s\n\n- Host: `%s`\n- Project: `%s`\n- Remote project: `%s`\n- Compiler/runtime: `%s` / `%s`\n", strings.ToUpper(report.Status), report.Host, report.Project, report.RemoteProject, report.Compiler, report.Runtime)
	if report.RemoteDev != nil {
		fmt.Fprintf(&b, "- Remote dev: `%s`; runtime `%s`; run `%s`\n", report.RemoteDev.Status, report.RemoteDev.RuntimeState, report.RemoteDev.RunID)
	}
	if report.Error != "" {
		fmt.Fprintf(&b, "\n## Error\n\n%s\n", report.Error)
	}
	if len(report.Collected) > 0 {
		b.WriteString("\n## Collected Evidence\n\n| Remote | Local | SHA-256 |\n| --- | --- | --- |\n")
		for _, file := range report.Collected {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` |\n", file.RemotePath, file.LocalPath, file.SHA256)
		}
	}
	return b.String()
}

func RemoteCollectText(report RemoteCollectReport) string {
	return fmt.Sprintf("Windows lab collect %s\nrun       %s\nremote    %s\nlocal     %s\nsource    files=%d bytes=%d sha256=%s\nreports   %s\n", strings.ToUpper(report.Status), report.RemoteRunID, report.Host, report.LocalPath, report.Fingerprint.Files, report.Fingerprint.Bytes, report.Fingerprint.SHA256, report.EvidencePath)
}

func RemoteResetText(report RemoteResetReport) string {
	return fmt.Sprintf("Windows lab reset %s\nhost      %s\nscope     %s\nremoved   %s\nreports   %s\n", strings.ToUpper(report.Status), report.Host, report.Scope, strings.Join(report.Removed, ", "), report.EvidencePath)
}

func syncRemoteProject(ctx context.Context, project string, opts RemoteOptions, runID string) (string, evidence.TreeFingerprint, []TransportEvent, error) {
	info, err := os.Stat(project)
	if err != nil {
		return "", evidence.TreeFingerprint{}, nil, err
	}
	if !info.IsDir() {
		return "", evidence.TreeFingerprint{}, nil, fmt.Errorf("lab sync requires a BOF project directory, got %s", project)
	}
	if err := validateSyncTree(project); err != nil {
		return "", evidence.TreeFingerprint{}, nil, err
	}
	fingerprint, err := evidence.FingerprintTree(project)
	if err != nil {
		return "", evidence.TreeFingerprint{}, nil, err
	}
	name := remoteSafeName(project)
	if !safeRemoteName.MatchString(name) {
		return "", evidence.TreeFingerprint{}, nil, fmt.Errorf("project name %q is not portable", name)
	}
	stamp := time.Now().UTC().Format("20060102-150405.000000000")
	projectsRoot := windowsJoin(opts.RemoteRoot, "work", "projects")
	syncRoot := windowsJoin(opts.RemoteRoot, "work", "sync")
	if opts.ProfileName != "" {
		profileSegment := remoteProfileSegment(opts.ProfileName)
		projectsRoot = windowsJoin(projectsRoot, profileSegment)
		syncRoot = windowsJoin(syncRoot, profileSegment)
	}
	if runID != "" {
		if !safeRemoteName.MatchString(runID) {
			return "", evidence.TreeFingerprint{}, nil, fmt.Errorf("run id %q is not portable", runID)
		}
		projectsRoot = windowsJoin(projectsRoot, runID)
		syncRoot = windowsJoin(syncRoot, runID)
	}
	stagingParent := windowsJoin(syncRoot, stamp+"-"+name)
	stagedProject := windowsJoin(stagingParent, filepath.Base(filepath.Clean(project)))
	remoteProject := windowsJoin(projectsRoot, name)
	backupProject := remoteProject + ".previous-" + stamp
	var events []TransportEvent
	eventStart := time.Now()
	_, stderr, err := remoteExecute(ctx, opts, fmt.Sprintf(`New-Item -ItemType Directory -Force -Path %s | Out-Null`, powerShellQuote(stagingParent)))
	events = append(events, transportEvent(opts.Transport+"-prepare", eventStart, err, string(stderr)))
	if err != nil {
		return remoteProject, fingerprint, events, err
	}
	eventStart = time.Now()
	_, stderr, err = remoteUploadDirectory(ctx, opts, project, stagedProject)
	events = append(events, transportEvent(opts.Transport+"-project", eventStart, err, string(stderr)))
	if err != nil {
		return remoteProject, fingerprint, events, err
	}
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force -Path %s | Out-Null; if(Test-Path %s){Remove-Item -LiteralPath %s -Recurse -Force}; if(Test-Path %s){Move-Item -LiteralPath %s -Destination %s}; try { Move-Item -LiteralPath %s -Destination %s; if(Test-Path %s){Remove-Item -LiteralPath %s -Recurse -Force} } catch { if(Test-Path %s){Remove-Item -LiteralPath %s -Recurse -Force}; if(Test-Path %s){Move-Item -LiteralPath %s -Destination %s}; throw }; Remove-Item -LiteralPath %s -Recurse -Force -ErrorAction SilentlyContinue`,
		powerShellQuote(projectsRoot),
		powerShellQuote(backupProject), powerShellQuote(backupProject),
		powerShellQuote(remoteProject), powerShellQuote(remoteProject), powerShellQuote(backupProject),
		powerShellQuote(stagedProject), powerShellQuote(remoteProject),
		powerShellQuote(backupProject), powerShellQuote(backupProject),
		powerShellQuote(remoteProject), powerShellQuote(remoteProject),
		powerShellQuote(backupProject), powerShellQuote(backupProject), powerShellQuote(remoteProject),
		powerShellQuote(stagingParent))
	eventStart = time.Now()
	_, stderr, err = remoteExecute(ctx, opts, script)
	events = append(events, transportEvent(opts.Transport+"-activate", eventStart, err, string(stderr)))
	return remoteProject, fingerprint, events, err
}

func remoteProfileSegment(name string) string {
	if strings.TrimSpace(name) == "" {
		return "default"
	}
	return remoteSafeName(name)
}

func validateSyncTree(root string) error {
	const maxFiles = 2048
	const maxBytes = int64(128 << 20)
	files := 0
	var bytes int64
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("lab sync rejects symlink %s", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("lab sync rejects special file %s", path)
		}
		files++
		bytes += info.Size()
		if files > maxFiles {
			return fmt.Errorf("lab sync exceeds %d files", maxFiles)
		}
		if bytes > maxBytes {
			return fmt.Errorf("lab sync exceeds %d bytes", maxBytes)
		}
		return nil
	})
}

func collectDevEvidence(ctx context.Context, runDir string, dev RemoteDevReport, opts RemoteOptions) ([]CollectedFile, []TransportEvent, error) {
	paths := []struct {
		Label string
		Path  string
	}{
		{"dev.json", dev.EvidencePath}, {"dev.md", dev.MarkdownPath},
		{"source.json", dev.SourceJSONPath}, {"source.md", dev.SourceMDPath},
		{"analysis.json", dev.AnalysisJSONPath}, {"analysis.md", dev.AnalysisMDPath},
		{"build.json", dev.Build.EvidencePath}, {"build.log", dev.Build.LogPath}, {"payload.o", dev.Build.Object},
	}
	destination := filepath.Join(runDir, "remote-evidence")
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return nil, nil, err
	}
	var collected []CollectedFile
	var events []TransportEvent
	for _, item := range paths {
		if strings.TrimSpace(item.Path) == "" {
			continue
		}
		if err := validateRemoteRelativePath(item.Path); err != nil {
			return collected, events, err
		}
		localPath := filepath.Join(destination, item.Label)
		remotePath := windowsJoin(opts.RemoteRoot, item.Path)
		eventStart := time.Now()
		_, stderr, err := remoteDownloadFile(ctx, opts, remotePath, localPath)
		events = append(events, transportEvent(opts.Transport+"-"+item.Label, eventStart, err, string(stderr)))
		if err != nil {
			return collected, events, err
		}
		fingerprint, err := evidence.FingerprintFile(localPath)
		if err != nil {
			return collected, events, err
		}
		collected = append(collected, CollectedFile{RemotePath: item.Path, LocalPath: localPath, Size: fingerprint.Size, SHA256: fingerprint.SHA256})
	}
	return collected, events, nil
}

func normalizeRemoteOptions(opts RemoteOptions) (RemoteOptions, error) {
	defaults := DefaultRemoteOptions()
	if opts.Transport == "" {
		opts.Transport = defaults.Transport
	}
	if opts.RemoteRoot == "" {
		opts.RemoteRoot = defaults.RemoteRoot
	}
	if opts.Executable == "" {
		opts.Executable = windowsJoin(opts.RemoteRoot, "work", "bin", "bofbench.exe")
	}
	if opts.SSH == "" {
		opts.SSH = defaults.SSH
	}
	if opts.SCP == "" {
		opts.SCP = defaults.SCP
	}
	if opts.Port == 0 {
		if opts.Transport == "winrm" {
			if opts.WinRMHTTPS {
				opts.Port = 5986
			} else {
				opts.Port = 5985
			}
		} else {
			opts.Port = 22
		}
	}
	if opts.Transport != "ssh" && opts.Transport != "winrm" {
		return RemoteOptions{}, fmt.Errorf("remote transport must be ssh or winrm")
	}
	if strings.TrimSpace(opts.Host) == "" {
		return RemoteOptions{}, fmt.Errorf("remote host is required; select a configured lab profile")
	}
	if strings.HasPrefix(opts.Host, "-") || strings.ContainsAny(opts.Host, " \t\r\n;$`|&<>") {
		return RemoteOptions{}, fmt.Errorf("invalid remote host %q", opts.Host)
	}
	if strings.ContainsAny(opts.User, " \t\r\n;$`|&<>") {
		return RemoteOptions{}, fmt.Errorf("invalid remote user %q", opts.User)
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return RemoteOptions{}, fmt.Errorf("remote port must be between 1 and 65535")
	}
	if !looksWindowsPath(opts.RemoteRoot) || !looksWindowsPath(opts.Executable) {
		return RemoteOptions{}, fmt.Errorf("remote root and executable must be Windows paths")
	}
	return opts, nil
}

func doctorStatus(raw json.RawMessage, loaderReady bool) string {
	if !loaderReady {
		return "fail"
	}
	var report struct {
		Checks []struct {
			Status string `json:"status"`
		} `json:"checks"`
	}
	if json.Unmarshal(raw, &report) != nil || len(report.Checks) == 0 {
		return "fail"
	}
	status := "pass"
	for _, check := range report.Checks {
		if check.Status == "fail" {
			return "fail"
		}
		if check.Status == "warn" {
			status = "pass_with_warnings"
		}
	}
	return status
}

func validateRemoteRelativePath(path string) error {
	path = strings.ReplaceAll(path, `\`, "/")
	if strings.HasPrefix(path, "/") || (len(path) >= 2 && path[1] == ':') {
		return fmt.Errorf("remote evidence path must be relative: %s", path)
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." || part == "" {
			return fmt.Errorf("unsafe remote evidence path: %s", path)
		}
	}
	return nil
}

func windowsJoin(root string, parts ...string) string {
	root = strings.TrimRight(strings.ReplaceAll(root, "/", `\`), `\`)
	for _, part := range parts {
		part = strings.Trim(strings.ReplaceAll(part, "/", `\`), `\`)
		if part != "" {
			root += `\` + part
		}
	}
	return root
}

func powerShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func remoteSpec(host, path string) string {
	return host + ":" + strings.ReplaceAll(path, `\`, "/")
}

func remoteSafeName(path string) string {
	name := strings.TrimSuffix(filepath.Base(filepath.Clean(path)), filepath.Ext(path))
	name = strings.ToLower(name)
	name = strings.NewReplacer(" ", "-", "_", "-", ".", "-").Replace(name)
	if name == "" {
		return "project"
	}
	return name
}

func runTransport(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func transportEvent(kind string, start time.Time, err error, detail string) TransportEvent {
	status := "pass"
	message := ""
	if err != nil {
		status = "fail"
		message = err.Error()
	}
	return TransportEvent{Type: kind, Status: status, DurationMS: time.Since(start).Milliseconds(), Detail: boundedText(detail, 2048), Error: message}
}

func boundedText(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

func writeRemoteJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func finishRemoteStatus(report *RemoteStatusReport, start time.Time) {
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.DurationMS = time.Since(start).Milliseconds()
}

func finishRemoteSync(report *RemoteSyncReport, start time.Time) {
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.DurationMS = time.Since(start).Milliseconds()
}

func finishRemoteRun(report *RemoteRunReport, start time.Time) {
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.DurationMS = time.Since(start).Milliseconds()
}

func finishRemoteCollect(report *RemoteCollectReport, start time.Time) {
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.DurationMS = time.Since(start).Milliseconds()
}

func finishRemoteReset(report *RemoteResetReport, start time.Time) {
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.DurationMS = time.Since(start).Milliseconds()
}

func emptyRemote(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func yesNoRemote(value bool) string {
	if value {
		return "ready"
	}
	return "missing"
}

func SortedCollectedPaths(files []CollectedFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.LocalPath)
	}
	sort.Strings(paths)
	return paths
}
