package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"bofbench/internal/evidence"
	"bofbench/internal/runlog"
)

type RemoteOptions struct {
	Host       string
	RemoteRoot string
	Executable string
	SSH        string
	SCP        string
}

type RemoteStatusReport struct {
	evidence.Header
	Operation      string          `json:"operation"`
	Status         string          `json:"status"`
	Host           string          `json:"host"`
	RemoteRoot     string          `json:"remote_root"`
	Executable     string          `json:"executable"`
	ComputerName   string          `json:"computer_name,omitempty"`
	PowerShell     string          `json:"powershell,omitempty"`
	LoaderReady    bool            `json:"loader_ready"`
	Version        json.RawMessage `json:"version,omitempty"`
	Doctor         json.RawMessage `json:"doctor,omitempty"`
	StartedAt      string          `json:"started_at"`
	CompletedAt    string          `json:"completed_at"`
	DurationMS     int64           `json:"duration_ms"`
	Error          string          `json:"error,omitempty"`
	TransportError string          `json:"transport_error,omitempty"`
	EvidencePath   string          `json:"evidence_path"`
}

type RemoteSyncReport struct {
	evidence.Header
	Operation       string                   `json:"operation"`
	Status          string                   `json:"status"`
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
	Compiler string
	Runtime  string
	Profile  string
	NoSync   bool
	Args     []string
}

type RemoteRunReport struct {
	evidence.Header
	Operation       string           `json:"operation"`
	Status          string           `json:"status"`
	Host            string           `json:"host"`
	RemoteRoot      string           `json:"remote_root"`
	Project         string           `json:"project"`
	RemoteProject   string           `json:"remote_project"`
	Compiler        string           `json:"compiler"`
	Runtime         string           `json:"runtime"`
	Profile         string           `json:"profile,omitempty"`
	Arguments       []string         `json:"arguments,omitempty"`
	StartedAt       string           `json:"started_at"`
	CompletedAt     string           `json:"completed_at"`
	DurationMS      int64            `json:"duration_ms"`
	RemoteDev       *RemoteDevReport `json:"remote_dev,omitempty"`
	RemoteStderr    string           `json:"remote_stderr,omitempty"`
	Collected       []CollectedFile  `json:"collected,omitempty"`
	TransportEvents []TransportEvent `json:"transport_events"`
	Error           string           `json:"error,omitempty"`
	EvidencePath    string           `json:"evidence_path"`
	MarkdownPath    string           `json:"markdown_path"`
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
	RuntimeState string `json:"runtime_state"`
	Error        string `json:"error,omitempty"`
}

type RemoteCollectReport struct {
	evidence.Header
	Operation       string                   `json:"operation"`
	Status          string                   `json:"status"`
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
	ComputerName string          `json:"computer_name"`
	PowerShell   string          `json:"powershell"`
	LoaderReady  bool            `json:"loader_ready"`
	Version      json.RawMessage `json:"version"`
	Doctor       json.RawMessage `json:"doctor"`
}

type transportFunc func(context.Context, string, ...string) ([]byte, []byte, error)

var executeRemoteTransport transportFunc = runTransport

var safeRemoteName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func DefaultRemoteOptions() RemoteOptions {
	host := strings.TrimSpace(os.Getenv("BOFBENCH_LAB_HOST"))
	if host == "" {
		host = "bofbench-winvm"
	}
	root := strings.TrimSpace(os.Getenv("BOFBENCH_LAB_ROOT"))
	if root == "" {
		root = `C:\bofbench`
	}
	executable := strings.TrimSpace(os.Getenv("BOFBENCH_LAB_EXE"))
	if executable == "" {
		executable = windowsJoin(root, "work", "bin", "bofbench.exe")
	}
	return RemoteOptions{Host: host, RemoteRoot: root, Executable: executable, SSH: "ssh", SCP: "scp"}
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
		Host: opts.Host, RemoteRoot: opts.RemoteRoot, Executable: opts.Executable, StartedAt: start.UTC().Format(time.RFC3339Nano),
		EvidencePath: filepath.Join(runDir, "status.json"),
	}
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; Set-Location %s; $version=(& %s version --format json | ConvertFrom-Json); $doctor=(& %s doctor --format json | ConvertFrom-Json); [ordered]@{computer_name=$env:COMPUTERNAME; powershell=$PSVersionTable.PSVersion.ToString(); loader_ready=(Test-Path %s); version=$version; doctor=$doctor} | ConvertTo-Json -Depth 12 -Compress`,
		powerShellQuote(opts.RemoteRoot), powerShellQuote(opts.Executable), powerShellQuote(opts.Executable), powerShellQuote(windowsJoin(opts.RemoteRoot, "native", "loader", "bofbench-loader.exe")))
	stdout, stderr, runErr := executeRemoteTransport(ctx, opts.SSH, opts.Host, script)
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
			report.Version = payload.Version
			report.Doctor = payload.Doctor
			report.Status = doctorStatus(payload.Doctor, payload.LoaderReady)
			if report.Status == "fail" {
				runErr = errors.New("remote lab doctor has failing checks or the native loader is missing")
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
		Host: opts.Host, RemoteRoot: opts.RemoteRoot, Project: project, StartedAt: start.UTC().Format(time.RFC3339Nano),
		EvidencePath: filepath.Join(runDir, "sync.json"),
	}
	remoteProject, fingerprint, events, syncErr := syncRemoteProject(ctx, project, opts)
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
	if opts.Compiler == "" {
		opts.Compiler = "msvc"
	}
	if opts.Runtime == "" {
		opts.Runtime = "windows-coff"
	}
	runDir, err := runlog.NewDir("lab-run-" + remoteSafeName(project))
	if err != nil {
		return RemoteRunReport{}, err
	}
	report := RemoteRunReport{
		Header: evidence.New(evidence.SchemaLabRemoteRun, runlog.ID(runDir), ""), Operation: "run", Status: "fail",
		Host: opts.Host, RemoteRoot: opts.RemoteRoot, Project: project, Compiler: opts.Compiler, Runtime: opts.Runtime, Profile: opts.Profile, Arguments: append([]string(nil), opts.Args...),
		StartedAt: start.UTC().Format(time.RFC3339Nano), EvidencePath: filepath.Join(runDir, "lab-run.json"), MarkdownPath: filepath.Join(runDir, "lab-run.md"),
	}
	var runErr error
	if opts.NoSync {
		report.RemoteProject = windowsJoin(opts.RemoteRoot, "work", "projects", remoteSafeName(project))
	} else {
		remoteProject, _, events, syncErr := syncRemoteProject(ctx, project, opts.RemoteOptions)
		report.RemoteProject = remoteProject
		report.TransportEvents = append(report.TransportEvents, events...)
		if syncErr != nil {
			runErr = syncErr
			report.Error = syncErr.Error()
		}
	}
	if runErr == nil {
		args := []string{"dev", report.RemoteProject, "--compiler", opts.Compiler, "--runtime", opts.Runtime, "--format", "json"}
		if opts.Profile != "" {
			args = append(args, "--profile", opts.Profile)
		}
		for _, token := range opts.Args {
			args = append(args, "--arg-token", token)
		}
		quotedArgs := make([]string, 0, len(args))
		for _, arg := range args {
			quotedArgs = append(quotedArgs, powerShellQuote(arg))
		}
		script := fmt.Sprintf(`$ErrorActionPreference='Continue'; Set-Location %s; & %s %s`, powerShellQuote(opts.RemoteRoot), powerShellQuote(opts.Executable), strings.Join(quotedArgs, " "))
		eventStart := time.Now()
		stdout, stderr, devErr := executeRemoteTransport(ctx, opts.SSH, opts.Host, script)
		report.TransportEvents = append(report.TransportEvents, transportEvent("ssh-dev", eventStart, devErr, string(stderr)))
		report.RemoteStderr = boundedText(string(stderr), 8192)
		var remoteDev RemoteDevReport
		if decodeErr := json.Unmarshal(stdout, &remoteDev); decodeErr != nil {
			runErr = fmt.Errorf("decode remote dev report: %w", decodeErr)
		} else {
			report.RemoteDev = &remoteDev
			collected, events, collectErr := collectDevEvidence(ctx, runDir, remoteDev, opts.RemoteOptions)
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
	if persistErr := writeRemoteJSON(report.EvidencePath, report); persistErr != nil && runErr == nil {
		runErr = persistErr
	}
	if persistErr := os.WriteFile(report.MarkdownPath, []byte(RemoteRunMarkdown(report)), 0o644); persistErr != nil && runErr == nil {
		runErr = persistErr
	}
	return report, runErr
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
		Host: opts.Host, RemoteRoot: opts.RemoteRoot, RemoteRunID: remoteRunID, LocalPath: localPath,
		StartedAt: start.UTC().Format(time.RFC3339Nano), EvidencePath: filepath.Join(runDir, "collect.json"),
	}
	remotePath := windowsJoin(opts.RemoteRoot, "runs", remoteRunID)
	eventStart := time.Now()
	_, stderr, collectErr := executeRemoteTransport(ctx, opts.SCP, "-r", remoteSpec(opts.Host, remotePath), localPath)
	report.TransportEvents = append(report.TransportEvents, transportEvent("scp-run", eventStart, collectErr, string(stderr)))
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
	paths := []string{windowsJoin(opts.RemoteRoot, "work", "projects"), windowsJoin(opts.RemoteRoot, "work", "sync")}
	switch scope {
	case "managed":
	case "artifacts":
		paths = append(paths, windowsJoin(opts.RemoteRoot, "dist"), windowsJoin(opts.RemoteRoot, "stage"))
	case "runs":
		paths = append(paths, windowsJoin(opts.RemoteRoot, "dist"), windowsJoin(opts.RemoteRoot, "stage"), windowsJoin(opts.RemoteRoot, "runs"))
	default:
		return RemoteResetReport{}, fmt.Errorf("reset scope must be managed, artifacts, or runs")
	}
	runDir, err := runlog.NewDir("lab-reset-" + scope)
	if err != nil {
		return RemoteResetReport{}, err
	}
	report := RemoteResetReport{
		Header: evidence.New(evidence.SchemaLabRemoteReset, runlog.ID(runDir), ""), Operation: "reset", Status: "fail",
		Host: opts.Host, RemoteRoot: opts.RemoteRoot, Scope: scope, Removed: paths, StartedAt: start.UTC().Format(time.RFC3339Nano),
		EvidencePath: filepath.Join(runDir, "reset.json"),
	}
	var statements []string
	for _, path := range paths {
		statements = append(statements, fmt.Sprintf(`if(Test-Path %s){Remove-Item -LiteralPath %s -Recurse -Force}`, powerShellQuote(path), powerShellQuote(path)))
	}
	statements = append(statements, fmt.Sprintf(`New-Item -ItemType Directory -Force -Path %s,%s | Out-Null`, powerShellQuote(windowsJoin(opts.RemoteRoot, "work", "projects")), powerShellQuote(windowsJoin(opts.RemoteRoot, "work", "sync"))))
	eventStart := time.Now()
	_, stderr, resetErr := executeRemoteTransport(ctx, opts.SSH, opts.Host, strings.Join(statements, "; "))
	report.TransportEvents = append(report.TransportEvents, transportEvent("ssh-reset", eventStart, resetErr, string(stderr)))
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
	return fmt.Sprintf("Windows lab %s\nhost      %s\ncomputer  %s\nroot      %s\nloader    %s\nreports   %s\n", strings.ToUpper(report.Status), report.Host, report.ComputerName, report.RemoteRoot, yesNoRemote(report.LoaderReady), report.EvidencePath)
}

func RemoteSyncText(report RemoteSyncReport) string {
	return fmt.Sprintf("Windows lab sync %s\nproject   %s\nremote    %s:%s\nsource    files=%d bytes=%d sha256=%s\nreports   %s\n", strings.ToUpper(report.Status), report.Project, report.Host, report.RemoteProject, report.SourceTree.Files, report.SourceTree.Bytes, report.SourceTree.SHA256, report.EvidencePath)
}

func RemoteRunText(report RemoteRunReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Windows lab run %s\n", strings.ToUpper(report.Status))
	fmt.Fprintf(&b, "project   %s\nremote    %s:%s\n", report.Project, report.Host, report.RemoteProject)
	if report.RemoteDev != nil {
		fmt.Fprintf(&b, "dev       %s runtime=%s run=%s\n", report.RemoteDev.Status, report.RemoteDev.RuntimeState, report.RemoteDev.RunID)
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

func syncRemoteProject(ctx context.Context, project string, opts RemoteOptions) (string, evidence.TreeFingerprint, []TransportEvent, error) {
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
	stagingParent := windowsJoin(opts.RemoteRoot, "work", "sync", stamp+"-"+name)
	stagedProject := windowsJoin(stagingParent, filepath.Base(filepath.Clean(project)))
	remoteProject := windowsJoin(opts.RemoteRoot, "work", "projects", name)
	backupProject := remoteProject + ".previous-" + stamp
	var events []TransportEvent
	eventStart := time.Now()
	_, stderr, err := executeRemoteTransport(ctx, opts.SSH, opts.Host, fmt.Sprintf(`New-Item -ItemType Directory -Force -Path %s | Out-Null`, powerShellQuote(stagingParent)))
	events = append(events, transportEvent("ssh-prepare", eventStart, err, string(stderr)))
	if err != nil {
		return remoteProject, fingerprint, events, err
	}
	eventStart = time.Now()
	_, stderr, err = executeRemoteTransport(ctx, opts.SCP, "-r", project, remoteSpec(opts.Host, stagingParent))
	events = append(events, transportEvent("scp-project", eventStart, err, string(stderr)))
	if err != nil {
		return remoteProject, fingerprint, events, err
	}
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force -Path %s | Out-Null; if(Test-Path %s){Remove-Item -LiteralPath %s -Recurse -Force}; if(Test-Path %s){Move-Item -LiteralPath %s -Destination %s}; try { Move-Item -LiteralPath %s -Destination %s; if(Test-Path %s){Remove-Item -LiteralPath %s -Recurse -Force} } catch { if(Test-Path %s){Remove-Item -LiteralPath %s -Recurse -Force}; if(Test-Path %s){Move-Item -LiteralPath %s -Destination %s}; throw }; Remove-Item -LiteralPath %s -Recurse -Force -ErrorAction SilentlyContinue`,
		powerShellQuote(windowsJoin(opts.RemoteRoot, "work", "projects")),
		powerShellQuote(backupProject), powerShellQuote(backupProject),
		powerShellQuote(remoteProject), powerShellQuote(remoteProject), powerShellQuote(backupProject),
		powerShellQuote(stagedProject), powerShellQuote(remoteProject),
		powerShellQuote(backupProject), powerShellQuote(backupProject),
		powerShellQuote(remoteProject), powerShellQuote(remoteProject),
		powerShellQuote(backupProject), powerShellQuote(backupProject), powerShellQuote(remoteProject),
		powerShellQuote(stagingParent))
	eventStart = time.Now()
	_, stderr, err = executeRemoteTransport(ctx, opts.SSH, opts.Host, script)
	events = append(events, transportEvent("ssh-activate", eventStart, err, string(stderr)))
	return remoteProject, fingerprint, events, err
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
		_, stderr, err := executeRemoteTransport(ctx, opts.SCP, remoteSpec(opts.Host, remotePath), localPath)
		events = append(events, transportEvent("scp-"+item.Label, eventStart, err, string(stderr)))
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
	if opts.Host == "" {
		opts.Host = defaults.Host
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
	if strings.HasPrefix(opts.Host, "-") || strings.ContainsAny(opts.Host, " \t\r\n;$`|&<>") {
		return RemoteOptions{}, fmt.Errorf("invalid SSH host %q", opts.Host)
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
