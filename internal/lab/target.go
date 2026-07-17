package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	TargetServiceName    = "BOFBenchTarget"
	TargetX86ServiceName = "BOFBenchTargetX86"
	TargetJobMemberTask  = "BOFBenchTargetJobMember"
)

type TargetState struct {
	Schema                string `json:"schema"`
	SchemaVersion         int    `json:"schema_version"`
	Service               string `json:"service"`
	PID                   int    `json:"pid"`
	Architecture          string `json:"architecture,omitempty"`
	KnownModuleBase       string `json:"known_module_base,omitempty"`
	KnownModulePath       string `json:"known_module_path,omitempty"`
	X86PID                int    `json:"x86_pid,omitempty"`
	X86AlertableTID       uint32 `json:"x86_alertable_tid,omitempty"`
	X86KnownModuleBase    string `json:"x86_known_module_base,omitempty"`
	X86KnownModulePath    string `json:"x86_known_module_path,omitempty"`
	AlertableTID          uint32 `json:"alertable_tid"`
	NamedPipe             string `json:"named_pipe,omitempty"`
	NamedPipeHandle       string `json:"named_pipe_handle,omitempty"`
	NamedPipeClientHandle string `json:"named_pipe_client_handle,omitempty"`
	NamedPipeSHA256       string `json:"named_pipe_sha256,omitempty"`
	ProcessPipePID        int    `json:"process_pipe_pid,omitempty"`
	ProcessStdinHandle    string `json:"process_stdin_handle,omitempty"`
	ProcessStdoutHandle   string `json:"process_stdout_handle,omitempty"`
	ProcessPipeSHA256     string `json:"process_pipe_sha256,omitempty"`
	KnownHandle           string `json:"known_handle,omitempty"`
	HolderPID             int    `json:"holder_pid,omitempty"`
	JobMemberPID          int    `json:"job_member_pid,omitempty"`
	EventName             string `json:"event_name,omitempty"`
	SectionName           string `json:"section_name,omitempty"`
	JobName               string `json:"job_name,omitempty"`
	MutexName             string `json:"mutex_name,omitempty"`
	SemaphoreName         string `json:"semaphore_name,omitempty"`
	TimerName             string `json:"timer_name,omitempty"`
	MailslotName          string `json:"mailslot_name,omitempty"`
	MailslotHandle        string `json:"mailslot_handle,omitempty"`
	MailslotSHA256        string `json:"mailslot_sha256,omitempty"`
	MailslotAccess        uint32 `json:"mailslot_access,omitempty"`
	ALPCPort              string `json:"alpc_port,omitempty"`
	ALPCHandle            string `json:"alpc_handle,omitempty"`
	WindowHandle          string `json:"window_handle,omitempty"`
	WindowTextHandle      string `json:"window_text_handle,omitempty"`
	WindowHelperPID       int    `json:"window_helper_pid,omitempty"`
	WindowStation         string `json:"window_station,omitempty"`
	WindowClass           string `json:"window_class,omitempty"`
	WindowMessage         uint32 `json:"window_message,omitempty"`
	WindowPostMessage     uint32 `json:"window_post_message,omitempty"`
	WatchRegistryHive     string `json:"watch_registry_hive,omitempty"`
	WatchRegistryPath     string `json:"watch_registry_path,omitempty"`
	WatchRegistryValue    string `json:"watch_registry_value,omitempty"`
	WatchDirectory        string `json:"watch_directory,omitempty"`
	WatchService          string `json:"watch_service,omitempty"`
	ExitPID               int    `json:"exit_pid,omitempty"`
	EventLogChannel       string `json:"event_log_channel,omitempty"`
	EventLogProvider      string `json:"event_log_provider,omitempty"`
	ETWProviderGUID       string `json:"etw_provider_guid,omitempty"`
	ETWSessionName        string `json:"etw_session_name,omitempty"`
	TCPHost               string `json:"tcp_host,omitempty"`
	TCPPort               int    `json:"tcp_port,omitempty"`
	UDPHost               string `json:"udp_host,omitempty"`
	UDPPort               int    `json:"udp_port,omitempty"`
	HTTPURL               string `json:"http_url,omitempty"`
	HTTPBlobURL           string `json:"http_blob_url,omitempty"`
	HTTPTransientURL      string `json:"http_transient_url,omitempty"`
	HTTPSURL              string `json:"https_url,omitempty"`
	HTTPSBlobURL          string `json:"https_blob_url,omitempty"`
	HTTPSAuthURL          string `json:"https_auth_url,omitempty"`
	HTTPAuthUser          string `json:"http_auth_user,omitempty"`
	TLSCertificateSHA256  string `json:"tls_certificate_sha256,omitempty"`
	WebSocketURL          string `json:"websocket_url,omitempty"`
	DNSName               string `json:"dns_name,omitempty"`
	NetworkPayloadSHA256  string `json:"network_payload_sha256,omitempty"`
	User                  string `json:"user"`
	CanaryFile            string `json:"canary_file"`
	CanaryFileSHA256      string `json:"canary_file_sha256,omitempty"`
	MemoryCanaryAddress   string `json:"memory_canary_address,omitempty"`
	MemoryCanarySize      int    `json:"memory_canary_size,omitempty"`
	MemoryCanarySHA256    string `json:"memory_canary_sha256,omitempty"`
	ExecutionAddress      string `json:"execution_address,omitempty"`
	MemoryWriteAddress    string `json:"memory_write_address,omitempty"`
	MemoryWriteSize       int    `json:"memory_write_size,omitempty"`
	MemoryWriteSHA256     string `json:"memory_write_sha256,omitempty"`
	MemoryProtectAddress  string `json:"memory_protection_address,omitempty"`
	MemoryProtectSize     int    `json:"memory_protection_size,omitempty"`
	MemoryProtection      string `json:"memory_protection,omitempty"`
	FixtureError          string `json:"fixture_error,omitempty"`
	StartedAt             string `json:"started_at"`
}

type TargetFixtureState struct {
	Schema                string `json:"schema"`
	SchemaVersion         int    `json:"schema_version"`
	User                  string `json:"user"`
	CredentialTarget      string `json:"credential_target"`
	CredentialSHA256      string `json:"credential_sha256"`
	CredentialSize        int    `json:"credential_size"`
	DPAPIUserPath         string `json:"dpapi_user_path"`
	DPAPIUserSHA256       string `json:"dpapi_user_sha256"`
	DPAPIMachinePath      string `json:"dpapi_machine_path"`
	DPAPIMachineSHA256    string `json:"dpapi_machine_sha256"`
	WMIMarkerPath         string `json:"wmi_marker_path"`
	VaultGUID             string `json:"vault_guid,omitempty"`
	VaultResource         string `json:"vault_resource,omitempty"`
	VaultIdentity         string `json:"vault_identity,omitempty"`
	VaultSHA256           string `json:"vault_sha256,omitempty"`
	VaultSize             int    `json:"vault_size,omitempty"`
	CertificateStore      string `json:"certificate_store,omitempty"`
	CertificateSubject    string `json:"certificate_subject,omitempty"`
	CertificateThumbprint string `json:"certificate_thumbprint,omitempty"`
	RemoteRegistryHive    string `json:"remote_registry_hive,omitempty"`
	RemoteRegistryPath    string `json:"remote_registry_path,omitempty"`
	RemoteRegistryName    string `json:"remote_registry_name,omitempty"`
	RemoteRegistrySHA256  string `json:"remote_registry_sha256,omitempty"`
	RemoteRegistrySize    int    `json:"remote_registry_size,omitempty"`
	RemoteRegistryStatus  string `json:"remote_registry_previous_status,omitempty"`
	RemoteRegistryStart   string `json:"remote_registry_previous_start_type,omitempty"`
	RemoteRegistryKeyMade bool   `json:"remote_registry_key_created,omitempty"`
	RemoteComputerName    string `json:"remote_computer_name,omitempty"`
	RemoteStageShare      string `json:"remote_stage_share,omitempty"`
	RemoteStageRelative   string `json:"remote_stage_relative_root,omitempty"`
	RemoteStageLocal      string `json:"remote_stage_local_root,omitempty"`
	CreatedAt             string `json:"created_at"`
}

type TargetReport struct {
	Operation     string             `json:"operation"`
	Status        string             `json:"status"`
	Profile       string             `json:"profile"`
	Host          string             `json:"host"`
	Service       string             `json:"service"`
	ServiceBinary string             `json:"service_binary,omitempty"`
	State         TargetState        `json:"state,omitempty"`
	Fixtures      TargetFixtureState `json:"fixtures,omitempty"`
	Error         string             `json:"error,omitempty"`
}

func DeployTarget(ctx context.Context, name string, profile Profile, repository string) (TargetReport, error) {
	profile = NormalizeProfile(profile)
	opts, resolveErr := ResolveRemoteOptions(ctx, name, profile)
	report := TargetReport{Operation: "deploy", Status: "fail", Profile: name, Host: opts.Host, Service: TargetServiceName}
	if resolveErr != nil {
		return report, resolveErr
	}
	if repository == "" {
		var err error
		repository, err = os.Getwd()
		if err != nil {
			return report, err
		}
	}
	directory, err := os.MkdirTemp("", "bofbench-target-*")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(directory)
	executable := filepath.Join(directory, "bofbench-target.exe")
	x86Executable := filepath.Join(directory, "bofbench-target-x86.exe")
	serviceFixture := filepath.Join(directory, "bofbench-service-fixture.exe")
	for outputPath, source := range map[string]string{executable: "./cmd/bofbench-target", serviceFixture: "./cmd/bofbench-service-fixture"} {
		build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", outputPath, source)
		build.Dir = repository
		build.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
		if output, err := build.CombinedOutput(); err != nil {
			return report, fmt.Errorf("build disposable Windows target %s: %w: %s", source, err, strings.TrimSpace(string(output)))
		}
	}
	x86Build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", x86Executable, "./cmd/bofbench-target")
	x86Build.Dir = repository
	x86Build.Env = append(os.Environ(), "GOOS=windows", "GOARCH=386", "CGO_ENABLED=0")
	if output, err := x86Build.CombinedOutput(); err != nil {
		return report, fmt.Errorf("build disposable Windows x86 target: %w: %s", err, strings.TrimSpace(string(output)))
	}
	remoteExecutable := windowsJoin(profile.RemoteRoot, "target", "bofbench-target.exe")
	remoteX86Executable := windowsJoin(profile.RemoteRoot, "target", "bofbench-target-x86.exe")
	remoteServiceFixture := windowsJoin(profile.RemoteRoot, "target", "bofbench-service-fixture.exe")
	targetDirectory := windowsJoin(profile.RemoteRoot, "target")
	report.ServiceBinary = remoteServiceFixture
	if _, stderr, err := remoteExecute(ctx, opts, targetCleanupScript(targetDirectory)); err != nil {
		return report, fmt.Errorf("clean prior disposable target: %w: %s", err, boundedText(string(stderr), 2048))
	}
	if _, stderr, err := remoteExecute(ctx, opts, fmt.Sprintf(`New-Item -ItemType Directory -Force -Path %s | Out-Null`, powerShellQuote(windowsDir(remoteExecutable)))); err != nil {
		return report, fmt.Errorf("prepare disposable target directory: %w: %s", err, boundedText(string(stderr), 2048))
	}
	if _, stderr, err := remoteUploadFile(ctx, opts, executable, remoteExecutable); err != nil {
		return report, fmt.Errorf("deploy disposable target: %w: %s", err, boundedText(string(stderr), 2048))
	}
	if _, stderr, err := remoteUploadFile(ctx, opts, x86Executable, remoteX86Executable); err != nil {
		return report, fmt.Errorf("deploy disposable x86 target: %w: %s", err, boundedText(string(stderr), 2048))
	}
	if _, stderr, err := remoteUploadFile(ctx, opts, serviceFixture, remoteServiceFixture); err != nil {
		return report, fmt.Errorf("deploy disposable service fixture: %w: %s", err, boundedText(string(stderr), 2048))
	}
	remoteFixtureOutput, remoteFixtureStderr, remoteFixtureErr := remoteExecute(ctx, opts, targetRemoteFixtureScript(targetDirectory))
	if remoteFixtureErr != nil {
		_, _, _ = remoteExecute(ctx, opts, targetCleanupScript(targetDirectory))
		return report, fmt.Errorf("prepare remote-operation fixtures: %w: %s", remoteFixtureErr, boundedText(string(remoteFixtureStderr), 2048))
	}
	var remoteFixtures TargetFixtureState
	if err := decodeTargetJSON(remoteFixtureOutput, &remoteFixtures); err != nil {
		_, _, _ = remoteExecute(ctx, opts, targetCleanupScript(targetDirectory))
		return report, fmt.Errorf("decode remote-operation fixtures: %w", err)
	}
	statePath := windowsJoin(profile.RemoteRoot, "target", "target.json")
	windowStatePath := windowsJoin(profile.RemoteRoot, "target", "window-helper.json")
	x86StatePath := windowsJoin(profile.RemoteRoot, "target", "x86", "x86-helper.json")
	x86Command := fmt.Sprintf(`"%s" --helper-service --service-name %s --root "%s"`, remoteX86Executable, TargetX86ServiceName, windowsDir(x86StatePath))
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force -Path %s|Out-Null; Unregister-ScheduledTask -TaskName 'BOFBenchWindowTarget' -Confirm:$false -ErrorAction SilentlyContinue; $windowAction=New-ScheduledTaskAction -Execute %s -Argument ('--window-helper --root "'+%s+'"'); $windowPrincipal=New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest; Register-ScheduledTask -TaskName 'BOFBenchWindowTarget' -Action $windowAction -Principal $windowPrincipal -Force|Out-Null; Start-ScheduledTask -TaskName 'BOFBenchWindowTarget'; $windowDeadline=(Get-Date).AddSeconds(15); do{Start-Sleep -Milliseconds 250}until((Test-Path %s)-or(Get-Date)-gt$windowDeadline); if(-not(Test-Path %s)){throw 'window helper state was not created'}; New-Service -Name %s -BinaryPathName %s -DisplayName 'BOFBench disposable x86 capability target' -StartupType Manual|Out-Null; Start-Service -Name %s; $x86deadline=(Get-Date).AddSeconds(15); do{Start-Sleep -Milliseconds 250}until((Test-Path %s)-or(Get-Date)-gt$x86deadline); if(-not(Test-Path %s)){throw 'x86 helper state was not created'}; New-Service -Name %s -BinaryPathName %s -DisplayName 'BOFBench disposable capability target' -StartupType Manual | Out-Null; Start-Service -Name %s; $deadline=(Get-Date).AddSeconds(15); do { Start-Sleep -Milliseconds 250 } until ((Test-Path %s) -or (Get-Date) -gt $deadline); if(-not (Test-Path %s)){throw 'target state file was not created'}; Get-Content -LiteralPath %s -Raw`, powerShellQuote(statePath), powerShellQuote(windowStatePath), powerShellQuote(windowsDir(x86StatePath)), powerShellQuote(remoteExecutable), powerShellQuote(targetDirectory), powerShellQuote(windowStatePath), powerShellQuote(windowStatePath), powerShellQuote(TargetX86ServiceName), powerShellQuote(x86Command), powerShellQuote(TargetX86ServiceName), powerShellQuote(x86StatePath), powerShellQuote(x86StatePath), powerShellQuote(TargetServiceName), powerShellQuote(remoteExecutable), powerShellQuote(TargetServiceName), powerShellQuote(statePath), powerShellQuote(statePath), powerShellQuote(statePath))
	stdout, stderr, err := remoteExecute(ctx, opts, script)
	if err != nil {
		report.Error = boundedText(string(stderr), 4096)
		startupErrorPath := windowsJoin(profile.RemoteRoot, "target", "startup-error.json")
		if diagnostic, _, diagnosticErr := remoteExecute(ctx, opts, fmt.Sprintf(`if(Test-Path -LiteralPath %s){Get-Content -LiteralPath %s -Raw}`, powerShellQuote(startupErrorPath), powerShellQuote(startupErrorPath))); diagnosticErr == nil && len(strings.TrimSpace(string(diagnostic))) > 0 {
			report.Error += "; startup=" + boundedText(strings.TrimSpace(string(diagnostic)), 2048)
		}
		_, _, _ = remoteExecute(ctx, opts, targetCleanupScript(targetDirectory))
		return report, fmt.Errorf("start disposable target: %w: %s", err, report.Error)
	}
	if err := decodeTargetJSON(stdout, &report.State); err != nil {
		return report, fmt.Errorf("decode disposable target state: %w", err)
	}
	jobStatePath := windowsJoin(profile.RemoteRoot, "target", "job-member.pid")
	jobArgument := fmt.Sprintf(`--job-child --job-state "%s"`, jobStatePath)
	jobMemberScript := fmt.Sprintf(`$ErrorActionPreference='Stop'; Unregister-ScheduledTask -TaskName %s -Confirm:$false -ErrorAction SilentlyContinue; Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue; $user=[Security.Principal.WindowsIdentity]::GetCurrent().Name; $action=New-ScheduledTaskAction -Execute %s -Argument %s; $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Highest; $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName %s -Action $action -Principal $principal -Settings $settings -Force|Out-Null; Start-ScheduledTask -TaskName %s; $deadline=(Get-Date).AddSeconds(15); do{Start-Sleep -Milliseconds 250}until((Test-Path -LiteralPath %s)-or(Get-Date)-gt$deadline); if(-not(Test-Path -LiteralPath %s)){throw 'job-member PID file was not created'}; $pidValue=[int](Get-Content -LiteralPath %s -Raw); $state=Get-Content -LiteralPath %s -Raw|ConvertFrom-Json; $state.job_member_pid=$pidValue; $state|ConvertTo-Json -Depth 8|Set-Content -LiteralPath %s -Encoding utf8; Write-Output $pidValue`, powerShellQuote(TargetJobMemberTask), powerShellQuote(jobStatePath), powerShellQuote(remoteExecutable), powerShellQuote(jobArgument), powerShellQuote(TargetJobMemberTask), powerShellQuote(TargetJobMemberTask), powerShellQuote(jobStatePath), powerShellQuote(jobStatePath), powerShellQuote(jobStatePath), powerShellQuote(statePath), powerShellQuote(statePath))
	jobMemberOutput, jobMemberStderr, jobMemberErr := remoteExecute(ctx, opts, jobMemberScript)
	if jobMemberErr != nil {
		_, _, _ = remoteExecute(ctx, opts, targetCleanupScript(targetDirectory))
		return report, fmt.Errorf("start scheduled disposable job member: %w: %s", jobMemberErr, boundedText(string(jobMemberStderr), 2048))
	}
	jobMemberPID, jobMemberParseErr := strconv.Atoi(strings.TrimSpace(string(jobMemberOutput)))
	if jobMemberParseErr != nil || jobMemberPID <= 0 {
		_, _, _ = remoteExecute(ctx, opts, targetCleanupScript(targetDirectory))
		return report, fmt.Errorf("decode scheduled disposable job member PID: %s", boundedText(string(jobMemberOutput), 256))
	}
	report.State.JobMemberPID = jobMemberPID
	if helperOutput, helperStderr, helperErr := remoteExecute(ctx, opts, fmt.Sprintf(`$ErrorActionPreference='Stop'; $service=Get-Service -Name %s -ErrorAction Stop; if($service.Status -ne 'Running'){throw 'x86 target service is not running'}; Get-Content -LiteralPath %s -Raw`, powerShellQuote(TargetX86ServiceName), powerShellQuote(x86StatePath))); helperErr == nil {
		var helper TargetState
		if err := decodeTargetJSON(helperOutput, &helper); err != nil {
			return report, err
		}
		report.State.X86PID, report.State.X86AlertableTID, report.State.X86KnownModuleBase, report.State.X86KnownModulePath = helper.PID, helper.AlertableTID, helper.KnownModuleBase, helper.KnownModulePath
	} else {
		return report, fmt.Errorf("read disposable x86 target: %w: %s", helperErr, boundedText(string(helperStderr), 2048))
	}
	fixturePath := windowsJoin(profile.RemoteRoot, "target", "fixtures", "fixture.json")
	fixtureOutput, fixtureStderr, fixtureErr := remoteExecute(ctx, opts, fmt.Sprintf(`$ErrorActionPreference='Stop'; Get-Content -LiteralPath %s -Raw`, powerShellQuote(fixturePath)))
	if fixtureErr == nil {
		if err := decodeTargetJSON(fixtureOutput, &report.Fixtures); err != nil {
			return report, fmt.Errorf("decode disposable target fixtures: %w", err)
		}
	} else if report.State.FixtureError == "" {
		return report, fmt.Errorf("read disposable target fixtures: %w: %s", fixtureErr, boundedText(string(fixtureStderr), 2048))
	}
	mergeRemoteFixtures(&report.Fixtures, remoteFixtures)
	report.Status = "pass"
	return report, nil
}

func TargetStatus(ctx context.Context, name string, profile Profile) (TargetReport, error) {
	profile = NormalizeProfile(profile)
	opts, resolveErr := ResolveRemoteOptions(ctx, name, profile)
	report := TargetReport{Operation: "status", Status: "fail", Profile: name, Host: opts.Host, Service: TargetServiceName}
	report.ServiceBinary = windowsJoin(profile.RemoteRoot, "target", "bofbench-service-fixture.exe")
	if resolveErr != nil {
		return report, resolveErr
	}
	statePath := windowsJoin(profile.RemoteRoot, "target", "target.json")
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; $service=Get-Service -Name %s -ErrorAction Stop; if($service.Status -ne 'Running'){throw 'target service is not running'}; Get-Content -LiteralPath %s -Raw`, powerShellQuote(TargetServiceName), powerShellQuote(statePath))
	stdout, stderr, err := remoteExecute(ctx, opts, script)
	if err != nil {
		report.Error = boundedText(string(stderr), 4096)
		return report, err
	}
	if err := decodeTargetJSON(stdout, &report.State); err != nil {
		return report, err
	}
	x86StatePath := windowsJoin(profile.RemoteRoot, "target", "x86", "x86-helper.json")
	if helperOutput, helperStderr, helperErr := remoteExecute(ctx, opts, fmt.Sprintf(`$ErrorActionPreference='Stop'; $service=Get-Service -Name %s -ErrorAction Stop; if($service.Status -ne 'Running'){throw 'x86 target service is not running'}; Get-Content -LiteralPath %s -Raw`, powerShellQuote(TargetX86ServiceName), powerShellQuote(x86StatePath))); helperErr == nil {
		var helper TargetState
		if err := decodeTargetJSON(helperOutput, &helper); err != nil {
			return report, err
		}
		report.State.X86PID, report.State.X86AlertableTID, report.State.X86KnownModuleBase, report.State.X86KnownModulePath = helper.PID, helper.AlertableTID, helper.KnownModuleBase, helper.KnownModulePath
	} else {
		return report, fmt.Errorf("read disposable x86 target: %w: %s", helperErr, boundedText(string(helperStderr), 2048))
	}
	fixturePath := windowsJoin(profile.RemoteRoot, "target", "fixtures", "fixture.json")
	fixtureOutput, fixtureStderr, fixtureErr := remoteExecute(ctx, opts, fmt.Sprintf(`$ErrorActionPreference='Stop'; Get-Content -LiteralPath %s -Raw`, powerShellQuote(fixturePath)))
	if fixtureErr == nil {
		if err := decodeTargetJSON(fixtureOutput, &report.Fixtures); err != nil {
			return report, fmt.Errorf("decode disposable target fixtures: %w", err)
		}
	} else if report.State.FixtureError == "" {
		report.Error = boundedText(string(fixtureStderr), 4096)
		return report, fmt.Errorf("read disposable target fixtures: %w: %s", fixtureErr, report.Error)
	}
	remoteFixturePath := windowsJoin(profile.RemoteRoot, "target", "remote-fixture.json")
	remoteFixtureOutput, remoteFixtureStderr, remoteFixtureErr := remoteExecute(ctx, opts, fmt.Sprintf(`$ErrorActionPreference='Stop'; Get-Content -LiteralPath %s -Raw`, powerShellQuote(remoteFixturePath)))
	if remoteFixtureErr != nil {
		return report, fmt.Errorf("read remote-operation fixtures: %w: %s", remoteFixtureErr, boundedText(string(remoteFixtureStderr), 2048))
	}
	var remoteFixtures TargetFixtureState
	if err := decodeTargetJSON(remoteFixtureOutput, &remoteFixtures); err != nil {
		return report, fmt.Errorf("decode remote-operation fixtures: %w", err)
	}
	mergeRemoteFixtures(&report.Fixtures, remoteFixtures)
	report.Status = "pass"
	return report, nil
}

func RemoveTarget(ctx context.Context, name string, profile Profile) (TargetReport, error) {
	profile = NormalizeProfile(profile)
	opts, resolveErr := ResolveRemoteOptions(ctx, name, profile)
	report := TargetReport{Operation: "remove", Status: "fail", Profile: name, Host: opts.Host, Service: TargetServiceName}
	if resolveErr != nil {
		return report, resolveErr
	}
	targetDirectory := windowsJoin(profile.RemoteRoot, "target")
	script := targetCleanupScript(targetDirectory)
	_, stderr, err := remoteExecute(ctx, opts, script)
	if err != nil {
		report.Error = boundedText(string(stderr), 4096)
		return report, err
	}
	report.Status = "pass"
	return report, nil
}

func targetRemoteFixtureScript(targetDirectory string) string {
	fixturePath := windowsJoin(targetDirectory, "remote-fixture.json")
	return fmt.Sprintf(`$ErrorActionPreference='Stop'; $service=Get-Service -Name 'RemoteRegistry' -ErrorAction Stop; $previousStatus=[string]$service.Status; $previousStart=[string]$service.StartType; if($service.StartType -eq 'Disabled'){Set-Service -Name 'RemoteRegistry' -StartupType Manual}; if((Get-Service -Name 'RemoteRegistry').Status -ne 'Running'){Start-Service -Name 'RemoteRegistry'}; $bytes=New-Object byte[] 48; $rng=[Security.Cryptography.RandomNumberGenerator]::Create(); try{$rng.GetBytes($bytes)}finally{$rng.Dispose()}; $sha=[BitConverter]::ToString(([Security.Cryptography.SHA256]::Create()).ComputeHash($bytes)).Replace('-','').ToLowerInvariant(); $registryPath='Software\BOFBench'; $registryProvider='HKLM:\'+$registryPath; $registryKeyCreated=-not (Test-Path -LiteralPath $registryProvider); New-Item -Path $registryProvider -Force | Out-Null; New-ItemProperty -Path $registryProvider -Name 'RemoteCanary' -PropertyType Binary -Value $bytes -Force | Out-Null; $stageLocal='C:\bofbench\proof'; New-Item -ItemType Directory -Path $stageLocal -Force | Out-Null; $record=[ordered]@{schema='bofbench.target-remote-fixtures';schema_version=1;remote_computer_name=$env:COMPUTERNAME;remote_registry_hive='HKLM';remote_registry_path=$registryPath;remote_registry_name='RemoteCanary';remote_registry_sha256=$sha;remote_registry_size=$bytes.Length;remote_registry_previous_status=$previousStatus;remote_registry_previous_start_type=$previousStart;remote_registry_key_created=$registryKeyCreated;remote_stage_share='C$';remote_stage_relative_root='bofbench\proof';remote_stage_local_root=$stageLocal;created_at=[DateTime]::UtcNow.ToString('o')}; $json=$record|ConvertTo-Json -Compress; [IO.File]::WriteAllText(%s,$json,(New-Object Text.UTF8Encoding($false))); Write-Output $json`, powerShellQuote(fixturePath))
}

func targetCleanupScript(targetDirectory string) string {
	fixturePath := windowsJoin(targetDirectory, "remote-fixture.json")
	statePath := windowsJoin(targetDirectory, "target.json")
	return fmt.Sprintf(`$ErrorActionPreference='Continue'; $fixture=$null; $targetState=$null; if(Test-Path -LiteralPath %s){try{$fixture=Get-Content -LiteralPath %s -Raw|ConvertFrom-Json}catch{}}; if(Test-Path -LiteralPath %s){try{$targetState=Get-Content -LiteralPath %s -Raw|ConvertFrom-Json}catch{}}; Stop-ScheduledTask -TaskName %s -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName %s -Confirm:$false -ErrorAction SilentlyContinue; Stop-ScheduledTask -TaskName 'BOFBenchWindowTarget' -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName 'BOFBenchWindowTarget' -Confirm:$false -ErrorAction SilentlyContinue; if($targetState -and [int]$targetState.job_member_pid -gt 0){Stop-Process -Id ([int]$targetState.job_member_pid) -Force -ErrorAction SilentlyContinue}; if($targetState -and [int]$targetState.window_helper_pid -gt 0){Stop-Process -Id ([int]$targetState.window_helper_pid) -Force -ErrorAction SilentlyContinue}; foreach($name in @(%s,%s)){$service=Get-Service -Name $name -ErrorAction SilentlyContinue; if($service -and $service.Status -ne 'Stopped'){Stop-Service -Name $name -Force -ErrorAction SilentlyContinue}; if($service){sc.exe delete $name|Out-Null}}; Start-Sleep -Milliseconds 500; if($fixture){$key='HKLM:\'+[string]$fixture.remote_registry_path; $keyItem=Get-Item -LiteralPath $key -ErrorAction SilentlyContinue; if($keyItem){foreach($valueName in @($keyItem.GetValueNames()|Where-Object{$_ -like 'BOFBench-Remote-*'})){Remove-ItemProperty -LiteralPath $key -Name $valueName -Force -ErrorAction SilentlyContinue}}; Remove-ItemProperty -LiteralPath $key -Name ([string]$fixture.remote_registry_name) -Force -ErrorAction SilentlyContinue; if([bool]$fixture.remote_registry_key_created){Remove-Item -LiteralPath $key -Force -ErrorAction SilentlyContinue}; Remove-Item -LiteralPath ([string]$fixture.remote_stage_local_root) -Recurse -Force -ErrorAction SilentlyContinue; $remote=Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue; if($remote){if($remote.Status -ne 'Stopped'){Stop-Service -Name 'RemoteRegistry' -Force -ErrorAction SilentlyContinue}; switch([string]$fixture.remote_registry_previous_start_type){'Automatic'{Set-Service -Name 'RemoteRegistry' -StartupType Automatic};'Manual'{Set-Service -Name 'RemoteRegistry' -StartupType Manual};'Disabled'{Set-Service -Name 'RemoteRegistry' -StartupType Disabled}}; if([string]$fixture.remote_registry_previous_status -eq 'Running'){Start-Service -Name 'RemoteRegistry'}else{Stop-Service -Name 'RemoteRegistry' -Force -ErrorAction SilentlyContinue}; $after=Get-Service -Name 'RemoteRegistry'; if([string]$after.Status -ne [string]$fixture.remote_registry_previous_status){throw 'RemoteRegistry status was not restored'}; if([string]$after.StartType -ne [string]$fixture.remote_registry_previous_start_type){throw 'RemoteRegistry start type was not restored'}}}; Remove-Item -LiteralPath %s -Recurse -Force -ErrorAction SilentlyContinue; if(Get-Service -Name %s -ErrorAction SilentlyContinue){throw 'target service still exists'}; if(Get-Service -Name %s -ErrorAction SilentlyContinue){throw 'x86 target service still exists'}; if(Get-ScheduledTask -TaskName %s -ErrorAction SilentlyContinue){throw 'job-member task still exists'}; if(Get-ScheduledTask -TaskName 'BOFBenchWindowTarget' -ErrorAction SilentlyContinue){throw 'window-helper task still exists'}; if(Test-Path -LiteralPath %s){throw 'target directory still exists'}; Write-Output 'removed'`, powerShellQuote(fixturePath), powerShellQuote(fixturePath), powerShellQuote(statePath), powerShellQuote(statePath), powerShellQuote(TargetJobMemberTask), powerShellQuote(TargetJobMemberTask), powerShellQuote(TargetServiceName), powerShellQuote(TargetX86ServiceName), powerShellQuote(targetDirectory), powerShellQuote(TargetServiceName), powerShellQuote(TargetX86ServiceName), powerShellQuote(TargetJobMemberTask), powerShellQuote(targetDirectory))
}

func decodeTargetJSON(data []byte, target any) error {
	if err := json.Unmarshal(data, target); err == nil {
		return nil
	}
	text := strings.TrimSpace(string(data))
	start, end := strings.IndexByte(text, '{'), strings.LastIndexByte(text, '}')
	if start < 0 || end < start {
		return fmt.Errorf("target output did not contain a JSON object")
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), target); err != nil {
		return fmt.Errorf("decode target JSON: %w", err)
	}
	return nil
}

func mergeRemoteFixtures(target *TargetFixtureState, remote TargetFixtureState) {
	target.RemoteRegistryHive = remote.RemoteRegistryHive
	target.RemoteRegistryPath = remote.RemoteRegistryPath
	target.RemoteRegistryName = remote.RemoteRegistryName
	target.RemoteRegistrySHA256 = remote.RemoteRegistrySHA256
	target.RemoteRegistrySize = remote.RemoteRegistrySize
	target.RemoteRegistryStatus = remote.RemoteRegistryStatus
	target.RemoteRegistryStart = remote.RemoteRegistryStart
	target.RemoteRegistryKeyMade = remote.RemoteRegistryKeyMade
	target.RemoteComputerName = remote.RemoteComputerName
	target.RemoteStageShare = remote.RemoteStageShare
	target.RemoteStageRelative = remote.RemoteStageRelative
	target.RemoteStageLocal = remote.RemoteStageLocal
}

func TargetReportText(report TargetReport) string {
	if report.Status == "pass" && report.Operation != "remove" {
		computer := report.Fixtures.RemoteComputerName
		if computer == "" {
			computer = report.Host
		}
		text := fmt.Sprintf("BOFBench target %s\nprofile     %s\ncomputer    %s\nservice     %s\nx64 target  pid=%d tid=%d module=%s\nx86 target  pid=%d tid=%d module=%s\nknown handle %s\nnamed pipe  %s client=%s\nalpc        port=%s handle=%s\nwindow      hwnd=%s text=%s station=%s class=%s send=%d post=%d\nobjects     event=%s section=%s job=%s\nnetwork     tcp=%s:%d udp=%s:%d dns=%s\nhttp        request=%s blob=%s transient=%s\nwebsocket   %s payload_sha256=%s\nmemory      address=%s bytes=%d sha256=%s\nwrite test  address=%s bytes=%d sha256=%s\nprotect test address=%s bytes=%d protection=%s\nfile        %s\ncredential  %s user=%s bytes=%d\ndpapi user  %s\ndpapi host  %s\nvault       %s resource=%s identity=%s bytes=%d\ncertificate store=%s thumbprint=%s subject=%s\nwmi marker  %s\nremote reg  %s\\%s\\%s bytes=%d sha256=%s previous=%s/%s\nremote file share=%s root=%s local=%s\n", strings.ToUpper(report.Status), report.Profile, computer, report.Service, report.State.PID, report.State.AlertableTID, report.State.KnownModuleBase, report.State.X86PID, report.State.X86AlertableTID, report.State.X86KnownModuleBase, report.State.KnownHandle, report.State.NamedPipe, report.State.NamedPipeClientHandle, report.State.ALPCPort, report.State.ALPCHandle, report.State.WindowHandle, report.State.WindowTextHandle, report.State.WindowStation, report.State.WindowClass, report.State.WindowMessage, report.State.WindowPostMessage, report.State.EventName, report.State.SectionName, report.State.JobName, report.State.TCPHost, report.State.TCPPort, report.State.UDPHost, report.State.UDPPort, report.State.DNSName, report.State.HTTPURL, report.State.HTTPBlobURL, report.State.HTTPTransientURL, report.State.WebSocketURL, report.State.NetworkPayloadSHA256, report.State.MemoryCanaryAddress, report.State.MemoryCanarySize, report.State.MemoryCanarySHA256, report.State.MemoryWriteAddress, report.State.MemoryWriteSize, report.State.MemoryWriteSHA256, report.State.MemoryProtectAddress, report.State.MemoryProtectSize, report.State.MemoryProtection, report.State.CanaryFile, report.Fixtures.CredentialTarget, report.Fixtures.User, report.Fixtures.CredentialSize, report.Fixtures.DPAPIUserPath, report.Fixtures.DPAPIMachinePath, report.Fixtures.VaultGUID, report.Fixtures.VaultResource, report.Fixtures.VaultIdentity, report.Fixtures.VaultSize, report.Fixtures.CertificateStore, report.Fixtures.CertificateThumbprint, report.Fixtures.CertificateSubject, report.Fixtures.WMIMarkerPath, report.Fixtures.RemoteRegistryHive, report.Fixtures.RemoteRegistryPath, report.Fixtures.RemoteRegistryName, report.Fixtures.RemoteRegistrySize, report.Fixtures.RemoteRegistrySHA256, report.Fixtures.RemoteRegistryStatus, report.Fixtures.RemoteRegistryStart, report.Fixtures.RemoteStageShare, report.Fixtures.RemoteStageRelative, report.Fixtures.RemoteStageLocal)
		text += fmt.Sprintf("https       request=%s blob=%s auth=%s user=%s cert_sha256=%s\n", report.State.HTTPSURL, report.State.HTTPSBlobURL, report.State.HTTPSAuthURL, report.State.HTTPAuthUser, report.State.TLSCertificateSHA256)
		if report.State.FixtureError != "" {
			text += fmt.Sprintf("fixtures    unavailable: %s\n", report.State.FixtureError)
		}
		return text
	}
	return fmt.Sprintf("BOFBench target %s\nprofile    %s\nservice    %s\noperation  %s\n", strings.ToUpper(report.Status), report.Profile, report.Service, report.Operation)
}
