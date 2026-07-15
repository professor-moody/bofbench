package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const TargetServiceName = "BOFBenchTarget"

type TargetState struct {
	Schema               string `json:"schema"`
	SchemaVersion        int    `json:"schema_version"`
	Service              string `json:"service"`
	PID                  int    `json:"pid"`
	Architecture         string `json:"architecture,omitempty"`
	KnownModuleBase      string `json:"known_module_base,omitempty"`
	KnownModulePath      string `json:"known_module_path,omitempty"`
	X86PID               int    `json:"x86_pid,omitempty"`
	X86AlertableTID      uint32 `json:"x86_alertable_tid,omitempty"`
	X86KnownModuleBase   string `json:"x86_known_module_base,omitempty"`
	X86KnownModulePath   string `json:"x86_known_module_path,omitempty"`
	AlertableTID         uint32 `json:"alertable_tid"`
	NamedPipe            string `json:"named_pipe,omitempty"`
	KnownHandle          string `json:"known_handle,omitempty"`
	User                 string `json:"user"`
	CanaryFile           string `json:"canary_file"`
	CanaryFileSHA256     string `json:"canary_file_sha256,omitempty"`
	MemoryCanaryAddress  string `json:"memory_canary_address,omitempty"`
	MemoryCanarySize     int    `json:"memory_canary_size,omitempty"`
	MemoryCanarySHA256   string `json:"memory_canary_sha256,omitempty"`
	ExecutionAddress     string `json:"execution_address,omitempty"`
	MemoryWriteAddress   string `json:"memory_write_address,omitempty"`
	MemoryWriteSize      int    `json:"memory_write_size,omitempty"`
	MemoryWriteSHA256    string `json:"memory_write_sha256,omitempty"`
	MemoryProtectAddress string `json:"memory_protection_address,omitempty"`
	MemoryProtectSize    int    `json:"memory_protection_size,omitempty"`
	MemoryProtection     string `json:"memory_protection,omitempty"`
	FixtureError         string `json:"fixture_error,omitempty"`
	StartedAt            string `json:"started_at"`
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
	if err := json.Unmarshal(remoteFixtureOutput, &remoteFixtures); err != nil {
		_, _, _ = remoteExecute(ctx, opts, targetCleanupScript(targetDirectory))
		return report, fmt.Errorf("decode remote-operation fixtures: %w", err)
	}
	statePath := windowsJoin(profile.RemoteRoot, "target", "target.json")
	x86StatePath := windowsJoin(profile.RemoteRoot, "target", "x86", "x86-helper.json")
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force -Path %s|Out-Null; Start-Process -FilePath %s -ArgumentList @('--helper','--root',%s) -WindowStyle Hidden|Out-Null; $x86deadline=(Get-Date).AddSeconds(15); do{Start-Sleep -Milliseconds 250}until((Test-Path %s)-or(Get-Date)-gt$x86deadline); if(-not(Test-Path %s)){throw 'x86 helper state was not created'}; New-Service -Name %s -BinaryPathName %s -DisplayName 'BOFBench disposable capability target' -StartupType Manual | Out-Null; Start-Service -Name %s; $deadline=(Get-Date).AddSeconds(15); do { Start-Sleep -Milliseconds 250 } until ((Test-Path %s) -or (Get-Date) -gt $deadline); if(-not (Test-Path %s)){throw 'target state file was not created'}; Get-Content -LiteralPath %s -Raw`, powerShellQuote(statePath), powerShellQuote(windowsDir(x86StatePath)), powerShellQuote(remoteX86Executable), powerShellQuote(windowsDir(x86StatePath)), powerShellQuote(x86StatePath), powerShellQuote(x86StatePath), powerShellQuote(TargetServiceName), powerShellQuote(remoteExecutable), powerShellQuote(TargetServiceName), powerShellQuote(statePath), powerShellQuote(statePath), powerShellQuote(statePath))
	stdout, stderr, err := remoteExecute(ctx, opts, script)
	if err != nil {
		report.Error = boundedText(string(stderr), 4096)
		_, _, _ = remoteExecute(ctx, opts, targetCleanupScript(targetDirectory))
		return report, fmt.Errorf("start disposable target: %w: %s", err, report.Error)
	}
	if err := json.Unmarshal(stdout, &report.State); err != nil {
		return report, fmt.Errorf("decode disposable target state: %w", err)
	}
	if helperOutput, helperStderr, helperErr := remoteExecute(ctx, opts, fmt.Sprintf(`Get-Content -LiteralPath %s -Raw`, powerShellQuote(x86StatePath))); helperErr == nil {
		var helper TargetState
		if err := json.Unmarshal(helperOutput, &helper); err != nil {
			return report, err
		}
		report.State.X86PID, report.State.X86AlertableTID, report.State.X86KnownModuleBase, report.State.X86KnownModulePath = helper.PID, helper.AlertableTID, helper.KnownModuleBase, helper.KnownModulePath
	} else {
		return report, fmt.Errorf("read disposable x86 target: %w: %s", helperErr, boundedText(string(helperStderr), 2048))
	}
	fixturePath := windowsJoin(profile.RemoteRoot, "target", "fixtures", "fixture.json")
	fixtureOutput, fixtureStderr, fixtureErr := remoteExecute(ctx, opts, fmt.Sprintf(`$ErrorActionPreference='Stop'; Get-Content -LiteralPath %s -Raw`, powerShellQuote(fixturePath)))
	if fixtureErr == nil {
		if err := json.Unmarshal(fixtureOutput, &report.Fixtures); err != nil {
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
	if err := json.Unmarshal(stdout, &report.State); err != nil {
		return report, err
	}
	x86StatePath := windowsJoin(profile.RemoteRoot, "target", "x86", "x86-helper.json")
	if helperOutput, helperStderr, helperErr := remoteExecute(ctx, opts, fmt.Sprintf(`Get-Content -LiteralPath %s -Raw`, powerShellQuote(x86StatePath))); helperErr == nil {
		var helper TargetState
		if err := json.Unmarshal(helperOutput, &helper); err != nil {
			return report, err
		}
		report.State.X86PID, report.State.X86AlertableTID, report.State.X86KnownModuleBase, report.State.X86KnownModulePath = helper.PID, helper.AlertableTID, helper.KnownModuleBase, helper.KnownModulePath
	} else {
		return report, fmt.Errorf("read disposable x86 target: %w: %s", helperErr, boundedText(string(helperStderr), 2048))
	}
	fixturePath := windowsJoin(profile.RemoteRoot, "target", "fixtures", "fixture.json")
	fixtureOutput, fixtureStderr, fixtureErr := remoteExecute(ctx, opts, fmt.Sprintf(`$ErrorActionPreference='Stop'; Get-Content -LiteralPath %s -Raw`, powerShellQuote(fixturePath)))
	if fixtureErr == nil {
		if err := json.Unmarshal(fixtureOutput, &report.Fixtures); err != nil {
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
	if err := json.Unmarshal(remoteFixtureOutput, &remoteFixtures); err != nil {
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
	x86StatePath := windowsJoin(targetDirectory, "x86", "x86-helper.json")
	return fmt.Sprintf(`$ErrorActionPreference='Continue'; $fixture=$null; if(Test-Path -LiteralPath %s){try{$fixture=Get-Content -LiteralPath %s -Raw|ConvertFrom-Json}catch{}}; if(Test-Path -LiteralPath %s){try{$x86=Get-Content -LiteralPath %s -Raw|ConvertFrom-Json; Stop-Process -Id ([int]$x86.pid) -Force -ErrorAction SilentlyContinue}catch{}}; $service=Get-Service -Name %s -ErrorAction SilentlyContinue; if($service -and $service.Status -ne 'Stopped'){Stop-Service -Name %s -Force}; if($service){sc.exe delete %s|Out-Null}; Start-Sleep -Milliseconds 500; if($fixture){$key='HKLM:\'+[string]$fixture.remote_registry_path; $keyItem=Get-Item -LiteralPath $key -ErrorAction SilentlyContinue; if($keyItem){foreach($valueName in @($keyItem.GetValueNames()|Where-Object{$_ -like 'BOFBench-Remote-*'})){Remove-ItemProperty -LiteralPath $key -Name $valueName -Force -ErrorAction SilentlyContinue}}; Remove-ItemProperty -LiteralPath $key -Name ([string]$fixture.remote_registry_name) -Force -ErrorAction SilentlyContinue; if([bool]$fixture.remote_registry_key_created){Remove-Item -LiteralPath $key -Force -ErrorAction SilentlyContinue}; Remove-Item -LiteralPath ([string]$fixture.remote_stage_local_root) -Recurse -Force -ErrorAction SilentlyContinue; $remote=Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue; if($remote){if($remote.Status -ne 'Stopped'){Stop-Service -Name 'RemoteRegistry' -Force -ErrorAction SilentlyContinue}; switch([string]$fixture.remote_registry_previous_start_type){'Automatic'{Set-Service -Name 'RemoteRegistry' -StartupType Automatic};'Manual'{Set-Service -Name 'RemoteRegistry' -StartupType Manual};'Disabled'{Set-Service -Name 'RemoteRegistry' -StartupType Disabled}}; if([string]$fixture.remote_registry_previous_status -eq 'Running'){Start-Service -Name 'RemoteRegistry'}else{Stop-Service -Name 'RemoteRegistry' -Force -ErrorAction SilentlyContinue}; $after=Get-Service -Name 'RemoteRegistry'; if([string]$after.Status -ne [string]$fixture.remote_registry_previous_status){throw 'RemoteRegistry status was not restored'}; if([string]$after.StartType -ne [string]$fixture.remote_registry_previous_start_type){throw 'RemoteRegistry start type was not restored'}}}; Remove-Item -LiteralPath %s -Recurse -Force -ErrorAction SilentlyContinue; if(Get-Service -Name %s -ErrorAction SilentlyContinue){throw 'target service still exists'}; if(Test-Path -LiteralPath %s){throw 'target directory still exists'}; Write-Output 'removed'`, powerShellQuote(fixturePath), powerShellQuote(fixturePath), powerShellQuote(x86StatePath), powerShellQuote(x86StatePath), powerShellQuote(TargetServiceName), powerShellQuote(TargetServiceName), TargetServiceName, powerShellQuote(targetDirectory), powerShellQuote(TargetServiceName), powerShellQuote(targetDirectory))
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
		text := fmt.Sprintf("BOFBench target %s\nprofile     %s\ncomputer    %s\nservice     %s\nx64 target  pid=%d tid=%d module=%s\nx86 target  pid=%d tid=%d module=%s\nknown handle %s\nnamed pipe  %s\nmemory      address=%s bytes=%d sha256=%s\nwrite test  address=%s bytes=%d sha256=%s\nprotect test address=%s bytes=%d protection=%s\nfile        %s\ncredential  %s user=%s bytes=%d\ndpapi user  %s\ndpapi host  %s\nvault       %s resource=%s identity=%s bytes=%d\ncertificate store=%s thumbprint=%s subject=%s\nwmi marker  %s\nremote reg  %s\\%s\\%s bytes=%d sha256=%s previous=%s/%s\nremote file share=%s root=%s local=%s\n", strings.ToUpper(report.Status), report.Profile, computer, report.Service, report.State.PID, report.State.AlertableTID, report.State.KnownModuleBase, report.State.X86PID, report.State.X86AlertableTID, report.State.X86KnownModuleBase, report.State.KnownHandle, report.State.NamedPipe, report.State.MemoryCanaryAddress, report.State.MemoryCanarySize, report.State.MemoryCanarySHA256, report.State.MemoryWriteAddress, report.State.MemoryWriteSize, report.State.MemoryWriteSHA256, report.State.MemoryProtectAddress, report.State.MemoryProtectSize, report.State.MemoryProtection, report.State.CanaryFile, report.Fixtures.CredentialTarget, report.Fixtures.User, report.Fixtures.CredentialSize, report.Fixtures.DPAPIUserPath, report.Fixtures.DPAPIMachinePath, report.Fixtures.VaultGUID, report.Fixtures.VaultResource, report.Fixtures.VaultIdentity, report.Fixtures.VaultSize, report.Fixtures.CertificateStore, report.Fixtures.CertificateThumbprint, report.Fixtures.CertificateSubject, report.Fixtures.WMIMarkerPath, report.Fixtures.RemoteRegistryHive, report.Fixtures.RemoteRegistryPath, report.Fixtures.RemoteRegistryName, report.Fixtures.RemoteRegistrySize, report.Fixtures.RemoteRegistrySHA256, report.Fixtures.RemoteRegistryStatus, report.Fixtures.RemoteRegistryStart, report.Fixtures.RemoteStageShare, report.Fixtures.RemoteStageRelative, report.Fixtures.RemoteStageLocal)
		if report.State.FixtureError != "" {
			text += fmt.Sprintf("fixtures    unavailable: %s\n", report.State.FixtureError)
		}
		return text
	}
	return fmt.Sprintf("BOFBench target %s\nprofile    %s\nservice    %s\noperation  %s\n", strings.ToUpper(report.Status), report.Profile, report.Service, report.Operation)
}
