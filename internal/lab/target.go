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
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	Service       string `json:"service"`
	PID           int    `json:"pid"`
	AlertableTID  uint32 `json:"alertable_tid"`
	User          string `json:"user"`
	CanaryFile    string `json:"canary_file"`
	StartedAt     string `json:"started_at"`
}

type TargetReport struct {
	Operation string      `json:"operation"`
	Status    string      `json:"status"`
	Profile   string      `json:"profile"`
	Host      string      `json:"host"`
	Service   string      `json:"service"`
	State     TargetState `json:"state,omitempty"`
	Error     string      `json:"error,omitempty"`
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
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", executable, "./cmd/bofbench-target")
	build.Dir = repository
	build.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		return report, fmt.Errorf("build disposable Windows target: %w: %s", err, strings.TrimSpace(string(output)))
	}
	remoteExecutable := windowsJoin(profile.RemoteRoot, "target", "bofbench-target.exe")
	if _, stderr, err := remoteExecute(ctx, opts, fmt.Sprintf(`New-Item -ItemType Directory -Force -Path %s | Out-Null`, powerShellQuote(windowsDir(remoteExecutable)))); err != nil {
		return report, fmt.Errorf("prepare disposable target directory: %w: %s", err, boundedText(string(stderr), 2048))
	}
	stopScript := fmt.Sprintf(`$existing=Get-Service -Name %s -ErrorAction SilentlyContinue; if($existing){if($existing.Status -ne 'Stopped'){Stop-Service -Name %s -Force}; sc.exe delete %s | Out-Null; Start-Sleep -Milliseconds 500}`, powerShellQuote(TargetServiceName), powerShellQuote(TargetServiceName), TargetServiceName)
	if _, stderr, err := remoteExecute(ctx, opts, stopScript); err != nil {
		return report, fmt.Errorf("stop prior disposable target: %w: %s", err, boundedText(string(stderr), 2048))
	}
	if _, stderr, err := remoteUploadFile(ctx, opts, executable, remoteExecutable); err != nil {
		return report, fmt.Errorf("deploy disposable target: %w: %s", err, boundedText(string(stderr), 2048))
	}
	statePath := windowsJoin(profile.RemoteRoot, "target", "target.json")
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue; New-Service -Name %s -BinaryPathName %s -DisplayName 'BOFBench disposable capability target' -StartupType Manual | Out-Null; Start-Service -Name %s; $deadline=(Get-Date).AddSeconds(15); do { Start-Sleep -Milliseconds 250 } until ((Test-Path %s) -or (Get-Date) -gt $deadline); if(-not (Test-Path %s)){throw 'target state file was not created'}; Get-Content -LiteralPath %s -Raw`, powerShellQuote(statePath), powerShellQuote(TargetServiceName), powerShellQuote(remoteExecutable), powerShellQuote(TargetServiceName), powerShellQuote(statePath), powerShellQuote(statePath), powerShellQuote(statePath))
	stdout, stderr, err := remoteExecute(ctx, opts, script)
	if err != nil {
		report.Error = boundedText(string(stderr), 4096)
		return report, fmt.Errorf("start disposable target: %w: %s", err, report.Error)
	}
	if err := json.Unmarshal(stdout, &report.State); err != nil {
		return report, fmt.Errorf("decode disposable target state: %w", err)
	}
	report.Status = "pass"
	return report, nil
}

func TargetStatus(ctx context.Context, name string, profile Profile) (TargetReport, error) {
	profile = NormalizeProfile(profile)
	opts, resolveErr := ResolveRemoteOptions(ctx, name, profile)
	report := TargetReport{Operation: "status", Status: "fail", Profile: name, Host: opts.Host, Service: TargetServiceName}
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
	script := fmt.Sprintf(`$ErrorActionPreference='Continue'; $service=Get-Service -Name %s -ErrorAction SilentlyContinue; if($service -and $service.Status -ne 'Stopped'){Stop-Service -Name %s -Force}; if($service){sc.exe delete %s | Out-Null}; Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath %s -Recurse -Force -ErrorAction SilentlyContinue; if(Get-Service -Name %s -ErrorAction SilentlyContinue){throw 'target service still exists'}; Write-Output 'removed'`, powerShellQuote(TargetServiceName), powerShellQuote(TargetServiceName), TargetServiceName, powerShellQuote(windowsJoin(profile.RemoteRoot, "target")), powerShellQuote(TargetServiceName))
	_, stderr, err := remoteExecute(ctx, opts, script)
	if err != nil {
		report.Error = boundedText(string(stderr), 4096)
		return report, err
	}
	report.Status = "pass"
	return report, nil
}

func TargetReportText(report TargetReport) string {
	if report.Status == "pass" && report.Operation != "remove" {
		return fmt.Sprintf("BOFBench target %s\nprofile    %s\ncomputer   %s\nservice    %s\npid        %d\nalertable  tid=%d\ncanary     %s\n", strings.ToUpper(report.Status), report.Profile, report.Host, report.Service, report.State.PID, report.State.AlertableTID, report.State.CanaryFile)
	}
	return fmt.Sprintf("BOFBench target %s\nprofile    %s\nservice    %s\noperation  %s\n", strings.ToUpper(report.Status), report.Profile, report.Service, report.Operation)
}
