package app

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/spf13/cobra"

	"bofbench/internal/runlog"
	"bofbench/internal/runtimeadapter"
	"bofbench/internal/stage"
)

type sliverOptions struct {
	Client        string
	SessionFilter string
}

type sliverExtension struct {
	Name        string `json:"name"`
	CommandName string `json:"command_name"`
	Arguments   []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Optional bool   `json:"optional"`
	} `json:"arguments,omitempty"`
}

var (
	ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	shortSessionID    = regexp.MustCompile(`^[0-9a-f]{8}$`)
	safeSliverCommand = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	sliverTaskID      = regexp.MustCompile(`(?i)task(?:ed)?(?:\s+id)?[:= ]+([0-9a-f-]{8,})`)
)

func sliverCommand(stdout io.Writer) *cobra.Command {
	opts := sliverOptions{}
	cmd := &cobra.Command{
		Use:   "sliver",
		Short: "Load and run verified BOFBench extensions through Sliver",
	}
	cmd.PersistentFlags().StringVar(&opts.Client, "client", filepath.Join("work", "tools", "sliver", "sliver-client_macos-arm64"), "Sliver client binary")
	cmd.PersistentFlags().StringVar(&opts.SessionFilter, "session", "DEVBOX", "live session name or filter")
	cmd.AddCommand(sliverSessionsCommand(stdout, &opts), sliverRunCommand(stdout, &opts))
	return cmd
}

func sliverSessionsCommand(stdout io.Writer, opts *sliverOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "sessions",
		Short: "Find the live Sliver session selected for BOF execution",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			session, err := findSliverSession(*opts)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "SLIVER SESSION PASS\nfilter    %s\nsession   %s [ALIVE]\n", opts.SessionFilter, session)
			return nil
		},
	}
}

func sliverRunCommand(stdout io.Writer, opts *sliverOptions) *cobra.Command {
	var commandName string
	cmd := &cobra.Command{
		Use:   "run <staged-extension-directory> [argument ...]",
		Short: "Verify, load, and execute a staged Sliver BOF extension",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSliverExtension(stdout, *opts, args[0], commandName, args[1:])
		},
	}
	cmd.Flags().StringVar(&commandName, "command", "", "extension command override; defaults to extension.json command_name")
	return cmd
}

func runSliverExtension(stdout io.Writer, opts sliverOptions, extensionPath, commandOverride string, commandArgs []string) error {
	if _, err := os.Stat(opts.Client); err != nil {
		return fmt.Errorf("Sliver client %s: %w", opts.Client, err)
	}
	verification := stage.Verify(extensionPath)
	if !verification.Passed() {
		return fmt.Errorf("exported extension verification failed; run 'bofbench export verify %s'", extensionPath)
	}
	extension, err := loadSliverExtension(extensionPath)
	if err != nil {
		return err
	}
	commandName := extension.CommandName
	if commandOverride != "" {
		commandName = commandOverride
	}
	if commandName == "" {
		return fmt.Errorf("extension command is empty; set command_name in extension.json or pass --command")
	}
	if !safeSliverCommand.MatchString(commandName) {
		return fmt.Errorf("extension command %q is not safe for the Sliver console", commandName)
	}
	required := 0
	for _, argument := range extension.Arguments {
		if !argument.Optional {
			required++
		}
	}
	if len(commandArgs) < required || len(commandArgs) > len(extension.Arguments) {
		return fmt.Errorf("extension command requires %d to %d argument(s), got %d", required, len(extension.Arguments), len(commandArgs))
	}
	absolute, err := filepath.Abs(extensionPath)
	if err != nil {
		return err
	}
	session, err := findSliverSession(opts)
	if err != nil {
		return err
	}
	commandLine := commandName
	for _, value := range commandArgs {
		quoted, err := sliverConsoleQuote(value)
		if err != nil {
			return err
		}
		commandLine += " " + quoted
	}
	quotedExtension, _ := sliverConsoleQuote(absolute)
	rc := fmt.Sprintf("extensions load %s\nuse %s\n%s\nexit\n", quotedExtension, session, commandLine)
	started := time.Now()
	output, runErr := runSliverRC(opts.Client, rc)
	clean := stripANSI(output)
	if runErr == nil && !strings.Contains(clean, "Successfully executed") {
		runErr = fmt.Errorf("Sliver did not report successful execution")
	}
	runDir, receiptErr := runlog.NewDir("sliver-" + safeName(extension.Name))
	if receiptErr != nil {
		return receiptErr
	}
	receipt := runtimeadapter.Receipt{
		Schema: runtimeadapter.ReceiptSchema, SchemaVersion: 1, Runtime: "sliver", Status: "fail",
		Session: session, Entrypoint: "go", StartedAt: started.UTC().Format(time.RFC3339Nano),
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), DurationMS: time.Since(started).Milliseconds(),
		ReceiptPath: filepath.Join(runDir, "sliver.json"),
	}
	if manifest, manifestErr := loadStageManifest(filepath.Join(extensionPath, "manifest.json")); manifestErr == nil {
		receipt.Object = manifest.Object
		receipt.ObjectSHA256 = manifest.ObjectFingerprint.SHA256
		receipt.Entrypoint = manifest.Entrypoint
	}
	for _, argument := range extension.Arguments {
		receipt.Arguments = append(receipt.Arguments, argument.Type)
	}
	if clean != "" {
		receipt.Output = strings.Split(strings.TrimSpace(clean), "\n")
	}
	if match := sliverTaskID.FindStringSubmatch(clean); len(match) == 2 {
		receipt.TaskID = match[1]
	}
	if runErr == nil {
		receipt.Status = "pass"
	} else {
		receipt.Error = runErr.Error()
	}
	if err := writeJSON(receipt.ReceiptPath, receipt); err != nil {
		return err
	}
	if runErr != nil {
		return runErr
	}
	fmt.Fprintln(stdout, "SLIVER BOF PASS")
	fmt.Fprintf(stdout, "extension  %s\ncommand    %s\nsession    %s\narguments  %d\nreceipt    %s\n", extension.Name, commandName, session, len(commandArgs), receipt.ReceiptPath)
	for _, line := range conciseSliverLines(clean, commandName) {
		fmt.Fprintln(stdout, line)
	}
	return nil
}

func sliverConsoleQuote(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("Sliver command arguments cannot contain newlines")
	}
	if value == "" || strings.ContainsAny(value, " \t\"'") {
		return strconv.Quote(value), nil
	}
	return value, nil
}

func loadSliverExtension(extensionPath string) (sliverExtension, error) {
	path := filepath.Join(extensionPath, "extension.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return sliverExtension{}, fmt.Errorf("read Sliver extension %s: %w", path, err)
	}
	var extension sliverExtension
	if err := json.Unmarshal(data, &extension); err != nil {
		return sliverExtension{}, fmt.Errorf("parse Sliver extension %s: %w", path, err)
	}
	if extension.Name == "" {
		extension.Name = filepath.Base(extensionPath)
	}
	return extension, nil
}

func findSliverSession(opts sliverOptions) (string, error) {
	output, err := runSliverRC(opts.Client, fmt.Sprintf("sessions -f %s\nexit\n", opts.SessionFilter))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(stripANSI(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && shortSessionID.MatchString(fields[0]) && strings.Contains(line, "[ALIVE]") {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no live Sliver session matched %q", opts.SessionFilter)
}

func runSliverRC(client, body string) (string, error) {
	file, err := os.CreateTemp("", "bofbench-sliver-*.rc")
	if err != nil {
		return "", err
	}
	path := file.Name()
	defer os.Remove(path)
	if _, err := file.WriteString(body); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, client, "console", "--rc", path).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(output), fmt.Errorf("Sliver console timed out after 90s")
	}
	if err != nil {
		return string(output), fmt.Errorf("Sliver console failed: %w\n%s", err, stripANSI(string(output)))
	}
	return string(output), nil
}

func conciseSliverLines(output, command string) []string {
	var lines []string
	processRows, serviceRows, tcpRows := 0, 0, 0
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		keep := strings.HasPrefix(line, "[process]") || strings.HasPrefix(line, "[host]") || strings.HasPrefix(line, "[token-context]") || strings.HasPrefix(line, "[domain-context]") || strings.HasPrefix(line, "[lab-")
		switch {
		case strings.HasPrefix(line, "[process-list]") && processRows < 3:
			processRows++
			keep = true
		case strings.HasPrefix(line, "[service-list]") && serviceRows < 3:
			serviceRows++
			keep = true
		case strings.HasPrefix(line, "[tcp-connections]") && tcpRows < 3:
			tcpRows++
			keep = true
		}
		if keep {
			lines = append(lines, formatSliverReceipt(line))
		}
	}
	if len(lines) == 0 {
		return []string{"output     command completed"}
	}
	return lines
}

func formatSliverReceipt(line string) string {
	switch {
	case strings.HasPrefix(line, "[lab-file-write]"):
		return "action     file       %TEMP%\\bofbench-active-marker.txt"
	case strings.HasPrefix(line, "[lab-registry-write]"):
		return "action     registry   HKCU\\Software\\BOFBench\\LabMarker"
	case strings.HasPrefix(line, "[lab-run-key]"):
		return "action     run-key    HKCU\\...\\Run\\BOFBenchLab (inert)"
	case strings.HasPrefix(line, "[lab-process-launch]"):
		pid := "created"
		if start := strings.Index(line, "child_pid="); start >= 0 {
			value := line[start+len("child_pid="):]
			if end := strings.IndexByte(value, ' '); end >= 0 {
				value = value[:end]
			}
			pid = "pid=" + value
		}
		return "action     process    " + pid + " marker=%TEMP%\\bofbench-process-marker.txt"
	case strings.HasPrefix(line, "[lab-cleanup]"):
		return "cleanup    owned files + registry values removed"
	default:
		return line
	}
}

func stripANSI(value string) string {
	return ansiEscapePattern.ReplaceAllString(value, "")
}

func labStateCommand(stdout io.Writer) *cobra.Command {
	var host string
	cmd := &cobra.Command{
		Use:   "verify <active|clean>",
		Short: "Verify BOFBench-managed state independently on the Windows lab host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "active":
				return verifyActiveState(stdout, host)
			case "clean":
				return verifyCleanState(stdout, host)
			default:
				return fmt.Errorf("state must be active or clean")
			}
		},
	}
	cmd.Flags().StringVar(&host, "host", "bofbench-winvm", "SSH alias for the Windows lab host")
	return cmd
}

func verifyActiveState(stdout io.Writer, host string) error {
	script := `$ProgressPreference='SilentlyContinue'; $count=0; foreach($path in @("$env:TEMP\bofbench-active-marker.txt","$env:TEMP\bofbench-process-marker.txt")){ if(Test-Path $path){$item=Get-Item $path; Write-Output ("[file] present name="+$item.Name+" bytes="+$item.Length); $count++}}; $marker=Get-ItemPropertyValue -Path HKCU:\Software\BOFBench -Name LabMarker -ErrorAction SilentlyContinue; if($marker){Write-Output ("[registry] LabMarker="+$marker);$count++}; $run=Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name BOFBenchLab -ErrorAction SilentlyContinue; if($run){Write-Output ("[run-key] BOFBenchLab="+$run);$count++}; if($count -ne 4){Write-Error ("expected 4 BOFBench artifacts; found "+$count);exit 1}; Write-Output "LAB STATE PASS  expected=active artifacts=4"`
	return runRemotePowerShell(stdout, host, script)
}

func verifyCleanState(stdout io.Writer, host string) error {
	script := `$ProgressPreference='SilentlyContinue'; $run=Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue; $bad=(Test-Path "$env:TEMP\bofbench-active-marker.txt") -or (Test-Path "$env:TEMP\bofbench-process-marker.txt") -or ($null -ne (Get-ItemProperty -Path HKCU:\Software\BOFBench -ErrorAction SilentlyContinue)) -or ($null -ne $run.BOFBenchLab); if($bad){Write-Error "BOFBench-managed state remains";exit 1}; Write-Output "LAB STATE PASS  expected=clean artifacts=0"`
	return runRemotePowerShell(stdout, host, script)
}

func runRemotePowerShell(stdout io.Writer, host, script string) error {
	encoded := encodePowerShell(script)
	remote := fmt.Sprintf("powershell -NoProfile -NonInteractive -EncodedCommand %s; exit $LASTEXITCODE", encoded)
	output, err := exec.Command("ssh", host, remote).CombinedOutput()
	clean := strings.TrimSpace(stripANSI(string(output)))
	if clean != "" {
		fmt.Fprintln(stdout, clean)
	}
	if err != nil {
		return fmt.Errorf("lab check failed: %w", err)
	}
	return nil
}

func encodePowerShell(script string) string {
	encoded := utf16.Encode([]rune(script))
	data := make([]byte, len(encoded)*2)
	for index, value := range encoded {
		binary.LittleEndian.PutUint16(data[index*2:], value)
	}
	return base64.StdEncoding.EncodeToString(data)
}
