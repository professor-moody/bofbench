package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/lab"
	"bofbench/internal/runlog"
	"bofbench/internal/runtimeadapter"
	"bofbench/internal/stage"
)

type sliverOptions struct {
	Client                 string
	SessionFilter          string
	Lab                    string
	Profiles               string
	ProfileName            string
	RemoteHost             string
	SensitiveOutputFields  []string
	SensitiveArgumentNames []string
	SensitiveValues        []string
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
	opts := sliverOptions{Profiles: lab.ProfilesPath()}
	cmd := &cobra.Command{
		Use:   "sliver",
		Short: "Load and run verified BOFBench extensions through Sliver",
	}
	cmd.PersistentFlags().StringVar(&opts.Client, "client", "", "Sliver client binary; discovered automatically when omitted")
	cmd.PersistentFlags().StringVar(&opts.SessionFilter, "session", "", "live session selector; defaults to the selected lab profile")
	cmd.PersistentFlags().StringVar(&opts.Lab, "lab", "", "named lab profile")
	cmd.PersistentFlags().StringVar(&opts.Profiles, "profiles", opts.Profiles, "global lab profiles file")
	cmd.AddCommand(sliverSetupCommand(stdout, &opts), sliverSessionsCommand(stdout, &opts), sliverRunCommand(stdout, &opts), sliverLabSessionCommand(stdout, &opts))
	return cmd
}

func sliverSessionsCommand(stdout io.Writer, opts *sliverOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "sessions",
		Short: "Find the live Sliver session selected for BOF execution",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := resolveSliverOptions(*opts, ".", true)
			if err != nil {
				return err
			}
			session, err := findSliverSession(resolved)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "Sliver session ready\nSelector   %s\nSession    %s [ALIVE]\n", resolved.SessionFilter, session)
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
			resolved, err := resolveSliverOptions(*opts, args[0], true)
			if err != nil {
				return err
			}
			return runSliverExtension(stdout, resolved, args[0], commandName, args[1:])
		},
	}
	cmd.Flags().StringVar(&commandName, "command", "", "extension command override; defaults to extension.json command_name")
	return cmd
}

func sliverSetupCommand(stdout io.Writer, opts *sliverOptions) *cobra.Command {
	var install bool
	cmd := &cobra.Command{
		Use: "setup", Short: "Verify the Sliver client, config, and coff-loader for a lab profile", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := resolveSliverOptions(*opts, ".", false)
			if err != nil {
				return err
			}
			configs := discoverSliverConfigs()
			if len(configs) == 0 {
				return fmt.Errorf("no Sliver client config found; set BOFBENCH_SLIVER_CONFIG or place a config in ~/.sliver-client/configs")
			}
			loaderPath := filepath.Join(sliverClientHome(), "extensions", "coff-loader", "extension.json")
			if _, err := os.Stat(loaderPath); err != nil && install {
				output, installErr := runSliverRC(resolved.Client, "armory install coff-loader\nexit\n")
				if installErr != nil {
					return fmt.Errorf("install coff-loader: %w", installErr)
				}
				if !strings.Contains(strings.ToLower(stripANSI(output)), "coff") {
					return fmt.Errorf("Sliver did not confirm coff-loader installation")
				}
			}
			if _, err := os.Stat(loaderPath); err != nil {
				return fmt.Errorf("coff-loader is not installed at %s; rerun with --install", loaderPath)
			}
			fmt.Fprintf(stdout, "Sliver support ready\nClient      %s\nConfig      %s\ncoff-loader %s\n", resolved.Client, configs[0], loaderPath)
			if resolved.SessionFilter != "" {
				fmt.Fprintf(stdout, "Session     %s\n", resolved.SessionFilter)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&install, "install", false, "explicitly install coff-loader through the configured Sliver server")
	return cmd
}

func runSliverExtension(stdout io.Writer, opts sliverOptions, extensionPath, commandOverride string, commandArgs []string) error {
	_, err := executeSliverExtension(stdout, opts, extensionPath, commandOverride, commandArgs)
	return err
}

func executeSliverExtension(stdout io.Writer, opts sliverOptions, extensionPath, commandOverride string, commandArgs []string) (runtimeadapter.Receipt, error) {
	if _, err := os.Stat(opts.Client); err != nil {
		return runtimeadapter.Receipt{}, fmt.Errorf("Sliver client %s: %w", opts.Client, err)
	}
	verification := stage.Verify(extensionPath)
	if !verification.Passed() {
		return runtimeadapter.Receipt{}, fmt.Errorf("exported extension verification failed; run 'bofbench export verify %s'", extensionPath)
	}
	extension, err := loadSliverExtension(extensionPath)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	commandName := extension.CommandName
	if commandOverride != "" {
		commandName = commandOverride
	}
	if commandName == "" {
		return runtimeadapter.Receipt{}, fmt.Errorf("extension command is empty; set command_name in extension.json or pass --command")
	}
	if !safeSliverCommand.MatchString(commandName) {
		return runtimeadapter.Receipt{}, fmt.Errorf("extension command %q is not safe for the Sliver console", commandName)
	}
	required := 0
	for _, argument := range extension.Arguments {
		if !argument.Optional {
			required++
		}
	}
	if len(commandArgs) < required || len(commandArgs) > len(extension.Arguments) {
		return runtimeadapter.Receipt{}, fmt.Errorf("extension command requires %d to %d argument(s), got %d", required, len(extension.Arguments), len(commandArgs))
	}
	absolute, err := filepath.Abs(extensionPath)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	session, err := findSliverSession(opts)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	commandLine, err := sliverExtensionCommandLine(commandName, extension, commandArgs)
	if err != nil {
		return runtimeadapter.Receipt{}, err
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
		return runtimeadapter.Receipt{}, receiptErr
	}
	receipt := runtimeadapter.Receipt{
		Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion, Runtime: "sliver", Status: "fail", ExecutionState: "failed", Profile: opts.ProfileName,
		Transport: "sliver", RemoteHost: opts.RemoteHost, Session: session, Entrypoint: "go", TimeoutMS: 90000, StartedAt: started.UTC().Format(time.RFC3339Nano),
		CompletedAt: time.Now().UTC().Format(time.RFC3339Nano), DurationMS: time.Since(started).Milliseconds(),
		ReceiptPath: filepath.Join(runDir, "result.json"),
	}
	runtimeadapter.AddTransition(&receipt, "submitted", "extension command sent to selected Sliver session", started)
	runtimeadapter.AddTransition(&receipt, "running", "Sliver task output collection started", started)
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
		receipt.RemoteComputer = sliverOutputComputer(receipt.Output)
	}
	if match := sliverTaskID.FindStringSubmatch(clean); len(match) == 2 {
		receipt.TaskID = match[1]
	}
	if runErr == nil {
		receipt.Status = "pass"
		receipt.ExecutionState = "completed"
		receipt.OutputComplete = true
		receipt.ExitState = "success"
		runtimeadapter.AddTransition(&receipt, "completed", "Sliver reported successful execution and complete output", time.Now())
		receipt.CompletionSource = "sliver-console"
		receipt.OutputClassification = "complete"
		receipt.FinalChunk = true
		receipt.OutputChunks = append(receipt.OutputChunks, runtimeadapter.OutputChunk{Number: 1, LineCount: len(receipt.Output), Final: true, ReceivedAt: receipt.CompletedAt})
	} else {
		receipt.Error = runErr.Error()
		receipt.ExitState = "error"
		receipt.TimedOut = strings.Contains(strings.ToLower(receipt.Error), "timed out")
		if receipt.TimedOut {
			receipt.ExecutionState = "timeout"
			runtimeadapter.AddTransition(&receipt, "timeout", receipt.Error, time.Now())
		} else {
			runtimeadapter.AddTransition(&receipt, "failed", receipt.Error, time.Now())
		}
	}
	rawOutput := append([]string(nil), receipt.Output...)
	receipt = redactReceiptValues(receipt, opts.SensitiveOutputFields, opts.SensitiveArgumentNames, opts.SensitiveValues)
	receipt.TransientOutput = rawOutput
	if err := writeJSON(receipt.ReceiptPath, receipt); err != nil {
		return receipt, err
	}
	if runErr != nil {
		return receipt, runErr
	}
	fmt.Fprintln(stdout, "SLIVER BOF PASS")
	fmt.Fprintf(stdout, "extension  %s\ncommand    %s\nsession    %s\narguments  %d\nreceipt    %s\n", extension.Name, commandName, session, len(commandArgs), receipt.ReceiptPath)
	for _, line := range conciseSliverLines(clean, commandName) {
		fmt.Fprintln(stdout, line)
	}
	return receipt, nil
}

func refreshSliverRuntimeReceipt(ctx context.Context, receipt runtimeadapter.Receipt, opts sliverOptions) (runtimeadapter.Receipt, error) {
	if runtimeTaskTerminal(receipt.ExecutionState) {
		return receipt, nil
	}
	if strings.TrimSpace(receipt.TaskID) == "" {
		return receipt, fmt.Errorf("Sliver receipt has no persisted task ID")
	}
	if opts.Client == "" {
		client, err := discoverSliverClient()
		if err != nil {
			return receipt, err
		}
		opts.Client = client
	}
	session := strings.TrimSpace(receipt.Session)
	if session == "" {
		return receipt, fmt.Errorf("Sliver receipt has no selected session")
	}
	quotedSession, err := sliverConsoleQuote(session)
	if err != nil {
		return receipt, err
	}
	quotedTask, err := sliverConsoleQuote(receipt.TaskID)
	if err != nil {
		return receipt, err
	}
	select {
	case <-ctx.Done():
		return receipt, ctx.Err()
	default:
	}
	output, runErr := runSliverRCContext(ctx, opts.Client, fmt.Sprintf("use %s\ntasks fetch %s\nexit\n", quotedSession, quotedTask))
	now := time.Now().UTC()
	receipt.LastRefreshAt = now.Format(time.RFC3339Nano)
	receipt.CompletionSource = "sliver-task-store"
	clean := strings.TrimSpace(stripANSI(output))
	lines := nonemptyLines(clean)
	if len(lines) > 0 {
		receipt.Output = redactRuntimeLines(lines, receipt.RedactedOutputFields, nil)
		receipt.OutputChunks = append(receipt.OutputChunks, runtimeadapter.OutputChunk{Number: len(receipt.OutputChunks) + 1, LineCount: len(lines), ReceivedAt: receipt.LastRefreshAt})
	}
	state := sliverFetchedTaskState(lines)
	switch state {
	case "completed":
		receipt.Status, receipt.ExecutionState, receipt.OutputComplete = "pass", "completed", true
		receipt.OutputClassification, receipt.FinalChunk, receipt.TerminalReason = "complete", true, "completed"
		receipt.CompletedAt = receipt.LastRefreshAt
		if len(receipt.OutputChunks) > 0 {
			receipt.OutputChunks[len(receipt.OutputChunks)-1].Final = true
		}
		runtimeadapter.AddTransition(&receipt, "completed", "Sliver persisted task output reached completed state", now)
	case "failed", "canceled":
		receipt.Status, receipt.ExecutionState, receipt.OutputComplete = "fail", state, true
		receipt.OutputClassification, receipt.FinalChunk, receipt.TerminalReason = "complete", true, state
		receipt.RemoteTaskError = sliverTaskError(lines)
		receipt.Error = receipt.RemoteTaskError
		receipt.CompletedAt = receipt.LastRefreshAt
		if len(receipt.OutputChunks) > 0 {
			receipt.OutputChunks[len(receipt.OutputChunks)-1].Final = true
		}
		runtimeadapter.AddTransition(&receipt, state, receipt.RemoteTaskError, now)
	case "pending", "sent", "running":
		receipt.Status, receipt.ExecutionState, receipt.OutputComplete = "incomplete", "running", false
		receipt.OutputClassification = "partial"
		runtimeadapter.AddTransition(&receipt, "running", "Sliver persisted task is not terminal", now)
	default:
		if runErr != nil {
			return receipt, runErr
		}
		return receipt, fmt.Errorf("Sliver task %s returned no recognizable state", receipt.TaskID)
	}
	return receipt, nil
}

func sliverFetchedTaskState(lines []string) string {
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if !strings.Contains(lower, "state") {
			continue
		}
		for _, state := range []string{"completed", "canceled", "failed", "pending", "sent", "running"} {
			if strings.Contains(lower, state) {
				return state
			}
		}
	}
	return ""
}

func sliverTaskError(lines []string) string {
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") || strings.Contains(lower, "failed") {
			return strings.TrimSpace(line)
		}
	}
	return "Sliver task ended without successful completion"
}

func sliverExtensionCommandLine(commandName string, extension sliverExtension, commandArgs []string) (string, error) {
	commandLine := commandName
	if len(commandArgs) > 0 {
		// Sliver v1.7 parses extension values with a second flag parser. The
		// separator keeps Cobra from consuming those manifest-defined flags.
		commandLine += " --"
	}
	for index, value := range commandArgs {
		if index >= len(extension.Arguments) {
			return "", fmt.Errorf("extension command has no definition for argument %d", index+1)
		}
		name := extension.Arguments[index].Name
		if !safeSliverCommand.MatchString(name) {
			return "", fmt.Errorf("extension argument name %q is not safe for the Sliver console", name)
		}
		quoted, err := sliverConsoleQuote(value)
		if err != nil {
			return "", err
		}
		commandLine += " --" + name + " " + quoted
	}
	return commandLine, nil
}

func resolveSliverOptions(opts sliverOptions, project string, requireSession bool) (sliverOptions, error) {
	if opts.Client == "" {
		client, err := discoverSliverClient()
		if err != nil {
			return opts, err
		}
		opts.Client = client
	}
	if opts.Lab != "" || opts.SessionFilter == "" {
		resolved, err := lab.ResolveProfile(opts.Lab, project, opts.Profiles)
		if err != nil {
			if opts.Lab != "" || (opts.SessionFilter == "" && requireSession) {
				return opts, err
			}
		} else if opts.SessionFilter == "" {
			opts.SessionFilter = resolved.Profile.SliverSession
		}
		if err == nil {
			opts.ProfileName = resolved.Name
			opts.RemoteHost = resolved.Profile.Host
		}
	}
	if requireSession && opts.SessionFilter == "" {
		return opts, fmt.Errorf("Sliver session selector is required; set --session or sliver_session in the selected lab profile")
	}
	return opts, nil
}

func sliverOutputComputer(lines []string) string {
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[host] name=") {
			return strings.TrimPrefix(line, "[host] name=")
		}
	}
	return ""
}

func discoverSliverClient() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("BOFBENCH_SLIVER_CLIENT")); configured != "" {
		if info, err := os.Stat(configured); err == nil && !info.IsDir() {
			return configured, nil
		}
		return "", fmt.Errorf("BOFBENCH_SLIVER_CLIENT points to an unavailable file: %s", configured)
	}
	for _, name := range []string{"sliver-client", "sliver"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	platform := runtime.GOOS + "-" + runtime.GOARCH
	candidates := []string{
		filepath.Join("work", "tools", "sliver", "sliver-client_"+platform),
		filepath.Join("work", "tools", "sliver", "sliver-client_macos-arm64"),
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			absolute, _ := filepath.Abs(candidate)
			return absolute, nil
		}
	}
	return "", fmt.Errorf("Sliver client not found; install it, set BOFBENCH_SLIVER_CLIENT, or pass --client")
}

func discoverSliverConfigs() []string {
	seen := map[string]bool{}
	configs := []string{}
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			seen[path] = true
			configs = append(configs, path)
		}
	}
	add(strings.TrimSpace(os.Getenv("BOFBENCH_SLIVER_CONFIG")))
	for _, root := range []string{filepath.Join(sliverClientHome(), "configs"), filepath.Join("work", "sliver-lab", "client")} {
		matches, _ := filepath.Glob(filepath.Join(root, "*.cfg"))
		for _, match := range matches {
			add(match)
		}
	}
	return configs
}

func sliverClientHome() string {
	if configured := strings.TrimSpace(os.Getenv("SLIVER_CLIENT_HOME")); configured != "" {
		return configured
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".sliver-client"
	}
	return filepath.Join(home, ".sliver-client")
}

func sliverConsoleQuote(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("Sliver command arguments cannot contain newlines")
	}
	if value == "" || strings.ContainsAny(value, " \t\"'\\") {
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return runSliverRCContext(ctx, client, body)
}

func runSliverRCContext(ctx context.Context, client, body string) (string, error) {
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
	command := exec.CommandContext(ctx, client, "console", "--rc", path)
	command.Stdin = strings.NewReader(sliverClientSelection() + "\n")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), fmt.Errorf("Sliver console stopped before completion: %w", ctx.Err())
	}
	if err != nil {
		return string(output), fmt.Errorf("Sliver console failed: %w\n%s", err, stripANSI(string(output)))
	}
	return string(output), nil
}

// sliverClientSelection returns the one-based profile number used by the
// interactive Sliver client. The client does not currently accept a config
// path on its command line, so selecting profile 1 unconditionally connects to
// the wrong control plane whenever an operator has more than one profile.
func sliverClientSelection() string {
	selected := strings.TrimSpace(os.Getenv("BOFBENCH_SLIVER_CONFIG"))
	if selected == "" {
		return "1"
	}
	selectedInfo, err := os.Stat(selected)
	if err != nil {
		return "1"
	}
	matches, _ := filepath.Glob(filepath.Join(sliverClientHome(), "configs", "*.cfg"))
	for index, match := range matches {
		matchInfo, statErr := os.Stat(match)
		if statErr == nil && os.SameFile(selectedInfo, matchInfo) {
			return strconv.Itoa(index + 1)
		}
	}
	return "1"
}

func conciseSliverLines(output, _ string) []string {
	var lines []string
	rowsByTag := map[string]int{}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		tag := structuredSliverTag(line)
		if tag == "" || rowsByTag[tag] >= 8 || len(lines) >= 24 {
			continue
		}
		rowsByTag[tag]++
		lines = append(lines, formatSliverReceipt(line))
	}
	if len(lines) == 0 {
		return []string{"output     command completed"}
	}
	return lines
}

func structuredSliverTag(line string) string {
	if !strings.HasPrefix(line, "[") {
		return ""
	}
	end := strings.IndexByte(line, ']')
	if end < 2 || end > 80 {
		return ""
	}
	for _, char := range line[1:end] {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return ""
		}
	}
	return line[1:end]
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
	var labName string
	var profilesPath string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "verify <active|clean>",
		Short: "Verify BOFBench-managed state independently on the Windows lab host",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := lab.ResolveProfile(labName, ".", profilesPath)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			opts, resolveErr := lab.ResolveRemoteOptions(ctx, resolved.Name, resolved.Profile)
			if resolveErr != nil {
				return resolveErr
			}
			switch args[0] {
			case "active":
				return verifyActiveState(ctx, stdout, opts)
			case "clean":
				return verifyCleanState(ctx, stdout, opts)
			default:
				return fmt.Errorf("state must be active or clean")
			}
		},
	}
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile")
	cmd.Flags().StringVar(&profilesPath, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().DurationVar(&timeout, "transport-timeout", 2*time.Minute, "verification timeout")
	return cmd
}

func verifyActiveState(ctx context.Context, stdout io.Writer, opts lab.RemoteOptions) error {
	script := `$ProgressPreference='SilentlyContinue'; $count=0; foreach($path in @("$env:TEMP\bofbench-active-marker.txt","$env:TEMP\bofbench-process-marker.txt")){ if(Test-Path $path){$item=Get-Item $path; Write-Output ("[file] present name="+$item.Name+" bytes="+$item.Length); $count++}}; $marker=Get-ItemPropertyValue -Path HKCU:\Software\BOFBench -Name LabMarker -ErrorAction SilentlyContinue; if($marker){Write-Output ("[registry] LabMarker="+$marker);$count++}; $run=Get-ItemPropertyValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name BOFBenchLab -ErrorAction SilentlyContinue; if($run){Write-Output ("[run-key] BOFBenchLab="+$run);$count++}; if($count -ne 4){Write-Error ("expected 4 BOFBench artifacts; found "+$count);exit 1}; Write-Output "LAB STATE PASS  expected=active artifacts=4"`
	return runRemotePowerShell(ctx, stdout, opts, script)
}

func verifyCleanState(ctx context.Context, stdout io.Writer, opts lab.RemoteOptions) error {
	script := `$ProgressPreference='SilentlyContinue'; $run=Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -ErrorAction SilentlyContinue; $remoteKey=Get-Item -Path HKLM:\Software\BOFBench -ErrorAction SilentlyContinue; $remoteCanary=Get-ItemProperty -Path HKLM:\Software\BOFBench -Name RemoteCanary -ErrorAction SilentlyContinue; $remoteValues=@(); if($remoteKey){$remoteValues=@($remoteKey.GetValueNames()|Where-Object{$_ -like 'BOFBench-Remote-*'})}; $services=@(Get-Service -Name 'BOFBench-*' -ErrorAction SilentlyContinue); $tasks=@(Get-ScheduledTask -TaskName 'BOFBench-*' -ErrorAction SilentlyContinue); $bad=(Test-Path "$env:TEMP\bofbench-active-marker.txt") -or (Test-Path "$env:TEMP\bofbench-process-marker.txt") -or ($null -ne (Get-ItemProperty -Path HKCU:\Software\BOFBench -ErrorAction SilentlyContinue)) -or ($null -ne $run.BOFBenchLab) -or ($null -ne $remoteCanary) -or ($remoteValues.Count -gt 0) -or (Test-Path 'C:\bofbench\target') -or (Test-Path 'C:\bofbench\proof') -or ($services.Count -gt 0) -or ($tasks.Count -gt 0); if($bad){Write-Error "BOFBench-managed state remains";exit 1}; Write-Output "LAB STATE PASS  expected=clean artifacts=0"`
	return runRemotePowerShell(ctx, stdout, opts, script)
}

func runRemotePowerShell(ctx context.Context, stdout io.Writer, opts lab.RemoteOptions, script string) error {
	output, stderr, err := lab.ExecutePowerShell(ctx, opts, script)
	clean := strings.TrimSpace(stripANSI(string(output)))
	if clean != "" {
		fmt.Fprintln(stdout, clean)
	}
	if err != nil {
		return fmt.Errorf("lab check failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	return nil
}
