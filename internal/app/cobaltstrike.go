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
	"strconv"
	"strings"
	"time"

	"bofbench/internal/argpack"
	"bofbench/internal/runlog"
	"bofbench/internal/runtimeadapter"
	"bofbench/internal/stage"
)

var (
	cobaltCallbackPattern = regexp.MustCompile(`BOFBENCH_CALLBACK\s+type=([A-Za-z_]+)\s+chunk=([0-9]+)\s+final=([01])(?:\s+task=([^\s]+))?`)
	cobaltTimeoutMarker   = "BOFBENCH_CALLBACK_TIMEOUT"
)

type cobaltStrikeRunOptions struct {
	Input                  string
	Entrypoint             string
	Compiler               string
	Arch                   string
	Runtime                string
	ArgumentTokens         []string
	ArgumentNames          []string
	ArgumentOptional       []bool
	CLIValues              []string
	SensitiveOutputFields  []string
	SensitiveArgumentNames []string
	SensitiveValues        []string
}

func runCobaltStrike(stdout io.Writer, opts cobaltStrikeRunOptions) error {
	_, err := executeCobaltStrike(context.Background(), stdout, opts)
	return err
}

func executeCobaltStrike(parent context.Context, stdout io.Writer, opts cobaltStrikeRunOptions) (runtimeadapter.Receipt, error) {
	host := strings.TrimSpace(os.Getenv("BOFBENCH_CS_HOST"))
	port := strings.TrimSpace(os.Getenv("BOFBENCH_CS_PORT"))
	user := strings.TrimSpace(os.Getenv("BOFBENCH_CS_USER"))
	password := os.Getenv("BOFBENCH_CS_PASSWORD")
	beacon := strings.TrimSpace(os.Getenv("BOFBENCH_CS_BEACON"))
	agscript := strings.TrimSpace(os.Getenv("BOFBENCH_CS_AGSCRIPT"))
	if agscript == "" {
		agscript = "agscript"
	}
	var missing []string
	for name, value := range map[string]string{"BOFBENCH_CS_HOST": host, "BOFBENCH_CS_PORT": port, "BOFBENCH_CS_USER": user, "BOFBENCH_CS_PASSWORD": password, "BOFBENCH_CS_BEACON": beacon} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return runtimeadapter.Receipt{}, fmt.Errorf("Cobalt Strike execution needs %s in the environment; credentials are never read from a project", strings.Join(missing, ", "))
	}
	if _, err := exec.LookPath(agscript); err != nil {
		return runtimeadapter.Receipt{}, fmt.Errorf("licensed Cobalt Strike agscript client %q was not found: %w", agscript, err)
	}
	options, err := prepareStageOptions(stageInputOptions{
		Input: opts.Input, Target: "cobaltstrike", Entrypoint: opts.Entrypoint, ArgumentTokens: opts.ArgumentTokens,
		ArgumentNames: opts.ArgumentNames, ArgumentOptional: opts.ArgumentOptional, ArgumentsExplicit: true, Compiler: opts.Compiler, Arch: opts.Arch, Runtime: opts.Runtime, SkipRun: true,
	})
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	staged, err := stage.StageWithOptions(options)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	manifest, err := loadStageManifest(staged.Manifest)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	object := filepath.Join(staged.Output, filepath.FromSlash(manifest.StagedObject))
	script, argumentTypes, err := cobaltAutomationScript(beacon, object, manifest.Entrypoint, opts.ArgumentTokens, opts.CLIValues)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	temp, err := os.CreateTemp("", "bofbench-cobaltstrike-*.cna")
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	scriptPath := temp.Name()
	defer os.Remove(scriptPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return runtimeadapter.Receipt{}, err
	}
	if _, err := temp.WriteString(script); err != nil {
		temp.Close()
		return runtimeadapter.Receipt{}, err
	}
	if err := temp.Close(); err != nil {
		return runtimeadapter.Receipt{}, err
	}
	runDir, err := runlog.NewDir("cobaltstrike-" + safeName(filepath.Base(opts.Input)))
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	started := time.Now()
	receipt := runtimeadapter.Receipt{
		Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion,
		Runtime: "cobaltstrike", Status: "fail", ExecutionState: "failed", Transport: "agscript", RemoteHost: host + ":" + port,
		Session: beacon, Object: object, Entrypoint: manifest.Entrypoint, Arguments: argumentTypes,
		TimeoutMS: 90000, StartedAt: started.UTC().Format(time.RFC3339Nano), ReceiptPath: filepath.Join(runDir, "result.json"),
	}
	runtimeadapter.AddTransition(&receipt, "submitted", "Aggressor client started", started)
	ctx, cancel := context.WithTimeout(parent, 100*time.Second)
	defer cancel()
	output, runErr := exec.CommandContext(ctx, agscript, host, port, user, password, scriptPath).CombinedOutput()
	clean := strings.TrimSpace(stripANSI(string(output)))
	if clean != "" {
		receipt.Output = strings.Split(clean, "\n")
	}
	if ctx.Err() == context.DeadlineExceeded {
		runErr = fmt.Errorf("Cobalt Strike execution timed out waiting for task output")
		receipt.TimedOut = true
	}
	if runErr == nil && strings.Contains(clean, "BOFBENCH_TASK_SUBMITTED") {
		callbackState, chunks, taskID, remoteError := parseCobaltCallbacks(strings.Split(clean, "\n"))
		receipt.OutputChunks = chunks
		receipt.TaskID = taskID
		receipt.CompletionSource = "cobaltstrike-callback"
		receipt.RemoteTaskError = remoteError
		switch callbackState {
		case "completed":
			receipt.Status, receipt.ExecutionState, receipt.OutputComplete = "pass", "completed", true
			receipt.OutputClassification, receipt.FinalChunk, receipt.ExitState, receipt.TerminalReason = "complete", true, "success", "task_completed"
			runtimeadapter.AddTransition(&receipt, "completed", "Cobalt Strike callback reported task completion", time.Now())
		case "failed":
			receipt.Status, receipt.ExecutionState, receipt.OutputComplete = "fail", "failed", true
			receipt.OutputClassification, receipt.FinalChunk, receipt.ExitState, receipt.TerminalReason = "complete", true, "error", "callback_error"
			receipt.Error = remoteError
			runtimeadapter.AddTransition(&receipt, "failed", remoteError, time.Now())
			runErr = fmt.Errorf("%s", emptyText(remoteError, "Cobalt Strike callback reported failure"))
		case "canceled":
			receipt.Status, receipt.ExecutionState, receipt.OutputComplete = "canceled", "canceled", false
			receipt.OutputClassification, receipt.FinalChunk, receipt.ExitState, receipt.TerminalReason = "partial", true, "canceled", "task_canceled"
			receipt.CanceledAt = time.Now().UTC().Format(time.RFC3339Nano)
			runtimeadapter.AddTransition(&receipt, "canceled", "Cobalt Strike callback reported task cancellation", time.Now())
		case "timeout":
			receipt.Status, receipt.ExecutionState, receipt.OutputComplete = "fail", "timeout", false
			receipt.OutputClassification, receipt.ExitState, receipt.TerminalReason = "partial", "timeout", "callback_timeout"
			receipt.TimedOut = true
			receipt.Error = "Cobalt Strike task did not deliver a terminal callback before timeout"
			runtimeadapter.AddTransition(&receipt, "timeout", receipt.Error, time.Now())
			runErr = fmt.Errorf("%s", receipt.Error)
		default:
			receipt.Status, receipt.ExecutionState, receipt.OutputComplete = "submitted", "submitted", false
			receipt.OutputClassification, receipt.ExitState = "partial", "submitted"
			runtimeadapter.AddTransition(&receipt, "acknowledged", "Cobalt Strike accepted the inline-execute request without terminal callback", time.Now())
		}
	} else if runErr == nil {
		runErr = fmt.Errorf("agscript exited without confirming BOF task submission")
	}
	if runErr != nil {
		receipt.Error = runErr.Error()
		receipt.ExitState = "error"
		if receipt.TimedOut {
			receipt.ExecutionState = "timeout"
			runtimeadapter.AddTransition(&receipt, "timeout", receipt.Error, time.Now())
		} else {
			runtimeadapter.AddTransition(&receipt, "failed", receipt.Error, time.Now())
		}
	}
	receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	receipt.DurationMS = time.Since(started).Milliseconds()
	rawOutput := append([]string(nil), receipt.Output...)
	receipt = redactReceiptValues(receipt, opts.SensitiveOutputFields, opts.SensitiveArgumentNames, opts.SensitiveValues)
	receipt.TransientOutput = rawOutput
	_ = writeJSON(receipt.ReceiptPath, receipt)
	if printErr := printJSON(stdout, receipt); printErr != nil {
		return receipt, printErr
	}
	if runErr != nil {
		return receipt, codedError{code: 1, err: runErr}
	}
	return receipt, nil
}

func refreshCobaltStrikeRuntimeReceipt(_ context.Context, receipt runtimeadapter.Receipt) (runtimeadapter.Receipt, error) {
	if runtimeTaskTerminal(receipt.ExecutionState) {
		return receipt, nil
	}
	now := time.Now().UTC()
	receipt.LastRefreshAt = now.Format(time.RFC3339Nano)
	receipt.CompletionSource = "cobaltstrike-callback"
	if strings.TrimSpace(receipt.ReceiptPath) != "" {
		if data, err := os.ReadFile(receipt.ReceiptPath); err == nil {
			var persisted runtimeadapter.Receipt
			if json.Unmarshal(data, &persisted) == nil {
				normalized, normalizeErr := runtimeadapter.NormalizeReceipt(persisted)
				if normalizeErr == nil && (runtimeTaskTerminal(normalized.ExecutionState) || len(normalized.OutputChunks) > len(receipt.OutputChunks)) {
					normalized.LastRefreshAt = receipt.LastRefreshAt
					return normalized, nil
				}
			}
		}
	}
	receipt.OutputClassification = "partial"
	return receipt, nil
}

func loadStageManifest(path string) (stage.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return stage.Manifest{}, err
	}
	var manifest stage.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return stage.Manifest{}, err
	}
	return manifest, nil
}

func cobaltAutomationScript(beacon, object, entry string, tokens, cliValues []string) (string, []string, error) {
	items, err := argpack.ParseTokens(tokens)
	if err != nil {
		return "", nil, err
	}
	if len(items) != len(cliValues) {
		return "", nil, fmt.Errorf("Cobalt Strike argument contract mismatch")
	}
	format := ""
	var setup []string
	var values []string
	var types []string
	for index, item := range items {
		format += item.Kind
		types = append(types, item.Kind)
		if item.Kind == "b" || item.Kind == "x" {
			handle := fmt.Sprintf("$bofbench_handle_%d", index)
			data := fmt.Sprintf("$bofbench_data_%d", index)
			setup = append(setup, fmt.Sprintf("  %s = openf(%s);", handle, sleepString(cliValues[index])), fmt.Sprintf("  %s = readb(%s, -1);", data, handle), fmt.Sprintf("  closef(%s);", handle))
			values = append(values, data)
		} else if item.Kind == "i" || item.Kind == "s" {
			if _, err := strconv.ParseInt(item.Value, 0, 32); err != nil {
				return "", nil, err
			}
			values = append(values, item.Value)
		} else {
			values = append(values, sleepString(item.Value))
		}
	}
	locals := []string{"$bofbench_handle", "$bofbench_object", "$bofbench_args"}
	for index, item := range items {
		if item.Kind == "b" || item.Kind == "x" {
			locals = append(locals, fmt.Sprintf("$bofbench_handle_%d", index), fmt.Sprintf("$bofbench_data_%d", index))
		}
	}
	var b strings.Builder
	b.WriteString("# Ephemeral BOFBench licensed Cobalt Strike adapter\n")
	b.WriteString("global('$bofbench_done $bofbench_failed');\n")
	b.WriteString("sub bofbench_callback {\n")
	b.WriteString("  local('$type $chunk $final $task');\n")
	b.WriteString("  $type = $3[\"type\"];\n  $chunk = $3[\"chunk_num\"];\n  $final = $3[\"is_final\"];\n  $task = $3[\"task_id\"];\n")
	b.WriteString("  if ($task eq \"\") { $task = $3[\"jid\"]; }\n")
	b.WriteString("  println(\"BOFBENCH_CALLBACK type=\" $+ $type $+ \" chunk=\" $+ $chunk $+ \" final=\" $+ $final $+ \" task=\" $+ $task);\n")
	b.WriteString("  if ($2 ne \"\") { println($2); }\n")
	b.WriteString("  if ($type eq \"error\") { $bofbench_failed = 1; $bofbench_done = 1; }\n")
	b.WriteString("  if ($type eq \"task_completed\" || $type eq \"task_canceled\" || $type eq \"canceled\" || $type eq \"job_completed\" || $final) { $bofbench_done = 1; }\n")
	b.WriteString("}\n")
	b.WriteString("on ready {\n")
	locals = append(locals, "$bofbench_elapsed")
	fmt.Fprintf(&b, "  local('%s');\n", strings.Join(locals, " "))
	b.WriteString("  $bofbench_done = 0; $bofbench_failed = 0; $bofbench_elapsed = 0;\n")
	fmt.Fprintf(&b, "  $bofbench_handle = openf(%s);\n", sleepString(object))
	b.WriteString("  $bofbench_object = readb($bofbench_handle, -1);\n  closef($bofbench_handle);\n")
	for _, line := range setup {
		b.WriteString(line + "\n")
	}
	if len(items) == 0 {
		b.WriteString("  $bofbench_args = \"\";\n")
	} else {
		fmt.Fprintf(&b, "  $bofbench_args = bof_pack(%s, %s", sleepString(beacon), sleepString(format))
		for _, value := range values {
			b.WriteString(", " + value)
		}
		b.WriteString(");\n")
	}
	fmt.Fprintf(&b, "  beacon_inline_execute(%s, $bofbench_object, %s, $bofbench_args, &bofbench_callback);\n", sleepString(beacon), sleepString(entry))
	fmt.Fprintf(&b, "  println(\"BOFBENCH_TASK_SUBMITTED beacon=%s\");\n", sleepEscapeInline(beacon))
	b.WriteString("  while (!$bofbench_done && $bofbench_elapsed < 90000) { sleep(250); $bofbench_elapsed += 250; }\n")
	b.WriteString("  if (!$bofbench_done) { println(\"BOFBENCH_CALLBACK_TIMEOUT\"); }\n")
	b.WriteString("  closeClient();\n}\n")
	return b.String(), types, nil
}

func parseCobaltCallbacks(lines []string) (string, []runtimeadapter.OutputChunk, string, string) {
	state, taskID, remoteError := "submitted", "", ""
	var chunks []runtimeadapter.OutputChunk
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for index, line := range lines {
		if strings.Contains(line, cobaltTimeoutMarker) {
			state = "timeout"
			continue
		}
		match := cobaltCallbackPattern.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		number, _ := strconv.Atoi(match[2])
		final := match[3] == "1"
		if match[4] != "" && match[4] != "null" {
			taskID = match[4]
		}
		chunk := runtimeadapter.OutputChunk{Number: number, Final: final, ReceivedAt: now}
		if index+1 < len(lines) && !strings.Contains(lines[index+1], "BOFBENCH_CALLBACK") {
			chunk.LineCount = 1
		}
		chunks = append(chunks, chunk)
		switch match[1] {
		case "error", "failed":
			state = "failed"
			if index+1 < len(lines) {
				remoteError = strings.TrimSpace(lines[index+1])
			}
		case "task_canceled", "canceled", "cancelled":
			state = "canceled"
		case "task_completed", "job_completed", "success":
			state = "completed"
		default:
			if final && state != "failed" {
				state = "completed"
			}
		}
	}
	return state, chunks, taskID, remoteError
}

func sleepString(value string) string {
	return `"` + sleepEscapeInline(value) + `"`
}

func sleepEscapeInline(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\r", `\r`)
	return strings.ReplaceAll(value, "\n", `\n`)
}
