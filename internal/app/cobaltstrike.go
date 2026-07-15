package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"bofbench/internal/argpack"
	"bofbench/internal/runlog"
	"bofbench/internal/runtimeadapter"
	"bofbench/internal/stage"
)

type cobaltStrikeRunOptions struct {
	Input                  string
	Entrypoint             string
	Compiler               string
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
		ArgumentNames: opts.ArgumentNames, ArgumentOptional: opts.ArgumentOptional, ArgumentsExplicit: true, Compiler: opts.Compiler, Runtime: opts.Runtime, SkipRun: true,
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
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
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
		receipt.Status = "submitted"
		receipt.ExecutionState = "submitted"
		receipt.OutputComplete = false
		receipt.ExitState = "submitted"
		runtimeadapter.AddTransition(&receipt, "acknowledged", "Cobalt Strike accepted the inline-execute request", time.Now())
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
	receipt = redactReceiptValues(receipt, opts.SensitiveOutputFields, opts.SensitiveArgumentNames, opts.SensitiveValues)
	_ = writeJSON(receipt.ReceiptPath, receipt)
	if printErr := printJSON(stdout, receipt); printErr != nil {
		return receipt, printErr
	}
	if runErr != nil {
		return receipt, codedError{code: 1, err: runErr}
	}
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
	b.WriteString("on ready {\n")
	fmt.Fprintf(&b, "  local('%s');\n", strings.Join(locals, " "))
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
	fmt.Fprintf(&b, "  beacon_inline_execute(%s, $bofbench_object, %s, $bofbench_args);\n", sleepString(beacon), sleepString(entry))
	fmt.Fprintf(&b, "  println(\"BOFBENCH_TASK_SUBMITTED beacon=%s\");\n", sleepEscapeInline(beacon))
	b.WriteString("  sleep(5000);\n  closeClient();\n}\n")
	b.WriteString("on beacon_output { println($2); }\n")
	return b.String(), types, nil
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
