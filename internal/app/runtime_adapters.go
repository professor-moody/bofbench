package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"bofbench/internal/argpack"
	"bofbench/internal/buildsys"
	"bofbench/internal/config"
	"bofbench/internal/evidence"
	"bofbench/internal/lab"
	"bofbench/internal/runlog"
	runtimesvc "bofbench/internal/runtime"
	"bofbench/internal/runtimeadapter"
	"bofbench/internal/stage"
)

type runtimeRunContext struct {
	stdout                 io.Writer
	input                  string
	projectInput           bool
	entry                  string
	timeout                int
	runtimeName            string
	compiler               string
	arch                   string
	resolved               resolvedRunArguments
	packed                 []byte
	items                  []argpack.Item
	labName                string
	labProfiles            string
	labHost                string
	labRoot                string
	labExecutable          string
	transportTimeout       time.Duration
	bootstrapMode          string
	sliverClient           string
	sliverSession          string
	sensitiveOutputFields  []string
	sensitiveArgumentNames []string
	sensitiveValues        []string
	interactiveLab         bool
}

func runtimeAdapterRegistry(run *runtimeRunContext) (*runtimeadapter.Registry, error) {
	if run == nil {
		return nil, fmt.Errorf("runtime execution context is required")
	}
	makeAdapter := func(name string, detect func(context.Context) (runtimeadapter.Availability, error), sessions func(context.Context) ([]runtimeadapter.Session, error), execute func(context.Context, runtimeadapter.Prepared) (runtimeadapter.Receipt, error)) (runtimeadapter.Adapter, error) {
		return runtimeadapter.New(name, runtimeadapter.Hooks{
			Detect: detect, Sessions: sessions, ConvertArguments: convertRuntimeArguments,
			Prepare: func(_ context.Context, request runtimeadapter.Request) (runtimeadapter.Prepared, error) {
				return runtimeadapter.Prepared{Runtime: name, Request: request, PreparedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
			},
			Execute: execute,
			Cleanup: execute,
		})
	}
	native, err := makeAdapter("native", run.detectNative, run.nativeSessions, run.executeNative)
	if err != nil {
		return nil, err
	}
	remoteLab, err := makeAdapter("lab", run.detectLab, run.labSessions, run.executeLab)
	if err != nil {
		return nil, err
	}
	sliver, err := makeAdapter("sliver", run.detectSliver, run.sliverSessions, run.executeSliver)
	if err != nil {
		return nil, err
	}
	cobaltStrike, err := makeAdapter("cobaltstrike", run.detectCobaltStrike, run.cobaltStrikeSessions, run.executeCobaltStrike)
	if err != nil {
		return nil, err
	}
	return runtimeadapter.NewRegistry(native, remoteLab, sliver, cobaltStrike)
}

func convertRuntimeArguments(arguments []runtimeadapter.Argument) ([]string, error) {
	tokens := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		if argument.Required && argument.Value == "" {
			return nil, fmt.Errorf("missing required runtime argument %q", argument.Name)
		}
		if argument.Value == "" {
			continue
		}
		kind := strings.TrimSpace(argument.Type)
		switch kind {
		case "z", "Z", "i", "s", "b", "x":
			tokens = append(tokens, kind+":"+argument.Value)
		default:
			token, _, err := packArgumentToken(kind, argument.Value)
			if err != nil {
				return nil, fmt.Errorf("runtime argument %q: %w", argument.Name, err)
			}
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

func (run *runtimeRunContext) detectNative(context.Context) (runtimeadapter.Availability, error) {
	return runtimeadapter.Availability{Available: true, Version: runtime.GOOS + "/" + runtime.GOARCH, Detail: "local BOFBench runtime"}, nil
}

func (run *runtimeRunContext) detectLab(ctx context.Context) (runtimeadapter.Availability, error) {
	resolved, err := lab.ResolveProfile(run.labName, run.input, run.labProfiles)
	if err != nil {
		return runtimeadapter.Availability{Detail: err.Error()}, nil
	}
	opts, err := lab.ResolveRemoteOptions(ctx, resolved.Name, resolved.Profile)
	if err != nil {
		return runtimeadapter.Availability{Detail: err.Error()}, nil
	}
	return runtimeadapter.Availability{Available: true, Detail: opts.Transport + "://" + opts.Host}, nil
}

func (run *runtimeRunContext) detectSliver(context.Context) (runtimeadapter.Availability, error) {
	client := run.sliverClient
	if client == "" {
		var err error
		client, err = discoverSliverClient()
		if err != nil {
			return runtimeadapter.Availability{Detail: err.Error()}, nil
		}
	}
	if _, err := os.Stat(filepath.Join(sliverClientHome(), "extensions", "coff-loader", "extension.json")); err != nil {
		return runtimeadapter.Availability{Detail: "coff-loader is not installed"}, nil
	}
	return runtimeadapter.Availability{Available: true, Detail: client}, nil
}

func (run *runtimeRunContext) detectCobaltStrike(context.Context) (runtimeadapter.Availability, error) {
	agscript := strings.TrimSpace(os.Getenv("BOFBENCH_CS_AGSCRIPT"))
	if agscript == "" {
		agscript = "agscript"
	}
	path, err := exec.LookPath(agscript)
	if err != nil {
		return runtimeadapter.Availability{Detail: "licensed agscript client is unavailable"}, nil
	}
	return runtimeadapter.Availability{Available: true, Detail: path}, nil
}

func (run *runtimeRunContext) nativeSessions(context.Context) ([]runtimeadapter.Session, error) {
	host, err := os.Hostname()
	if err != nil {
		host = "local"
	}
	return []runtimeadapter.Session{{ID: "local", Name: "local", Host: host, OS: runtime.GOOS, Arch: runtime.GOARCH, Status: "ready", Selected: true}}, nil
}

func (run *runtimeRunContext) labSessions(ctx context.Context) ([]runtimeadapter.Session, error) {
	resolved, err := lab.ResolveProfile(run.labName, run.input, run.labProfiles)
	if err != nil {
		return nil, err
	}
	opts, err := lab.ResolveRemoteOptions(ctx, resolved.Name, resolved.Profile)
	if err != nil {
		return nil, err
	}
	return []runtimeadapter.Session{{ID: resolved.Name, Name: resolved.Name, Host: opts.Host, OS: "windows", Status: "configured", Selected: true}}, nil
}

func (run *runtimeRunContext) sliverSessions(context.Context) ([]runtimeadapter.Session, error) {
	opts := sliverOptions{Client: run.sliverClient, SessionFilter: run.sliverSession, Lab: run.labName, Profiles: run.labProfiles}
	resolved, err := resolveSliverOptions(opts, run.input, true)
	if err != nil {
		return nil, err
	}
	session, err := findSliverSession(resolved)
	if err != nil {
		return nil, err
	}
	return []runtimeadapter.Session{{ID: session, Name: session, Host: resolved.RemoteHost, OS: "windows", Status: "alive", Selected: true}}, nil
}

func (run *runtimeRunContext) cobaltStrikeSessions(context.Context) ([]runtimeadapter.Session, error) {
	beacon := strings.TrimSpace(os.Getenv("BOFBENCH_CS_BEACON"))
	if beacon == "" {
		return nil, nil
	}
	return []runtimeadapter.Session{{ID: beacon, Name: beacon, Status: "selected", Selected: true}}, nil
}

func (run *runtimeRunContext) executeLab(ctx context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
	if !run.projectInput {
		return runtimeadapter.Receipt{}, fmt.Errorf("lab execution requires a project directory so BOFBench can sync its source and lockfile")
	}
	if run.transportTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, run.transportTimeout)
		defer cancel()
	}
	resolvedLab, err := lab.ResolveProfile(run.labName, run.input, run.labProfiles)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	remoteOptions, err := lab.ResolveRemoteOptions(ctx, resolvedLab.Name, resolvedLab.Profile)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	if run.labHost != "" {
		remoteOptions.Host = run.labHost
	}
	if run.labRoot != "" {
		remoteOptions.RemoteRoot = run.labRoot
		remoteOptions.Executable = ""
	}
	if run.labExecutable != "" {
		remoteOptions.Executable = run.labExecutable
	}
	ensured, err := lab.EnsureRuntime(ctx, run.bootstrapMode, lab.BootstrapOptions{ProfileName: resolvedLab.Name, Profile: resolvedLab.Profile})
	if err != nil {
		return runtimeadapter.Receipt{}, codedError{code: 1, err: err}
	}
	if ensured.Bootstrap != nil {
		fmt.Fprint(run.stdout, lab.BootstrapText(*ensured.Bootstrap))
	}
	report, runErr := lab.RemoteRun(ctx, run.input, lab.RemoteRunOptions{
		RemoteOptions: remoteOptions, Compiler: run.compiler, Arch: run.arch,
		Runtime: "windows-coff", Args: run.resolved.Tokens, TimeoutMS: run.timeout,
		SensitiveArguments: run.resolved.Sensitive, SensitiveArgumentNames: run.sensitiveArgumentNames,
		SensitiveOutputFields: run.sensitiveOutputFields, SensitiveValues: run.sensitiveValues,
		Interactive: run.interactiveLab,
	})
	fmt.Fprint(run.stdout, lab.RemoteRunText(report))
	receipt := runtimeadapter.Receipt{}
	if report.Receipt != nil {
		receipt = *report.Receipt
	}
	if runErr != nil {
		return receipt, codedError{code: 1, err: runErr}
	}
	return receipt, nil
}

func (run *runtimeRunContext) executeSliver(ctx context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
	profileName, remoteHost := "", ""
	selector := run.sliverSession
	if run.labName != "" || selector == "" {
		resolvedLab, resolveErr := lab.ResolveProfile(run.labName, run.input, run.labProfiles)
		if resolveErr != nil {
			if selector == "" {
				return runtimeadapter.Receipt{}, resolveErr
			}
		} else {
			if selector == "" {
				selector = resolvedLab.Profile.SliverSession
			}
			profileName = resolvedLab.Name
			if remote, remoteErr := lab.ResolveRemoteOptions(ctx, resolvedLab.Name, resolvedLab.Profile); remoteErr == nil {
				remoteHost = remote.Host
			} else {
				remoteHost = resolvedLab.Profile.Host
			}
		}
	}
	if selector == "" {
		return runtimeadapter.Receipt{}, fmt.Errorf("Sliver session selector is required; set --session or sliver_session in the selected lab profile")
	}
	client := run.sliverClient
	if client == "" {
		var err error
		client, err = discoverSliverClient()
		if err != nil {
			return runtimeadapter.Receipt{}, err
		}
	}
	options, err := prepareStageOptions(stageInputOptions{
		Input: run.input, Target: "sliver", Entrypoint: run.entry, ArgumentTokens: run.resolved.Tokens,
		ArgumentNames: run.resolved.Names, ArgumentOptional: run.resolved.Optional, ArgumentsExplicit: true,
		Compiler: run.compiler, Runtime: run.runtimeName, SkipRun: true,
	})
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	result, err := stage.StageWithOptions(options)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	return executeSliverExtension(run.stdout, sliverOptions{Client: client, SessionFilter: selector, ProfileName: profileName, RemoteHost: remoteHost, SensitiveOutputFields: run.sensitiveOutputFields, SensitiveArgumentNames: run.sensitiveArgumentNames, SensitiveValues: run.sensitiveValues}, result.Output, "", run.resolved.CLIValues)
}

func (run *runtimeRunContext) executeCobaltStrike(ctx context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
	return executeCobaltStrike(ctx, run.stdout, cobaltStrikeRunOptions{
		Input: run.input, Entrypoint: run.entry, Compiler: run.compiler, Runtime: run.runtimeName,
		ArgumentTokens: run.resolved.Tokens, ArgumentNames: run.resolved.Names,
		ArgumentOptional: run.resolved.Optional, CLIValues: run.resolved.CLIValues,
		SensitiveOutputFields: run.sensitiveOutputFields, SensitiveArgumentNames: run.sensitiveArgumentNames, SensitiveValues: run.sensitiveValues,
	})
}

func (run *runtimeRunContext) executeNative(_ context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
	object := run.input
	if run.projectInput {
		build, err := buildsys.BuildWithOptions(run.input, buildsys.Options{Arch: run.arch, Compiler: run.compiler})
		if err != nil {
			return runtimeadapter.Receipt{}, codedError{code: 1, err: err}
		}
		object = build.Object
		cfg, _, cfgErr := config.LoadFor(run.input)
		if cfgErr == nil {
			if run.entry == "go" && cfg.Entrypoint != "" {
				run.entry = cfg.Entrypoint
			}
			if run.timeout == 5000 && cfg.TimeoutMS > 0 {
				run.timeout = cfg.TimeoutMS
			}
		}
	}
	runDir, err := runlog.NewDir("run-" + safeName(objectBase(run.input)))
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	started := time.Now()
	result, runErr := runtimesvc.Run(runtimesvc.Request{
		Path: object, Entry: run.entry, ArgHex: argpack.Hex(run.packed), Tokens: run.resolved.Tokens,
		TimeoutMS: run.timeout, Runtime: run.runtimeName,
	})
	result.Header = evidence.New(evidence.SchemaRun, runlog.ID(runDir), "")
	persisted := run.redactResult(result)
	_ = os.WriteFile(filepath.Join(runDir, "result.md"), []byte(runMarkdown(persisted, run.redactItems(run.items))), 0o644)
	_ = writeJSON(filepath.Join(runDir, "runtime.json"), persisted)
	receipt := persistNativeRuntimeReceipt(runDir, started, persisted, run.items, runErr, run)
	_ = printJSON(run.stdout, result)
	if runErr != nil {
		return receipt, codedError{code: 1, err: runErr}
	}
	if result.Status != "pass" {
		return receipt, codedError{code: 1, err: fmt.Errorf("payload run failed: %s", result.ExitState)}
	}
	return receipt, nil
}

func persistNativeRuntimeReceipt(runDir string, started time.Time, result runtimesvc.Result, arguments []argpack.Item, operationErr error, run *runtimeRunContext) runtimeadapter.Receipt {
	receipt := runtimeadapter.Receipt{
		Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion,
		Runtime: "native", Status: "fail", ExecutionState: "failed", Object: result.Object, Entrypoint: result.Entry,
		Output: cleanRuntimeOutput(result.Output), ExitState: result.ExitState,
		StartedAt: started.UTC().Format(time.RFC3339Nano), CompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		DurationMS: result.DurationMS, TimedOut: result.ExitState == "timeout", ReceiptPath: filepath.Join(runDir, "result.json"),
	}
	runtimeadapter.AddTransition(&receipt, "submitted", "native loader child prepared", started)
	runtimeadapter.AddTransition(&receipt, "running", "BOF entrypoint invoked", started)
	if result.Status == "pass" && operationErr == nil {
		receipt.Status = "pass"
		receipt.ExecutionState = "completed"
		receipt.OutputComplete = true
		runtimeadapter.AddTransition(&receipt, "completed", "native loader returned complete output", time.Now())
	} else if result.ExitState == "timeout" {
		receipt.ExecutionState = "timeout"
		runtimeadapter.AddTransition(&receipt, "timeout", "native loader timed out", time.Now())
	} else {
		runtimeadapter.AddTransition(&receipt, "failed", emptyText(receipt.Error, result.ExitState), time.Now())
	}
	if result.ObjectFingerprint != nil {
		receipt.ObjectSHA256 = result.ObjectFingerprint.SHA256
	}
	if result.LoaderProcess != nil {
		receipt.ExitCode = result.LoaderProcess.ExitCode
	}
	for _, argument := range arguments {
		receipt.Arguments = append(receipt.Arguments, argument.Kind)
	}
	if operationErr != nil {
		receipt.Error = operationErr.Error()
	} else if len(result.Errors) > 0 {
		receipt.Error = strings.Join(result.Errors, "; ")
	}
	receipt = run.redactReceipt(receipt)
	_ = writeJSON(receipt.ReceiptPath, receipt)
	return receipt
}

func cleanRuntimeOutput(lines []string) []string {
	clean := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			clean = append(clean, line)
		}
	}
	return clean
}
