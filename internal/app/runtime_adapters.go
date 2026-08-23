package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/argpack"
	"github.com/professor-moody/bofbench/internal/buildsys"
	"github.com/professor-moody/bofbench/internal/config"
	"github.com/professor-moody/bofbench/internal/evidence"
	"github.com/professor-moody/bofbench/internal/lab"
	"github.com/professor-moody/bofbench/internal/runlog"
	runtimesvc "github.com/professor-moody/bofbench/internal/runtime"
	"github.com/professor-moody/bofbench/internal/runtimeadapter"
	"github.com/professor-moody/bofbench/internal/stage"
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
	sliverControl          string
	runtimeControls        string
	sensitiveOutputFields  []string
	sensitiveArgumentNames []string
	sensitiveValues        []string
	interactiveLab         bool
	forceLocalLab          bool
	observe                string
	progress               func(string)
	controller             func(lab.RemoteTaskController)
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
			Start: func(ctx context.Context, prepared runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
				if name == "sliver" || name == "cobaltstrike" {
					return execute(ctx, prepared)
				}
				return run.startRuntimeTask(ctx, name, prepared, execute)
			},
			Execute: execute,
			Refresh: run.refreshRuntimeReceipt,
			Cancel:  run.cancelRuntimeReceipt,
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

func (run *runtimeRunContext) refreshRuntimeReceipt(ctx context.Context, receipt runtimeadapter.Receipt) (runtimeadapter.Receipt, error) {
	normalized, err := runtimeadapter.NormalizeReceipt(receipt)
	if err != nil {
		return receipt, err
	}
	switch normalized.Runtime {
	case "native", "lab":
		if normalized.ReceiptPath == "" {
			return normalized, nil
		}
		data, readErr := os.ReadFile(normalized.ReceiptPath)
		if readErr != nil {
			return normalized, readErr
		}
		var updated runtimeadapter.Receipt
		if err := json.Unmarshal(data, &updated); err != nil {
			return normalized, err
		}
		if updated.CancelRequestedAt != "" && !runtimeTaskTerminal(updated.ExecutionState) {
			runtimeTasks.Lock()
			task, ok := runtimeTasks.items[updated.TaskID]
			if !ok {
				task, ok = runtimeTasks.items[updated.ReceiptPath]
			}
			runtimeTasks.Unlock()
			if ok {
				task.cancel()
			}
		}
		return runtimeadapter.NormalizeReceipt(updated)
	case "sliver":
		return refreshSliverRuntimeReceipt(ctx, normalized, sliverOptions{Client: run.sliverClient, SessionFilter: normalized.Session, Lab: run.labName, Profiles: run.labProfiles, Control: run.sliverControl, Controls: run.runtimeControls, ProfileName: normalized.Profile, RemoteHost: normalized.RemoteHost})
	case "cobaltstrike":
		return refreshCobaltStrikeRuntimeReceipt(ctx, normalized)
	default:
		return normalized, fmt.Errorf("runtime %s does not support receipt refresh", normalized.Runtime)
	}
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
	if resolved.Profile.Provider == "operator-lab" {
		if resolved.Profile.OperatorLab == nil {
			return runtimeadapter.Availability{Detail: "operator-lab profile configuration is missing"}, nil
		}
		client, clientErr := lab.NewOperatorLabClient(*resolved.Profile.OperatorLab)
		if clientErr != nil {
			return runtimeadapter.Availability{Detail: clientErr.Error()}, nil
		}
		if doctorErr := client.Doctor(ctx); doctorErr != nil {
			return runtimeadapter.Availability{Detail: doctorErr.Error()}, nil
		}
		return runtimeadapter.Availability{Available: true, Version: "operator-lab/v1", Detail: resolved.Profile.OperatorLab.Profile + " (disposable lease)"}, nil
	}
	opts, err := lab.ResolveRemoteOptions(ctx, resolved.Name, resolved.Profile)
	if err != nil {
		return runtimeadapter.Availability{Detail: err.Error()}, nil
	}
	return runtimeadapter.Availability{Available: true, Detail: opts.Transport + "://" + opts.Host}, nil
}

func (run *runtimeRunContext) detectSliver(ctx context.Context) (runtimeadapter.Availability, error) {
	opts, err := resolveSliverOptions(ctx, sliverOptions{Client: run.sliverClient, Lab: run.labName, Profiles: run.labProfiles, Control: run.sliverControl, Controls: run.runtimeControls}, run.input, false)
	if err != nil {
		return runtimeadapter.Availability{Detail: err.Error()}, nil
	}
	loaderPath := filepath.Join(sliverClientHome(), "extensions", "coff-loader", "extension.json")
	detail := opts.Client
	if opts.RemoteClient != nil {
		if err := sliverRemotePreflight(ctx, opts.RemoteClient); err != nil {
			return runtimeadapter.Availability{Detail: err.Error()}, nil
		}
		loaderPath = filepath.Join(opts.RemoteClient.Home, "extensions", "coff-loader", "extension.json")
		detail = fmt.Sprintf("ssh://%s@%s (%s)", opts.RemoteClient.User, opts.RemoteClient.Host, opts.Control)
		if !sliverRemoteFileExists(ctx, opts.RemoteClient, loaderPath) {
			return runtimeadapter.Availability{Detail: "coff-loader is not installed on remote control " + opts.Control}, nil
		}
	} else if _, err := os.Stat(loaderPath); err != nil {
		return runtimeadapter.Availability{Detail: "coff-loader is not installed"}, nil
	}
	return runtimeadapter.Availability{Available: true, Detail: detail}, nil
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
	if resolved.Profile.Provider == "operator-lab" {
		if resolved.Profile.OperatorLab == nil {
			return nil, fmt.Errorf("operator-lab settings are missing")
		}
		return []runtimeadapter.Session{{ID: resolved.Name, Name: resolved.Name, Host: resolved.Profile.OperatorLab.Profile, OS: "windows", Arch: "x64", Status: "lease-on-run", Selected: true}}, nil
	}
	opts, err := lab.ResolveRemoteOptions(ctx, resolved.Name, resolved.Profile)
	if err != nil {
		return nil, err
	}
	return []runtimeadapter.Session{{ID: resolved.Name, Name: resolved.Name, Host: opts.Host, OS: "windows", Status: "configured", Selected: true}}, nil
}

func (run *runtimeRunContext) sliverSessions(ctx context.Context) ([]runtimeadapter.Session, error) {
	opts := sliverOptions{Client: run.sliverClient, SessionFilter: run.sliverSession, Lab: run.labName, Profiles: run.labProfiles, Control: run.sliverControl, Controls: run.runtimeControls}
	resolved, err := resolveSliverOptions(ctx, opts, run.input, true)
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
	var remoteOptions lab.RemoteOptions
	var operatorClient *lab.OperatorLabClient
	var operatorLease lab.OperatorLabLease
	var stopHeartbeat func()
	var heartbeatErrors <-chan error
	released := false
	if resolvedLab.Profile.Provider == "operator-lab" {
		if resolvedLab.Profile.OperatorLab == nil {
			return runtimeadapter.Receipt{}, fmt.Errorf("operator-lab settings are missing")
		}
		operatorClient, err = lab.NewOperatorLabClient(*resolvedLab.Profile.OperatorLab)
		if err != nil {
			return runtimeadapter.Receipt{}, err
		}
		ttl := run.transportTimeout
		if ttl < time.Minute {
			ttl = time.Hour
		}
		operatorLease, err = operatorClient.Acquire(ctx, resolvedLab.Profile.OperatorLab.Profile, ttl)
		if err != nil {
			return runtimeadapter.Receipt{}, err
		}
		leaseDir, dirErr := runlog.NewDir("operator-lab-" + safeName(resolvedLab.Name))
		if dirErr != nil {
			_, _ = operatorClient.Release(context.Background(), operatorLease.ID)
			return runtimeadapter.Receipt{}, dirErr
		}
		remoteOptions, err = lab.OperatorLabRemoteOptions(resolvedLab.Name, resolvedLab.Profile, operatorLease, leaseDir)
		if err != nil {
			_, _ = operatorClient.Release(context.Background(), operatorLease.ID)
			return runtimeadapter.Receipt{}, err
		}
		if strings.ToLower(strings.TrimSpace(run.observe)) == "full" {
			if err = operatorClient.Marker(ctx, operatorLease.ID, "lease-verified", 1); err != nil {
				_, _ = operatorClient.Release(context.Background(), operatorLease.ID)
				return runtimeadapter.Receipt{}, fmt.Errorf("record operator-lab lease marker: %w", err)
			}
			if err = operatorClient.Marker(ctx, operatorLease.ID, "operation-started", 2); err != nil {
				_, _ = operatorClient.Release(context.Background(), operatorLease.ID)
				return runtimeadapter.Receipt{}, fmt.Errorf("record operator-lab operation marker: %w", err)
			}
		}
		stopHeartbeat, heartbeatErrors = operatorClient.StartHeartbeat(ctx, operatorLease.ID)
		defer func() {
			if stopHeartbeat != nil {
				stopHeartbeat()
			}
			if !released {
				_, _ = operatorClient.Release(context.Background(), operatorLease.ID)
			}
		}()
	} else {
		remoteOptions, err = lab.ResolveRemoteOptions(ctx, resolvedLab.Name, resolvedLab.Profile)
		if err != nil {
			return runtimeadapter.Receipt{}, err
		}
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
	if run.progress != nil || run.forceLocalLab {
		// Background operation steps must stream output from the exact object
		// that was built, analyzed, and pinned during wave preparation.
		remoteOptions.BuildMode = "local"
	}
	if resolvedLab.Profile.Provider != "operator-lab" {
		ensured, ensureErr := lab.EnsureRuntime(ctx, run.bootstrapMode, lab.BootstrapOptions{ProfileName: resolvedLab.Name, Profile: resolvedLab.Profile})
		if ensureErr != nil {
			return runtimeadapter.Receipt{}, codedError{code: 1, err: ensureErr}
		}
		if ensured.Bootstrap != nil {
			fmt.Fprint(run.stdout, lab.BootstrapText(*ensured.Bootstrap))
		}
	}
	report, runErr := lab.RemoteRun(ctx, run.input, lab.RemoteRunOptions{
		RemoteOptions: remoteOptions, Compiler: run.compiler, Arch: run.arch,
		Runtime: "windows-coff", Args: run.resolved.Tokens, TimeoutMS: run.timeout,
		SensitiveArguments: run.resolved.Sensitive, SensitiveArgumentNames: run.sensitiveArgumentNames,
		SensitiveOutputFields: run.sensitiveOutputFields, SensitiveValues: run.sensitiveValues,
		Interactive: run.interactiveLab, Progress: run.progress, Controller: run.controller,
	})
	fmt.Fprint(run.stdout, lab.RemoteRunText(report))
	receipt := runtimeadapter.Receipt{}
	if report.Receipt != nil {
		receipt = *report.Receipt
	}
	if report.RemoteResult != nil {
		receipt.TransientOutput = append([]string(nil), report.RemoteResult.Output...)
	} else if report.RemoteDev != nil && report.RemoteDev.Run != nil {
		receipt.TransientOutput = append([]string(nil), report.RemoteDev.Run.Output...)
	}
	if operatorClient != nil {
		var markerErr error
		var cleanupErr error
		var evidenceErr error
		var operatorEvidence lab.OperatorLabEvidence
		if strings.ToLower(strings.TrimSpace(run.observe)) == "full" {
			markerErr = operatorClient.Marker(context.Background(), operatorLease.ID, "operation-complete", 3)
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 2*time.Minute)
			cleanupErr = lab.CleanupOperatorLabWorkspace(cleanupCtx, remoteOptions)
			cancelCleanup()
			cleanupMarker := "cleanup-complete"
			if cleanupErr != nil {
				cleanupMarker = "cleanup-failed"
			}
			if markerErr == nil {
				markerErr = operatorClient.Marker(context.Background(), operatorLease.ID, cleanupMarker, 4)
			}
			if markerErr == nil {
				operatorEvidence, evidenceErr = operatorClient.Evidence(context.Background(), operatorLease.ID)
			}
			if markerErr == nil {
				markerErr = operatorClient.Marker(context.Background(), operatorLease.ID, "destruction-requested", 5)
			}
		}
		if stopHeartbeat != nil {
			stopHeartbeat()
			stopHeartbeat = nil
		}
		var heartbeatErr error
		for heartbeatErr = range heartbeatErrors {
			break
		}
		releaseCtx, cancelRelease := context.WithTimeout(context.Background(), 6*time.Minute)
		releasedLease, releaseErr := operatorClient.Release(releaseCtx, operatorLease.ID)
		cancelRelease()
		released = releaseErr == nil
		leaseRef := &runtimeadapter.LabLeaseReference{Provider: "operator-lab", LeaseID: operatorLease.ID, Profile: operatorLease.Profile, ProfileIdentity: operatorLease.ProfileIdentity, VMID: operatorLease.VMID, SensorSession: operatorLease.SensorSession, Deadline: operatorLease.Deadline.UTC().Format(time.RFC3339Nano), CloneTask: operatorLease.CloneTask}
		if evidenceErr == nil {
			leaseRef.EvidenceSnapshot = operatorEvidence.SnapshotDigest
			leaseRef.PCAPComplete = operatorEvidence.PCAPComplete
		}
		if releaseErr == nil {
			leaseRef.DestroyTask, leaseRef.DestructionProof, leaseRef.DestructionProved = releasedLease.DestroyTask, releasedLease.DestructionProof, releasedLease.State == "released" && releasedLease.DestructionProof != ""
		}
		receipt.LabLease = leaseRef
		if receipt.ReceiptPath != "" {
			if persistErr := runtimeadapter.PersistReceipt(receipt); persistErr != nil && runErr == nil {
				runErr = fmt.Errorf("persist operator-lab destruction receipt: %w", persistErr)
			}
		}
		if markerErr != nil && runErr == nil {
			runErr = fmt.Errorf("record operator-lab completion marker: %w", markerErr)
		}
		if cleanupErr != nil && runErr == nil {
			runErr = cleanupErr
		}
		if evidenceErr != nil && runErr == nil {
			runErr = fmt.Errorf("freeze operator-lab evidence: %w", evidenceErr)
		}
		if heartbeatErr != nil && runErr == nil {
			runErr = fmt.Errorf("operator-lab heartbeat failed: %w", heartbeatErr)
		}
		if releaseErr != nil {
			runErr = fmt.Errorf("operator-lab clone destruction failed: %w", releaseErr)
		}
	}
	if runErr != nil {
		return receipt, codedError{code: 1, err: runErr}
	}
	return receipt, nil
}

func (run *runtimeRunContext) executeSliver(ctx context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
	resolvedOptions, err := resolveSliverOptions(ctx, sliverOptions{
		Client: run.sliverClient, SessionFilter: run.sliverSession,
		Lab: run.labName, Profiles: run.labProfiles,
		Control: run.sliverControl, Controls: run.runtimeControls,
	}, run.input, true)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	if resolvedOptions.ProfileName != "" {
		if resolvedLab, resolveErr := lab.ResolveProfile(resolvedOptions.ProfileName, run.input, run.labProfiles); resolveErr == nil {
			if remote, remoteErr := lab.ResolveRemoteOptions(ctx, resolvedLab.Name, resolvedLab.Profile); remoteErr == nil {
				resolvedOptions.RemoteHost = remote.Host
			}
		}
	}
	options, err := prepareStageOptions(stageInputOptions{
		Input: run.input, Target: "sliver", Entrypoint: run.entry, ArgumentTokens: run.resolved.Tokens,
		ArgumentNames: run.resolved.Names, ArgumentOptional: run.resolved.Optional, ArgumentsExplicit: true,
		Compiler: run.compiler, Arch: run.arch, Runtime: run.runtimeName, SkipRun: true,
	})
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	result, err := stage.StageWithOptions(options)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	resolvedOptions.SensitiveOutputFields = run.sensitiveOutputFields
	resolvedOptions.SensitiveArgumentNames = run.sensitiveArgumentNames
	resolvedOptions.SensitiveValues = run.sensitiveValues
	return executeSliverExtension(run.stdout, resolvedOptions, result.Output, "", run.resolved.CLIValues)
}

func (run *runtimeRunContext) executeCobaltStrike(ctx context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
	return executeCobaltStrike(ctx, run.stdout, cobaltStrikeRunOptions{
		Input: run.input, Entrypoint: run.entry, Compiler: run.compiler, Arch: run.arch, Runtime: run.runtimeName,
		ArgumentTokens: run.resolved.Tokens, ArgumentNames: run.resolved.Names,
		ArgumentOptional: run.resolved.Optional, CLIValues: run.resolved.CLIValues,
		SensitiveOutputFields: run.sensitiveOutputFields, SensitiveArgumentNames: run.sensitiveArgumentNames, SensitiveValues: run.sensitiveValues,
	})
}

func (run *runtimeRunContext) executeNative(ctx context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
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
	progress := run.progress
	if progressPath := strings.TrimSpace(os.Getenv("BOFBENCH_PROGRESS_FILE")); progressPath != "" {
		progress = func(line string) {
			if run.progress != nil {
				run.progress(line)
			}
			redacted := run.redactReceipt(runtimeadapter.Receipt{Output: []string{line}})
			if len(redacted.Output) == 0 {
				return
			}
			file, openErr := os.OpenFile(progressPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if openErr != nil {
				return
			}
			_, _ = fmt.Fprintln(file, redacted.Output[0])
			_ = file.Close()
		}
	}
	started := time.Now()
	result, runErr := runtimesvc.Run(runtimesvc.Request{
		Path: object, Entry: run.entry, ArgHex: argpack.Hex(run.packed), Tokens: run.resolved.Tokens,
		TimeoutMS: run.timeout, Runtime: run.runtimeName, Context: ctx, OnOutput: progress,
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
		receipt.OutputClassification = "complete"
		receipt.FinalChunk = true
		receipt.CompletionSource = "native-loader"
		receipt.TerminalReason = "loader_completed"
		receipt.OutputChunks = append(receipt.OutputChunks, runtimeadapter.OutputChunk{Number: 1, LineCount: len(receipt.Output), Final: true, ReceivedAt: receipt.CompletedAt})
		runtimeadapter.AddTransition(&receipt, "completed", "native loader returned complete output", time.Now())
	} else if result.ExitState == "timeout" {
		receipt.ExecutionState = "timeout"
		receipt.OutputClassification = "partial"
		receipt.TerminalReason = "loader_timeout"
		runtimeadapter.AddTransition(&receipt, "timeout", "native loader timed out", time.Now())
	} else {
		receipt.OutputClassification = "partial"
		receipt.TerminalReason = "loader_failed"
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
	receipt.TransientOutput = append([]string(nil), result.Output...)
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
