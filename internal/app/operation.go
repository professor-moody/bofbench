package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/argpack"
	"bofbench/internal/artifact"
	"bofbench/internal/buildsys"
	"bofbench/internal/lab"
	operationsvc "bofbench/internal/operation"
	packsvc "bofbench/internal/pack"
	"bofbench/internal/runlog"
	"bofbench/internal/runtimeadapter"
)

type operationOptions struct {
	project, via, lab, topology, arch, compiler string
	catalogs, arguments                         []string
	cleanup, cleanupOnFailure                   bool
	profiles                                    string
}

func operationCommand(stdout io.Writer) *cobra.Command {
	var project string
	var catalogs []string
	cmd := &cobra.Command{Use: "operation", Short: "Compose capability packs into resumable multi-step operations"}
	cmd.PersistentFlags().StringVar(&project, "project", ".", "project used for project-local operation discovery")
	cmd.PersistentFlags().StringSliceVar(&catalogs, "catalog", nil, "additional pack and operation catalog path; repeatable")
	load := func() (*operationsvc.Registry, error) {
		packs, err := packsvc.Load(packsvc.LoadOptions{Project: project, ExtraCatalogs: catalogs})
		if err != nil {
			return nil, err
		}
		return operationsvc.Load(operationsvc.LoadOptions{Project: project, ExtraCatalogs: catalogs, PackRegistry: packs})
	}
	cmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List available multi-step operations", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
			registry, err := load()
			if err != nil {
				return err
			}
			printOperations(stdout, registry.List())
			return nil
		}},
		&cobra.Command{Use: "search <terms...>", Short: "Search operation names and objectives", Args: cobra.MinimumNArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			registry, err := load()
			if err != nil {
				return err
			}
			printOperations(stdout, registry.Search(strings.Join(args, " ")))
			return nil
		}},
		&cobra.Command{Use: "show <operation>", Short: "Show inputs, steps, captures, and cleanup", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			registry, err := load()
			if err != nil {
				return err
			}
			item, err := registry.Resolve(args[0])
			if err != nil {
				return err
			}
			printOperation(stdout, item)
			return nil
		}},
		&cobra.Command{Use: "validate <operation-or-operation.json>", Short: "Validate a resolved operation or definition file", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			var document operationsvc.Document
			qualified := args[0]
			registry, err := load()
			if err != nil {
				return err
			}
			if info, statErr := os.Stat(args[0]); statErr == nil && !info.IsDir() {
				parsed, err := operationsvc.ValidateFile(args[0])
				if err != nil {
					return err
				}
				if err := operationsvc.ValidatePackReferences(parsed, registry.PackRegistry()); err != nil {
					return err
				}
				document = parsed
			} else {
				item, err := registry.Resolve(args[0])
				if err != nil {
					return err
				}
				document, qualified = item.Document, item.Qualified
			}
			fmt.Fprintf(stdout, "OPERATION VALID\noperation  %s\nid         %s\nversion    %s\nsteps      %d\n", qualified, document.ID, document.Version, len(document.Steps))
			return nil
		}},
		operationDocsCommand(stdout, load), operationRunCommand(stdout, load), operationResumeCommand(stdout, load), operationCleanupCommand(stdout, load),
	)
	return cmd
}

func operationDocsCommand(stdout io.Writer, load func() (*operationsvc.Registry, error)) *cobra.Command {
	var output, catalogName, tier string
	cmd := &cobra.Command{Use: "docs", Short: "Generate Markdown reference from resolved operation definitions", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		registry, err := load()
		if err != nil {
			return err
		}
		items := registry.List()
		if catalogName != "" || tier != "" {
			filtered := items[:0]
			for _, item := range items {
				if catalogName != "" && item.Catalog != catalogName {
					continue
				}
				if tier != "" && item.Document.Tier != tier {
					continue
				}
				filtered = append(filtered, item)
			}
			items = filtered
		}
		body := operationsvc.ReferenceMarkdown(items)
		if output == "" || output == "-" {
			fmt.Fprint(stdout, body)
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(output, []byte(body), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "operation reference written to %s\n", output)
		return nil
	}}
	cmd.Flags().StringVar(&output, "output", "", "Markdown output path; default stdout")
	cmd.Flags().StringVar(&catalogName, "catalog-name", "", "include only one resolved catalog name")
	cmd.Flags().StringVar(&tier, "tier", "", "include only public or internal operations")
	return cmd
}

func operationRunCommand(stdout io.Writer, load func() (*operationsvc.Registry, error)) *cobra.Command {
	opts := operationOptions{via: "native", arch: "x64", compiler: "auto", profiles: lab.ProfilesPath()}
	cmd := &cobra.Command{Use: "run <operation>", Short: "Build, analyze, and execute a linear operation", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		registry, err := load()
		if err != nil {
			return err
		}
		item, err := registry.Resolve(args[0])
		if err != nil {
			return err
		}
		inputs, err := resolveOperationInputs(item.Document, opts.arguments, nil, false)
		if err != nil {
			return err
		}
		return runOperation(cmd.Context(), stdout, registry, item, inputs, opts, "")
	}}
	bindOperationRunFlags(cmd, &opts, true)
	return cmd
}

func operationResumeCommand(stdout io.Writer, load func() (*operationsvc.Registry, error)) *cobra.Command {
	opts := operationOptions{profiles: lab.ProfilesPath()}
	cmd := &cobra.Command{Use: "resume <operation.json>", Short: "Continue an incomplete operation from its persisted captures", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		path := operationReceiptPath(args[0])
		receipt, err := operationsvc.LoadReceipt(path)
		if err != nil {
			return err
		}
		registry, err := load()
		if err != nil {
			return err
		}
		item, err := registry.Resolve(receipt.Operation)
		if err != nil {
			return err
		}
		if item.SHA256 != receipt.OperationSHA256 {
			return fmt.Errorf("operation definition changed since %s; start a new operation run", path)
		}
		inputs, err := resolveOperationInputs(item.Document, opts.arguments, receipt.Inputs, true)
		if err != nil {
			return err
		}
		opts.via, opts.lab, opts.topology, opts.arch, opts.compiler = receipt.Runtime, receipt.Lab, receipt.Topology, receipt.Architecture, receipt.Compiler
		return runOperation(cmd.Context(), stdout, registry, item, inputs, opts, path)
	}}
	cmd.Flags().StringArrayVar(&opts.arguments, "arg", nil, "operation input (name=value); repeatable; resupply sensitive inputs when required")
	cmd.Flags().StringVar(&opts.profiles, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().BoolVar(&opts.cleanup, "cleanup", false, "clean completed stateful steps after completion")
	cmd.Flags().BoolVar(&opts.cleanupOnFailure, "cleanup-on-failure", false, "clean completed stateful steps after a failure")
	return cmd
}

func operationCleanupCommand(stdout io.Writer, load func() (*operationsvc.Registry, error)) *cobra.Command {
	opts := operationOptions{profiles: lab.ProfilesPath()}
	cmd := &cobra.Command{Use: "cleanup <operation.json>", Short: "Run completed step cleanup in reverse order", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		path := operationReceiptPath(args[0])
		receipt, err := operationsvc.LoadReceipt(path)
		if err != nil {
			return err
		}
		registry, err := load()
		if err != nil {
			return err
		}
		item, err := registry.Resolve(receipt.Operation)
		if err != nil {
			return err
		}
		if item.SHA256 != receipt.OperationSHA256 {
			return fmt.Errorf("operation definition changed since %s; cleanup requires the pinned definition", path)
		}
		inputs, err := resolveOperationInputs(item.Document, opts.arguments, receipt.Inputs, true)
		if err != nil {
			return err
		}
		opts.via, opts.lab, opts.topology, opts.arch, opts.compiler = receipt.Runtime, receipt.Lab, receipt.Topology, receipt.Architecture, receipt.Compiler
		return cleanupOperation(cmd.Context(), stdout, registry, item, inputs, &receipt, path, opts)
	}}
	cmd.Flags().StringArrayVar(&opts.arguments, "arg", nil, "resupply sensitive operation inputs needed by cleanup")
	cmd.Flags().StringVar(&opts.profiles, "profiles", lab.ProfilesPath(), "global lab profiles file")
	return cmd
}

func bindOperationRunFlags(cmd *cobra.Command, opts *operationOptions, includeRuntime bool) {
	cmd.Flags().StringArrayVar(&opts.arguments, "arg", nil, "operation input (name=value); repeatable")
	cmd.Flags().StringVar(&opts.via, "via", "native", "runtime: native, lab, sliver, or cobaltstrike")
	cmd.Flags().StringVar(&opts.lab, "lab", "", "named lab profile")
	cmd.Flags().StringVar(&opts.topology, "topology", "", "named multi-host topology")
	cmd.Flags().StringVar(&opts.arch, "arch", "x64", "build architecture: x64 or x86")
	cmd.Flags().StringVar(&opts.compiler, "compiler", "auto", "compiler: auto, mingw, or msvc")
	cmd.Flags().StringVar(&opts.profiles, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().BoolVar(&opts.cleanup, "cleanup", false, "clean completed stateful steps after completion")
	cmd.Flags().BoolVar(&opts.cleanupOnFailure, "cleanup-on-failure", false, "clean completed stateful steps after a failure")
	cmd.MarkFlagsMutuallyExclusive("lab", "topology")
}

func resolveOperationInputs(document operationsvc.Document, values []string, persisted map[string]string, allowMissingSensitive bool) (map[string]string, error) {
	definitions := map[string]operationsvc.Input{}
	result := map[string]string{}
	provided := map[string]bool{}
	for _, input := range document.Inputs {
		definitions[input.Name] = input
		result[input.Name] = ""
		if input.Default != "" {
			result[input.Name] = input.Default
		}
	}
	for name, value := range persisted {
		result[name] = value
	}
	for _, value := range values {
		name, raw, ok := strings.Cut(value, "=")
		name = strings.TrimSpace(name)
		if !ok || definitions[name].Name == "" {
			return nil, fmt.Errorf("unknown or malformed operation input %q", value)
		}
		if provided[name] {
			return nil, fmt.Errorf("operation input %q was provided more than once", name)
		}
		provided[name] = true
		if definitions[name].Sensitive && strings.ToLower(definitions[name].Type) != "file" {
			resolved, err := resolveSensitiveArgument(name, raw)
			if err != nil {
				return nil, err
			}
			raw = resolved
		}
		result[name] = raw
	}
	for _, input := range document.Inputs {
		if input.Required && !(allowMissingSensitive && input.Sensitive) {
			if result[input.Name] == "" && input.TopologyValue == "" {
				return nil, fmt.Errorf("missing required operation input %q", input.Name)
			}
		}
		if value := result[input.Name]; value != "" {
			switch strings.ToLower(input.Type) {
			case "int":
				if _, err := strconv.ParseInt(value, 0, 32); err != nil {
					return nil, fmt.Errorf("operation input %s must be a 32-bit integer: %w", input.Name, err)
				}
			case "short":
				if _, err := strconv.ParseInt(value, 0, 16); err != nil {
					return nil, fmt.Errorf("operation input %s must be a 16-bit integer: %w", input.Name, err)
				}
			}
			token, _, err := packArgumentToken(input.Type, value)
			if err != nil {
				return nil, fmt.Errorf("operation input %s: %w", input.Name, err)
			}
			if _, err := argpack.ParseTokens([]string{token}); err != nil {
				return nil, fmt.Errorf("operation input %s: %w", input.Name, err)
			}
		}
	}
	return result, nil
}

func runOperation(ctx context.Context, stdout io.Writer, registry *operationsvc.Registry, item operationsvc.Resolved, inputs map[string]string, opts operationOptions, resumePath string) error {
	if opts.via != "native" && opts.via != "lab" && opts.via != "sliver" && opts.via != "cobaltstrike" {
		return fmt.Errorf("unsupported operation runtime %q", opts.via)
	}
	var topologyValues map[string]string
	if len(item.Document.Roles) > 0 && opts.topology == "" {
		return fmt.Errorf("operation %s requires topology roles %s; select one with --topology", item.Document.ID, strings.Join(item.Document.Roles, ", "))
	}
	if opts.topology != "" {
		resolved, err := resolveTopologyRuntimeValues(ctx, opts.topology, opts.profiles)
		if err != nil {
			return err
		}
		topologyValues = resolved.Values
		opts.lab = resolved.Topology.Execution.Name
	}
	if topologyValues == nil {
		topologyValues = map[string]string{}
	}
	if err := operationsvc.ValidateTopologyRoles(item.Document.Roles, topologyValues); err != nil {
		return err
	}
	for _, input := range item.Document.Inputs {
		if inputs[input.Name] == "" && input.TopologyValue != "" {
			inputs[input.Name] = topologyValues[input.TopologyValue]
		}
		if input.Required && inputs[input.Name] == "" {
			return fmt.Errorf("operation input %s requires %s, but the selected topology does not provide it", input.Name, input.TopologyValue)
		}
	}
	var receipt operationsvc.Receipt
	path := resumePath
	if resumePath == "" {
		runDir, err := runlog.NewDir("operation-" + safeName(item.Document.ID))
		if err != nil {
			return err
		}
		path = filepath.Join(runDir, "operation.json")
		receipt = operationsvc.NewReceipt(item, registry.PackRegistry(), path, opts.via, opts.lab, opts.topology, opts.arch, opts.compiler, inputs)
	} else {
		var err error
		receipt, err = operationsvc.LoadReceipt(path)
		if err != nil {
			return err
		}
	}
	if err := validatePinnedOperationPacks(item.Document, &receipt, registry.PackRegistry()); err != nil {
		return err
	}
	runnable := operationsvc.RunnableStepIndexes(receipt)
	if resumePath != "" && len(runnable) == 0 {
		if opts.cleanup && receipt.CleanupState != "completed" {
			return cleanupOperation(ctx, stdout, registry, item, inputs, &receipt, path, opts)
		}
		fmt.Fprintf(stdout, "operation  %s\nreceipt    %s\n", receipt.Status, path)
		return nil
	}
	receipt.Status = "running"
	receipt.Error = ""
	if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
		return err
	}
	work := filepath.Join("work", "operations", filepath.Base(filepath.Dir(path)))
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	for _, index := range runnable {
		step := item.Document.Steps[index]
		stepReceipt := &receipt.Steps[index]
		if stepReceipt.State == "incomplete" {
			updated, err := operationsvc.RefreshRuntimeReceipt(stepReceipt.Runtime)
			if err != nil {
				return failOperation(path, &receipt, stepReceipt, fmt.Errorf("refresh runtime task for step %s: %w", step.ID, err))
			}
			if stepReceipt.ObjectSHA256 != "" && updated.ObjectSHA256 != stepReceipt.ObjectSHA256 {
				return failOperation(path, &receipt, stepReceipt, fmt.Errorf("runtime task object hash changed for step %s", step.ID))
			}
			stepReceipt.Runtime, stepReceipt.OutputComplete = updated, updated.OutputComplete
			stepReceipt.State, receipt.Status = operationsvc.ClassifyExecution(updated.ExecutionState, updated.OutputComplete, false)
			switch stepReceipt.State {
			case "completed":
				captured, captureErr := operationsvc.CaptureOutput(updated.Output, step.Captures)
				if captureErr != nil {
					return failOperation(path, &receipt, stepReceipt, captureErr)
				}
				stepReceipt.Captures = captured
				for name, value := range captured {
					receipt.Captures[name] = value
				}
				stepReceipt.Error = ""
				printOperationResult(stdout, updated.Output, captured)
				if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
					return err
				}
				continue
			case "failed":
				return failOperation(path, &receipt, stepReceipt, fmt.Errorf("runtime task for step %s ended in %s: %s", step.ID, updated.ExecutionState, updated.Error))
			default:
				if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
					return err
				}
				return fmt.Errorf("operation step %s is still %s; resume %s after the runtime receipt is complete", step.ID, updated.ExecutionState, path)
			}
		}
		packItem, err := registry.PackRegistry().Resolve(step.Pack)
		if err != nil {
			return failOperation(path, &receipt, stepReceipt, err)
		}
		if stepReceipt.PackSHA256 != "" && stepReceipt.PackSHA256 != packItem.SHA256 {
			return failOperation(path, &receipt, stepReceipt, fmt.Errorf("pack %s changed since operation start", step.Pack))
		}
		if err := requireReferencedSensitiveInputs(item.Document, receipt, inputs, step.Arguments); err != nil {
			return failOperation(path, &receipt, stepReceipt, err)
		}
		arguments, err := resolveOperationArguments(step.Arguments, inputs, receipt.Captures, topologyValues)
		if err != nil {
			return failOperation(path, &receipt, stepReceipt, err)
		}
		fmt.Fprintf(stdout, "step %d/%d  %s → %s\n", index+1, len(item.Document.Steps), step.ID, packItem.Qualified)
		stepReceipt.State = "running"
		if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
			return err
		}
		runtimeReceipt, runErr := executeOperationPack(ctx, stdout, registry.PackRegistry(), packItem, arguments, operationArgumentSensitivity(item.Document, step.Arguments), opts, work)
		stepReceipt.Runtime, stepReceipt.ObjectSHA256, stepReceipt.OutputComplete = runtimeReceipt, runtimeReceipt.ObjectSHA256, runtimeReceipt.OutputComplete
		stepReceipt.State, receipt.Status = operationsvc.ClassifyExecution(runtimeReceipt.ExecutionState, runtimeReceipt.OutputComplete, runErr != nil)
		if stepReceipt.State != "completed" {
			if runErr != nil {
				stepReceipt.Error, receipt.Error = runErr.Error(), runErr.Error()
			}
			if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "operation  %s\nreceipt    %s\n", receipt.Status, path)
			if opts.cleanupOnFailure && receipt.Status == "failed" {
				_ = cleanupOperation(ctx, stdout, registry, item, inputs, &receipt, path, opts)
			}
			if runErr != nil {
				return runErr
			}
			return fmt.Errorf("operation step %s has incomplete runtime output; resume %s", step.ID, path)
		}
		captured, err := operationsvc.CaptureOutput(runtimeReceipt.Output, step.Captures)
		if err != nil {
			return failOperation(path, &receipt, stepReceipt, err)
		}
		stepReceipt.Captures = captured
		for name, value := range captured {
			receipt.Captures[name] = value
		}
		printOperationResult(stdout, runtimeReceipt.Output, captured)
		stepReceipt.State = "completed"
		if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
			return err
		}
	}
	receipt.Status, receipt.CompletedAt = "completed", time.Now().UTC().Format(time.RFC3339Nano)
	if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "operation  completed\nreceipt    %s\n", path)
	if opts.cleanup {
		return cleanupOperation(ctx, stdout, registry, item, inputs, &receipt, path, opts)
	}
	return nil
}

func validatePinnedOperationPacks(document operationsvc.Document, receipt *operationsvc.Receipt, packs *packsvc.Registry) error {
	if len(document.Steps) != len(receipt.Steps) {
		return fmt.Errorf("operation receipt step count does not match the pinned definition")
	}
	for index, step := range document.Steps {
		resolved, err := packs.Resolve(step.Pack)
		if err != nil {
			return err
		}
		if receipt.Steps[index].PackSHA256 == "" || receipt.Steps[index].PackSHA256 != resolved.SHA256 {
			return fmt.Errorf("pack %s changed since operation start", step.Pack)
		}
		if step.Cleanup == nil {
			continue
		}
		cleanup, err := packs.Resolve(step.Cleanup.Pack)
		if err != nil {
			return err
		}
		if receipt.Steps[index].CleanupSHA256 == "" || receipt.Steps[index].CleanupSHA256 != cleanup.SHA256 {
			return fmt.Errorf("cleanup pack %s changed since operation start", step.Cleanup.Pack)
		}
	}
	return nil
}

func executeOperationPack(ctx context.Context, stdout io.Writer, packs *packsvc.Registry, item packsvc.Resolved, arguments map[string]string, sensitiveArguments map[string]bool, opts operationOptions, work string) (runtimeadapter.Receipt, error) {
	project, err := materializePackProject(work, item, packs)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	build, err := buildsys.BuildWithOptions(project, buildsys.Options{Arch: opts.arch, Compiler: opts.compiler})
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	analysis, err := artifact.Analyze(build.Object, "go")
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	artifact.ApplyDeclarativeSignatures(&analysis, declarativeSignatures([]packsvc.Resolved{item}))
	names := make([]string, 0, len(arguments))
	for name := range arguments {
		names = append(names, name)
	}
	sort.Strings(names)
	named := make([]string, 0, len(names))
	for _, name := range names {
		named = append(named, name+"="+arguments[name])
	}
	resolved, err := resolveRunArguments(project, named, nil)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	for index, name := range resolved.Names {
		if sensitiveArguments[name] && index < len(resolved.Sensitive) {
			resolved.Sensitive[index] = true
		}
	}
	packed, items, err := argpack.PackTokens(resolved.Tokens)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	// Operation output is intentionally compact. The adapter's full diagnostics
	// and evidence remain available in its runtime receipt.
	run := &runtimeRunContext{stdout: io.Discard, input: project, projectInput: true, entry: "go", timeout: 5000, runtimeName: "auto", compiler: opts.compiler, arch: opts.arch, resolved: resolved, packed: packed, items: items, labName: opts.lab, labProfiles: opts.profiles, transportTimeout: 3 * time.Minute, bootstrapMode: "auto", interactiveLab: requiresInteractiveLabSession(project)}
	run.sensitiveOutputFields, run.sensitiveArgumentNames, run.sensitiveValues = runtimeSensitivity(project, resolved)
	adapters, err := runtimeAdapterRegistry(run)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	adapter, err := adapters.Resolve(opts.via)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	availability, err := adapter.Detect(ctx)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	if !availability.Available {
		return runtimeadapter.Receipt{}, fmt.Errorf("%s runtime is unavailable: %s", adapter.Name(), availability.Detail)
	}
	request := runtimeadapter.Request{Input: project, Entrypoint: "go"}
	for index, arg := range items {
		name := fmt.Sprintf("arg%d", index+1)
		if index < len(resolved.Names) {
			name = resolved.Names[index]
		}
		request.Arguments = append(request.Arguments, runtimeadapter.Argument{Name: name, Type: arg.Kind, Value: arg.Value, Sensitive: index < len(resolved.Sensitive) && resolved.Sensitive[index]})
	}
	prepared, err := adapter.Prepare(ctx, request)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	return adapter.Execute(ctx, prepared)
}

func cleanupOperation(ctx context.Context, stdout io.Writer, registry *operationsvc.Registry, item operationsvc.Resolved, inputs map[string]string, receipt *operationsvc.Receipt, path string, opts operationOptions) error {
	topologyValues := map[string]string{}
	if opts.topology != "" {
		resolved, err := resolveTopologyRuntimeValues(ctx, opts.topology, opts.profiles)
		if err != nil {
			return err
		}
		topologyValues, opts.lab = resolved.Values, resolved.Topology.Execution.Name
	}
	if err := operationsvc.ValidateTopologyRoles(item.Document.Roles, topologyValues); err != nil {
		return err
	}
	if err := validatePinnedOperationPacks(item.Document, receipt, registry.PackRegistry()); err != nil {
		return err
	}
	receipt.CleanupState = "running"
	if err := operationsvc.SaveReceipt(path, receipt); err != nil {
		return err
	}
	work := filepath.Join("work", "operations", filepath.Base(filepath.Dir(path)), "cleanup")
	for _, index := range operationsvc.CleanupStepIndexes(item.Document, *receipt) {
		step, stepReceipt := item.Document.Steps[index], &receipt.Steps[index]
		cleanupPack, err := registry.PackRegistry().Resolve(step.Cleanup.Pack)
		if err != nil {
			return cleanupFailure(path, receipt, stepReceipt, err)
		}
		if err := requireReferencedSensitiveInputs(item.Document, *receipt, inputs, step.Cleanup.Arguments); err != nil {
			return cleanupFailure(path, receipt, stepReceipt, err)
		}
		arguments, err := resolveOperationArguments(step.Cleanup.Arguments, inputs, receipt.Captures, topologyValues)
		if err != nil {
			return cleanupFailure(path, receipt, stepReceipt, err)
		}
		fmt.Fprintf(stdout, "cleanup     %s → %s\n", step.ID, cleanupPack.Qualified)
		result, err := executeOperationPack(ctx, stdout, registry.PackRegistry(), cleanupPack, arguments, operationArgumentSensitivity(item.Document, step.Cleanup.Arguments), opts, work)
		stepReceipt.CleanupRuntime = &result
		if err != nil || !result.OutputComplete {
			if err == nil {
				err = fmt.Errorf("cleanup output was incomplete")
			}
			return cleanupFailure(path, receipt, stepReceipt, err)
		}
		printOperationResult(stdout, result.Output, nil)
		stepReceipt.CleanupState = "completed"
		if err := operationsvc.SaveReceipt(path, receipt); err != nil {
			return err
		}
	}
	receipt.CleanupState = "completed"
	if receipt.Status == "completed" {
		receipt.Status = "cleaned"
	}
	if err := operationsvc.SaveReceipt(path, receipt); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "cleanup     completed\nreceipt     %s\n", path)
	return nil
}

func requireReferencedSensitiveInputs(document operationsvc.Document, receipt operationsvc.Receipt, inputs map[string]string, arguments map[string]string) error {
	redacted := map[string]bool{}
	for _, name := range receipt.RedactedInputs {
		redacted[name] = true
	}
	sensitive := map[string]bool{}
	for _, input := range document.Inputs {
		sensitive[input.Name] = input.Sensitive
	}
	for _, value := range arguments {
		if !strings.HasPrefix(value, "$input.") {
			continue
		}
		name := strings.TrimPrefix(value, "$input.")
		if sensitive[name] && redacted[name] && inputs[name] == "" {
			return fmt.Errorf("resupply sensitive operation input %s with --arg %s=@prompt, @env, or @file", name, name)
		}
	}
	return nil
}

func operationArgumentSensitivity(document operationsvc.Document, arguments map[string]string) map[string]bool {
	inputs := map[string]bool{}
	for _, input := range document.Inputs {
		inputs[input.Name] = input.Sensitive
	}
	result := map[string]bool{}
	for name, value := range arguments {
		if strings.HasPrefix(value, "$input.") && inputs[strings.TrimPrefix(value, "$input.")] {
			result[name] = true
		}
	}
	return result
}

func printOperationResult(stdout io.Writer, output []string, captures map[string]string) {
	for _, line := range output {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
			fmt.Fprintf(stdout, "  result     %s\n", line)
		}
	}
	names := make([]string, 0, len(captures))
	for name := range captures {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(stdout, "  captured   %s=%s\n", name, captures[name])
	}
}

func resolveOperationArguments(source map[string]string, inputs, captures, topology map[string]string) (map[string]string, error) {
	result := map[string]string{}
	for name, raw := range source {
		value, err := operationsvc.ResolveValue(raw, inputs, captures, topology)
		if err != nil {
			return nil, fmt.Errorf("argument %s: %w", name, err)
		}
		result[name] = value
	}
	return result, nil
}
func failOperation(path string, receipt *operationsvc.Receipt, step *operationsvc.StepReceipt, err error) error {
	step.State, step.Error, receipt.Status, receipt.Error = "failed", err.Error(), "failed", err.Error()
	_ = operationsvc.SaveReceipt(path, receipt)
	return err
}
func cleanupFailure(path string, receipt *operationsvc.Receipt, step *operationsvc.StepReceipt, err error) error {
	step.CleanupState, step.Error, receipt.CleanupState, receipt.Error = "failed", err.Error(), "failed", err.Error()
	_ = operationsvc.SaveReceipt(path, receipt)
	return err
}
func operationReceiptPath(path string) string {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return filepath.Join(path, "operation.json")
	}
	return path
}

func printOperations(stdout io.Writer, items []operationsvc.Resolved) {
	if len(items) == 0 {
		fmt.Fprintln(stdout, "No operations found.")
		return
	}
	fmt.Fprintln(stdout, "OPERATION                                  TIER      STEPS  SUMMARY")
	for _, item := range items {
		fmt.Fprintf(stdout, "%-42s %-9s %-6d %s\n", item.Qualified, item.Document.Tier, len(item.Document.Steps), item.Document.Summary)
	}
}
func printOperation(stdout io.Writer, item operationsvc.Resolved) {
	fmt.Fprintf(stdout, "%s\n%s\n\nqualified  %s\nversion    %s\ntier       %s\nhash       %s\n", item.Document.Title, item.Document.Summary, item.Qualified, item.Document.Version, item.Document.Tier, item.SHA256)
	if len(item.Document.Roles) > 0 {
		fmt.Fprintf(stdout, "roles      %s\n", strings.Join(item.Document.Roles, ", "))
	}
	if len(item.Document.Inputs) > 0 {
		fmt.Fprintln(stdout, "\ninputs")
		for _, input := range item.Document.Inputs {
			flags := ""
			if input.Required {
				flags += " required"
			}
			if input.Sensitive {
				flags += " sensitive"
			}
			if input.Default != "" {
				flags += " default=" + input.Default
			}
			if input.TopologyValue != "" {
				flags += " topology=" + input.TopologyValue
			}
			fmt.Fprintf(stdout, "  %-22s %-8s%s\n", input.Name, input.Type, flags)
		}
	}
	fmt.Fprintln(stdout, "\nsteps")
	for index, step := range item.Document.Steps {
		fmt.Fprintf(stdout, "  %d. %-20s %s\n", index+1, step.ID, step.Pack)
		argumentNames := make([]string, 0, len(step.Arguments))
		for name := range step.Arguments {
			argumentNames = append(argumentNames, name)
		}
		sort.Strings(argumentNames)
		for _, name := range argumentNames {
			fmt.Fprintf(stdout, "     argument %-13s %s\n", name, step.Arguments[name])
		}
		captureNames := make([]string, 0, len(step.Captures))
		for name := range step.Captures {
			captureNames = append(captureNames, name)
		}
		sort.Strings(captureNames)
		for _, name := range captureNames {
			capture := step.Captures[name]
			fmt.Fprintf(stdout, "     capture %-14s [%s] %s\n", name, capture.Tag, capture.Field)
		}
		if step.Cleanup != nil {
			fmt.Fprintf(stdout, "     cleanup              %s\n", step.Cleanup.Pack)
			cleanupNames := make([]string, 0, len(step.Cleanup.Arguments))
			for name := range step.Cleanup.Arguments {
				cleanupNames = append(cleanupNames, name)
			}
			sort.Strings(cleanupNames)
			for _, name := range cleanupNames {
				fmt.Fprintf(stdout, "       argument %-11s %s\n", name, step.Cleanup.Arguments[name])
			}
		}
	}
}
