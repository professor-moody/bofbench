package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	parallelism                                 int
	parallelSem                                 chan struct{}
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
		operationShowCommand(stdout, load),
		operationGraphCommand(stdout, load),
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
				if err := registry.ValidateDocumentReferences(parsed); err != nil {
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
		operationDocsCommand(stdout, load), operationTestCommand(stdout, load, func() []string { return append([]string(nil), catalogs...) }), operationProveCommand(stdout, load, func() []string { return append([]string(nil), catalogs...) }), operationRunCommand(stdout, load), operationResumeCommand(stdout, load), operationWatchCommand(stdout), operationCancelCommand(stdout, load), operationCleanupCommand(stdout, load),
	)
	return cmd
}

func operationWatchCommand(stdout io.Writer) *cobra.Command {
	var follow bool
	var interval, timeout time.Duration
	var format string
	cmd := &cobra.Command{Use: "watch <operation.json>", Short: "Watch persisted operation step and readiness state", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		path := operationReceiptPath(args[0])
		ctx := cmd.Context()
		if follow {
			var cancel context.CancelFunc
			ctx, cancel = contextWithTimeout(ctx, timeout)
			defer cancel()
		}
		previous := ""
		for {
			receipt, err := operationsvc.LoadReceipt(path)
			if err != nil {
				return err
			}
			data := operationWatchText(receipt)
			if format == "json" {
				encoded, encodeErr := json.Marshal(receipt)
				if encodeErr != nil {
					return encodeErr
				}
				data = string(encoded) + "\n"
			}
			if data != previous {
				fmt.Fprint(stdout, data)
				previous = data
			}
			if !follow || operationTerminal(receipt.Status) {
				return nil
			}
			select {
			case <-ctx.Done():
				if ctx.Err() == context.DeadlineExceeded {
					return nil
				}
				return ctx.Err()
			case <-time.After(interval):
			}
		}
	}}
	cmd.Flags().BoolVar(&follow, "follow", false, "follow changes until the operation reaches a terminal state")
	cmd.Flags().DurationVar(&interval, "interval", 250*time.Millisecond, "receipt polling interval")
	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Minute, "maximum follow duration")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func operationCancelCommand(stdout io.Writer, load func() (*operationsvc.Registry, error)) *cobra.Command {
	opts := operationOptions{profiles: lab.ProfilesPath(), parallelism: 4}
	var cleanup bool
	cmd := &cobra.Command{Use: "cancel <operation.json>", Short: "Cancel active operation runtime tasks", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		path := operationReceiptPath(args[0])
		receipt, err := operationsvc.LoadReceipt(path)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		receipt.CancelRequestedAt, receipt.CancellationState = now.Format(time.RFC3339Nano), "canceling"
		var failures []string
		for index := range receipt.Steps {
			step := &receipt.Steps[index]
			if step.State != "running" && step.State != "ready" && step.State != "incomplete" {
				continue
			}
			updated, cancelErr := cancelOperationRuntimeReceipt(cmd.Context(), step.Runtime, opts)
			if cancelErr != nil {
				step.CancellationState = "unsupported"
				failures = append(failures, step.ID+": "+cancelErr.Error())
				continue
			}
			step.Runtime, step.CancellationState = updated, "requested"
		}
		if len(failures) == 0 {
			receipt.CancellationState = "requested"
		}
		if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "operation  cancellation_%s\nreceipt    %s\n", receipt.CancellationState, path)
		if cleanup {
			registry, loadErr := load()
			if loadErr != nil {
				return loadErr
			}
			item, resolveErr := registry.Resolve(receipt.Operation)
			if resolveErr != nil {
				return resolveErr
			}
			inputs, inputErr := resolveOperationInputs(item.Document, opts.arguments, receipt.Inputs, true)
			if inputErr != nil {
				return inputErr
			}
			opts.via, opts.lab, opts.topology, opts.arch, opts.compiler = receipt.Runtime, receipt.Lab, receipt.Topology, receipt.Architecture, receipt.Compiler
			if cleanupErr := cleanupOperation(cmd.Context(), stdout, registry, item, inputs, &receipt, path, opts); cleanupErr != nil {
				return cleanupErr
			}
		}
		if len(failures) > 0 {
			return fmt.Errorf("some active runtime tasks could not be canceled: %s", strings.Join(failures, "; "))
		}
		return nil
	}}
	cmd.Flags().BoolVar(&cleanup, "cleanup", false, "clean completed stateful steps after requesting cancellation")
	cmd.Flags().StringArrayVar(&opts.arguments, "arg", nil, "resupply sensitive operation inputs needed by cleanup")
	cmd.Flags().StringVar(&opts.profiles, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().IntVar(&opts.parallelism, "parallelism", 4, "maximum concurrent cleanup branches (1-16)")
	return cmd
}

func cancelOperationRuntimeReceipt(ctx context.Context, receipt runtimeadapter.Receipt, opts operationOptions) (runtimeadapter.Receipt, error) {
	run := &runtimeRunContext{stdout: io.Discard, input: ".", runtimeName: receipt.Runtime, labName: opts.lab, labProfiles: opts.profiles, sliverSession: receipt.Session}
	registry, err := runtimeAdapterRegistry(run)
	if err != nil {
		return receipt, err
	}
	adapter, err := registry.Resolve(receipt.Runtime)
	if err != nil {
		return receipt, err
	}
	return adapter.Cancel(ctx, receipt)
}

func operationWatchText(receipt operationsvc.Receipt) string {
	var body strings.Builder
	fmt.Fprintf(&body, "operation  %s\nstatus     %s\n", receipt.Operation, receipt.Status)
	for _, step := range receipt.Steps {
		fmt.Fprintf(&body, "%-18s %-10s ready=%-8s runtime=%s\n", step.ID, step.State, step.ReadyState, emptyText(step.Runtime.ExecutionState, "-"))
	}
	fmt.Fprintf(&body, "receipt    %s\n", receipt.Path)
	return body.String()
}

func operationTerminal(status string) bool {
	switch status {
	case "completed", "cleaned", "failed", "canceled", "cancelled":
		return true
	}
	return false
}

func operationShowCommand(stdout io.Writer, load func() (*operationsvc.Registry, error)) *cobra.Command {
	var expand bool
	cmd := &cobra.Command{Use: "show <operation>", Short: "Show inputs, steps, captures, and cleanup", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		registry, err := load()
		if err != nil {
			return err
		}
		item, err := registry.Resolve(args[0])
		if err != nil {
			return err
		}
		printOperation(stdout, item)
		if expand {
			printChildOperations(stdout, registry, item, "  ", map[string]bool{})
		}
		return nil
	}}
	cmd.Flags().BoolVar(&expand, "expand", false, "show nested operation definitions")
	return cmd
}

func operationGraphCommand(stdout io.Writer, load func() (*operationsvc.Registry, error)) *cobra.Command {
	var format string
	var expand bool
	cmd := &cobra.Command{Use: "graph <operation>", Short: "Show operation steps and result routes", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		registry, err := load()
		if err != nil {
			return err
		}
		item, err := registry.Resolve(args[0])
		if err != nil {
			return err
		}
		body, err := registry.Graph(item, format, expand)
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(stdout, body)
		return err
	}}
	cmd.Flags().StringVar(&format, "format", "text", "graph format: text, mermaid, or json")
	cmd.Flags().BoolVar(&expand, "expand", false, "include slash-qualified child operation steps")
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
	opts := operationOptions{via: "native", arch: "x64", compiler: "auto", profiles: lab.ProfilesPath(), parallelism: 4}
	cmd := &cobra.Command{Use: "run <operation>", Short: "Build, analyze, and execute a result-aware operation", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
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
	opts := operationOptions{profiles: lab.ProfilesPath(), parallelism: 4}
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
		runnable := false
		if operationsvc.IsDAG(item.Document) {
			ready, readyErr := operationsvc.ReadyDAGSteps(item.Document, receipt)
			if readyErr != nil {
				return readyErr
			}
			runnable = len(ready) > 0
		} else {
			_, linearRunnable, routeErr := operationsvc.NextRunnableStep(item.Document, receipt)
			if routeErr != nil {
				return routeErr
			}
			runnable = linearRunnable
		}
		if !runnable && !opts.cleanup {
			fmt.Fprintf(stdout, "operation  %s\nreceipt    %s\n", receipt.Status, path)
			return nil
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
	cmd.Flags().IntVar(&opts.parallelism, "parallelism", 4, "maximum concurrent operation branches (1-16)")
	return cmd
}

func operationCleanupCommand(stdout io.Writer, load func() (*operationsvc.Registry, error)) *cobra.Command {
	opts := operationOptions{profiles: lab.ProfilesPath(), parallelism: 4}
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
	cmd.Flags().IntVar(&opts.parallelism, "parallelism", 4, "maximum concurrent cleanup branches (1-16)")
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
	cmd.Flags().IntVar(&opts.parallelism, "parallelism", 4, "maximum concurrent operation branches (1-16)")
	cmd.MarkFlagsMutuallyExclusive("lab", "topology")
}

func refreshOperationRuntimeReceipt(ctx context.Context, receipt runtimeadapter.Receipt, opts operationOptions) (runtimeadapter.Receipt, error) {
	run := &runtimeRunContext{stdout: io.Discard, input: ".", runtimeName: receipt.Runtime, labName: opts.lab, labProfiles: opts.profiles, sliverSession: receipt.Session}
	registry, err := runtimeAdapterRegistry(run)
	if err != nil {
		return receipt, err
	}
	adapter, err := registry.Resolve(receipt.Runtime)
	if err != nil {
		return receipt, err
	}
	updated, err := adapter.Refresh(ctx, receipt)
	if err != nil {
		return receipt, err
	}
	if updated.ReceiptPath != "" {
		if err := writeJSON(updated.ReceiptPath, updated); err != nil {
			return updated, err
		}
	}
	return updated, nil
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
	if opts.parallelism == 0 {
		opts.parallelism = 4
	}
	if opts.parallelism < 1 || opts.parallelism > 16 {
		return fmt.Errorf("operation parallelism must be between 1 and 16")
	}
	if opts.parallelSem == nil {
		opts.parallelSem = make(chan struct{}, opts.parallelism)
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
		receipt = operationsvc.NewReceipt(item, registry, path, opts.via, opts.lab, opts.topology, opts.arch, opts.compiler, inputs)
		receipt.Parallelism = opts.parallelism
	} else if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		receipt = operationsvc.NewReceipt(item, registry, path, opts.via, opts.lab, opts.topology, opts.arch, opts.compiler, inputs)
		receipt.Parallelism = opts.parallelism
	} else {
		var err error
		receipt, err = operationsvc.LoadReceipt(path)
		if err != nil {
			return err
		}
		if receipt.Parallelism != 0 {
			opts.parallelism = receipt.Parallelism
			if cap(opts.parallelSem) != opts.parallelism {
				opts.parallelSem = make(chan struct{}, opts.parallelism)
			}
		}
	}
	if err := validatePinnedOperation(item, &receipt, registry); err != nil {
		return err
	}
	if operationsvc.IsDAG(item.Document) {
		return runDAGOperation(ctx, stdout, registry, item, inputs, topologyValues, opts, &receipt, path, resumePath != "")
	}
	_, hasRunnable, routeErr := operationsvc.NextRunnableStep(item.Document, receipt)
	if routeErr != nil {
		return routeErr
	}
	if resumePath != "" && !hasRunnable {
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
	for {
		index, runnable, err := operationsvc.NextRunnableStep(item.Document, receipt)
		if err != nil {
			receipt.Status, receipt.Error = "failed", err.Error()
			_ = operationsvc.SaveReceipt(path, &receipt)
			return err
		}
		if !runnable {
			break
		}
		step := item.Document.Steps[index]
		stepReceipt := &receipt.Steps[index]
		if step.Parallel != nil {
			completed, parallelErr := executeOperationParallelStep(ctx, stdout, registry, item, step, stepReceipt, index, inputs, topologyValues, &receipt, path, opts)
			if parallelErr != nil {
				if stepReceipt.State == "incomplete" {
					if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
						return err
					}
					fmt.Fprintf(stdout, "operation  incomplete\nreceipt    %s\n", path)
					return parallelErr
				}
				return failOperation(stdout, path, &receipt, stepReceipt, parallelErr)
			}
			if completed {
				continue
			}
		}
		if step.Operation != "" {
			completed, childErr := executeOperationChildStep(ctx, stdout, registry, item, step, stepReceipt, index, inputs, topologyValues, &receipt, path, opts)
			if childErr != nil {
				if stepReceipt.State == "incomplete" {
					if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
						return err
					}
					fmt.Fprintf(stdout, "operation  incomplete\nreceipt    %s\n", path)
					return childErr
				}
				return failOperation(stdout, path, &receipt, stepReceipt, childErr)
			}
			if completed {
				if stepReceipt.NextStep == "$fail" {
					err := fmt.Errorf("step %s selected the explicit failure route", step.ID)
					receipt.Status, receipt.Error = "failed", err.Error()
					if saveErr := operationsvc.SaveReceipt(path, &receipt); saveErr != nil {
						return saveErr
					}
					if opts.cleanupOnFailure {
						_ = cleanupOperation(ctx, stdout, registry, item, inputs, &receipt, path, opts)
					}
					return err
				}
				continue
			}
		}
		if stepReceipt.State == "incomplete" {
			updated, err := refreshOperationRuntimeReceipt(ctx, stepReceipt.Runtime, opts)
			if err != nil {
				return failOperation(stdout, path, &receipt, stepReceipt, fmt.Errorf("refresh runtime task for step %s: %w", step.ID, err))
			}
			if stepReceipt.ObjectSHA256 != "" && updated.ObjectSHA256 != stepReceipt.ObjectSHA256 {
				return failOperation(stdout, path, &receipt, stepReceipt, fmt.Errorf("runtime task object hash changed for step %s", step.ID))
			}
			stepReceipt.Runtime, stepReceipt.OutputComplete = updated, updated.OutputComplete
			stepReceipt.State, receipt.Status = operationsvc.ClassifyExecution(updated.ExecutionState, updated.OutputComplete, false)
			switch stepReceipt.State {
			case "completed":
				contractOutput := updated.TransientOutput
				if len(contractOutput) == 0 {
					contractOutput = updated.Output
				}
				if err := applyOperationContract(step, stepReceipt, contractOutput, inputs, receipt.Captures, topologyValues); err != nil {
					return failOperation(stdout, path, &receipt, stepReceipt, err)
				}
				captured, captureErr := captureOperationOutput(step, contractOutput)
				if captureErr != nil {
					return failOperation(stdout, path, &receipt, stepReceipt, captureErr)
				}
				stepReceipt.Captures = captured
				for name, value := range captured {
					receipt.Captures[name] = value
				}
				stepReceipt.State = "completed"
				if err := operationsvc.ApplyRoute(item.Document, &receipt, index); err != nil {
					return failOperation(stdout, path, &receipt, stepReceipt, err)
				}
				stepReceipt.Error = ""
				printOperationResult(stdout, updated.Output, captured)
				if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
					return err
				}
				if stepReceipt.NextStep == "$fail" {
					err := fmt.Errorf("step %s selected the explicit failure route", step.ID)
					receipt.Status, receipt.Error = "failed", err.Error()
					if saveErr := operationsvc.SaveReceipt(path, &receipt); saveErr != nil {
						return saveErr
					}
					if opts.cleanupOnFailure {
						_ = cleanupOperation(ctx, stdout, registry, item, inputs, &receipt, path, opts)
					}
					return err
				}
				continue
			case "failed":
				return failOperation(stdout, path, &receipt, stepReceipt, fmt.Errorf("runtime task for step %s ended in %s: %s", step.ID, updated.ExecutionState, updated.Error))
			default:
				if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
					return err
				}
				return fmt.Errorf("operation step %s is still %s; resume %s after the runtime receipt is complete", step.ID, updated.ExecutionState, path)
			}
		}
		packItem, err := registry.PackRegistry().Resolve(step.Pack)
		if err != nil {
			return failOperation(stdout, path, &receipt, stepReceipt, err)
		}
		if stepReceipt.PackSHA256 != "" && stepReceipt.PackSHA256 != packItem.SHA256 {
			return failOperation(stdout, path, &receipt, stepReceipt, fmt.Errorf("pack %s changed since operation start", step.Pack))
		}
		if err := requireReferencedSensitiveInputs(item.Document, receipt, inputs, step.Arguments); err != nil {
			return failOperation(stdout, path, &receipt, stepReceipt, err)
		}
		arguments, err := resolveOperationArguments(step.Arguments, inputs, receipt.Captures, topologyValues)
		if err != nil {
			return failOperation(stdout, path, &receipt, stepReceipt, err)
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
		contractOutput := runtimeReceipt.TransientOutput
		if len(contractOutput) == 0 {
			contractOutput = runtimeReceipt.Output
		}
		if err := applyOperationContract(step, stepReceipt, contractOutput, inputs, receipt.Captures, topologyValues); err != nil {
			return failOperation(stdout, path, &receipt, stepReceipt, err)
		}
		captured, err := captureOperationOutput(step, contractOutput)
		if err != nil {
			return failOperation(stdout, path, &receipt, stepReceipt, err)
		}
		stepReceipt.Captures = captured
		for name, value := range captured {
			receipt.Captures[name] = value
		}
		printOperationResult(stdout, runtimeReceipt.Output, captured)
		stepReceipt.State = "completed"
		if err := operationsvc.ApplyRoute(item.Document, &receipt, index); err != nil {
			return failOperation(stdout, path, &receipt, stepReceipt, err)
		}
		if err := operationsvc.SaveReceipt(path, &receipt); err != nil {
			return err
		}
		if stepReceipt.NextStep == "$fail" {
			err := fmt.Errorf("step %s selected the explicit failure route", step.ID)
			receipt.Status, receipt.Error = "failed", err.Error()
			if saveErr := operationsvc.SaveReceipt(path, &receipt); saveErr != nil {
				return saveErr
			}
			if opts.cleanupOnFailure {
				_ = cleanupOperation(ctx, stdout, registry, item, inputs, &receipt, path, opts)
			}
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

type parallelBranchResult struct {
	index   int
	receipt operationsvc.StepReceipt
	output  []string
	err     error
}

func executeOperationParallelStep(ctx context.Context, stdout io.Writer, registry *operationsvc.Registry, parent operationsvc.Resolved, step operationsvc.Step, stepReceipt *operationsvc.StepReceipt, index int, inputs, topology map[string]string, receipt *operationsvc.Receipt, path string, opts operationOptions) (bool, error) {
	if step.Parallel == nil || stepReceipt.Parallel == nil {
		return false, fmt.Errorf("parallel step %s has no pinned parallel receipt", step.ID)
	}
	if stepReceipt.State == "completed" {
		return true, nil
	}
	resolvedArguments := make(map[int]map[string]string, len(step.Parallel.Branches))
	for branchIndex, branch := range step.Parallel.Branches {
		if branchIndex >= len(stepReceipt.Parallel.Branches) {
			return false, fmt.Errorf("parallel step %s branch receipt count changed", step.ID)
		}
		branchReceipt := stepReceipt.Parallel.Branches[branchIndex]
		if branchReceipt.ID != branch.ID {
			return false, fmt.Errorf("parallel step %s branch definition changed", step.ID)
		}
		if branch.Pack != "" {
			item, err := registry.PackRegistry().Resolve(branch.Pack)
			if err != nil {
				return false, err
			}
			if branchReceipt.PackSHA256 == "" || branchReceipt.PackSHA256 != item.SHA256 {
				return false, fmt.Errorf("parallel branch %s/%s pack changed since operation start", step.ID, branch.ID)
			}
		} else {
			item, err := registry.Resolve(branch.Operation)
			if err != nil {
				return false, err
			}
			if branchReceipt.OperationSHA256 == "" || branchReceipt.OperationSHA256 != item.SHA256 {
				return false, fmt.Errorf("parallel branch %s/%s operation changed since operation start", step.ID, branch.ID)
			}
		}
		if err := requireReferencedSensitiveInputs(parent.Document, *receipt, inputs, branch.Arguments); err != nil {
			return false, err
		}
		arguments, err := resolveOperationArguments(branch.Arguments, inputs, receipt.Captures, topology)
		if err != nil {
			return false, fmt.Errorf("parallel branch %s/%s: %w", step.ID, branch.ID, err)
		}
		resolvedArguments[branchIndex] = arguments
	}

	// A parallel group is atomic at launch: every direct pack branch is built,
	// analyzed, argument-packed, runtime-checked, and adapter-prepared before
	// any branch is allowed to execute. Child operations are definition-pinned
	// here and perform the same preparation inside their own execution scope.
	preparedBranches := make(map[int]*preparedOperationPack)
	for branchIndex, branch := range step.Parallel.Branches {
		current := stepReceipt.Parallel.Branches[branchIndex]
		if branch.Pack == "" || current.State == "completed" || current.State == "failed" || (current.Runtime.ExecutionState != "" && !current.OutputComplete) {
			continue
		}
		packItem, err := registry.PackRegistry().Resolve(branch.Pack)
		if err != nil {
			return false, err
		}
		work := filepath.Join("work", "operations", filepath.Base(filepath.Dir(path)), "parallel", step.ID, branch.ID)
		prepared, err := prepareOperationPack(ctx, registry.PackRegistry(), packItem, resolvedArguments[branchIndex], operationArgumentSensitivity(parent.Document, branch.Arguments), opts, work)
		if err != nil {
			return false, fmt.Errorf("prepare parallel branch %s/%s: %w", step.ID, branch.ID, err)
		}
		preparedBranches[branchIndex] = &prepared
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	stepReceipt.State, stepReceipt.ContractState, stepReceipt.StartedAt = "running", "pending", now
	stepReceipt.Parallel.State, stepReceipt.Parallel.StartedAt = "running", now
	receipt.Status = "running"
	for branchIndex := range stepReceipt.Parallel.Branches {
		branchReceipt := &stepReceipt.Parallel.Branches[branchIndex]
		if branchReceipt.State == "pending" || branchReceipt.State == "incomplete" {
			branchReceipt.State = "running"
			if branchReceipt.StartedAt == "" {
				branchReceipt.StartedAt = now
			}
		}
	}
	if err := operationsvc.SaveReceipt(path, receipt); err != nil {
		return false, err
	}

	results := make(chan parallelBranchResult, len(step.Parallel.Branches))
	var active, observed int
	var concurrencyMu sync.Mutex
	launchSem := make(chan struct{}, opts.parallelism)
	launched := 0
	for branchIndex, branch := range step.Parallel.Branches {
		current := stepReceipt.Parallel.Branches[branchIndex]
		if current.State == "completed" || current.State == "failed" {
			continue
		}
		launched++
		launchSem <- struct{}{}
		go func(branchIndex int, branch operationsvc.ParallelBranch, current operationsvc.StepReceipt) {
			defer func() { <-launchSem }()
			concurrencyMu.Lock()
			active++
			if active > observed {
				observed = active
			}
			concurrencyMu.Unlock()
			var output bytes.Buffer
			updated, err := executeOperationParallelBranch(ctx, &output, registry, parent, step.ID, branch, current, inputs, receipt.Captures, topology, path, opts, preparedBranches[branchIndex])
			concurrencyMu.Lock()
			active--
			concurrencyMu.Unlock()
			results <- parallelBranchResult{index: branchIndex, receipt: updated, output: nonemptyLines(output.String()), err: err}
		}(branchIndex, branch, current)
	}
	collected := make([]parallelBranchResult, 0, launched)
	for count := 0; count < launched; count++ {
		result := <-results
		stepReceipt.Parallel.Branches[result.index] = result.receipt
		collected = append(collected, result)
	}
	close(results)
	sort.Slice(collected, func(i, j int) bool { return collected[i].index < collected[j].index })
	for _, result := range collected {
		for _, line := range result.output {
			fmt.Fprintf(stdout, "  branch %-12s %s\n", step.Parallel.Branches[result.index].ID, line)
		}
	}
	stepReceipt.Parallel.ObservedConcurrency = observed
	if observed > receipt.MaxConcurrency {
		receipt.MaxConcurrency = observed
	}

	hasIncomplete, hasFailed := false, false
	var failures []string
	for branchIndex, branchReceipt := range stepReceipt.Parallel.Branches {
		switch branchReceipt.State {
		case "incomplete", "running", "pending":
			hasIncomplete = true
		case "failed":
			hasFailed = true
			failures = append(failures, step.Parallel.Branches[branchIndex].ID+": "+branchReceipt.Error)
		}
	}
	if hasIncomplete {
		stepReceipt.State, stepReceipt.Parallel.State, receipt.Status = "incomplete", "incomplete", "incomplete"
		stepReceipt.Error = strings.Join(failures, "; ")
		_ = operationsvc.SaveReceipt(path, receipt)
		return false, fmt.Errorf("parallel step %s has incomplete branches; resume %s", step.ID, path)
	}
	if hasFailed {
		stepReceipt.State, stepReceipt.Parallel.State, stepReceipt.ContractState = "failed", "failed", "failed"
		stepReceipt.Error = strings.Join(failures, "; ")
		_ = operationsvc.SaveReceipt(path, receipt)
		return false, fmt.Errorf("parallel step %s failed: %s", step.ID, stepReceipt.Error)
	}

	exports := map[string]string{}
	for name, reference := range step.Parallel.Exports {
		parts := strings.Split(strings.TrimPrefix(reference, "$branch."), ".")
		if len(parts) != 2 {
			return false, fmt.Errorf("parallel step %s has invalid export %s=%s", step.ID, name, reference)
		}
		found := false
		for branchIndex, branch := range step.Parallel.Branches {
			if branch.ID != parts[0] {
				continue
			}
			value := stepReceipt.Parallel.Branches[branchIndex].Captures[parts[1]]
			if value == "" {
				return false, fmt.Errorf("parallel step %s export %s did not find %s", step.ID, name, reference)
			}
			exports[name], receipt.Captures[name], found = value, value, true
			break
		}
		if !found {
			return false, fmt.Errorf("parallel step %s export %s did not find %s", step.ID, name, reference)
		}
	}
	completedAt := time.Now().UTC().Format(time.RFC3339Nano)
	stepReceipt.State, stepReceipt.ContractState, stepReceipt.CompletedAt = "completed", "matched", completedAt
	stepReceipt.Parallel.State, stepReceipt.Parallel.Exports, stepReceipt.Parallel.CompletedAt = "completed", exports, completedAt
	operationsvc.RecordParallelPath(receipt, step.ID, *stepReceipt.Parallel)
	if err := operationsvc.ApplyRoute(parent.Document, receipt, index); err != nil {
		return false, err
	}
	if err := operationsvc.SaveReceipt(path, receipt); err != nil {
		return false, err
	}
	return true, nil
}

func executeOperationParallelBranch(ctx context.Context, stdout io.Writer, registry *operationsvc.Registry, parent operationsvc.Resolved, stepID string, branch operationsvc.ParallelBranch, current operationsvc.StepReceipt, inputs, captures, topology map[string]string, parentPath string, opts operationOptions, prepared *preparedOperationPack) (operationsvc.StepReceipt, error) {
	current.State, current.Error = "running", ""
	arguments, err := resolveOperationArguments(branch.Arguments, inputs, captures, topology)
	if err != nil {
		current.State, current.Error = "failed", err.Error()
		return current, err
	}
	if branch.Operation != "" {
		child, err := registry.Resolve(branch.Operation)
		if err != nil {
			current.State, current.Error = "failed", err.Error()
			return current, err
		}
		childPath := current.ChildReceipt
		if childPath == "" {
			childPath = filepath.Join(filepath.Dir(parentPath), "children", stepID, branch.ID, "operation.json")
			current.ChildReceipt = childPath
		}
		childOpts := opts
		childOpts.cleanup, childOpts.cleanupOnFailure = false, false
		runErr := runOperation(ctx, stdout, registry, child, arguments, childOpts, childPath)
		childReceipt, loadErr := operationsvc.LoadReceipt(childPath)
		if loadErr != nil {
			if runErr != nil {
				current.State, current.Error = "failed", runErr.Error()
				return current, runErr
			}
			current.State, current.Error = "failed", loadErr.Error()
			return current, loadErr
		}
		current.ChildCleanupState = childReceipt.CleanupState
		switch childReceipt.Status {
		case "completed", "cleaned":
		case "running", "incomplete", "pending":
			current.State, current.Error = "incomplete", childReceipt.Error
			return current, fmt.Errorf("child operation %s is incomplete", child.Qualified)
		default:
			err := runErr
			if err == nil {
				err = fmt.Errorf("child operation %s ended in %s: %s", child.Qualified, childReceipt.Status, childReceipt.Error)
			}
			current.State, current.Error = "failed", err.Error()
			return current, err
		}
		output := []string{fmt.Sprintf("[operation] status=complete operation=%s receipt=%s cleanup=%s", child.Qualified, childPath, childReceipt.CleanupState)}
		fields, payload, err := operationsvc.EvaluateExpectation(output, branch.Expect, inputs, captures, topology)
		if err != nil {
			current.State, current.ContractState, current.Error = "failed", "failed", err.Error()
			return current, err
		}
		exported, err := operationsvc.CaptureChildOutput(childReceipt, branch.Captures)
		if err != nil {
			current.State, current.ContractState, current.Error = "failed", "failed", err.Error()
			return current, err
		}
		current.State, current.ContractState, current.MatchedTag, current.MatchedFields, current.PayloadVerified = "completed", "matched", branch.Expect.Tag, fields, payload
		current.Captures, current.CompletedAt = exported, time.Now().UTC().Format(time.RFC3339Nano)
		printOperationResult(stdout, output, exported)
		return current, nil
	}

	packItem, err := registry.PackRegistry().Resolve(branch.Pack)
	if err != nil {
		current.State, current.Error = "failed", err.Error()
		return current, err
	}
	var runtimeReceipt runtimeadapter.Receipt
	if current.Runtime.ExecutionState != "" && !current.OutputComplete {
		runtimeReceipt, err = refreshOperationRuntimeReceipt(ctx, current.Runtime, opts)
	} else if prepared != nil {
		runtimeReceipt, err = executePreparedOperationPack(ctx, *prepared, opts)
	} else {
		work := filepath.Join("work", "operations", filepath.Base(filepath.Dir(parentPath)), "parallel", stepID, branch.ID)
		runtimeReceipt, err = executeOperationPack(ctx, stdout, registry.PackRegistry(), packItem, arguments, operationArgumentSensitivity(parent.Document, branch.Arguments), opts, work)
	}
	current.Runtime, current.ObjectSHA256, current.OutputComplete = runtimeReceipt, runtimeReceipt.ObjectSHA256, runtimeReceipt.OutputComplete
	current.State, _ = operationsvc.ClassifyExecution(runtimeReceipt.ExecutionState, runtimeReceipt.OutputComplete, err != nil)
	if current.State != "completed" {
		if err != nil {
			current.Error = err.Error()
		}
		return current, err
	}
	output := runtimeReceipt.TransientOutput
	if len(output) == 0 {
		output = runtimeReceipt.Output
	}
	fields, payload, err := operationsvc.EvaluateExpectation(output, branch.Expect, inputs, captures, topology)
	if err != nil {
		current.State, current.ContractState, current.Error = "failed", "failed", err.Error()
		return current, err
	}
	exported, err := operationsvc.CaptureOutput(output, branch.Captures)
	if err != nil {
		current.State, current.ContractState, current.Error = "failed", "failed", err.Error()
		return current, err
	}
	current.State, current.ContractState, current.MatchedTag, current.MatchedFields, current.PayloadVerified = "completed", "matched", branch.Expect.Tag, fields, payload
	current.Captures, current.CompletedAt = exported, time.Now().UTC().Format(time.RFC3339Nano)
	printOperationResult(stdout, runtimeReceipt.Output, exported)
	return current, nil
}

func captureOperationOutput(step operationsvc.Step, output []string) (map[string]string, error) {
	if len(step.Outcomes) > 0 {
		return operationsvc.CaptureAvailableOutput(output, step.Captures), nil
	}
	return operationsvc.CaptureOutput(output, step.Captures)
}

func executeOperationChildStep(ctx context.Context, stdout io.Writer, registry *operationsvc.Registry, parent operationsvc.Resolved, step operationsvc.Step, stepReceipt *operationsvc.StepReceipt, index int, inputs, topology map[string]string, receipt *operationsvc.Receipt, path string, opts operationOptions) (bool, error) {
	child, err := registry.Resolve(step.Operation)
	if err != nil {
		return false, err
	}
	if stepReceipt.OperationSHA256 == "" || stepReceipt.OperationSHA256 != child.SHA256 {
		return false, fmt.Errorf("child operation %s changed since operation start", step.Operation)
	}
	if err := requireReferencedSensitiveInputs(parent.Document, *receipt, inputs, step.Arguments); err != nil {
		return false, err
	}
	childInputs, err := resolveOperationArguments(step.Arguments, inputs, receipt.Captures, topology)
	if err != nil {
		return false, err
	}
	childPath := stepReceipt.ChildReceipt
	if childPath == "" {
		childPath = filepath.Join(filepath.Dir(path), "children", step.ID, "operation.json")
		stepReceipt.ChildReceipt = childPath
	}
	fmt.Fprintf(stdout, "step %d/%d  %s → operation:%s\n", index+1, len(parent.Document.Steps), step.ID, child.Qualified)
	stepReceipt.State = "running"
	receipt.Status = "running"
	if err := operationsvc.SaveReceipt(path, receipt); err != nil {
		return false, err
	}
	childOpts := opts
	childOpts.cleanup, childOpts.cleanupOnFailure = false, false
	runErr := runOperation(ctx, stdout, registry, child, childInputs, childOpts, childPath)
	childReceipt, loadErr := operationsvc.LoadReceipt(childPath)
	if loadErr != nil {
		if runErr != nil {
			return false, runErr
		}
		return false, loadErr
	}
	stepReceipt.ChildCleanupState = childReceipt.CleanupState
	switch childReceipt.Status {
	case "completed", "cleaned":
		// Continue below. A child is atomic from the parent route's point of view.
	case "running", "incomplete", "pending":
		stepReceipt.State, receipt.Status = "incomplete", "incomplete"
		stepReceipt.Error = childReceipt.Error
		return false, fmt.Errorf("child operation %s is incomplete; resume %s", child.Qualified, path)
	default:
		if runErr != nil {
			return false, runErr
		}
		return false, fmt.Errorf("child operation %s ended in %s: %s", child.Qualified, childReceipt.Status, childReceipt.Error)
	}
	output := []string{fmt.Sprintf("[operation] status=complete operation=%s receipt=%s cleanup=%s", child.Qualified, childPath, childReceipt.CleanupState)}
	if err := applyOperationContract(step, stepReceipt, output, inputs, receipt.Captures, topology); err != nil {
		return false, err
	}
	captured, err := operationsvc.CaptureChildOutput(childReceipt, step.Captures)
	if err != nil {
		return false, err
	}
	stepReceipt.Captures = captured
	for name, value := range captured {
		receipt.Captures[name] = value
	}
	stepReceipt.State, stepReceipt.Error = "completed", ""
	operationsvc.RecordChildPath(receipt, step.ID, childReceipt)
	if err := operationsvc.ApplyRoute(parent.Document, receipt, index); err != nil {
		return false, err
	}
	printOperationResult(stdout, output, captured)
	if err := operationsvc.SaveReceipt(path, receipt); err != nil {
		return false, err
	}
	return true, nil
}

func applyOperationContract(step operationsvc.Step, receipt *operationsvc.StepReceipt, output []string, inputs, captures, topology map[string]string) error {
	if len(step.Outcomes) > 0 {
		outcome, fields, payloadVerified, err := operationsvc.EvaluateOutcomes(output, step.Outcomes, inputs, captures, topology)
		if err != nil {
			receipt.ContractState = "failed"
			return fmt.Errorf("step %s result outcomes: %w", step.ID, err)
		}
		receipt.ContractState = "matched"
		receipt.MatchedOutcome = outcome.ID
		receipt.NextStep = outcome.Next
		receipt.MatchedTag = outcome.Expect.Tag
		receipt.MatchedFields = fields
		receipt.PayloadVerified = payloadVerified
		return nil
	}
	fields, payloadVerified, err := operationsvc.EvaluateExpectation(output, step.Expect, inputs, captures, topology)
	if err != nil {
		receipt.ContractState = "failed"
		return fmt.Errorf("step %s result contract: %w", step.ID, err)
	}
	if step.Expect == nil {
		receipt.ContractState = "legacy"
		return nil
	}
	receipt.ContractState = "matched"
	receipt.MatchedTag = step.Expect.Tag
	receipt.MatchedFields = fields
	receipt.PayloadVerified = payloadVerified
	receipt.NextStep = ""
	return nil
}

func validatePinnedOperation(item operationsvc.Resolved, receipt *operationsvc.Receipt, registry *operationsvc.Registry) error {
	document := item.Document
	if receipt.Execution != "" && receipt.Execution != operationsvc.ExecutionMode(document) {
		return fmt.Errorf("operation execution mode changed since operation start")
	}
	if len(document.Steps) != len(receipt.Steps) {
		return fmt.Errorf("operation receipt step count does not match the pinned definition")
	}
	wantDependencies := registry.DependencyHashes(item)
	if len(receipt.DependencySHA256) > 0 {
		for name, hash := range wantDependencies {
			if receipt.DependencySHA256[name] != hash {
				return fmt.Errorf("dependency %s changed since operation start", name)
			}
		}
	}
	for index, step := range document.Steps {
		if strings.Join(receipt.Steps[index].DependsOn, "\x00") != strings.Join(step.DependsOn, "\x00") {
			return fmt.Errorf("step %s dependencies changed since operation start", step.ID)
		}
		if step.Parallel != nil {
			if receipt.Steps[index].Parallel == nil || len(receipt.Steps[index].Parallel.Branches) != len(step.Parallel.Branches) {
				return fmt.Errorf("parallel step %s branch count does not match the pinned definition", step.ID)
			}
			for branchIndex, branch := range step.Parallel.Branches {
				pinned := receipt.Steps[index].Parallel.Branches[branchIndex]
				if branch.Pack != "" {
					resolved, err := registry.PackRegistry().Resolve(branch.Pack)
					if err != nil {
						return err
					}
					if pinned.PackSHA256 == "" || pinned.PackSHA256 != resolved.SHA256 {
						return fmt.Errorf("parallel branch %s/%s pack changed since operation start", step.ID, branch.ID)
					}
				} else {
					resolved, err := registry.Resolve(branch.Operation)
					if err != nil {
						return err
					}
					if pinned.OperationSHA256 == "" || pinned.OperationSHA256 != resolved.SHA256 {
						return fmt.Errorf("parallel branch %s/%s operation changed since operation start", step.ID, branch.ID)
					}
				}
				if branch.Cleanup != nil {
					cleanup, err := registry.PackRegistry().Resolve(branch.Cleanup.Pack)
					if err != nil {
						return err
					}
					if pinned.CleanupSHA256 == "" || pinned.CleanupSHA256 != cleanup.SHA256 {
						return fmt.Errorf("parallel branch %s/%s cleanup pack changed since operation start", step.ID, branch.ID)
					}
				}
			}
			continue
		}
		if step.Pack != "" {
			resolved, err := registry.PackRegistry().Resolve(step.Pack)
			if err != nil {
				return err
			}
			if receipt.Steps[index].PackSHA256 == "" || receipt.Steps[index].PackSHA256 != resolved.SHA256 {
				return fmt.Errorf("pack %s changed since operation start", step.Pack)
			}
		} else {
			resolved, err := registry.Resolve(step.Operation)
			if err != nil {
				return err
			}
			if receipt.Steps[index].OperationSHA256 == "" || receipt.Steps[index].OperationSHA256 != resolved.SHA256 {
				return fmt.Errorf("operation %s changed since operation start", step.Operation)
			}
		}
		if step.Cleanup == nil {
			continue
		}
		cleanup, err := registry.PackRegistry().Resolve(step.Cleanup.Pack)
		if err != nil {
			return err
		}
		if receipt.Steps[index].CleanupSHA256 == "" || receipt.Steps[index].CleanupSHA256 != cleanup.SHA256 {
			return fmt.Errorf("cleanup pack %s changed since operation start", step.Cleanup.Pack)
		}
	}
	return nil
}

type preparedOperationPack struct {
	adapter  runtimeadapter.Adapter
	prepared runtimeadapter.Prepared
}

func prepareOperationPack(ctx context.Context, packs *packsvc.Registry, item packsvc.Resolved, arguments map[string]string, sensitiveArguments map[string]bool, opts operationOptions, work string) (preparedOperationPack, error) {
	project, err := materializePackProject(work, item, packs)
	if err != nil {
		return preparedOperationPack{}, err
	}
	build, err := buildsys.BuildWithOptions(project, buildsys.Options{Arch: opts.arch, Compiler: opts.compiler})
	if err != nil {
		return preparedOperationPack{}, err
	}
	analysis, err := artifact.Analyze(build.Object, "go")
	if err != nil {
		return preparedOperationPack{}, err
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
		return preparedOperationPack{}, err
	}
	for index, name := range resolved.Names {
		if sensitiveArguments[name] && index < len(resolved.Sensitive) {
			resolved.Sensitive[index] = true
		}
	}
	packed, items, err := argpack.PackTokens(resolved.Tokens)
	if err != nil {
		return preparedOperationPack{}, err
	}
	// Operation output is intentionally compact. The adapter's full diagnostics
	// and evidence remain available in its runtime receipt.
	run := &runtimeRunContext{stdout: io.Discard, input: project, projectInput: true, entry: "go", timeout: operationPackTimeout(arguments), runtimeName: "auto", compiler: opts.compiler, arch: opts.arch, resolved: resolved, packed: packed, items: items, labName: opts.lab, labProfiles: opts.profiles, transportTimeout: 3 * time.Minute, bootstrapMode: "auto", interactiveLab: requiresInteractiveLabSession(project)}
	run.sensitiveOutputFields, run.sensitiveArgumentNames, run.sensitiveValues = runtimeSensitivity(project, resolved)
	adapters, err := runtimeAdapterRegistry(run)
	if err != nil {
		return preparedOperationPack{}, err
	}
	adapter, err := adapters.Resolve(opts.via)
	if err != nil {
		return preparedOperationPack{}, err
	}
	availability, err := adapter.Detect(ctx)
	if err != nil {
		return preparedOperationPack{}, err
	}
	if !availability.Available {
		return preparedOperationPack{}, fmt.Errorf("%s runtime is unavailable: %s", adapter.Name(), availability.Detail)
	}
	request := runtimeadapter.Request{Input: project, Object: build.Object, Entrypoint: "go"}
	for index, arg := range items {
		name := fmt.Sprintf("arg%d", index+1)
		if index < len(resolved.Names) {
			name = resolved.Names[index]
		}
		request.Arguments = append(request.Arguments, runtimeadapter.Argument{Name: name, Type: arg.Kind, Value: arg.Value, Sensitive: index < len(resolved.Sensitive) && resolved.Sensitive[index]})
	}
	prepared, err := adapter.Prepare(ctx, request)
	if err != nil {
		return preparedOperationPack{}, err
	}
	return preparedOperationPack{adapter: adapter, prepared: prepared}, nil
}

func operationPackTimeout(arguments map[string]string) int {
	timeout := 5000
	for _, name := range []string{"timeout_ms", "wait_ms", "read_timeout_ms"} {
		value, err := strconv.Atoi(strings.TrimSpace(arguments[name]))
		if err == nil && value > timeout {
			timeout = value
		}
	}
	if timeout > 600000 {
		return 600000
	}
	return timeout
}

func executePreparedOperationPack(ctx context.Context, prepared preparedOperationPack, opts operationOptions) (runtimeadapter.Receipt, error) {
	if opts.parallelSem != nil {
		select {
		case opts.parallelSem <- struct{}{}:
			defer func() { <-opts.parallelSem }()
		case <-ctx.Done():
			return runtimeadapter.Receipt{}, ctx.Err()
		}
	}
	return prepared.adapter.Execute(ctx, prepared.prepared)
}

func startPreparedOperationPack(ctx context.Context, prepared preparedOperationPack, opts operationOptions) (runtimeadapter.Receipt, error) {
	if opts.parallelSem != nil {
		select {
		case opts.parallelSem <- struct{}{}:
			defer func() { <-opts.parallelSem }()
		case <-ctx.Done():
			return runtimeadapter.Receipt{}, ctx.Err()
		}
	}
	return prepared.adapter.Start(ctx, prepared.prepared)
}

func executeOperationPack(ctx context.Context, stdout io.Writer, packs *packsvc.Registry, item packsvc.Resolved, arguments map[string]string, sensitiveArguments map[string]bool, opts operationOptions, work string) (runtimeadapter.Receipt, error) {
	prepared, err := prepareOperationPack(ctx, packs, item, arguments, sensitiveArguments, opts, work)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	return executePreparedOperationPack(ctx, prepared, opts)
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
	if err := validatePinnedOperation(item, receipt, registry); err != nil {
		return err
	}
	receipt.CleanupState = "running"
	if err := operationsvc.SaveReceipt(path, receipt); err != nil {
		return err
	}
	work := filepath.Join("work", "operations", filepath.Base(filepath.Dir(path)), "cleanup")
	for _, index := range operationsvc.CleanupStepIndexes(item.Document, *receipt) {
		step, stepReceipt := item.Document.Steps[index], &receipt.Steps[index]
		if step.Parallel != nil && stepReceipt.Parallel != nil {
			for branchIndex := len(step.Parallel.Branches) - 1; branchIndex >= 0; branchIndex-- {
				branch, branchReceipt := step.Parallel.Branches[branchIndex], &stepReceipt.Parallel.Branches[branchIndex]
				if branchReceipt.State != "completed" {
					continue
				}
				if branch.Operation != "" {
					if branchReceipt.ChildReceipt == "" || branchReceipt.ChildCleanupState == "completed" {
						continue
					}
					child, err := registry.Resolve(branch.Operation)
					if err != nil {
						return cleanupFailure(path, receipt, branchReceipt, err)
					}
					childInputs, err := resolveOperationArguments(branch.Arguments, inputs, receipt.Captures, topologyValues)
					if err != nil {
						return cleanupFailure(path, receipt, branchReceipt, err)
					}
					childReceipt, err := operationsvc.LoadReceipt(branchReceipt.ChildReceipt)
					if err != nil {
						return cleanupFailure(path, receipt, branchReceipt, err)
					}
					fmt.Fprintf(stdout, "cleanup     %s/%s → operation:%s\n", step.ID, branch.ID, child.Qualified)
					if err := cleanupOperation(ctx, stdout, registry, child, childInputs, &childReceipt, branchReceipt.ChildReceipt, opts); err != nil {
						return cleanupFailure(path, receipt, branchReceipt, err)
					}
					branchReceipt.ChildCleanupState, branchReceipt.CleanupState = "completed", "completed"
					if err := operationsvc.SaveReceipt(path, receipt); err != nil {
						return err
					}
					continue
				}
				if branch.Cleanup == nil || branchReceipt.CleanupState == "completed" {
					continue
				}
				cleanupPack, err := registry.PackRegistry().Resolve(branch.Cleanup.Pack)
				if err != nil {
					return cleanupFailure(path, receipt, branchReceipt, err)
				}
				if err := requireReferencedSensitiveInputs(item.Document, *receipt, inputs, branch.Cleanup.Arguments); err != nil {
					return cleanupFailure(path, receipt, branchReceipt, err)
				}
				captures := mergeOperationCaptures(receipt.Captures, branchReceipt.Captures)
				arguments, err := resolveOperationArguments(branch.Cleanup.Arguments, inputs, captures, topologyValues)
				if err != nil {
					return cleanupFailure(path, receipt, branchReceipt, err)
				}
				fmt.Fprintf(stdout, "cleanup     %s/%s → %s\n", step.ID, branch.ID, cleanupPack.Qualified)
				result, err := executeOperationPack(ctx, stdout, registry.PackRegistry(), cleanupPack, arguments, operationArgumentSensitivity(item.Document, branch.Cleanup.Arguments), opts, filepath.Join(work, step.ID, branch.ID))
				branchReceipt.CleanupRuntime = &result
				if err != nil || !result.OutputComplete {
					if err == nil {
						err = fmt.Errorf("cleanup output was incomplete")
					}
					return cleanupFailure(path, receipt, branchReceipt, err)
				}
				printOperationResult(stdout, result.Output, nil)
				branchReceipt.CleanupState = "completed"
				if err := operationsvc.SaveReceipt(path, receipt); err != nil {
					return err
				}
			}
			stepReceipt.CleanupState = "completed"
			if err := operationsvc.SaveReceipt(path, receipt); err != nil {
				return err
			}
			continue
		}
		if step.Operation != "" {
			child, err := registry.Resolve(step.Operation)
			if err != nil {
				return cleanupFailure(path, receipt, stepReceipt, err)
			}
			childInputs, err := resolveOperationArguments(step.Arguments, inputs, receipt.Captures, topologyValues)
			if err != nil {
				return cleanupFailure(path, receipt, stepReceipt, err)
			}
			childReceipt, err := operationsvc.LoadReceipt(stepReceipt.ChildReceipt)
			if err != nil {
				return cleanupFailure(path, receipt, stepReceipt, err)
			}
			fmt.Fprintf(stdout, "cleanup     %s → operation:%s\n", step.ID, child.Qualified)
			if err := cleanupOperation(ctx, stdout, registry, child, childInputs, &childReceipt, stepReceipt.ChildReceipt, opts); err != nil {
				return cleanupFailure(path, receipt, stepReceipt, err)
			}
			stepReceipt.ChildCleanupState, stepReceipt.CleanupState = "completed", "completed"
			if err := operationsvc.SaveReceipt(path, receipt); err != nil {
				return err
			}
			continue
		}
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

func mergeOperationCaptures(parent, local map[string]string) map[string]string {
	result := map[string]string{}
	for name, value := range parent {
		result[name] = value
	}
	for name, value := range local {
		result[name] = value
	}
	return result
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
func failOperation(stdout io.Writer, path string, receipt *operationsvc.Receipt, step *operationsvc.StepReceipt, err error) error {
	step.State, step.Error, receipt.Status, receipt.Error = "failed", err.Error(), "failed", err.Error()
	_ = operationsvc.SaveReceipt(path, receipt)
	fmt.Fprintf(stdout, "operation  failed\nreceipt    %s\n", path)
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
		target := step.Pack
		if step.Operation != "" {
			target = "operation:" + step.Operation
		} else if step.Parallel != nil {
			target = fmt.Sprintf("parallel:%s branches=%d", step.Parallel.Join, len(step.Parallel.Branches))
		}
		fmt.Fprintf(stdout, "  %d. %-20s %s\n", index+1, step.ID, target)
		if step.Parallel != nil {
			for _, branch := range step.Parallel.Branches {
				branchTarget := branch.Pack
				if branch.Operation != "" {
					branchTarget = "operation:" + branch.Operation
				}
				fmt.Fprintf(stdout, "     branch %-14s %s\n", branch.ID, branchTarget)
			}
			exportNames := make([]string, 0, len(step.Parallel.Exports))
			for name := range step.Parallel.Exports {
				exportNames = append(exportNames, name)
			}
			sort.Strings(exportNames)
			for _, name := range exportNames {
				fmt.Fprintf(stdout, "     export %-14s %s\n", name, step.Parallel.Exports[name])
			}
			continue
		}
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
			if capture.Capture != "" {
				fmt.Fprintf(stdout, "     capture %-14s child:%s\n", name, capture.Capture)
			} else {
				fmt.Fprintf(stdout, "     capture %-14s [%s] %s\n", name, capture.Tag, capture.Field)
			}
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

func printChildOperations(stdout io.Writer, registry *operationsvc.Registry, item operationsvc.Resolved, indent string, seen map[string]bool) {
	if seen[item.Qualified] {
		return
	}
	seen[item.Qualified] = true
	for _, step := range item.Document.Steps {
		if step.Parallel != nil {
			for _, branch := range step.Parallel.Branches {
				if branch.Operation == "" {
					continue
				}
				child, err := registry.Resolve(branch.Operation)
				if err != nil {
					continue
				}
				fmt.Fprintf(stdout, "\n%s%s/%s/%s → %s\n", indent, item.Document.ID, step.ID, branch.ID, child.Qualified)
				printChildOperations(stdout, registry, child, indent+"  ", seen)
			}
			continue
		}
		if step.Operation == "" {
			continue
		}
		child, err := registry.Resolve(step.Operation)
		if err != nil {
			continue
		}
		fmt.Fprintf(stdout, "\n%s%s/%s → %s\n", indent, item.Document.ID, step.ID, child.Qualified)
		for index, childStep := range child.Document.Steps {
			target := childStep.Pack
			if childStep.Operation != "" {
				target = "operation:" + childStep.Operation
			}
			fmt.Fprintf(stdout, "%s  %d. %-20s %s\n", indent, index+1, childStep.ID, target)
		}
		printChildOperations(stdout, registry, child, indent+"  ", seen)
	}
}
