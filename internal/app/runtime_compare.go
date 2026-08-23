package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/professor-moody/bofbench/internal/argpack"
	"github.com/professor-moody/bofbench/internal/lab"
	operationsvc "github.com/professor-moody/bofbench/internal/operation"
	packsvc "github.com/professor-moody/bofbench/internal/pack"
	"github.com/professor-moody/bofbench/internal/runlog"
	"github.com/professor-moody/bofbench/internal/runtimeadapter"
	"github.com/professor-moody/bofbench/internal/runtimecomparison"
	"github.com/professor-moody/bofbench/internal/sourceaudit"
)

type runtimeCompareOptions struct {
	via, arguments                                                         []string
	lab, profiles, arch, compiler, entry                                   string
	sliverClient, sliverSession, sliverControl, runtimeControls, bootstrap string
	timeout                                                                int
	format                                                                 string
}

func runtimeCompareCommand(stdout io.Writer) *cobra.Command {
	opts := runtimeCompareOptions{via: []string{"lab", "sliver"}, profiles: lab.ProfilesPath(), arch: "x64", compiler: "auto", entry: "go", bootstrap: "auto", timeout: 5000, format: "text"}
	cmd := &cobra.Command{
		Use: "compare <project>", Short: "Run the same exact BOF through multiple runtimes and compare structured results", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return compareProjectRuntimes(cmd.Context(), stdout, args[0], opts)
		},
	}
	cmd.Flags().StringSliceVar(&opts.via, "via", opts.via, "runtime adapters to compare; comma-separated")
	cmd.Flags().StringArrayVar(&opts.arguments, "arg", nil, "typed project argument name=value; repeatable")
	cmd.Flags().StringVar(&opts.lab, "lab", "", "named lab profile")
	cmd.Flags().StringVar(&opts.profiles, "profiles", opts.profiles, "global lab profiles file")
	cmd.Flags().StringVar(&opts.arch, "arch", opts.arch, "build architecture: x64 or x86")
	cmd.Flags().StringVar(&opts.compiler, "compiler", opts.compiler, "compiler: auto, mingw, or msvc")
	cmd.Flags().StringVar(&opts.entry, "entry", opts.entry, "BOF entrypoint")
	cmd.Flags().StringVar(&opts.sliverClient, "sliver-client", "", "Sliver client path")
	cmd.Flags().StringVar(&opts.sliverSession, "session", "", "Sliver session selector")
	cmd.Flags().StringVar(&opts.sliverControl, "sliver-control", "", "remote Sliver runtime control; defaults to the active control")
	cmd.Flags().StringVar(&opts.runtimeControls, "runtime-controls", "", "runtime control profiles file")
	cmd.Flags().StringVar(&opts.bootstrap, "bootstrap", opts.bootstrap, "lab bootstrap mode: auto, always, or never")
	cmd.Flags().IntVar(&opts.timeout, "timeout", opts.timeout, "per-runtime timeout in milliseconds")
	cmd.Flags().StringVar(&opts.format, "format", opts.format, "output format: text or json")
	cmd.AddCommand(runtimeCompareOperationCommand(stdout))
	return cmd
}

func compareProjectRuntimes(ctx context.Context, stdout io.Writer, project string, opts runtimeCompareOptions) error {
	if !sourceaudit.IsSourceInput(project) {
		return fmt.Errorf("runtime compare requires a BOF project so every adapter can use the same pack and argument contract")
	}
	via, err := normalizeComparisonRuntimes(opts.via)
	if err != nil {
		return err
	}
	resolved, err := resolveRunArguments(project, opts.arguments, nil)
	if err != nil {
		return err
	}
	packed, items, err := argpack.PackTokens(resolved.Tokens)
	if err != nil {
		return err
	}
	started := time.Now()
	runDir, err := runlog.NewDir("runtime-compare-" + safeName(objectBase(project)))
	if err != nil {
		return err
	}
	results := make([]runtimecomparison.RuntimeResult, 0, len(via))
	for _, runtimeName := range via {
		result := executeComparisonRuntime(ctx, project, runtimeName, opts, resolved, packed, items)
		results = append(results, result)
	}
	receipt := runtimecomparison.Compare(project, "pack", runlog.ID(runDir), results, projectComparisonContracts(project), started)
	receipt.ReceiptPath = filepathJoin(runDir, "comparison.json")
	if err := writeJSON(receipt.ReceiptPath, receipt); err != nil {
		return err
	}
	return printRuntimeComparison(stdout, receipt, opts.format)
}

func executeComparisonRuntime(ctx context.Context, project, runtimeName string, opts runtimeCompareOptions, resolved resolvedRunArguments, packed []byte, items []argpack.Item) runtimecomparison.RuntimeResult {
	result := runtimecomparison.RuntimeResult{Runtime: runtimeName, Status: "unavailable"}
	run := &runtimeRunContext{
		stdout: io.Discard, input: project, projectInput: true, entry: opts.entry, timeout: opts.timeout,
		compiler: opts.compiler, arch: opts.arch, runtimeName: "windows-coff", resolved: resolved, packed: packed, items: items,
		labName: opts.lab, labProfiles: opts.profiles, bootstrapMode: opts.bootstrap,
		sliverClient: opts.sliverClient, sliverSession: opts.sliverSession,
		sliverControl: opts.sliverControl, runtimeControls: opts.runtimeControls,
		// A runtime comparison is meaningful only when every lane executes the
		// same object. Force the lab adapter to build locally and upload instead
		// of allowing a remote compiler to produce an equivalent-but-different
		// COFF object.
		forceLocalLab: runtimeName == "lab",
	}
	run.sensitiveOutputFields, run.sensitiveArgumentNames, run.sensitiveValues = runtimeSensitivity(project, resolved)
	registry, err := runtimeAdapterRegistry(run)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	adapter, err := registry.Resolve(runtimeName)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	availability, err := adapter.Detect(ctx)
	if err != nil || !availability.Available {
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Error = emptyText(availability.Detail, "runtime unavailable")
		}
		return result
	}
	request := runtimeadapter.Request{Input: project, Entrypoint: opts.entry}
	for index, item := range items {
		name := fmt.Sprintf("arg%d", index+1)
		if index < len(resolved.Names) {
			name = resolved.Names[index]
		}
		request.Arguments = append(request.Arguments, runtimeadapter.Argument{Name: name, Type: item.Kind, Value: item.Value, Sensitive: index < len(resolved.Sensitive) && resolved.Sensitive[index]})
	}
	prepared, err := adapter.Prepare(ctx, request)
	if err != nil {
		result.Status, result.Error = "failed", err.Error()
		return result
	}
	receipt, executeErr := adapter.Execute(ctx, prepared)
	result.ReceiptPath, result.ObjectSHA256 = receipt.ReceiptPath, receipt.ObjectSHA256
	result.OutputComplete = receipt.OutputComplete && receipt.ExecutionState == "completed"
	result.Status = receipt.ExecutionState
	if result.Status == "" {
		result.Status = receipt.Status
	}
	result.Output = receipt.TransientOutput
	if len(result.Output) == 0 {
		result.Output = receipt.Output
	}
	if executeErr != nil {
		result.Error = executeErr.Error()
	}
	if receipt.Error != "" {
		result.Error = receipt.Error
	}
	return result
}

func projectComparisonContracts(project string) []packsvc.ComparisonContract {
	lock, _, err := packsvc.LoadLock(project)
	if err != nil {
		return nil
	}
	registry, err := packsvc.Load(packsvc.LoadOptions{Project: project})
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var contracts []packsvc.ComparisonContract
	for _, record := range lock.Packs {
		item, resolveErr := registry.Resolve(record.Qualified)
		if resolveErr != nil {
			continue
		}
		for _, contract := range item.Document.ComparisonContracts {
			keyData, _ := json.Marshal(contract)
			key := string(keyData)
			if !seen[key] {
				seen[key] = true
				contracts = append(contracts, contract)
			}
		}
	}
	return contracts
}

func runtimeCompareOperationCommand(stdout io.Writer) *cobra.Command {
	var via, catalogs, arguments []string
	var project, labName, topology, targets, profiles, arch, compiler, format string
	var parallelism int
	cmd := &cobra.Command{Use: "operation <operation>", Short: "Run one operation through multiple runtimes and compare completed step results", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		runtimes, err := normalizeComparisonRuntimes(via)
		if err != nil {
			return err
		}
		packs, err := packsvc.Load(packsvc.LoadOptions{Project: project, ExtraCatalogs: catalogs})
		if err != nil {
			return err
		}
		registry, err := operationsvc.Load(operationsvc.LoadOptions{Project: project, ExtraCatalogs: catalogs, PackRegistry: packs})
		if err != nil {
			return err
		}
		item, err := registry.Resolve(args[0])
		if err != nil {
			return err
		}
		inputs, err := resolveOperationInputs(item.Document, arguments, nil, false)
		if err != nil {
			return err
		}
		started := time.Now()
		runDir, err := runlog.NewDir("runtime-compare-operation-" + safeName(item.Document.ID))
		if err != nil {
			return err
		}
		var results []runtimecomparison.RuntimeResult
		for _, runtimeName := range runtimes {
			var output bytes.Buffer
			opts := operationOptions{project: project, via: runtimeName, lab: labName, topology: topology, targets: targets, arch: arch, compiler: compiler, catalogs: catalogs, arguments: arguments, profiles: profiles, parallelism: parallelism}
			runErr := runOperation(cmd.Context(), &output, registry, item, inputs, opts, "")
			result := runtimecomparison.RuntimeResult{Runtime: runtimeName, Status: "failed"}
			path := comparisonReceiptPath(output.String())
			if path != "" {
				operationReceipt, loadErr := operationsvc.LoadReceipt(path)
				if loadErr == nil {
					result = operationRuntimeResult(runtimeName, operationReceipt)
				}
			}
			if runErr != nil {
				result.Error = runErr.Error()
				if strings.Contains(strings.ToLower(runErr.Error()), "unavailable") {
					result.Status = "unavailable"
				}
			}
			results = append(results, result)
		}
		receipt := runtimecomparison.Compare(item.Qualified, "operation", runlog.ID(runDir), results, nil, started)
		receipt.ReceiptPath = filepathJoin(runDir, "comparison.json")
		if err := writeJSON(receipt.ReceiptPath, receipt); err != nil {
			return err
		}
		return printRuntimeComparison(stdout, receipt, format)
	}}
	cmd.Flags().StringSliceVar(&via, "via", []string{"lab", "sliver"}, "runtime adapters to compare; comma-separated")
	cmd.Flags().StringVar(&project, "project", ".", "project used for catalog and operation discovery")
	cmd.Flags().StringSliceVar(&catalogs, "catalog", nil, "additional pack and operation catalog path; repeatable")
	cmd.Flags().StringArrayVar(&arguments, "arg", nil, "operation input name=value; repeatable")
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile")
	cmd.Flags().StringVar(&topology, "topology", "", "named topology")
	cmd.Flags().StringVar(&targets, "targets", "", "named topology target set")
	cmd.Flags().StringVar(&profiles, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&arch, "arch", "x64", "build architecture: x64 or x86")
	cmd.Flags().StringVar(&compiler, "compiler", "auto", "compiler: auto, mingw, or msvc")
	cmd.Flags().IntVar(&parallelism, "parallelism", 4, "maximum concurrent operation branches")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.MarkFlagsMutuallyExclusive("lab", "topology")
	return cmd
}

func operationRuntimeResult(runtimeName string, receipt operationsvc.Receipt) runtimecomparison.RuntimeResult {
	result := runtimecomparison.RuntimeResult{Runtime: runtimeName, Status: receipt.Status, ReceiptPath: receipt.Path, ObjectHashes: map[string]string{}}
	var output []string
	for _, step := range receipt.Steps {
		if step.Runtime.ObjectSHA256 != "" {
			result.ObjectHashes[step.ID] = step.Runtime.ObjectSHA256
		}
		if len(step.Runtime.TransientOutput) > 0 {
			output = append(output, step.Runtime.TransientOutput...)
		} else {
			output = append(output, step.Runtime.Output...)
		}
	}
	result.Output = output
	result.ObjectSHA256 = objectHashSetDigest(result.ObjectHashes)
	result.OutputComplete = receipt.Status == "completed"
	if result.OutputComplete {
		result.Status = "completed"
	}
	result.Error = receipt.Error
	return result
}

func objectHashSetDigest(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	hash := sha256.New()
	for _, key := range keys {
		fmt.Fprintf(hash, "%s=%s\n", key, strings.ToLower(values[key]))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func comparisonReceiptPath(output string) string {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "receipt" {
			return fields[1]
		}
	}
	return ""
}

func normalizeComparisonRuntimes(values []string) ([]string, error) {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		for _, name := range strings.Split(value, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" || seen[name] {
				continue
			}
			if name != "native" && name != "lab" && name != "sliver" && name != "cobaltstrike" {
				return nil, fmt.Errorf("unsupported comparison runtime %q", name)
			}
			seen[name] = true
			result = append(result, name)
		}
	}
	if len(result) < 2 {
		return nil, fmt.Errorf("runtime compare requires at least two distinct runtimes")
	}
	return result, nil
}

func printRuntimeComparison(stdout io.Writer, receipt runtimecomparison.Receipt, format string) error {
	switch format {
	case "text":
		_, err := fmt.Fprint(stdout, runtimecomparison.Text(receipt))
		return err
	case "json":
		return printJSON(stdout, receipt)
	default:
		return fmt.Errorf("runtime comparison format must be text or json")
	}
}

// filepathJoin exists to keep all comparison receipts relative to the normal
// run directory while avoiding user-supplied path concatenation.
func filepathJoin(elements ...string) string { return strings.Join(elements, string(os.PathSeparator)) }
