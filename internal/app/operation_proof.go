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
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/evidence"
	"bofbench/internal/lab"
	operationsvc "bofbench/internal/operation"
	packsvc "bofbench/internal/pack"
	"bofbench/internal/runlog"
)

type operationTestResult struct {
	Operation string           `json:"operation"`
	Status    string           `json:"status"`
	Packs     []packTestResult `json:"packs"`
	Error     string           `json:"error,omitempty"`
}

type operationTestReport struct {
	evidence.Header
	Status      string                `json:"status"`
	GeneratedAt string                `json:"generated_at"`
	Results     []operationTestResult `json:"results"`
	JSONPath    string                `json:"json_path,omitempty"`
}

type operationProofResult struct {
	Operation    string            `json:"operation"`
	Case         string            `json:"case"`
	Runtime      string            `json:"runtime"`
	Architecture string            `json:"architecture"`
	Status       string            `json:"status"`
	Receipt      string            `json:"receipt,omitempty"`
	Captures     map[string]string `json:"captures,omitempty"`
	ActualPath   []string          `json:"actual_path,omitempty"`
	StateChecks  int               `json:"state_checks,omitempty"`
	CleanupState string            `json:"cleanup_state,omitempty"`
	Output       []string          `json:"output,omitempty"`
	Error        string            `json:"error,omitempty"`
}

type operationProofReport struct {
	evidence.Header
	Status       string                 `json:"status"`
	Runtime      string                 `json:"runtime"`
	Lab          string                 `json:"lab,omitempty"`
	Topology     string                 `json:"topology,omitempty"`
	Architecture string                 `json:"architecture"`
	GeneratedAt  string                 `json:"generated_at"`
	Declared     int                    `json:"declared"`
	Passed       int                    `json:"passed"`
	Unavailable  int                    `json:"unavailable"`
	Incomplete   int                    `json:"incomplete"`
	Failed       int                    `json:"failed"`
	WithoutProof int                    `json:"without_proof"`
	Results      []operationProofResult `json:"results"`
	JSONPath     string                 `json:"json_path,omitempty"`
}

func operationTestCommand(stdout io.Writer, load func() (*operationsvc.Registry, error), catalogSelectors func() []string) *cobra.Command {
	var all bool
	var compilers []string
	var format string
	cmd := &cobra.Command{Use: "test [operation]", Short: "Build, analyze, and verify every pack used by an operation", Args: cobra.MaximumNArgs(1), RunE: func(*cobra.Command, []string) error { return nil }}
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		if (len(args) == 0) == !all {
			return fmt.Errorf("provide one operation or use --all")
		}
		registry, err := load()
		if err != nil {
			return err
		}
		items, err := selectedOperations(registry, args, all, catalogSelectors())
		if err != nil {
			return err
		}
		report := operationTestReport{Header: evidence.New("bofbench.operation-test", "", ""), Status: "pass", GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
		for _, item := range items {
			result := operationTestResult{Operation: item.Qualified, Status: "pass"}
			seen := map[string]bool{}
			for _, step := range item.Document.Steps {
				for _, name := range []string{step.Pack, cleanupPackName(step)} {
					if name == "" || seen[name] {
						continue
					}
					seen[name] = true
					packItem, resolveErr := registry.PackRegistry().Resolve(name)
					if resolveErr != nil {
						result.Status, result.Error = "fail", resolveErr.Error()
						continue
					}
					packResult := testOnePack(packItem, registry.PackRegistry(), compilers)
					result.Packs = append(result.Packs, packResult)
					if packResult.Status == "fail" {
						result.Status = "fail"
					} else if packResult.Status == "pass_with_unavailable" && result.Status == "pass" {
						result.Status = "pass_with_unavailable"
					}
				}
			}
			if result.Status == "fail" {
				report.Status = "fail"
			} else if result.Status == "pass_with_unavailable" && report.Status == "pass" {
				report.Status = "pass_with_unavailable"
			}
			report.Results = append(report.Results, result)
		}
		runDir, err := runlog.NewDir("operation-test")
		if err != nil {
			return err
		}
		report.Header = evidence.New("bofbench.operation-test", runlog.ID(runDir), "")
		report.JSONPath = filepath.Join(runDir, "operation-test.json")
		if err := writeJSON(report.JSONPath, report); err != nil {
			return err
		}
		if format == "json" {
			return printJSON(stdout, report)
		}
		printOperationTestReport(stdout, report)
		if report.Status == "fail" {
			return codedError{code: 1, err: fmt.Errorf("one or more operation tests failed")}
		}
		return nil
	}
	cmd.Flags().BoolVar(&all, "all", false, "test every resolved operation, optionally limited by --catalog")
	cmd.Flags().StringSliceVar(&compilers, "compiler", []string{"mingw", "msvc"}, "compiler coverage; repeatable")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func operationProveCommand(stdout io.Writer, load func() (*operationsvc.Registry, error), catalogSelectors func() []string) *cobra.Command {
	var all bool
	var via, labName, topologyName, arch, compiler, format string
	cmd := &cobra.Command{Use: "prove [operation]", Short: "Run declared operation proofs and independent cleanup checks", Args: cobra.MaximumNArgs(1)}
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if (len(args) == 0) == !all {
			return fmt.Errorf("provide one operation or use --all")
		}
		if via != "native" && via != "lab" && via != "sliver" && via != "cobaltstrike" {
			return fmt.Errorf("unsupported proof runtime %q", via)
		}
		registry, err := load()
		if err != nil {
			return err
		}
		items, err := selectedOperations(registry, args, all, catalogSelectors())
		if err != nil {
			return err
		}
		var topology *resolvedTopologyValues
		if topologyName != "" {
			resolved, topologyErr := resolveTopologyRuntimeValues(cmd.Context(), topologyName, lab.ProfilesPath())
			if topologyErr != nil {
				return topologyErr
			}
			topology = &resolved
			labName = resolved.Topology.Execution.Name
		}
		report, proofErr := proveOperations(cmd.Context(), stdout, registry, items, via, labName, topologyName, topology, arch, compiler)
		if format == "json" {
			if err := printJSON(stdout, report); err != nil {
				return err
			}
		} else {
			printOperationProofReport(stdout, report)
		}
		return proofErr
	}
	cmd.Flags().BoolVar(&all, "all", false, "prove every resolved operation with a matching proof case")
	cmd.Flags().StringVar(&via, "via", "lab", "runtime: native, lab, sliver, or cobaltstrike")
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile")
	cmd.Flags().StringVar(&topologyName, "topology", "", "named execution, target, and optional domain-controller role mapping")
	cmd.Flags().StringVar(&arch, "arch", "x64", "proof architecture: x64 or x86")
	cmd.Flags().StringVar(&compiler, "compiler", "auto", "compiler: auto, mingw, or msvc")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.MarkFlagsMutuallyExclusive("lab", "topology")
	return cmd
}

func proveOperations(ctx context.Context, stdout io.Writer, registry *operationsvc.Registry, items []operationsvc.Resolved, via, labName, topologyName string, topology *resolvedTopologyValues, arch, compiler string) (operationProofReport, error) {
	report := operationProofReport{Header: evidence.New("bofbench.operation-proof", "", ""), Status: "pass", Runtime: via, Lab: labName, Topology: topologyName, Architecture: arch, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	runDir, err := runlog.NewDir("operation-proof")
	if err != nil {
		return report, err
	}
	report.Header = evidence.New("bofbench.operation-proof", runlog.ID(runDir), "")
	report.JSONPath = filepath.Join(runDir, "operation-proof.json")
	work := filepath.Join("work", "operation-proofs", report.RunID)
	if err := os.MkdirAll(work, 0o755); err != nil {
		return report, err
	}
	retPath := filepath.Join(work, "payload-ret.bin")
	if err := os.WriteFile(retPath, []byte{0xc3}, 0o600); err != nil {
		return report, err
	}
	memoryNeedle := filepath.Join(work, "memory-needle.bin")
	memoryNeedleBytes := []byte("BOFBenchOperationNeedle")
	if err := os.WriteFile(memoryNeedle, memoryNeedleBytes, 0o600); err != nil {
		return report, err
	}
	memoryNeedleHash := sha256.Sum256(memoryNeedleBytes)
	targets, owned := map[string]lab.TargetReport{}, map[string]bool{}
	ensureTarget := func(profile string) (lab.TargetReport, error) {
		if target, ok := targets[profile]; ok {
			return target, nil
		}
		var output bytes.Buffer
		args := []string{"lab", "target", "status", "--format", "json"}
		if profile != "" {
			args = append(args, "--lab", profile)
		}
		var target lab.TargetReport
		if statusErr := Run(args, &output, &output); statusErr == nil && json.Unmarshal(output.Bytes(), &target) == nil && target.Status == "pass" && target.State.SchemaVersion >= 5 {
			targets[profile] = target
			return target, nil
		}
		output.Reset()
		args = []string{"lab", "target", "deploy", "--format", "json"}
		if profile != "" {
			args = append(args, "--lab", profile)
		}
		if err := Run(args, &output, &output); err != nil {
			return target, fmt.Errorf("deploy operation proof target: %w: %s", err, strings.TrimSpace(output.String()))
		}
		if err := json.Unmarshal(output.Bytes(), &target); err != nil {
			return target, err
		}
		targets[profile], owned[profile] = target, true
		return target, nil
	}
	defer func() {
		for profile, remove := range owned {
			if !remove {
				continue
			}
			args := []string{"lab", "target", "remove", "--format", "json"}
			if profile != "" {
				args = append(args, "--lab", profile)
			}
			_ = Run(args, io.Discard, io.Discard)
		}
	}()
	for _, item := range items {
		matched := false
		for _, proof := range item.Document.ProofCases {
			if !containsString(proof.Via, via) || (len(proof.Architectures) > 0 && !containsString(proof.Architectures, arch)) {
				continue
			}
			matched, report.Declared = true, report.Declared+1
			result := operationProofResult{Operation: item.Qualified, Case: proof.ID, Runtime: via, Architecture: arch, Status: "pass"}
			if containsString(proof.Roles, "target") && (topology == nil || topology.Topology.Target == nil) {
				result.Status, result.Error = "unavailable", "proof requires a target topology role"
				report.Unavailable++
				report.Results = append(report.Results, result)
				continue
			}
			if containsString(proof.Roles, "domain_controller") && (topology == nil || topology.Topology.DomainController == nil) {
				result.Status, result.Error = "unavailable", "proof requires a domain_controller topology role"
				report.Unavailable++
				report.Results = append(report.Results, result)
				continue
			}
			fixtureProfile := labName
			if containsString(proof.Roles, "target") && topology != nil {
				fixtureProfile = topology.Topology.Target.Name
			}
			var target lab.TargetReport
			if via == "lab" || via == "sliver" {
				target, err = ensureTarget(fixtureProfile)
				if err != nil {
					result.Status, result.Error = "unavailable", err.Error()
					report.Unavailable++
					report.Results = append(report.Results, result)
					continue
				}
			}
			proofSecret, err := newProofSecret()
			if err != nil {
				result.Status, result.Error = "fail", err.Error()
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			}
			secretBytes, _ := hex.DecodeString(proofSecret)
			secretPath := filepath.Join(work, proofFileName(item.Document.ID+"-"+proof.ID)+"-secret.bin")
			if err := os.WriteFile(secretPath, secretBytes, 0o600); err != nil {
				return report, err
			}
			placeholders := proofPlaceholderValues(target, report.RunID, proofSecret)
			if arch == "x86" && target.State.X86PID != 0 {
				placeholders["$TARGET_PID"] = fmt.Sprintf("%d", target.State.X86PID)
				placeholders["$TARGET_TID"] = fmt.Sprintf("%d", target.State.X86AlertableTID)
				placeholders["$TARGET_ARCH"] = "x86"
				placeholders["$TARGET_MODULE_BASE"] = target.State.X86KnownModuleBase
				placeholders["$TARGET_MODULE_PATH"] = target.State.X86KnownModulePath
			}
			placeholders["$PAYLOAD_RET_PATH"] = retPath
			placeholders["$MEMORY_NEEDLE_PATH"] = memoryNeedle
			placeholders["$MEMORY_NEEDLE_SHA256"] = hex.EncodeToString(memoryNeedleHash[:])
			placeholders["$PROOF_SECRET_PATH"] = secretPath
			inputs, err := resolveProofValues(proof.Inputs, placeholders)
			if err != nil {
				result.Status, result.Error = "fail", err.Error()
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			}
			args := operationProofRunArgs(item, via, labName, topologyName, arch, compiler, inputs, proof.Cleanup)
			var output bytes.Buffer
			runErr := Run(args, &output, &output)
			result.Output = nonemptyLines(output.String())
			result.Receipt = operationReceiptFromOutput(result.Output)
			if runErr != nil || result.Receipt == "" {
				if runErr != nil && unavailableCoverage(runErr) {
					result.Status, result.Error = "unavailable", runErr.Error()
					report.Unavailable++
				} else if strings.Contains(strings.ToLower(output.String()), "incomplete") {
					result.Status, result.Error = "incomplete", operationProofErrorText(runErr, "operation output is incomplete")
					report.Incomplete++
				} else {
					result.Status, result.Error = "fail", operationProofErrorText(runErr, "operation did not produce a receipt")
					report.Failed++
				}
				report.Results = append(report.Results, result)
				continue
			}
			receipt, err := operationsvc.LoadReceipt(result.Receipt)
			if err != nil {
				result.Status, result.Error = "fail", err.Error()
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			}
			result.Captures = receipt.Captures
			result.ActualPath = append([]string(nil), receipt.ActualPath...)
			if err := matchOperationProofCaptures(proof.ExpectCaptures, receipt.Captures, placeholders); err != nil {
				result.Status, result.Error = "fail", err.Error()
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			}
			checks := resolveOperationStateChecks(proof.StateChecks, receipt.Captures)
			if count, checkErr := verifyProofStateChecks(ctx, via, labName, topology, checks, "after_run", placeholders); checkErr != nil {
				result.Status, result.Error = "fail", "state verification: "+checkErr.Error()
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			} else {
				result.StateChecks += count
			}
			if proof.Cleanup {
				cleanupArgs := []string{"operation"}
				if item.CatalogRoot != "" {
					cleanupArgs = append(cleanupArgs, "--catalog", item.CatalogRoot)
				}
				cleanupArgs = append(cleanupArgs, "cleanup", result.Receipt)
				var cleanup bytes.Buffer
				if cleanupErr := Run(cleanupArgs, &cleanup, &cleanup); cleanupErr != nil {
					result.Status, result.Error = "fail", "cleanup: "+cleanupErr.Error()
					report.Failed++
					report.Results = append(report.Results, result)
					continue
				}
				if err := matchOperationProofPath(proof.ExpectPath, receipt.ActualPath); err != nil {
					result.Status, result.Error = "fail", err.Error()
					report.Failed++
					report.Results = append(report.Results, result)
					continue
				}
				result.Output = append(result.Output, nonemptyLines(cleanup.String())...)
				result.CleanupState = "completed"
				if count, checkErr := verifyProofStateChecks(ctx, via, labName, topology, checks, "after_cleanup", placeholders); checkErr != nil {
					result.Status, result.Error = "fail", "cleanup verification: "+checkErr.Error()
					report.Failed++
					report.Results = append(report.Results, result)
					continue
				} else {
					result.StateChecks += count
				}
			}
			report.Passed++
			report.Results = append(report.Results, result)
		}
		if !matched {
			report.WithoutProof++
		}
	}
	if report.Failed > 0 {
		report.Status = "fail"
	} else if report.Unavailable > 0 || report.Incomplete > 0 || report.WithoutProof > 0 || len(report.Results) == 0 {
		report.Status = "pass_with_unavailable"
	}
	if err := writeJSON(report.JSONPath, report); err != nil {
		return report, err
	}
	if report.Status == "fail" {
		return report, codedError{code: 1, err: fmt.Errorf("one or more operation proofs failed")}
	}
	return report, nil
}

func selectedOperations(registry *operationsvc.Registry, args []string, all bool, selectors []string) ([]operationsvc.Resolved, error) {
	if !all {
		item, err := registry.Resolve(args[0])
		if err != nil {
			return nil, err
		}
		return []operationsvc.Resolved{item}, nil
	}
	items := registry.List()
	if len(selectors) == 0 {
		return items, nil
	}
	wanted := map[string]bool{}
	for _, selector := range selectors {
		wanted[selector] = true
		wanted[strings.ToLower(filepath.Base(filepath.Clean(selector)))] = true
	}
	filtered := items[:0]
	for _, item := range items {
		if wanted[item.Catalog] || wanted[item.CatalogRoot] {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func cleanupPackName(step operationsvc.Step) string {
	if step.Cleanup == nil {
		return ""
	}
	return step.Cleanup.Pack
}

func operationProofRunArgs(item operationsvc.Resolved, via, labName, topologyName, arch, compiler string, inputs map[string]string, cleanupOnFailure bool) []string {
	args := []string{"operation"}
	if item.CatalogRoot != "" {
		args = append(args, "--catalog", item.CatalogRoot)
	}
	args = append(args, "run", item.Qualified, "--via", via, "--arch", arch, "--compiler", compiler)
	if cleanupOnFailure {
		args = append(args, "--cleanup-on-failure")
	}
	if topologyName != "" {
		args = append(args, "--topology", topologyName)
	} else if labName != "" && (via == "lab" || via == "sliver") {
		args = append(args, "--lab", labName)
	}
	names := make([]string, 0, len(inputs))
	for name := range inputs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		args = append(args, "--arg", name+"="+inputs[name])
	}
	return args
}

func operationReceiptFromOutput(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		fields := strings.Fields(lines[i])
		if len(fields) >= 2 && strings.TrimSuffix(strings.ToLower(fields[0]), ":") == "receipt" {
			return fields[len(fields)-1]
		}
	}
	return ""
}

func matchOperationProofCaptures(expected, actual, placeholders map[string]string) error {
	for name, raw := range expected {
		want, err := resolveProofString(raw, placeholders)
		if err != nil {
			return err
		}
		got, ok := actual[name]
		if !ok || (want != "*" && got != want) {
			return fmt.Errorf("capture %s=%q did not match %q", name, got, want)
		}
	}
	return nil
}

func matchOperationProofPath(expected, actual []string) error {
	if len(expected) == 0 {
		return nil
	}
	if len(expected) != len(actual) {
		return fmt.Errorf("operation path %v did not match %v", actual, expected)
	}
	for index := range expected {
		if expected[index] != actual[index] {
			return fmt.Errorf("operation path %v did not match %v", actual, expected)
		}
	}
	return nil
}

func resolveOperationStateChecks(checks []packsvc.ProofStateCheck, captures map[string]string) []packsvc.ProofStateCheck {
	resolved := make([]packsvc.ProofStateCheck, len(checks))
	for index, check := range checks {
		resolved[index] = check
		resolved[index].Parameters = map[string]string{}
		for name, value := range check.Parameters {
			for capture, captured := range captures {
				value = strings.ReplaceAll(value, "$capture."+capture, captured)
			}
			resolved[index].Parameters[name] = value
		}
	}
	return resolved
}

func operationProofErrorText(err error, fallback string) string {
	if err != nil {
		return err.Error()
	}
	return fallback
}

func printOperationTestReport(w io.Writer, report operationTestReport) {
	fmt.Fprintf(w, "OPERATION TEST %s\noperations=%d\n", strings.ToUpper(report.Status), len(report.Results))
	for _, result := range report.Results {
		fmt.Fprintf(w, "%s  %s packs=%d\n", result.Operation, result.Status, len(result.Packs))
	}
	fmt.Fprintf(w, "report=%s\n", report.JSONPath)
}

func printOperationProofReport(w io.Writer, report operationProofReport) {
	fmt.Fprintf(w, "OPERATION PROOF %s\nruntime=%s arch=%s declared=%d passed=%d unavailable=%d incomplete=%d failed=%d without_proof=%d\n", strings.ToUpper(report.Status), report.Runtime, report.Architecture, report.Declared, report.Passed, report.Unavailable, report.Incomplete, report.Failed, report.WithoutProof)
	for _, result := range report.Results {
		fmt.Fprintf(w, "%s/%s  %s", result.Operation, result.Case, result.Status)
		if result.Error != "" {
			fmt.Fprintf(w, "  %s", result.Error)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "report=%s\n", report.JSONPath)
}
