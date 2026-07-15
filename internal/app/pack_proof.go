package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"bofbench/internal/evidence"
	"bofbench/internal/lab"
	packsvc "bofbench/internal/pack"
	"bofbench/internal/runlog"
	"bofbench/internal/stage"
)

type packTestCell struct {
	Arch     string `json:"arch"`
	Compiler string `json:"compiler"`
	Status   string `json:"status"`
	Object   string `json:"object,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Error    string `json:"error,omitempty"`
}

type packTestResult struct {
	Pack             string            `json:"pack"`
	Status           string            `json:"status"`
	Builds           []packTestCell    `json:"builds"`
	ExpectedAnalysis []string          `json:"expected_analysis,omitempty"`
	DetectedAnalysis []string          `json:"detected_analysis,omitempty"`
	Exports          map[string]string `json:"exports,omitempty"`
	Error            string            `json:"error,omitempty"`
}

type packTestReport struct {
	evidence.Header
	Status      string           `json:"status"`
	GeneratedAt string           `json:"generated_at"`
	Results     []packTestResult `json:"results"`
	JSONPath    string           `json:"json_path,omitempty"`
}

type packProofResult struct {
	Pack            string   `json:"pack"`
	Case            string   `json:"case"`
	Runtime         string   `json:"runtime"`
	Status          string   `json:"status"`
	Output          []string `json:"output,omitempty"`
	Receipt         string   `json:"receipt,omitempty"`
	ObjectSHA256    string   `json:"object_sha256,omitempty"`
	PayloadVerified bool     `json:"payload_verified,omitempty"`
	StateChecks     int      `json:"state_checks,omitempty"`
	Error           string   `json:"error,omitempty"`
}

type packProofReport struct {
	evidence.Header
	Status       string            `json:"status"`
	Lab          string            `json:"lab,omitempty"`
	Topology     string            `json:"topology,omitempty"`
	Runtime      string            `json:"runtime"`
	GeneratedAt  string            `json:"generated_at"`
	Results      []packProofResult `json:"results"`
	Declared     int               `json:"declared"`
	Passed       int               `json:"passed"`
	Unavailable  int               `json:"unavailable"`
	Failed       int               `json:"failed"`
	WithoutProof int               `json:"without_proof"`
	JSONPath     string            `json:"json_path,omitempty"`
}

func packTestCommand(stdout io.Writer, load func() (*packsvc.Registry, error), catalogSelectors func() []string) *cobra.Command {
	var all bool
	var compilers []string
	var format string
	cmd := &cobra.Command{
		Use: "test [pack]", Short: "Build, analyze, and verify exports for capability packs", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(args) == 0) == !all {
				return fmt.Errorf("provide one pack or use --all")
			}
			registry, err := load()
			if err != nil {
				return err
			}
			items, err := selectedPacks(registry, args, all, catalogSelectors())
			if err != nil {
				return err
			}
			report := packTestReport{Header: evidence.New("bofbench.pack-test", "", ""), Status: "pass", GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
			for _, item := range items {
				result := testOnePack(item, registry, compilers)
				if result.Status == "fail" {
					report.Status = "fail"
				} else if result.Status == "pass_with_unavailable" && report.Status == "pass" {
					report.Status = "pass_with_unavailable"
				}
				report.Results = append(report.Results, result)
			}
			runDir, err := runlog.NewDir("pack-test")
			if err != nil {
				return err
			}
			report.Header = evidence.New("bofbench.pack-test", runlog.ID(runDir), "")
			report.JSONPath = filepath.Join(runDir, "pack-test.json")
			if err := writeJSON(report.JSONPath, report); err != nil {
				return err
			}
			if format == "json" {
				return printJSON(stdout, report)
			}
			printPackTestReport(stdout, report)
			if report.Status == "fail" {
				return codedError{code: 1, err: fmt.Errorf("one or more pack tests failed")}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "test every resolved pack, optionally limited by --catalog")
	cmd.Flags().StringSliceVar(&compilers, "compiler", []string{"mingw", "msvc"}, "compiler coverage; repeatable")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func packProveCommand(stdout io.Writer, load func() (*packsvc.Registry, error), catalogSelectors func() []string) *cobra.Command {
	var all bool
	var via, labName, topologyName, format string
	cmd := &cobra.Command{
		Use: "prove [pack]", Short: "Run declared capability proofs and cleanup through a selected runtime", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(args) == 0) == !all {
				return fmt.Errorf("provide one pack or use --all")
			}
			if via != "native" && via != "lab" && via != "sliver" && via != "cobaltstrike" {
				return fmt.Errorf("unsupported proof runtime %q", via)
			}
			registry, err := load()
			if err != nil {
				return err
			}
			items, err := selectedPacks(registry, args, all, catalogSelectors())
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
			report, proofErr := provePacks(cmd.Context(), stdout, registry, items, via, labName, topology)
			if format == "json" {
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			} else {
				printPackProofReport(stdout, report)
			}
			return proofErr
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "prove every resolved pack with a matching proof case")
	cmd.Flags().StringVar(&via, "via", "lab", "runtime: native, lab, sliver, or cobaltstrike")
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile for lab or Sliver proof")
	cmd.Flags().StringVar(&topologyName, "topology", "", "named execution, target, and optional domain-controller role mapping")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.MarkFlagsMutuallyExclusive("lab", "topology")
	return cmd
}

func selectedPacks(registry *packsvc.Registry, args []string, all bool, selectors []string) ([]packsvc.Resolved, error) {
	if !all {
		item, err := registry.Resolve(args[0])
		if err != nil {
			return nil, err
		}
		return []packsvc.Resolved{item}, nil
	}
	items := registry.List()
	if len(selectors) == 0 {
		return items, nil
	}
	allowed := map[string]bool{}
	for _, selector := range selectors {
		allowed[selector] = true
		allowed[strings.ToLower(filepath.Base(filepath.Clean(selector)))] = true
	}
	var filtered []packsvc.Resolved
	for _, item := range items {
		if allowed[item.Catalog] {
			filtered = append(filtered, item)
		}
	}
	return filtered, nil
}

func testOnePack(item packsvc.Resolved, registry *packsvc.Registry, compilers []string) packTestResult {
	result := packTestResult{Pack: item.Qualified, Status: "pass", ExpectedAnalysis: append([]string(nil), item.Document.ExpectedAnalysis...), Exports: map[string]string{}}
	work, err := os.MkdirTemp("", "bofbench-pack-test-*")
	if err != nil {
		result.Status, result.Error = "fail", err.Error()
		return result
	}
	defer os.RemoveAll(work)
	project, err := materializePackProject(work, item, registry)
	if err != nil {
		result.Status, result.Error = "fail", err.Error()
		return result
	}
	previous, err := os.Getwd()
	if err != nil {
		result.Status, result.Error = "fail", err.Error()
		return result
	}
	if err := os.Chdir(work); err != nil {
		result.Status, result.Error = "fail", err.Error()
		return result
	}
	defer os.Chdir(previous)
	var exportObject string
	hasUnavailable := false
	for _, arch := range item.Document.Architecture {
		for _, compiler := range compilers {
			build, buildErr := buildsys.BuildWithOptions(project, buildsys.Options{Arch: arch, Compiler: compiler, VerifyReproducible: true})
			cell := packTestCell{Arch: arch, Compiler: compiler, Status: "pass", Object: build.Object}
			if build.ObjectFingerprint != nil {
				cell.SHA256 = build.ObjectFingerprint.SHA256
			}
			if buildErr != nil {
				cell.Error = buildErr.Error()
				if unavailableCoverage(buildErr) {
					cell.Status = "unavailable"
					hasUnavailable = true
				} else {
					cell.Status = "fail"
					result.Status = "fail"
				}
				result.Builds = append(result.Builds, cell)
				continue
			}
			analysis, analysisErr := artifact.Analyze(build.Object, "go")
			if analysisErr != nil {
				cell.Status, cell.Error, result.Status = "fail", analysisErr.Error(), "fail"
			} else {
				artifact.ApplyDeclarativeSignatures(&analysis, declarativeSignatures([]packsvc.Resolved{item}))
				result.DetectedAnalysis = appendUniqueStrings(result.DetectedAnalysis, analysisIDs(analysis)...)
				if missing := missingAnalysis(item.Document.ExpectedAnalysis, analysis); len(missing) > 0 {
					cell.Status, cell.Error, result.Status = "fail", "missing analyzer results: "+strings.Join(missing, ", "), "fail"
				}
			}
			result.Builds = append(result.Builds, cell)
			if exportObject == "" && arch == "x64" && cell.Status == "pass" {
				exportObject = build.Object
			}
		}
	}
	if result.Status == "pass" && hasUnavailable {
		result.Status = "pass_with_unavailable"
	}
	if exportObject != "" {
		args, names, optional, argsErr := exportPackArguments(item.Document.Arguments)
		if argsErr != nil {
			result.Status, result.Error = "fail", argsErr.Error()
			return result
		}
		for _, target := range []string{"raw", "sliver", "cobaltstrike"} {
			staged, stageErr := stage.StageWithOptions(stage.Options{Object: exportObject, Target: target, Entrypoint: "go", SourceInput: project, Project: project, Arguments: args, ArgumentNames: names, ArgumentOptional: optional, OutputRoot: "exports"})
			if stageErr != nil {
				result.Exports[target] = "fail: " + stageErr.Error()
				result.Status = "fail"
				continue
			}
			verification := stage.Verify(staged.Output)
			result.Exports[target] = verification.Status
			if verification.Status == "fail" {
				result.Status = "fail"
			}
		}
	}
	sort.Strings(result.DetectedAnalysis)
	return result
}

func materializePackProject(root string, item packsvc.Resolved, registry *packsvc.Registry) (string, error) {
	name := safeName("proof-" + item.Document.ID)
	project := filepath.Join(root, "bofs", name)
	// Cleanup packs can be reused by several proof cases in one run. Recreate
	// the generated project so a stale lock cannot suppress source insertion
	// after the template has been refreshed.
	if err := os.RemoveAll(project); err != nil {
		return "", err
	}
	if err := os.MkdirAll(project, 0o755); err != nil {
		return "", err
	}
	tpl, err := templateFor("hello", name)
	if err != nil {
		return "", err
	}
	for path, body := range map[string]string{
		filepath.Join(project, name+".c"): tpl.Source, filepath.Join(project, "beacon.h"): tpl.Header,
		filepath.Join(project, "bofbench.toml"): tpl.Config, filepath.Join(project, "README.md"): tpl.Readme,
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return "", err
		}
	}
	_, err = registry.Apply(project, []string{item.Qualified})
	return project, err
}

func analysisIDs(analysis artifact.Analysis) []string {
	var ids []string
	for _, capability := range analysis.Capabilities {
		ids = appendUniqueStrings(ids, capability.ID)
	}
	for _, chain := range analysis.BehaviorChains {
		ids = appendUniqueStrings(ids, chain.ID)
	}
	return ids
}

func missingAnalysis(expected []string, analysis artifact.Analysis) []string {
	seen := map[string]bool{}
	for _, id := range analysisIDs(analysis) {
		seen[id] = true
	}
	var missing []string
	for _, id := range expected {
		if !seen[id] {
			missing = append(missing, id)
		}
	}
	return missing
}

func exportPackArguments(arguments []packsvc.Argument) ([]argpack.Item, []string, []bool, error) {
	var items []argpack.Item
	var names []string
	var optional []bool
	for _, argument := range arguments {
		item, err := exportContractItem(argument)
		if err != nil {
			return nil, nil, nil, err
		}
		items = append(items, item)
		names = append(names, argument.Name)
		optional = append(optional, !argument.Required || argument.Default != "")
	}
	return items, names, optional, nil
}

func unavailableCoverage(err error) bool {
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "not found") || strings.Contains(value, "unavailable") || strings.Contains(value, "requires windows") || strings.Contains(value, "could not resolve compiler") || strings.Contains(value, "currently supports x64 only") || strings.Contains(value, "no live sliver session") || strings.Contains(value, "sliver session matched")
}

func provePacks(ctx context.Context, stdout io.Writer, registry *packsvc.Registry, items []packsvc.Resolved, via, labName string, topology *resolvedTopologyValues) (packProofReport, error) {
	report := packProofReport{Header: evidence.New("bofbench.pack-proof", "", ""), Status: "pass", Lab: labName, Runtime: via, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	if topology != nil {
		report.Topology = topology.Topology.Name
	}
	runDir, err := runlog.NewDir("pack-proof")
	if err != nil {
		return report, err
	}
	report.Header = evidence.New("bofbench.pack-proof", runlog.ID(runDir), "")
	report.JSONPath = filepath.Join(runDir, "pack-proof.json")
	work := filepath.Join("work", "pack-proofs", report.RunID)
	if err := os.MkdirAll(work, 0o755); err != nil {
		return report, err
	}
	retPayload := filepath.Join(work, "payload-ret.bin")
	if err := os.WriteFile(retPayload, []byte{0xc3}, 0o600); err != nil {
		return report, err
	}
	targets := map[string]lab.TargetReport{}
	targetOwned := map[string]bool{}
	proofWorkspaceReady := false
	ensureProofWorkspace := func() error {
		if proofWorkspaceReady || (via != "lab" && via != "sliver") {
			return nil
		}
		resolved, err := lab.ResolveProfile(labName, "", lab.ProfilesPath())
		if err != nil {
			return err
		}
		remote, err := lab.ResolveRemoteOptions(ctx, resolved.Name, resolved.Profile)
		if err != nil {
			return err
		}
		path := `C:\bofbench\proof\` + report.RunID
		script := `$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force -Path '` + strings.ReplaceAll(path, "'", "''") + `' | Out-Null`
		_, stderr, err := lab.ExecutePowerShell(ctx, remote, script)
		if err != nil {
			return fmt.Errorf("prepare proof workspace: %w: %s", err, strings.TrimSpace(string(stderr)))
		}
		proofWorkspaceReady = true
		return nil
	}
	ensureTarget := func(profileName string) (lab.TargetReport, error) {
		if via != "lab" && via != "sliver" {
			return lab.TargetReport{}, nil
		}
		if target, ok := targets[profileName]; ok {
			return target, ensureProofWorkspace()
		}
		var output bytes.Buffer
		statusArgs := []string{"lab", "target", "status", "--format", "json"}
		if profileName != "" {
			statusArgs = append(statusArgs, "--lab", profileName)
		}
		var target lab.TargetReport
		if statusErr := Run(statusArgs, &output, &output); statusErr == nil && json.Unmarshal(output.Bytes(), &target) == nil && target.Status == "pass" {
			targets[profileName] = target
			return target, ensureProofWorkspace()
		}
		output.Reset()
		deployArgs := []string{"lab", "target", "deploy", "--format", "json"}
		if profileName != "" {
			deployArgs = append(deployArgs, "--lab", profileName)
		}
		if err := Run(deployArgs, &output, &output); err != nil {
			return lab.TargetReport{}, fmt.Errorf("deploy proof target: %w: %s", err, strings.TrimSpace(output.String()))
		}
		if err := json.Unmarshal(output.Bytes(), &target); err != nil {
			return lab.TargetReport{}, fmt.Errorf("decode proof target: %w", err)
		}
		targets[profileName], targetOwned[profileName] = target, true
		return target, ensureProofWorkspace()
	}
	defer func() {
		for profileName, owned := range targetOwned {
			if !owned {
				continue
			}
			args := []string{"lab", "target", "remove", "--format", "json"}
			if profileName != "" {
				args = append(args, "--lab", profileName)
			}
			_ = Run(args, io.Discard, io.Discard)
		}
	}()
	for _, item := range items {
		matchedProof := false
		for _, proof := range item.Document.ProofCases {
			if !containsString(proof.Via, via) {
				continue
			}
			matchedProof = true
			report.Declared++
			result := packProofResult{Pack: item.Qualified, Case: proof.ID, Runtime: via, Status: "pass"}
			if containsString(proof.Roles, "domain_controller") && (topology == nil || topology.Topology.DomainController == nil) {
				result.Status, result.Error, report.Status = "unavailable", "proof requires a domain_controller role; select a topology with a domain-controller profile", "pass_with_unavailable"
				report.Unavailable++
				report.Results = append(report.Results, result)
				continue
			}
			fixtureProfile := labName
			if containsString(proof.Roles, "target") {
				if topology != nil && topology.Topology.Target == nil {
					result.Status, result.Error, report.Status = "unavailable", "proof requires a target role; select a topology with a target profile", "pass_with_unavailable"
					report.Unavailable++
					report.Results = append(report.Results, result)
					continue
				}
				if topology != nil {
					fixtureProfile = topology.Topology.Target.Name
				}
			}
			var target lab.TargetReport
			if proofUsesTarget(proof) {
				var targetErr error
				target, targetErr = ensureTarget(fixtureProfile)
				if targetErr != nil {
					result.Status, result.Error, report.Status = "unavailable", targetErr.Error(), "pass_with_unavailable"
					report.Unavailable++
					report.Results = append(report.Results, result)
					continue
				}
			}
			project, err := materializePackProject(work, item, registry)
			if err != nil {
				result.Status, result.Error, report.Status = "fail", err.Error(), "fail"
				report.Results = append(report.Results, result)
				continue
			}
			proofSecret, err := newProofSecret()
			if err != nil {
				result.Status, result.Error, report.Status = "fail", err.Error(), "fail"
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			}
			secretBytes, decodeErr := hex.DecodeString(proofSecret)
			if decodeErr != nil {
				result.Status, result.Error, report.Status = "fail", decodeErr.Error(), "fail"
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			}
			secretPath := filepath.Join(work, proofFileName(item.Document.ID+"-"+proof.ID)+"-secret.bin")
			if err := os.WriteFile(secretPath, secretBytes, 0o600); err != nil {
				result.Status, result.Error, report.Status = "fail", err.Error(), "fail"
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			}
			placeholders := proofPlaceholderValues(target, report.RunID, proofSecret)
			placeholders["$PAYLOAD_RET_PATH"] = retPayload
			placeholders["$PROOF_SECRET_PATH"] = secretPath
			expectation, err := resolveProofExpectation(proof.Expect, placeholders)
			if err != nil {
				result.Status, result.Error, report.Status = "fail", err.Error(), "fail"
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			}
			proofArguments := proof.Arguments
			if topology != nil {
				proofArguments = topologyProofArguments(item.Document, proofArguments, topology.Values)
			}
			arguments, err := resolveProofValues(proofArguments, placeholders)
			if err != nil {
				result.Status, result.Error, report.Status = "fail", err.Error(), "fail"
				report.Failed++
				report.Results = append(report.Results, result)
				continue
			}
			args := []string{"run", project, "--via", via}
			if labName != "" && (via == "lab" || via == "sliver") {
				args = append(args, "--lab", labName)
			}
			names := make([]string, 0, len(arguments))
			for name := range arguments {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				args = append(args, "--arg", name+"="+arguments[name])
			}
			var output bytes.Buffer
			runErr := Run(args, &output, &output)
			result.Output = nonemptyLines(output.String())
			if receiptOutput, receiptPath, objectSHA := receiptOutputFromLines(result.Output); len(receiptOutput) > 0 {
				result.Output = appendUniqueStrings(result.Output, receiptOutput...)
				result.Receipt, result.ObjectSHA256 = receiptPath, objectSHA
			}
			actionSucceeded := runErr == nil && matchesProofOutput(result.Output, expectation)
			if !actionSucceeded {
				if runErr != nil && unavailableCoverage(runErr) {
					result.Status, result.Error = "unavailable", runErr.Error()
					report.Unavailable++
					if report.Status != "fail" {
						report.Status = "pass_with_unavailable"
					}
				} else {
					result.Status, report.Status = "fail", "fail"
					report.Failed++
					if runErr != nil {
						result.Error = runErr.Error()
					} else {
						result.Error = "structured output did not match proof expectation"
					}
				}
			} else if expectation.Payload != nil {
				if err := verifyProofPayload(result.Output, *expectation.Payload, placeholders); err != nil {
					result.Status, result.Error, report.Status = "fail", "payload verification: "+err.Error(), "fail"
					report.Failed++
				} else {
					result.PayloadVerified = true
				}
			}
			if actionSucceeded && len(proof.Captures) > 0 {
				if err := applyProofCaptures(result.Output, proof.Captures, placeholders); err != nil {
					result.Status, result.Error, report.Status = "fail", "capture: "+err.Error(), "fail"
					report.Failed++
					actionSucceeded = false
				}
			}
			if actionSucceeded {
				if count, err := verifyProofStateChecks(ctx, via, labName, topology, proof.StateChecks, "after_run", placeholders); err != nil {
					if result.Status != "fail" {
						result.Status, result.Error, report.Status = "fail", "state verification: "+err.Error(), "fail"
						report.Failed++
					}
				} else {
					result.StateChecks += count
				}
			}
			if actionSucceeded && proof.Cleanup {
				cleanupArgs := append([]string(nil), args...)
				cleanupArgs = append(cleanupArgs, "--cleanup")
				var cleanup bytes.Buffer
				if cleanupErr := Run(cleanupArgs, &cleanup, &cleanup); cleanupErr != nil {
					if result.Status != "fail" {
						result.Status, result.Error, report.Status = "fail", "cleanup: "+cleanupErr.Error(), "fail"
						report.Failed++
					}
				}
				result.Output = append(result.Output, nonemptyLines(cleanup.String())...)
			}
			if actionSucceeded && len(proof.CleanupSteps) > 0 {
				cleanupOutput, cleanupErr := runProofCleanupSteps(via, labName, work, registry, item, proof.CleanupSteps, placeholders)
				result.Output = append(result.Output, cleanupOutput...)
				if cleanupErr != nil && result.Status != "fail" {
					result.Status, result.Error, report.Status = "fail", "cleanup: "+cleanupErr.Error(), "fail"
					report.Failed++
				}
			}
			if actionSucceeded && (proof.Cleanup || len(proof.CleanupSteps) > 0) {
				if count, err := verifyProofStateChecks(ctx, via, labName, topology, proof.StateChecks, "after_cleanup", placeholders); err != nil {
					if result.Status != "fail" {
						result.Status, result.Error, report.Status = "fail", "cleanup verification: "+err.Error(), "fail"
						report.Failed++
					}
				} else {
					result.StateChecks += count
				}
			}
			if result.Status == "pass" {
				report.Passed++
			}
			secretValues := sensitiveProofValues(item.Document, arguments)
			result.Output = redactRuntimeLines(result.Output, item.Document.SensitiveOutputFields, secretValues)
			result.Error = redactRuntimeLines([]string{result.Error}, nil, secretValues)[0]
			report.Results = append(report.Results, result)
		}
		if !matchedProof {
			report.WithoutProof++
		}
	}
	if len(report.Results) == 0 {
		report.Status = "pass_with_unavailable"
	}
	if err := writeJSON(report.JSONPath, report); err != nil {
		return report, err
	}
	if report.Status == "fail" {
		return report, codedError{code: 1, err: fmt.Errorf("one or more capability proofs failed")}
	}
	return report, nil
}

func proofFileName(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	name := strings.Trim(b.String(), "-_")
	if name == "" {
		return "proof"
	}
	return name
}

func receiptOutputFromLines(lines []string) ([]string, string, string) {
	seen := map[string]bool{}
	for _, line := range lines {
		for _, token := range strings.Fields(line) {
			path := strings.Trim(token, "`'\"(),")
			if !strings.HasSuffix(strings.ToLower(path), ".json") || seen[path] {
				continue
			}
			seen[path] = true
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if output, objectSHA, ok := decodeRuntimeReceiptOutput(data); ok {
				return output, path, objectSHA
			}
		}
	}
	return nil, "", ""
}

func decodeRuntimeReceiptOutput(data []byte) ([]string, string, bool) {
	var document struct {
		Schema       string          `json:"schema"`
		ObjectSHA256 string          `json:"object_sha256"`
		Output       []string        `json:"output"`
		Receipt      json.RawMessage `json:"receipt"`
	}
	if json.Unmarshal(data, &document) != nil {
		return nil, "", false
	}
	if document.Schema == "bofbench.runtime-receipt" && document.ObjectSHA256 != "" {
		return document.Output, document.ObjectSHA256, true
	}
	if len(document.Receipt) > 0 && string(document.Receipt) != "null" {
		return decodeRuntimeReceiptOutput(document.Receipt)
	}
	return nil, "", false
}

func proofUsesTarget(proof packsvc.ProofCase) bool {
	var values []string
	for _, value := range proof.Arguments {
		values = append(values, value)
	}
	if proof.Expect.Payload != nil {
		values = append(values, proof.Expect.Payload.SHA256)
	}
	for _, step := range proof.CleanupSteps {
		for _, value := range step.Arguments {
			values = append(values, value)
		}
	}
	for _, check := range proof.StateChecks {
		for _, value := range check.Parameters {
			values = append(values, value)
		}
	}
	for _, value := range values {
		for _, prefix := range []string{"$TARGET_", "$MEMORY_", "$CANARY_", "$CREDENTIAL_", "$DPAPI_", "$VAULT_", "$CERT_", "$LAB_HOST", "$SERVICE_BINARY", "$WMI_MARKER_PATH", "$REMOTE_", "$TEMP"} {
			if strings.Contains(value, prefix) {
				return true
			}
		}
	}
	return false
}

func resolveProofArguments(arguments map[string]string, target lab.TargetReport, runID string) (map[string]string, error) {
	return resolveProofValues(arguments, proofPlaceholderValues(target, runID, "proof-secret"))
}

func newProofSecret() (string, error) {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate proof secret: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func proofPlaceholderValues(target lab.TargetReport, runID, proofSecret string) map[string]string {
	secretBytes, err := hex.DecodeString(proofSecret)
	if err != nil {
		secretBytes = []byte(proofSecret)
	}
	secretHash := sha256.Sum256(secretBytes)
	secretCRLFHash := sha256.Sum256([]byte(proofSecret + "\r\n"))
	remoteRelative := strings.TrimRight(target.Fixtures.RemoteStageRelative, `\`) + `\remote-stage-` + runID + `.bin`
	remoteLocalPath := strings.TrimRight(target.Fixtures.RemoteStageLocal, `\`) + `\remote-stage-` + runID + `.bin`
	remoteTaskName := "BOFBench-Remote-" + runID
	remoteTaskMarker := strings.TrimRight(target.Fixtures.RemoteStageLocal, `\`) + `\remote-task-` + runID + `.txt`
	labHost := target.Fixtures.RemoteComputerName
	if labHost == "" {
		labHost = target.Host
	}
	return map[string]string{
		"$TARGET_PID": strconv.FormatUint(uint64(target.State.PID), 10), "$TARGET_TID": strconv.FormatUint(uint64(target.State.AlertableTID), 10), "$TARGET_HANDLE": target.State.KnownHandle,
		"$MEMORY_ADDRESS": target.State.MemoryCanaryAddress, "$MEMORY_SIZE": strconv.FormatUint(uint64(target.State.MemoryCanarySize), 10),
		"$MEMORY_SHA256":        target.State.MemoryCanarySHA256,
		"$MEMORY_WRITE_ADDRESS": target.State.MemoryWriteAddress, "$MEMORY_WRITE_SIZE": strconv.Itoa(target.State.MemoryWriteSize), "$MEMORY_WRITE_SHA256": target.State.MemoryWriteSHA256,
		"$MEMORY_PROTECTION_ADDRESS": target.State.MemoryProtectAddress, "$MEMORY_PROTECTION_SIZE": strconv.Itoa(target.State.MemoryProtectSize), "$MEMORY_PROTECTION": target.State.MemoryProtection,
		"$CANARY_PATH": target.State.CanaryFile, "$CANARY_SHA256": target.State.CanaryFileSHA256,
		"$CREDENTIAL_TARGET": target.Fixtures.CredentialTarget, "$CREDENTIAL_SHA256": target.Fixtures.CredentialSHA256, "$CREDENTIAL_SIZE": strconv.Itoa(target.Fixtures.CredentialSize),
		"$DPAPI_USER_PATH": target.Fixtures.DPAPIUserPath, "$DPAPI_USER_SHA256": target.Fixtures.DPAPIUserSHA256,
		"$DPAPI_MACHINE_PATH": target.Fixtures.DPAPIMachinePath, "$DPAPI_MACHINE_SHA256": target.Fixtures.DPAPIMachineSHA256,
		"$VAULT_GUID": target.Fixtures.VaultGUID, "$VAULT_RESOURCE": target.Fixtures.VaultResource, "$VAULT_IDENTITY": target.Fixtures.VaultIdentity,
		"$VAULT_SHA256": target.Fixtures.VaultSHA256, "$VAULT_SIZE": strconv.Itoa(target.Fixtures.VaultSize),
		"$CERT_THUMBPRINT": target.Fixtures.CertificateThumbprint, "$CERT_STORE": target.Fixtures.CertificateStore, "$CERT_SUBJECT": target.Fixtures.CertificateSubject,
		"$LAB_HOST": labHost, "$SERVICE_BINARY": target.ServiceBinary, "$WMI_MARKER_PATH": target.Fixtures.WMIMarkerPath,
		"$TEMP": `C:\bofbench\proof\` + runID, "$RUN_ID": runID, "$PROOF_SECRET": proofSecret,
		"$PROOF_SECRET_SHA256":      hex.EncodeToString(secretHash[:]),
		"$PROOF_SECRET_CRLF_SHA256": hex.EncodeToString(secretCRLFHash[:]),
		"$REMOTE_REGISTRY_HIVE":     target.Fixtures.RemoteRegistryHive, "$REMOTE_REGISTRY_PATH": target.Fixtures.RemoteRegistryPath,
		"$REMOTE_REGISTRY_NAME": target.Fixtures.RemoteRegistryName, "$REMOTE_REGISTRY_SHA256": target.Fixtures.RemoteRegistrySHA256,
		"$REMOTE_REGISTRY_SIZE": strconv.Itoa(target.Fixtures.RemoteRegistrySize),
		"$REMOTE_STAGE_SHARE":   target.Fixtures.RemoteStageShare, "$REMOTE_STAGE_RELATIVE_ROOT": target.Fixtures.RemoteStageRelative,
		"$REMOTE_STAGE_LOCAL_ROOT": target.Fixtures.RemoteStageLocal, "$REMOTE_STAGE_RELATIVE": remoteRelative, "$REMOTE_STAGE_LOCAL_PATH": remoteLocalPath,
		"$REMOTE_TASK_NAME": remoteTaskName, "$REMOTE_TASK_MARKER_PATH": remoteTaskMarker,
	}
}

func resolveProofValues(input map[string]string, placeholders map[string]string) (map[string]string, error) {
	resolved := map[string]string{}
	for name, value := range input {
		value, err := resolveProofString(value, placeholders)
		if err != nil {
			return nil, err
		}
		resolved[name] = value
	}
	return resolved, nil
}

func topologyProofArguments(document packsvc.Document, input map[string]string, values map[string]string) map[string]string {
	resolved := make(map[string]string, len(input)+len(document.Arguments))
	for name, value := range input {
		resolved[name] = value
	}
	for _, argument := range document.Arguments {
		if argument.TopologyValue == "" || resolved[argument.Name] != "" {
			continue
		}
		if value := values[argument.TopologyValue]; value != "" {
			resolved[argument.Name] = value
		}
	}
	return resolved
}

func resolveProofExpectation(input packsvc.ProofExpectation, placeholders map[string]string) (packsvc.ProofExpectation, error) {
	resolved := input
	resolved.Fields = make(map[string]string, len(input.Fields))
	for name, value := range input.Fields {
		value, err := resolveProofString(value, placeholders)
		if err != nil {
			return packsvc.ProofExpectation{}, fmt.Errorf("resolve proof expectation %s: %w", name, err)
		}
		resolved.Fields[name] = value
	}
	return resolved, nil
}

func resolveProofString(value string, placeholders map[string]string) (string, error) {
	keys := make([]string, 0, len(placeholders))
	for placeholder := range placeholders {
		keys = append(keys, placeholder)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for _, placeholder := range keys {
		replacement := placeholders[placeholder]
		if !strings.Contains(value, placeholder) {
			continue
		}
		if replacement == "" || ((placeholder == "$TARGET_PID" || placeholder == "$TARGET_TID" || placeholder == "$MEMORY_SIZE" || placeholder == "$MEMORY_WRITE_SIZE" || placeholder == "$MEMORY_PROTECTION_SIZE" || placeholder == "$CREDENTIAL_SIZE" || placeholder == "$VAULT_SIZE") && replacement == "0") {
			return "", fmt.Errorf("proof placeholder %s is unavailable", placeholder)
		}
		value = strings.ReplaceAll(value, placeholder, replacement)
	}
	return value, nil
}

func verifyProofPayload(lines []string, expectation packsvc.ProofPayloadExpectation, placeholders map[string]string) error {
	expected, err := resolveProofString(expectation.SHA256, placeholders)
	if err != nil {
		return err
	}
	var payload []byte
	prefix := "[" + expectation.Tag + "]"
	for _, line := range lines {
		if !strings.Contains(line, prefix) {
			continue
		}
		value, ok := structuredFieldValue(line, expectation.Field)
		if !ok || value == "<redacted>" {
			continue
		}
		var chunk []byte
		switch expectation.Encoding {
		case "hex":
			chunk, err = hex.DecodeString(value)
		case "base64":
			chunk, err = base64.StdEncoding.DecodeString(value)
		}
		if err != nil {
			return fmt.Errorf("decode %s payload: %w", expectation.Encoding, err)
		}
		payload = append(payload, chunk...)
	}
	if len(payload) == 0 {
		return fmt.Errorf("no %s=%s payload was observed", expectation.Field, expectation.Encoding)
	}
	sum := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), expected) {
		return fmt.Errorf("payload SHA-256 did not match fixture")
	}
	return nil
}

func structuredFieldValue(line, field string) (string, bool) {
	needle := field + "="
	index := strings.Index(line, needle)
	if index < 0 {
		return "", false
	}
	value := line[index+len(needle):]
	if end := strings.IndexAny(value, " \t\r\n\\\"',}"); end >= 0 {
		value = value[:end]
	}
	return strings.TrimSpace(value), value != ""
}

func applyProofCaptures(lines []string, captures map[string]packsvc.ProofCapture, placeholders map[string]string) error {
	keys := make([]string, 0, len(captures))
	for placeholder := range captures {
		keys = append(keys, placeholder)
	}
	sort.Strings(keys)
	for _, placeholder := range keys {
		capture := captures[placeholder]
		prefix := "[" + capture.Tag + "]"
		captured := ""
		for _, line := range lines {
			if !strings.Contains(line, prefix) {
				continue
			}
			if value, ok := structuredFieldValue(line, capture.Field); ok && value != "<redacted>" {
				captured = value
				break
			}
		}
		if captured == "" {
			return fmt.Errorf("%s did not find %s=%s", placeholder, capture.Tag, capture.Field)
		}
		placeholders[placeholder] = captured
	}
	return nil
}

func verifyProofStateChecks(ctx context.Context, via, labName string, topology *resolvedTopologyValues, checks []packsvc.ProofStateCheck, phase string, placeholders map[string]string) (int, error) {
	var selected []packsvc.ProofStateCheck
	for _, check := range checks {
		if check.Phase == phase {
			selected = append(selected, check)
		}
	}
	if len(selected) == 0 {
		return 0, nil
	}
	if via != "lab" && via != "sliver" {
		return 0, fmt.Errorf("independent state checks require a lab profile")
	}
	for _, check := range selected {
		profileName := labName
		switch check.Role {
		case "", "execution":
		case "target":
			if topology != nil {
				if topology.Topology.Target == nil {
					return 0, fmt.Errorf("state check requires a target role")
				}
				profileName = topology.Topology.Target.Name
			}
		case "domain_controller":
			if topology == nil || topology.Topology.DomainController == nil {
				return 0, fmt.Errorf("state check requires a domain_controller role")
			}
			profileName = topology.Topology.DomainController.Name
		}
		resolved, err := lab.ResolveProfile(profileName, "", lab.ProfilesPath())
		if err != nil {
			return 0, err
		}
		remote, err := lab.ResolveRemoteOptions(ctx, resolved.Name, resolved.Profile)
		if err != nil {
			return 0, err
		}
		parameters, err := resolveProofValues(check.Parameters, placeholders)
		if err != nil {
			return 0, err
		}
		script, err := proofStateCheckScript(check.Kind, check.Expect, parameters)
		if err != nil {
			return 0, err
		}
		stdout, stderr, err := lab.ExecutePowerShell(ctx, remote, script)
		if err != nil {
			return 0, fmt.Errorf("%s %s: %w: %s", check.Kind, check.Expect, err, strings.TrimSpace(string(stderr)))
		}
		if !strings.Contains(string(stdout), "BOFBENCH_STATE_VERIFIED") {
			return 0, fmt.Errorf("%s %s was not confirmed", check.Kind, check.Expect)
		}
	}
	return len(selected), nil
}

func proofStateCheckScript(kind, expect string, parameters map[string]string) (string, error) {
	q := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	var probe string
	switch kind {
	case "file":
		probe = `$present=Test-Path -LiteralPath ` + q(parameters["path"])
	case "startup_file":
		leaf := parameters["name"]
		if leaf == "" || strings.ContainsAny(leaf, `\/:`) {
			return "", fmt.Errorf("startup_file requires an exact leaf name")
		}
		probe = `$leaf=` + q(leaf) + `; $relative='AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'; $users=Join-Path $env:SystemDrive 'Users'; $present=@(Get-ChildItem -LiteralPath $users -Directory -ErrorAction SilentlyContinue | ForEach-Object {Join-Path (Join-Path $_.FullName $relative) $leaf} | Where-Object {Test-Path -LiteralPath $_}).Count -gt 0`
	case "registry_value":
		hive := strings.ToUpper(parameters["hive"])
		prefix := map[string]string{"HKCU": "HKCU:", "HKLM": "HKLM:"}[hive]
		if prefix == "" {
			return "", fmt.Errorf("registry_value hive must be HKCU or HKLM")
		}
		probe = `$key=Join-Path ` + q(prefix) + ` ` + q(parameters["path"]) + `; $present=$false; $matches=$false; if(Test-Path -LiteralPath $key){$property=Get-ItemProperty -LiteralPath $key -Name ` + q(parameters["name"]) + ` -ErrorAction SilentlyContinue; $present=$null -ne $property; if($present -and ` + q(parameters["sha256"]) + `){$value=$property.PSObject.Properties[` + q(parameters["name"]) + `].Value; if($value -is [byte[]]){$bytes=$value}else{$bytes=[Text.Encoding]::Unicode.GetBytes([string]$value)}; $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)); $kind=(Get-Item -LiteralPath $key).GetValueKind(` + q(parameters["name"]) + `); $type=@{String=1;ExpandString=2;Binary=3;DWord=4;MultiString=7;QWord=11}[[string]$kind]; $matches=($hash -ieq ` + q(parameters["sha256"]) + `) -and ((-not ` + q(parameters["type"]) + `) -or ([int]$type -eq [int]` + q(parameters["type"]) + `))}}`
	case "service":
		probe = `$present=$null -ne (Get-Service -Name ` + q(parameters["name"]) + ` -ErrorAction SilentlyContinue)`
	case "scheduled_task":
		probe = `$present=$null -ne (Get-ScheduledTask -TaskName ` + q(parameters["name"]) + ` -ErrorAction SilentlyContinue)`
	case "credential":
		probe = `$present=((cmdkey.exe /list | Out-String) -like ('*'+` + q(parameters["target"]) + `+'*'))`
	case "certificate":
		scope := map[string]string{"current_user": "CurrentUser", "local_machine": "LocalMachine"}[strings.ToLower(parameters["scope"])]
		if scope == "" {
			return "", fmt.Errorf("certificate scope must be current_user or local_machine")
		}
		path := `Cert:\` + scope + `\` + parameters["store"] + `\` + strings.ReplaceAll(parameters["thumbprint"], " ", "")
		probe = `$present=Test-Path -LiteralPath ` + q(path)
	case "dpapi_file":
		probe = `$path=` + q(parameters["path"]) + `; $present=Test-Path -LiteralPath $path; $matches=$false; if($present){$blob=[IO.File]::ReadAllBytes($path); foreach($scope in @([Security.Cryptography.DataProtectionScope]::CurrentUser,[Security.Cryptography.DataProtectionScope]::LocalMachine)){try{$plain=[Security.Cryptography.ProtectedData]::Unprotect($blob,$null,$scope); $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($plain)); if($hash -ieq ` + q(parameters["sha256"]) + `){$matches=$true; break}}catch{}}}`
	case "pfx":
		probe = `$path=` + q(parameters["path"]) + `; $present=Test-Path -LiteralPath $path; $matches=$false; if($present){$secure=ConvertTo-SecureString ` + q(parameters["password"]) + ` -AsPlainText -Force; $pfx=Get-PfxData -FilePath $path -Password $secure; $matches=@($pfx.EndEntityCertificates | Where-Object {$_.Thumbprint -ieq ` + q(strings.ReplaceAll(parameters["thumbprint"], " ", "")) + `}).Count -gt 0}`
	case "process_memory":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchMemoryCheck{[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true)]public static extern bool ReadProcessMemory(IntPtr p,UInt64 a,byte[] b,UIntPtr s,out UIntPtr r);[DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr h);}' -ErrorAction SilentlyContinue; $handle=[BOFBenchMemoryCheck]::OpenProcess(0x1010,$false,[uint32]` + q(parameters["pid"]) + `); if($handle -eq [IntPtr]::Zero){throw 'OpenProcess failed'}; try{$bytes=New-Object byte[] ([int]` + q(parameters["size"]) + `); $read=[UIntPtr]::Zero; $addressText=(` + q(parameters["address"]) + ` -replace '^0x',''); $ok=[BOFBenchMemoryCheck]::ReadProcessMemory($handle,[Convert]::ToUInt64($addressText,16),$bytes,[UIntPtr]$bytes.Length,[ref]$read); $present=$ok; $matches=$ok -and ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)) -ieq ` + q(parameters["sha256"]) + `)}finally{[void][BOFBenchMemoryCheck]::CloseHandle($handle)}`
	case "process_protection":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchProtectCheck{[StructLayout(LayoutKind.Sequential)]public struct MBI{public IntPtr BaseAddress;public IntPtr AllocationBase;public uint AllocationProtect;public UIntPtr RegionSize;public uint State;public uint Protect;public uint Type;}[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true)]public static extern UIntPtr VirtualQueryEx(IntPtr p,UInt64 a,out MBI m,UIntPtr s);[DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr h);}' -ErrorAction SilentlyContinue; $handle=[BOFBenchProtectCheck]::OpenProcess(0x1000,$false,[uint32]` + q(parameters["pid"]) + `); if($handle -eq [IntPtr]::Zero){throw 'OpenProcess failed'}; try{$mbi=New-Object BOFBenchProtectCheck+MBI; $size=[Runtime.InteropServices.Marshal]::SizeOf($mbi); $addressText=(` + q(parameters["address"]) + ` -replace '^0x',''); $got=[BOFBenchProtectCheck]::VirtualQueryEx($handle,[Convert]::ToUInt64($addressText,16),[ref]$mbi,[UIntPtr]$size); $present=$got.ToUInt64() -gt 0; $expected=[Convert]::ToUInt32(` + q(parameters["protection"]) + `,16); $matches=$present -and (($mbi.Protect -band 0xff) -eq $expected)}finally{[void][BOFBenchProtectCheck]::CloseHandle($handle)}`
	case "process":
		probe = `Add-Type -TypeDefinition 'using System;using System.Text;using System.Runtime.InteropServices;public static class BOFBenchProcessCheck{[StructLayout(LayoutKind.Sequential)]struct US{public ushort Length;public ushort MaximumLength;public IntPtr Buffer;}[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]static extern bool QueryFullProcessImageName(IntPtr p,uint f,StringBuilder n,ref uint s);[DllImport("ntdll.dll")]static extern int NtQueryInformationProcess(IntPtr p,int c,IntPtr b,uint s,out uint r);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static string[] Inspect(uint pid){IntPtr h=OpenProcess(0x1000,false,pid);if(h==IntPtr.Zero)return null;try{var image=new StringBuilder(1024);uint chars=1024;if(!QueryFullProcessImageName(h,0,image,ref chars))return null;IntPtr buffer=Marshal.AllocHGlobal(8192);try{uint returned;int status=NtQueryInformationProcess(h,60,buffer,8192,out returned);if(status<0)return null;US value=(US)Marshal.PtrToStructure(buffer,typeof(US));string command=Marshal.PtrToStringUni(value.Buffer,value.Length/2);return new[]{image.ToString(),command};}finally{Marshal.FreeHGlobal(buffer);}}finally{CloseHandle(h);}}}' -ErrorAction SilentlyContinue; $info=[BOFBenchProcessCheck]::Inspect([uint32]` + q(parameters["pid"]) + `); $present=$null -ne $info; $matches=$present -and ([IO.Path]::GetFileName([string]$info[0]) -ieq ` + q(parameters["image"]) + `) -and ([string]$info[1] -like ('*'+` + q(parameters["marker"]) + `+'*'))`
	default:
		return "", fmt.Errorf("unsupported state check kind %q", kind)
	}
	assertion := ""
	switch expect {
	case "present":
		assertion = `if(-not $present){throw 'expected state is absent'}`
	case "absent":
		assertion = `if($present){throw 'expected state remains present'}`
	case "matches":
		assertion = `if(-not $matches){throw 'state content did not match'}`
	default:
		return "", fmt.Errorf("unsupported state expectation %q", expect)
	}
	return `$ErrorActionPreference='Stop'; ` + probe + `; ` + assertion + `; Write-Output 'BOFBENCH_STATE_VERIFIED'`, nil
}

func runProofCleanupSteps(via, labName, work string, registry *packsvc.Registry, owner packsvc.Resolved, steps []packsvc.ProofCleanupStep, placeholders map[string]string) ([]string, error) {
	var output []string
	for _, step := range steps {
		item, err := registry.ResolveRelated(owner, step.Pack)
		if err != nil {
			return output, err
		}
		project, err := materializePackProject(work, item, registry)
		if err != nil {
			return output, err
		}
		arguments, err := resolveProofValues(step.Arguments, placeholders)
		if err != nil {
			return output, err
		}
		args := []string{"run", project, "--via", via}
		if labName != "" && (via == "lab" || via == "sliver") {
			args = append(args, "--lab", labName)
		}
		names := make([]string, 0, len(arguments))
		for name := range arguments {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			args = append(args, "--arg", name+"="+arguments[name])
		}
		var buffer bytes.Buffer
		if err := Run(args, &buffer, &buffer); err != nil {
			return append(output, nonemptyLines(buffer.String())...), err
		}
		output = append(output, nonemptyLines(buffer.String())...)
	}
	return output, nil
}

func sensitiveProofValues(document packsvc.Document, arguments map[string]string) []string {
	var values []string
	for _, argument := range document.Arguments {
		if argument.Sensitive && arguments[argument.Name] != "" {
			values = append(values, arguments[argument.Name])
		}
	}
	return values
}

func matchesProofOutput(lines []string, expectation packsvc.ProofExpectation) bool {
	prefix := "[" + expectation.Tag + "]"
	for _, line := range lines {
		if !strings.Contains(line, prefix) {
			continue
		}
		matched := true
		for key, value := range expectation.Fields {
			if value == "*" {
				if !strings.Contains(line, key+"=") {
					matched = false
				}
			} else if !strings.Contains(line, key+"="+value) {
				matched = false
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func nonemptyLines(value string) []string {
	var result []string
	for _, line := range strings.Split(stripANSI(value), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			result = append(result, line)
		}
	}
	return result
}

func printPackTestReport(w io.Writer, report packTestReport) {
	fmt.Fprintf(w, "PACK TEST %s\n", strings.ToUpper(report.Status))
	for _, result := range report.Results {
		fmt.Fprintf(w, "%s  %s\n", result.Pack, result.Status)
		for _, cell := range result.Builds {
			fmt.Fprintf(w, "  build %-4s %-5s %s", cell.Arch, cell.Compiler, cell.Status)
			if cell.Error != "" {
				fmt.Fprintf(w, " — %s", firstLine(cell.Error))
			}
			fmt.Fprintln(w)
		}
		for _, target := range []string{"raw", "sliver", "cobaltstrike"} {
			if status := result.Exports[target]; status != "" {
				fmt.Fprintf(w, "  export %-12s %s\n", target, status)
			}
		}
	}
	fmt.Fprintf(w, "report  %s\n", report.JSONPath)
}

func printPackProofReport(w io.Writer, report packProofReport) {
	fmt.Fprintf(w, "PACK PROOF %s\n", strings.ToUpper(report.Status))
	if report.Topology != "" {
		fmt.Fprintf(w, "topology  %s execution=%s\n", report.Topology, report.Lab)
	}
	fmt.Fprintf(w, "coverage  declared=%d passed=%d unavailable=%d failed=%d without-proof=%d\n", report.Declared, report.Passed, report.Unavailable, report.Failed, report.WithoutProof)
	for _, result := range report.Results {
		fmt.Fprintf(w, "%s/%s via=%s %s\n", result.Pack, result.Case, result.Runtime, result.Status)
		if result.Error != "" {
			fmt.Fprintf(w, "  %s\n", result.Error)
		}
		for _, line := range result.Output {
			if strings.HasPrefix(line, "[") {
				fmt.Fprintf(w, "  %s\n", line)
			}
		}
	}
	fmt.Fprintf(w, "report  %s\n", report.JSONPath)
}

func firstLine(value string) string {
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		return value[:index]
	}
	return value
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
