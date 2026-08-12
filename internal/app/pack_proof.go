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

	"github.com/professor-moody/bofbench/internal/argpack"
	"github.com/professor-moody/bofbench/internal/artifact"
	"github.com/professor-moody/bofbench/internal/buildsys"
	"github.com/professor-moody/bofbench/internal/evidence"
	"github.com/professor-moody/bofbench/internal/lab"
	operationsvc "github.com/professor-moody/bofbench/internal/operation"
	packsvc "github.com/professor-moody/bofbench/internal/pack"
	"github.com/professor-moody/bofbench/internal/runlog"
	"github.com/professor-moody/bofbench/internal/stage"
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
	Pack             string   `json:"pack"`
	Case             string   `json:"case"`
	Runtime          string   `json:"runtime"`
	Architecture     string   `json:"architecture"`
	Status           string   `json:"status"`
	Output           []string `json:"output,omitempty"`
	Receipt          string   `json:"receipt,omitempty"`
	ObjectSHA256     string   `json:"object_sha256,omitempty"`
	PayloadVerified  bool     `json:"payload_verified,omitempty"`
	StateChecks      int      `json:"state_checks,omitempty"`
	OperationReceipt string   `json:"operation_receipt,omitempty"`
	OperationStep    string   `json:"operation_step,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type packProofReport struct {
	evidence.Header
	Status       string            `json:"status"`
	Lab          string            `json:"lab,omitempty"`
	Topology     string            `json:"topology,omitempty"`
	Runtime      string            `json:"runtime"`
	Architecture string            `json:"architecture"`
	GeneratedAt  string            `json:"generated_at"`
	Results      []packProofResult `json:"results"`
	Declared     int               `json:"declared"`
	Passed       int               `json:"passed"`
	Unavailable  int               `json:"unavailable"`
	Failed       int               `json:"failed"`
	WithoutProof int               `json:"without_proof"`
	ResumedFrom  string            `json:"resumed_from,omitempty"`
	OnlyStatuses []string          `json:"only_statuses,omitempty"`
	JSONPath     string            `json:"json_path,omitempty"`
}

type proofResumeSelection struct {
	Path string
	Only map[string]bool
	Keys map[string]bool
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
	var via, labName, topologyName, arch, format, resumePath string
	var onlyStatuses []string
	cmd := &cobra.Command{
		Use: "prove [pack]", Short: "Run declared capability proofs and cleanup through a selected runtime", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (len(args) == 0) == !all {
				return fmt.Errorf("provide one pack or use --all")
			}
			if via != "native" && via != "lab" && via != "sliver" && via != "cobaltstrike" {
				return fmt.Errorf("unsupported proof runtime %q", via)
			}
			if arch != "x64" && arch != "x86" {
				return fmt.Errorf("unsupported proof architecture %q", arch)
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
			resume, err := loadProofResumeSelection(resumePath, onlyStatuses, via, labName, topologyName, arch)
			if err != nil {
				return err
			}
			report, proofErr := provePacks(cmd.Context(), stdout, registry, items, via, labName, arch, topology, resume)
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
	cmd.Flags().StringVar(&arch, "arch", "x64", "proof architecture: x64 or x86")
	cmd.Flags().StringVar(&resumePath, "resume", "", "prior pack-proof report or directory; rerun only selected prior statuses")
	cmd.Flags().StringSliceVar(&onlyStatuses, "only", nil, "prior statuses to rerun with --resume: unavailable, failed, or passed")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.MarkFlagsMutuallyExclusive("lab", "topology")
	return cmd
}

func loadProofResumeSelection(path string, only []string, via, labName, topologyName, arch string) (*proofResumeSelection, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		if len(only) > 0 {
			return nil, fmt.Errorf("--only requires --resume")
		}
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("resume proof report: %w", err)
	}
	if info.IsDir() {
		path = filepath.Join(path, "pack-proof.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read resume proof report: %w", err)
	}
	var previous packProofReport
	if err := json.Unmarshal(data, &previous); err != nil {
		return nil, fmt.Errorf("parse resume proof report: %w", err)
	}
	if previous.Schema != "bofbench.pack-proof" {
		return nil, fmt.Errorf("resume report schema is %q, expected bofbench.pack-proof", previous.Schema)
	}
	if previous.Runtime != "" && previous.Runtime != via {
		return nil, fmt.Errorf("resume report runtime is %q, requested %q", previous.Runtime, via)
	}
	if previous.Architecture != "" && previous.Architecture != arch {
		return nil, fmt.Errorf("resume report architecture is %q, requested %q", previous.Architecture, arch)
	}
	if topologyName != "" && previous.Topology != "" && previous.Topology != topologyName {
		return nil, fmt.Errorf("resume report topology is %q, requested %q", previous.Topology, topologyName)
	}
	if topologyName == "" && labName != "" && previous.Lab != "" && previous.Lab != labName {
		return nil, fmt.Errorf("resume report lab is %q, requested %q", previous.Lab, labName)
	}
	if len(only) == 0 {
		only = []string{"unavailable", "failed"}
	}
	selection := &proofResumeSelection{Path: path, Only: map[string]bool{}, Keys: map[string]bool{}}
	for _, status := range only {
		normalized, err := normalizeProofResumeStatus(status)
		if err != nil {
			return nil, err
		}
		selection.Only[normalized] = true
	}
	for _, result := range previous.Results {
		status, err := normalizeProofResumeStatus(result.Status)
		if err != nil {
			continue
		}
		if selection.Only[status] {
			selection.Keys[proofResumeKey(result.Pack, result.Case, result.Runtime)] = true
		}
	}
	return selection, nil
}

func normalizeProofResumeStatus(status string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pass", "passed":
		return "pass", nil
	case "fail", "failed":
		return "fail", nil
	case "unavailable":
		return "unavailable", nil
	default:
		return "", fmt.Errorf("unsupported proof resume status %q; choose unavailable, failed, or passed", status)
	}
}

func proofResumeKey(pack, proofCase, runtime string) string {
	return strings.Join([]string{pack, proofCase, runtime}, "\x00")
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

func provePacks(ctx context.Context, stdout io.Writer, registry *packsvc.Registry, items []packsvc.Resolved, via, labName, arch string, topology *resolvedTopologyValues, resume *proofResumeSelection) (packProofReport, error) {
	report := packProofReport{Header: evidence.New("bofbench.pack-proof", "", ""), Status: "pass", Lab: labName, Runtime: via, Architecture: arch, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
	report.SchemaVersion = 2
	if topology != nil {
		report.Topology = topology.Topology.Name
	}
	if resume != nil {
		report.ResumedFrom = resume.Path
		for status := range resume.Only {
			report.OnlyStatuses = append(report.OnlyStatuses, status)
		}
		sort.Strings(report.OnlyStatuses)
	}
	runDir, err := runlog.NewDir("pack-proof")
	if err != nil {
		return report, err
	}
	report.Header = evidence.New("bofbench.pack-proof", runlog.ID(runDir), "")
	report.SchemaVersion = 2
	report.JSONPath = filepath.Join(runDir, "pack-proof.json")
	work := filepath.Join("work", "pack-proofs", report.RunID)
	if err := os.MkdirAll(work, 0o755); err != nil {
		return report, err
	}
	retPayload := filepath.Join(work, "payload-ret.bin")
	if err := os.WriteFile(retPayload, []byte{0xc3}, 0o600); err != nil {
		return report, err
	}
	memoryNeedle := filepath.Join(work, "memory-needle.bin")
	if err := os.WriteFile(memoryNeedle, []byte("BOFBenchOperationNeedle"), 0o600); err != nil {
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
		if statusErr := Run(statusArgs, &output, &output); statusErr == nil && json.Unmarshal(output.Bytes(), &target) == nil && target.Status == "pass" && target.State.SchemaVersion >= 6 {
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
			if resume != nil && !resume.Keys[proofResumeKey(item.Qualified, proof.ID, via)] {
				continue
			}
			matchedProof = true
			report.Declared++
			result := packProofResult{Pack: item.Qualified, Case: proof.ID, Runtime: via, Architecture: arch, Status: "pass"}
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
			selectProofArchitecture(placeholders, target, arch)
			placeholders["$PAYLOAD_RET_PATH"] = retPayload
			placeholders["$MEMORY_NEEDLE_PATH"] = memoryNeedle
			placeholders["$PROOF_SECRET_PATH"] = secretPath
			if proof.OperationProof != nil {
				delegated, delegatedErr := runDelegatedPackProof(ctx, item, proof, placeholders, via, labName, arch, topology)
				result.Output = delegated.Output
				result.OperationReceipt, result.OperationStep = delegated.OperationReceipt, delegated.OperationStep
				result.Receipt, result.ObjectSHA256 = delegated.Receipt, delegated.ObjectSHA256
				if delegatedErr != nil {
					if unavailableCoverage(delegatedErr) {
						result.Status, result.Error = "unavailable", delegatedErr.Error()
						report.Unavailable++
						if report.Status != "fail" {
							report.Status = "pass_with_unavailable"
						}
					} else {
						result.Status, result.Error, report.Status = "fail", delegatedErr.Error(), "fail"
						report.Failed++
					}
				} else {
					report.Passed++
				}
				report.Results = append(report.Results, result)
				continue
			}
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
			arguments = normalizeOperationPackArguments(item.Document, arguments)
			args := []string{"run", project, "--via", via, "--arch", arch}
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
				cleanupOutput, cleanupErr := runProofCleanupSteps(via, labName, arch, work, registry, item, proof.CleanupSteps, placeholders)
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

func runDelegatedPackProof(ctx context.Context, item packsvc.Resolved, proof packsvc.ProofCase, placeholders map[string]string, via, labName, arch string, topology *resolvedTopologyValues) (packProofResult, error) {
	delegation := proof.OperationProof
	if delegation == nil {
		return packProofResult{}, fmt.Errorf("delegated operation proof is missing")
	}
	inputs, err := resolveProofValues(delegation.Inputs, placeholders)
	if err != nil {
		return packProofResult{}, err
	}
	phase := delegation.Phase
	if phase == "" {
		phase = "action"
	}
	if phase != "action" && phase != "cleanup" {
		return packProofResult{}, fmt.Errorf("unsupported delegated operation proof phase %q", phase)
	}
	args := []string{"operation"}
	if item.CatalogRoot != "" {
		args = append(args, "--catalog", item.CatalogRoot)
	}
	args = append(args, "run", delegation.Operation, "--via", via, "--arch", arch)
	if phase == "cleanup" {
		args = append(args, "--cleanup")
	}
	if topology != nil {
		args = append(args, "--topology", topology.Topology.Name)
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
	var output bytes.Buffer
	runErr := Run(args, &output, &output)
	result := packProofResult{Output: nonemptyLines(output.String()), OperationStep: delegation.Step}
	operationPath := operationReceiptFromLines(result.Output)
	if operationPath == "" {
		if runErr != nil {
			return result, runErr
		}
		return result, fmt.Errorf("delegated operation did not report its receipt")
	}
	receipt, err := operationsvc.LoadReceipt(operationPath)
	if err != nil {
		return result, err
	}
	result.OperationReceipt = operationPath
	var selected *operationsvc.StepReceipt
	for index := range receipt.Steps {
		if receipt.Steps[index].ID == delegation.Step {
			selected = &receipt.Steps[index]
			break
		}
	}
	if selected == nil {
		return result, fmt.Errorf("delegated operation %s has no step %s", delegation.Operation, delegation.Step)
	}
	switch phase {
	case "action":
		if selected.State != "completed" || selected.PackSHA256 != item.SHA256 {
			return result, fmt.Errorf("delegated operation step %s did not complete with exact pack hash", delegation.Step)
		}
		result.ObjectSHA256, result.Receipt = selected.ObjectSHA256, selected.Runtime.ReceiptPath
	case "cleanup":
		if selected.CleanupState != "completed" || selected.CleanupSHA256 != item.SHA256 {
			return result, fmt.Errorf("delegated operation cleanup %s did not complete with exact pack hash", delegation.Step)
		}
		if selected.CleanupRuntime != nil {
			result.ObjectSHA256, result.Receipt = selected.CleanupRuntime.ObjectSHA256, selected.CleanupRuntime.ReceiptPath
		}
	}
	if runErr != nil {
		return result, runErr
	}
	return result, nil
}

func operationReceiptFromLines(lines []string) string {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "receipt" {
			return strings.TrimSpace(fields[len(fields)-1])
		}
	}
	return ""
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
	if proof.OperationProof != nil {
		for _, value := range proof.OperationProof.Inputs {
			values = append(values, value)
		}
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
	retHash := sha256.Sum256([]byte{0xc3})
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
		"$TARGET_NAMED_PIPE":        target.State.NamedPipe,
		"$TARGET_NAMED_PIPE_HANDLE": target.State.NamedPipeHandle, "$TARGET_NAMED_PIPE_CLIENT_HANDLE": target.State.NamedPipeClientHandle, "$TARGET_NAMED_PIPE_SHA256": target.State.NamedPipeSHA256,
		"$TARGET_PROCESS_PIPE_PID": strconv.Itoa(target.State.ProcessPipePID), "$TARGET_PROCESS_STDIN_HANDLE": target.State.ProcessStdinHandle,
		"$TARGET_PROCESS_STDOUT_HANDLE": target.State.ProcessStdoutHandle, "$TARGET_PROCESS_PIPE_SHA256": target.State.ProcessPipeSHA256,
		"$TARGET_HOLDER_PID": strconv.Itoa(target.State.HolderPID), "$TARGET_JOB_MEMBER_PID": strconv.Itoa(target.State.JobMemberPID),
		"$TARGET_EVENT_NAME": target.State.EventName, "$TARGET_SECTION_NAME": target.State.SectionName, "$TARGET_JOB_NAME": target.State.JobName,
		"$TARGET_MUTEX_NAME": target.State.MutexName, "$TARGET_SEMAPHORE_NAME": target.State.SemaphoreName, "$TARGET_TIMER_NAME": target.State.TimerName,
		"$TARGET_MAILSLOT_NAME": target.State.MailslotName, "$TARGET_MAILSLOT_HANDLE": target.State.MailslotHandle, "$TARGET_MAILSLOT_SHA256": target.State.MailslotSHA256,
		"$TARGET_ALPC_PORT": target.State.ALPCPort, "$TARGET_ALPC_HANDLE": target.State.ALPCHandle,
		"$TARGET_WINDOW_HANDLE": target.State.WindowHandle, "$TARGET_WINDOW_TEXT_HANDLE": target.State.WindowTextHandle, "$TARGET_WINDOW_CLASS": target.State.WindowClass,
		"$TARGET_WINDOW_MESSAGE": strconv.FormatUint(uint64(target.State.WindowMessage), 10), "$TARGET_WINDOW_POST_MESSAGE": strconv.FormatUint(uint64(target.State.WindowPostMessage), 10),
		"$TARGET_WATCH_REGISTRY_HIVE": target.State.WatchRegistryHive, "$TARGET_WATCH_REGISTRY_PATH": target.State.WatchRegistryPath, "$TARGET_WATCH_REGISTRY_VALUE": target.State.WatchRegistryValue,
		"$TARGET_WATCH_DIRECTORY": target.State.WatchDirectory, "$TARGET_WATCH_SERVICE": target.State.WatchService, "$TARGET_EXIT_PID": strconv.Itoa(target.State.ExitPID),
		"$TARGET_EVENTLOG_CHANNEL": target.State.EventLogChannel, "$TARGET_EVENTLOG_PROVIDER": target.State.EventLogProvider,
		"$TARGET_ETW_PROVIDER_GUID": target.State.ETWProviderGUID, "$TARGET_ETW_SESSION_NAME": target.State.ETWSessionName + "-$RUN_ID",
		"$TARGET_TCP_HOST": target.State.TCPHost, "$TARGET_TCP_PORT": strconv.Itoa(target.State.TCPPort),
		"$TARGET_UDP_HOST": target.State.UDPHost, "$TARGET_UDP_PORT": strconv.Itoa(target.State.UDPPort),
		"$TARGET_HTTP_URL": target.State.HTTPURL, "$TARGET_HTTP_BLOB_URL": target.State.HTTPBlobURL,
		"$TARGET_HTTP_TRANSIENT_URL": target.State.HTTPTransientURL, "$TARGET_WEBSOCKET_URL": target.State.WebSocketURL,
		"$TARGET_HTTPS_URL": target.State.HTTPSURL, "$TARGET_HTTPS_BLOB_URL": target.State.HTTPSBlobURL,
		"$TARGET_HTTPS_AUTH_URL": target.State.HTTPSAuthURL, "$TARGET_HTTP_AUTH_USER": target.State.HTTPAuthUser,
		"$TARGET_TLS_CERTIFICATE_SHA256": target.State.TLSCertificateSHA256,
		"$TARGET_DNS_NAME":               target.State.DNSName, "$TARGET_NETWORK_PAYLOAD_SHA256": target.State.NetworkPayloadSHA256,
		"$TARGET_ARCH": target.State.Architecture, "$TARGET_MODULE_BASE": target.State.KnownModuleBase, "$TARGET_MODULE_PATH": target.State.KnownModulePath,
		"$EXECUTION_ADDRESS": target.State.ExecutionAddress,
		"$X86_TARGET_PID":    strconv.Itoa(target.State.X86PID), "$X86_TARGET_TID": strconv.FormatUint(uint64(target.State.X86AlertableTID), 10), "$X86_TARGET_MODULE_BASE": target.State.X86KnownModuleBase, "$X86_TARGET_MODULE_PATH": target.State.X86KnownModulePath,
		"$MEMORY_ADDRESS": target.State.MemoryCanaryAddress, "$MEMORY_SIZE": strconv.FormatUint(uint64(target.State.MemoryCanarySize), 10),
		"$MEMORY_SHA256":        target.State.MemoryCanarySHA256,
		"$MEMORY_WRITE_ADDRESS": target.State.MemoryWriteAddress, "$MEMORY_WRITE_SIZE": strconv.Itoa(target.State.MemoryWriteSize), "$MEMORY_WRITE_SHA256": target.State.MemoryWriteSHA256,
		"$MEMORY_PROTECTION_ADDRESS": target.State.MemoryProtectAddress, "$MEMORY_PROTECTION_SIZE": strconv.Itoa(target.State.MemoryProtectSize), "$MEMORY_PROTECTION": target.State.MemoryProtection,
		"$CANARY_PATH": target.State.CanaryFile, "$CANARY_SHA256": target.State.CanaryFileSHA256, "$TARGET_MOVE_CANARY_PATH": target.State.MoveCanaryFile, "$TARGET_MOVE_CANARY_SHA256": target.State.MoveCanarySHA256,
		"$CREDENTIAL_TARGET": target.Fixtures.CredentialTarget, "$CREDENTIAL_SHA256": target.Fixtures.CredentialSHA256, "$CREDENTIAL_SIZE": strconv.Itoa(target.Fixtures.CredentialSize),
		"$DPAPI_USER_PATH": target.Fixtures.DPAPIUserPath, "$DPAPI_USER_SHA256": target.Fixtures.DPAPIUserSHA256, "$DPAPI_USER_FILE_SHA256": target.Fixtures.DPAPIUserFileSHA256,
		"$DPAPI_MACHINE_PATH": target.Fixtures.DPAPIMachinePath, "$DPAPI_MACHINE_SHA256": target.Fixtures.DPAPIMachineSHA256, "$DPAPI_MACHINE_FILE_SHA256": target.Fixtures.DPAPIMachineFileSHA256,
		"$VAULT_GUID": target.Fixtures.VaultGUID, "$VAULT_RESOURCE": target.Fixtures.VaultResource, "$VAULT_IDENTITY": target.Fixtures.VaultIdentity,
		"$VAULT_SHA256": target.Fixtures.VaultSHA256, "$VAULT_SIZE": strconv.Itoa(target.Fixtures.VaultSize),
		"$CERT_THUMBPRINT": target.Fixtures.CertificateThumbprint, "$CERT_STORE": target.Fixtures.CertificateStore, "$CERT_SUBJECT": target.Fixtures.CertificateSubject,
		"$LAB_HOST": labHost, "$SERVICE_BINARY": target.ServiceBinary, "$WMI_MARKER_PATH": target.Fixtures.WMIMarkerPath,
		"$TARGET_SERVICE": target.Service,
		"$TEMP":           `C:\bofbench\proof\` + runID, "$RUN_ID": runID, "$PROOF_SECRET": proofSecret,
		"$PROOF_SECRET_SIZE":        strconv.Itoa(len(secretBytes)),
		"$PROOF_SECRET_SHA256":      hex.EncodeToString(secretHash[:]),
		"$PROOF_SECRET_CRLF_SHA256": hex.EncodeToString(secretCRLFHash[:]),
		"$PAYLOAD_RET_SHA256":       hex.EncodeToString(retHash[:]),
		"$REMOTE_REGISTRY_HIVE":     target.Fixtures.RemoteRegistryHive, "$REMOTE_REGISTRY_PATH": target.Fixtures.RemoteRegistryPath,
		"$REMOTE_REGISTRY_NAME": target.Fixtures.RemoteRegistryName, "$REMOTE_REGISTRY_SHA256": target.Fixtures.RemoteRegistrySHA256,
		"$REMOTE_REGISTRY_SIZE": strconv.Itoa(target.Fixtures.RemoteRegistrySize),
		"$REMOTE_STAGE_SHARE":   target.Fixtures.RemoteStageShare, "$REMOTE_STAGE_RELATIVE_ROOT": target.Fixtures.RemoteStageRelative,
		"$REMOTE_STAGE_LOCAL_ROOT": target.Fixtures.RemoteStageLocal, "$REMOTE_STAGE_RELATIVE": remoteRelative, "$REMOTE_STAGE_LOCAL_PATH": remoteLocalPath,
		"$REMOTE_TASK_NAME": remoteTaskName, "$REMOTE_TASK_MARKER_PATH": remoteTaskMarker,
	}
}

func selectProofArchitecture(placeholders map[string]string, target lab.TargetReport, arch string) {
	if arch != "x86" {
		return
	}
	placeholders["$TARGET_PID"] = strconv.Itoa(target.State.X86PID)
	placeholders["$TARGET_TID"] = strconv.FormatUint(uint64(target.State.X86AlertableTID), 10)
	placeholders["$TARGET_ARCH"] = "x86"
	placeholders["$TARGET_MODULE_BASE"] = target.State.X86KnownModuleBase
	placeholders["$TARGET_MODULE_PATH"] = target.State.X86KnownModulePath
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
		if replacement == "" || ((placeholder == "$TARGET_PID" || placeholder == "$TARGET_TID" || placeholder == "$X86_TARGET_PID" || placeholder == "$X86_TARGET_TID" || placeholder == "$MEMORY_SIZE" || placeholder == "$MEMORY_WRITE_SIZE" || placeholder == "$MEMORY_PROTECTION_SIZE" || placeholder == "$CREDENTIAL_SIZE" || placeholder == "$VAULT_SIZE") && replacement == "0") {
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
	case "file_sha256":
		probe = `$path=` + q(parameters["path"]) + `; $present=Test-Path -LiteralPath $path; $matches=$false; if($present){$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash; $matches=$hash -ieq ` + q(parameters["sha256"]) + `}`
	case "alternate_stream":
		probe = `$path=` + q(parameters["path"]) + `; $stream=` + q(parameters["stream"]) + `; $item=Get-Item -LiteralPath $path -Stream $stream -ErrorAction SilentlyContinue; $present=$null -ne $item; $matches=$present; if($present -and ` + q(parameters["sha256"]) + `){if((Get-Command Get-Content).Parameters.ContainsKey('AsByteStream')){$bytes=[byte[]](Get-Content -LiteralPath $path -Stream $stream -AsByteStream -Raw)}else{$bytes=[byte[]](Get-Content -LiteralPath $path -Stream $stream -Encoding Byte -Raw)}; $sha=[Security.Cryptography.SHA256]::Create(); try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}finally{$sha.Dispose()}; $matches=$hash -ieq ` + q(parameters["sha256"]) + `}`
	case "reparse_point":
		probe = `$path=` + q(parameters["path"]) + `; $item=Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue; $present=($null -ne $item) -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0); $matches=$present; if($present -and ` + q(parameters["tag"]) + `){$text=(& fsutil.exe reparsepoint query $path 2>&1 | Out-String); $matches=$text -match [regex]::Escape(` + q(parameters["tag"]) + `)}`
	case "smb_connection":
		probe = `$remote=` + q(parameters["remote"]) + `; $items=@(Get-SmbMapping -ErrorAction SilentlyContinue | Where-Object {[string]$_.RemotePath -ieq $remote}); $present=$items.Count -gt 0; $matches=$present`
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
	case "service_state":
		probe = `$service=Get-Service -Name ` + q(parameters["name"]) + ` -ErrorAction SilentlyContinue; $present=$null -ne $service; $matches=$present -and ([string]$service.Status -ieq ` + q(parameters["state"]) + `)`
	case "process_id":
		probe = `$present=$null -ne (Get-Process -Id ([int]` + q(parameters["pid"]) + `) -ErrorAction SilentlyContinue); $matches=$present`
	case "process_image_path":
		probe = `$processes=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {[string]$_.ExecutablePath -ieq ` + q(parameters["path"]) + `}); $present=$processes.Count -gt 0; $matches=$present`
	case "etw_session":
		probe = `$text=(& logman.exe query ` + q(parameters["name"]) + ` -ets 2>&1 | Out-String); $present=$LASTEXITCODE -eq 0; $matches=$present`
	case "event_log_record":
		// The cap is applied before the message filter, so on a busy channel the
		// event being proved can fall outside the most recent 256 and the proof
		// reads as absent. A sibling collector reported no detections this way
		// while the product's own log held them. There is no server-side filter
		// for free-text message content, so the mitigation is a channel specific
		// enough that 256 covers the window.
		probe = `$events=@(Get-WinEvent -LogName ` + q(parameters["channel"]) + ` -MaxEvents 256 -ErrorAction SilentlyContinue | Where-Object {[string]$_.Message -like ('*'+` + q(parameters["message"]) + `+'*')}); $present=$events.Count -gt 0; $matches=$present`
	case "active_loader_tasks":
		probe = `$tasks=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'bofbench-loader*.exe' -or ($_.Name -ieq 'bofbench.exe' -and [string]$_.CommandLine -match '\btask\s+(run|worker)\b')}); $present=$tasks.Count -gt 0; $matches=$present`
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
	case "process_memory_region":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchRegionCheck{[StructLayout(LayoutKind.Sequential)]public struct MBI{public IntPtr BaseAddress;public IntPtr AllocationBase;public uint AllocationProtect;public UIntPtr RegionSize;public uint State;public uint Protect;public uint Type;}[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true)]public static extern UIntPtr VirtualQueryEx(IntPtr p,UInt64 a,out MBI m,UIntPtr s);[DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr h);}' -ErrorAction SilentlyContinue; $handle=[BOFBenchRegionCheck]::OpenProcess(0x1000,$false,[uint32]` + q(parameters["pid"]) + `); if($handle -eq [IntPtr]::Zero){throw 'OpenProcess failed'}; try{$mbi=New-Object BOFBenchRegionCheck+MBI; $size=[Runtime.InteropServices.Marshal]::SizeOf($mbi); $addressText=(` + q(parameters["address"]) + ` -replace '^0x',''); $got=[BOFBenchRegionCheck]::VirtualQueryEx($handle,[Convert]::ToUInt64($addressText,16),[ref]$mbi,[UIntPtr]$size); $present=($got.ToUInt64() -gt 0) -and ($mbi.State -eq 0x1000); $matches=$present; if(` + q(parameters["size"]) + `){$matches=$matches -and ($mbi.RegionSize.ToUInt64() -ge [uint64]` + q(parameters["size"]) + `)}; if(` + q(parameters["protection"]) + `){$expected=[Convert]::ToUInt32((` + q(parameters["protection"]) + ` -replace '^0x',''),16); $matches=$matches -and (($mbi.Protect -band 0xff) -eq $expected)}}finally{[void][BOFBenchRegionCheck]::CloseHandle($handle)}`
	case "thread_suspend_state":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchSuspendCheck{[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenThread(uint a,bool i,uint t);[DllImport("kernel32.dll",SetLastError=true)]public static extern uint SuspendThread(IntPtr h);[DllImport("kernel32.dll",SetLastError=true)]public static extern uint ResumeThread(IntPtr h);[DllImport("kernel32.dll")]public static extern bool CloseHandle(IntPtr h);}' -ErrorAction SilentlyContinue; $handle=[BOFBenchSuspendCheck]::OpenThread(0x0002,$false,[uint32]` + q(parameters["tid"]) + `); $present=$handle -ne [IntPtr]::Zero; $matches=$false; if($present){try{$previous=[BOFBenchSuspendCheck]::SuspendThread($handle); if($previous -eq [uint32]::MaxValue){throw 'SuspendThread failed'}; [void][BOFBenchSuspendCheck]::ResumeThread($handle); $want=([int]` + q(parameters["suspended"]) + `) -ne 0; $matches=(($previous -gt 0) -eq $want)}finally{[void][BOFBenchSuspendCheck]::CloseHandle($handle)}}`
	case "thread_context":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchContextCheck{[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenThread(uint a,bool i,uint t);[DllImport("kernel32.dll",SetLastError=true)]static extern uint SuspendThread(IntPtr h);[DllImport("kernel32.dll",SetLastError=true)]static extern uint ResumeThread(IntPtr h);[DllImport("kernel32.dll",SetLastError=true)]static extern bool GetThreadContext(IntPtr h,IntPtr c);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static ulong IP(uint tid){IntPtr h=OpenThread(0x0002|0x0008,false,tid);if(h==IntPtr.Zero)throw new System.ComponentModel.Win32Exception();IntPtr c=Marshal.AllocHGlobal(1232);try{for(int i=0;i<1232;i++)Marshal.WriteByte(c,i,0);Marshal.WriteInt32(c,48,0x100001);uint old=SuspendThread(h);if(old==uint.MaxValue)throw new System.ComponentModel.Win32Exception();try{if(!GetThreadContext(h,c))throw new System.ComponentModel.Win32Exception();return unchecked((ulong)Marshal.ReadInt64(c,248));}finally{ResumeThread(h);}}finally{Marshal.FreeHGlobal(c);CloseHandle(h);}}}' -ErrorAction SilentlyContinue; $actual=[BOFBenchContextCheck]::IP([uint32]` + q(parameters["tid"]) + `); $present=$true; $expected=[Convert]::ToUInt64((` + q(parameters["ip"]) + ` -replace '^0x',''),16); $matches=$actual -eq $expected`
	case "kernel_object":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchObjectCheck{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenEvent(uint a,bool i,string n);[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenMutex(uint a,bool i,string n);[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenSemaphore(uint a,bool i,string n);[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenWaitableTimer(uint a,bool i,string n);[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenFileMapping(uint a,bool i,string n);[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenJobObject(uint a,bool i,string n);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static bool Present(string t,string n){IntPtr h=t=="event"?OpenEvent(0x100000,false,n):t=="mutex"?OpenMutex(0x100000,false,n):t=="semaphore"?OpenSemaphore(0x100000,false,n):t=="timer"?OpenWaitableTimer(0x100000,false,n):t=="section"?OpenFileMapping(4,false,n):t=="job"?OpenJobObject(4,false,n):IntPtr.Zero;if(h==IntPtr.Zero)return false;CloseHandle(h);return true;}}' -ErrorAction SilentlyContinue; $present=[BOFBenchObjectCheck]::Present(` + q(strings.ToLower(parameters["object_type"])) + `,` + q(parameters["name"]) + `); $matches=$present`
	case "event_state":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchEventCheck{[StructLayout(LayoutKind.Sequential)]struct E{public int Type;public int State;}[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenEvent(uint a,bool i,string n);[DllImport("ntdll.dll")]static extern int NtQueryEvent(IntPtr h,int c,out E e,int s,out int r);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static int State(string n){IntPtr h=OpenEvent(1,false,n);if(h==IntPtr.Zero)return -1;try{E e;int r;return NtQueryEvent(h,0,out e,8,out r)>=0?e.State:-1;}finally{CloseHandle(h);}}}' -ErrorAction SilentlyContinue; $actual=[BOFBenchEventCheck]::State(` + q(parameters["name"]) + `); $present=$actual -ge 0; $want=if(` + q(strings.ToLower(parameters["state"])) + ` -eq 'signaled'){1}else{0}; $matches=$present -and $actual -eq $want`
	case "mutex_state":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchMutexCheck{[StructLayout(LayoutKind.Sequential)]struct M{public int CurrentCount;public byte OwnedByCaller;public byte Abandoned;public ushort Reserved;}[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenMutex(uint a,bool i,string n);[DllImport("ntdll.dll")]static extern int NtQueryMutant(IntPtr h,int c,out M m,int s,out int r);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static int State(string n){IntPtr h=OpenMutex(1,false,n);if(h==IntPtr.Zero)return -1;try{M m;int r;return NtQueryMutant(h,0,out m,8,out r)>=0?m.CurrentCount:-1;}finally{CloseHandle(h);}}}' -ErrorAction SilentlyContinue; $actual=[BOFBenchMutexCheck]::State(` + q(parameters["name"]) + `); $present=$actual -ge 0; $want=if(` + q(strings.ToLower(parameters["state"])) + ` -eq 'available'){1}else{0}; $matches=$present -and $actual -eq $want`
	case "semaphore_state":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchSemaphoreCheck{[StructLayout(LayoutKind.Sequential)]struct S{public int CurrentCount;public int MaximumCount;}[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenSemaphore(uint a,bool i,string n);[DllImport("ntdll.dll")]static extern int NtQuerySemaphore(IntPtr h,int c,out S s,int z,out int r);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static int Count(string n){IntPtr h=OpenSemaphore(1,false,n);if(h==IntPtr.Zero)return -1;try{S s;int r;return NtQuerySemaphore(h,0,out s,8,out r)>=0?s.CurrentCount:-1;}finally{CloseHandle(h);}}}' -ErrorAction SilentlyContinue; $actual=[BOFBenchSemaphoreCheck]::Count(` + q(parameters["name"]) + `); $present=$actual -ge 0; $matches=$present -and $actual -eq [int]` + q(parameters["count"])
	case "timer_state":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchTimerCheck{[StructLayout(LayoutKind.Sequential)]struct T{public long RemainingTime;public byte State;public byte P1;public byte P2;public byte P3;public uint P4;}[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenWaitableTimer(uint a,bool i,string n);[DllImport("ntdll.dll")]static extern int NtQueryTimer(IntPtr h,int c,out T t,int s,out int r);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static int State(string n){IntPtr h=OpenWaitableTimer(1,false,n);if(h==IntPtr.Zero)return -1;try{T t;int r;return NtQueryTimer(h,0,out t,16,out r)>=0?(t.State!=0?1:0):-1;}finally{CloseHandle(h);}}}' -ErrorAction SilentlyContinue; $actual=[BOFBenchTimerCheck]::State(` + q(parameters["name"]) + `); $present=$actual -ge 0; $want=if(` + q(strings.ToLower(parameters["state"])) + ` -eq 'signaled'){1}else{0}; $matches=$present -and $actual -eq $want`
	case "mailslot_state":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchMailslotCheck{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateFile(string n,uint a,uint s,IntPtr p,uint c,uint f,IntPtr t);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static bool Present(string n){IntPtr h=CreateFile(n,0x40000000,1,IntPtr.Zero,3,0,IntPtr.Zero);if(h.ToInt64()==-1)return false;CloseHandle(h);return true;}}' -ErrorAction SilentlyContinue; $present=[BOFBenchMailslotCheck]::Present(` + q(parameters["name"]) + `); $matches=$present`
	case "mailslot_queue":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchMailslotQueueCheck{[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true)]static extern bool DuplicateHandle(IntPtr s,IntPtr h,IntPtr d,out IntPtr c,uint a,bool i,uint o);[DllImport("kernel32.dll",SetLastError=true)]static extern bool GetMailslotInfo(IntPtr h,out uint m,out uint n,out uint c,out uint t);[DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static int Count(uint p,ulong v){IntPtr s=OpenProcess(0x40,false,p);if(s==IntPtr.Zero)return -1;try{IntPtr h;if(!DuplicateHandle(s,(IntPtr)unchecked((long)v),GetCurrentProcess(),out h,0,false,2))return -1;try{uint m,n,c,t;return GetMailslotInfo(h,out m,out n,out c,out t)?(int)c:-1;}finally{CloseHandle(h);}}finally{CloseHandle(s);}}}' -ErrorAction SilentlyContinue; $handleText=(` + q(parameters["handle"]) + ` -replace '^0x',''); $actual=[BOFBenchMailslotQueueCheck]::Count([uint32]` + q(parameters["holder_pid"]) + `,[Convert]::ToUInt64($handleText,16)); $present=$actual -ge 0; $matches=$present -and $actual -ge [int]` + q(parameters["minimum_count"])
	case "named_pipe":
		probe = `$leaf=[IO.Path]::GetFileName(` + q(parameters["name"]) + `); $present=@(Get-ChildItem -LiteralPath '\\.\pipe\' -Name -ErrorAction SilentlyContinue | Where-Object {$_ -ieq $leaf}).Count -gt 0; $matches=$present`
	case "named_pipe_queue":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchPipeQueueCheck{[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true)]static extern bool DuplicateHandle(IntPtr s,IntPtr h,IntPtr d,out IntPtr c,uint a,bool i,uint o);[DllImport("kernel32.dll",SetLastError=true)]static extern bool PeekNamedPipe(IntPtr h,byte[] b,uint z,out uint r,out uint a,out uint l);[DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static byte[] Peek(uint p,ulong v){IntPtr s=OpenProcess(0x40,false,p);if(s==IntPtr.Zero)return null;try{IntPtr h;if(!DuplicateHandle(s,(IntPtr)unchecked((long)v),GetCurrentProcess(),out h,0,false,2))return null;try{byte[] b=new byte[65536];uint r,a,l;if(!PeekNamedPipe(h,b,(uint)b.Length,out r,out a,out l))return null;Array.Resize(ref b,(int)r);return b;}finally{CloseHandle(h);}}finally{CloseHandle(s);}}}' -ErrorAction SilentlyContinue; $handleText=(` + q(parameters["handle"]) + ` -replace '^0x',''); $bytes=[BOFBenchPipeQueueCheck]::Peek([uint32]` + q(parameters["holder_pid"]) + `,[Convert]::ToUInt64($handleText,16)); $present=$null -ne $bytes; $matches=$present -and ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)) -ieq ` + q(parameters["sha256"]) + `)`
	case "named_pipe_mode":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchPipeModeCheck{[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true)]static extern bool DuplicateHandle(IntPtr s,IntPtr h,IntPtr d,out IntPtr c,uint a,bool i,uint o);[DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]static extern bool GetNamedPipeHandleState(IntPtr h,out uint s,IntPtr m,IntPtr t,IntPtr c,IntPtr u,uint z);[DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static long Mode(uint p,ulong v){IntPtr s=OpenProcess(0x40,false,p);if(s==IntPtr.Zero)return -1;try{IntPtr h;if(!DuplicateHandle(s,(IntPtr)unchecked((long)v),GetCurrentProcess(),out h,0,false,2))return -1;try{uint mode;return GetNamedPipeHandleState(h,out mode,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,0)?mode:-1;}finally{CloseHandle(h);}}finally{CloseHandle(s);}}}' -ErrorAction SilentlyContinue; $handleText=(` + q(parameters["handle"]) + ` -replace '^0x',''); $actual=[BOFBenchPipeModeCheck]::Mode([uint32]` + q(parameters["holder_pid"]) + `,[Convert]::ToUInt64($handleText,16)); $present=$actual -ge 0; $matches=$present -and $actual -eq [int64]` + q(parameters["mode"])
	case "alpc_exchange":
		probe = `$path=Join-Path $env:SystemDrive 'bofbench\target\alpc-state.json'; $present=Test-Path -LiteralPath $path; $matches=$false; if($present){$state=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $matches=([string]$state.request_sha256 -ieq ` + q(parameters["sha256"]) + `) -and ([string]$state.response_sha256 -ieq ` + q(parameters["sha256"]) + `)}`
	case "window_message":
		probe = `$path=Join-Path $env:SystemDrive 'bofbench\target\window-state.json'; $present=Test-Path -LiteralPath $path; $matches=$false; if($present){$state=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $matches=([uint32]$state.message_id -eq [uint32]` + q(parameters["message_id"]) + `) -and ([string]$state.wparam -ieq ` + q(parameters["wparam"]) + `) -and ([string]$state.lparam -ieq ` + q(parameters["lparam"]) + `)}`
	case "window_copydata":
		probe = `$path=Join-Path $env:SystemDrive 'bofbench\target\window-state.json'; $present=Test-Path -LiteralPath $path; $matches=$false; if($present){$state=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $matches=([string]$state.copydata_sha256 -ieq ` + q(parameters["sha256"]) + `) -and ([string]$state.copydata_id -ieq ` + q(parameters["data_id"]) + `)}`
	case "window_text":
		probe = `$path=Join-Path $env:SystemDrive 'bofbench\target\window-state.json'; $present=Test-Path -LiteralPath $path; $matches=$false; if($present){$state=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $matches=([string]$state.text_handle -ieq ` + q(parameters["window_handle"]) + `) -and ([string]$state.text -ceq ` + q(parameters["text"]) + `)}`
	case "network_listener":
		protocol := strings.ToLower(parameters["protocol"])
		if protocol != "tcp" && protocol != "udp" {
			return "", fmt.Errorf("network_listener protocol must be tcp or udp")
		}
		if protocol == "tcp" {
			probe = `$items=@(Get-NetTCPConnection -State Listen -LocalPort ([uint16]` + q(parameters["port"]) + `) -ErrorAction SilentlyContinue); $present=$items.Count -gt 0; $matches=$present`
		} else {
			probe = `$items=@(Get-NetUDPEndpoint -LocalPort ([uint16]` + q(parameters["port"]) + `) -ErrorAction SilentlyContinue); $present=$items.Count -gt 0; $matches=$present`
		}
	case "network_observation":
		probe = `$path=Join-Path $env:SystemDrive 'bofbench\target\network-state.json'; $present=Test-Path -LiteralPath $path; $matches=$false; if($present){$state=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $transport=` + q(strings.ToLower(parameters["transport"])) + `; $count=if($transport -eq 'tcp'){[uint32]$state.tcp_requests}elseif($transport -eq 'udp'){[uint32]$state.udp_requests}elseif($transport -eq 'http'){[uint32]$state.http_requests}elseif($transport -eq 'websocket'){[uint32]$state.websocket_requests}else{0}; $matches=($count -gt 0) -and ([string]$state.last_transport -ieq $transport) -and ([string]$state.last_request_sha256 -ieq ` + q(parameters["request_sha256"]) + `) -and ([string]$state.last_response_sha256 -ieq ` + q(parameters["response_sha256"]) + `); if(` + q(parameters["minimum_attempts"]) + `){$matches=$matches -and ([uint32]$state.transient_attempts -ge [uint32]` + q(parameters["minimum_attempts"]) + `)}}`
	case "bits_job":
		probe = `$jobs=@(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object {[string]$_.JobId -ieq ` + q(parameters["job_id"]) + `}); $present=$jobs.Count -gt 0; $matches=$present`
	case "inherited_handle":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchInheritedHandleCheck{[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true)]static extern bool DuplicateHandle(IntPtr s,IntPtr h,IntPtr d,out IntPtr c,uint a,bool i,uint o);[DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static bool Present(uint p,ulong v){IntPtr s=OpenProcess(0x40,false,p);if(s==IntPtr.Zero)return false;try{IntPtr h;if(!DuplicateHandle(s,(IntPtr)unchecked((long)v),GetCurrentProcess(),out h,0,false,2))return false;CloseHandle(h);return true;}finally{CloseHandle(s);}}}' -ErrorAction SilentlyContinue; $handleText=(` + q(parameters["handle"]) + ` -replace '^0x',''); $present=[BOFBenchInheritedHandleCheck]::Present([uint32]` + q(parameters["pid"]) + `,[Convert]::ToUInt64($handleText,16)); $matches=$present`
	case "section_payload":
		probe = `$present=$false; $matches=$false; try{$mapping=[IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting(` + q(parameters["name"]) + `,[IO.MemoryMappedFiles.MemoryMappedFileRights]::Read); try{$view=$mapping.CreateViewAccessor([int64]` + q(parameters["offset"]) + `,[int64]` + q(parameters["size"]) + `,[IO.MemoryMappedFiles.MemoryMappedFileAccess]::Read); try{$bytes=New-Object byte[] ([int]` + q(parameters["size"]) + `); [void]$view.ReadArray(0,$bytes,0,$bytes.Length); $present=$true; $matches=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)) -ieq ` + q(parameters["sha256"]) + `)}finally{$view.Dispose()}}finally{$mapping.Dispose()}}catch{}`
	case "job_membership":
		probe = `Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public static class BOFBenchJobCheck{[DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenJobObject(uint a,bool i,string n);[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true)]static extern bool IsProcessInJob(IntPtr p,IntPtr j,out bool r);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static bool Member(string n,uint p){IntPtr j=OpenJobObject(4,false,n),h=OpenProcess(0x1000,false,p);if(j==IntPtr.Zero||h==IntPtr.Zero){if(j!=IntPtr.Zero)CloseHandle(j);if(h!=IntPtr.Zero)CloseHandle(h);return false;}try{bool r;return IsProcessInJob(h,j,out r)&&r;}finally{CloseHandle(h);CloseHandle(j);}}}' -ErrorAction SilentlyContinue; $present=[BOFBenchJobCheck]::Member(` + q(parameters["name"]) + `,[uint32]` + q(parameters["pid"]) + `); $matches=$present`
	case "process":
		probe = `Add-Type -TypeDefinition 'using System;using System.Text;using System.Runtime.InteropServices;public static class BOFBenchProcessCheck{[StructLayout(LayoutKind.Sequential)]struct US{public ushort Length;public ushort MaximumLength;public IntPtr Buffer;}[DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,uint p);[DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]static extern bool QueryFullProcessImageName(IntPtr p,uint f,StringBuilder n,ref uint s);[DllImport("ntdll.dll")]static extern int NtQueryInformationProcess(IntPtr p,int c,IntPtr b,uint s,out uint r);[DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);public static string[] Inspect(uint pid){IntPtr h=OpenProcess(0x1000,false,pid);if(h==IntPtr.Zero)return null;try{var image=new StringBuilder(1024);uint chars=1024;if(!QueryFullProcessImageName(h,0,image,ref chars))return null;IntPtr buffer=Marshal.AllocHGlobal(8192);try{uint returned;int status=NtQueryInformationProcess(h,60,buffer,8192,out returned);if(status<0)return null;US value=(US)Marshal.PtrToStructure(buffer,typeof(US));string command=Marshal.PtrToStringUni(value.Buffer,value.Length/2);return new[]{image.ToString(),command};}finally{Marshal.FreeHGlobal(buffer);}}finally{CloseHandle(h);}}}' -ErrorAction SilentlyContinue; $info=[BOFBenchProcessCheck]::Inspect([uint32]` + q(parameters["pid"]) + `); $present=$null -ne $info; $matches=$present -and ([IO.Path]::GetFileName([string]$info[0]) -ieq ` + q(parameters["image"]) + `) -and ([string]$info[1] -like ('*'+` + q(parameters["marker"]) + `+'*'))`
	case "process_command_line":
		probe = `$process=Get-CimInstance Win32_Process -Filter ("ProcessId="+` + q(parameters["pid"]) + `) -ErrorAction SilentlyContinue; $present=$null -ne $process; $matches=$present -and ([string]$process.CommandLine -like ('*'+` + q(parameters["value"]) + `+'*'))`
	case "service_config":
		probe = `$service=Get-CimInstance Win32_Service -Filter ("Name='"+(` + q(parameters["name"]) + ` -replace "'","''")+"'") -ErrorAction SilentlyContinue; $present=$null -ne $service; $field=` + q(parameters["field"]) + `; $actual=if($field -eq 'description'){(Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+` + q(parameters["name"]) + `) -Name Description -ErrorAction SilentlyContinue).Description}elseif($field -eq 'binary_path'){$service.PathName}elseif($field -eq 'start_mode'){$service.StartMode}else{''}; $matches=$present -and ([string]$actual -like ('*'+` + q(parameters["value"]) + `+'*'))`
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
	case "contains":
		assertion = `if(-not $matches){throw 'state did not contain expected value'}`
	case "not_contains":
		assertion = `if($matches){throw 'state still contains unexpected value'}`
	default:
		return "", fmt.Errorf("unsupported state expectation %q", expect)
	}
	return `$ErrorActionPreference='Stop'; ` + probe + `; ` + assertion + `; Write-Output 'BOFBENCH_STATE_VERIFIED'`, nil
}

func runProofCleanupSteps(via, labName, arch, work string, registry *packsvc.Registry, owner packsvc.Resolved, steps []packsvc.ProofCleanupStep, placeholders map[string]string) ([]string, error) {
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
		args := []string{"run", project, "--via", via, "--arch", arch}
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
	if report.ResumedFrom != "" {
		fmt.Fprintf(w, "resume    %s only=%s\n", report.ResumedFrom, strings.Join(report.OnlyStatuses, ","))
	}
	if report.Topology != "" {
		fmt.Fprintf(w, "topology  %s execution=%s\n", report.Topology, report.Lab)
	}
	fmt.Fprintf(w, "runtime   %s arch=%s lab=%s\n", report.Runtime, report.Architecture, report.Lab)
	fmt.Fprintf(w, "coverage  declared=%d passed=%d unavailable=%d failed=%d without-proof=%d\n", report.Declared, report.Passed, report.Unavailable, report.Failed, report.WithoutProof)
	for _, result := range report.Results {
		fmt.Fprintf(w, "%s/%s via=%s arch=%s %s\n", result.Pack, result.Case, result.Runtime, result.Architecture, result.Status)
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
