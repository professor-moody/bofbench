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
	Pack         string   `json:"pack"`
	Case         string   `json:"case"`
	Runtime      string   `json:"runtime"`
	Status       string   `json:"status"`
	Output       []string `json:"output,omitempty"`
	Receipt      string   `json:"receipt,omitempty"`
	ObjectSHA256 string   `json:"object_sha256,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type packProofReport struct {
	evidence.Header
	Status      string            `json:"status"`
	Lab         string            `json:"lab,omitempty"`
	Runtime     string            `json:"runtime"`
	GeneratedAt string            `json:"generated_at"`
	Results     []packProofResult `json:"results"`
	JSONPath    string            `json:"json_path,omitempty"`
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
	var via, labName, format string
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
			report, proofErr := provePacks(cmd.Context(), stdout, registry, items, via, labName)
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
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
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

func provePacks(ctx context.Context, stdout io.Writer, registry *packsvc.Registry, items []packsvc.Resolved, via, labName string) (packProofReport, error) {
	report := packProofReport{Header: evidence.New("bofbench.pack-proof", "", ""), Status: "pass", Lab: labName, Runtime: via, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
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
	var target lab.TargetReport
	targetReady, targetOwned := false, false
	ensureTarget := func() error {
		if targetReady || (via != "lab" && via != "sliver") {
			return nil
		}
		var output bytes.Buffer
		statusArgs := []string{"lab", "target", "status", "--format", "json"}
		if labName != "" {
			statusArgs = append(statusArgs, "--lab", labName)
		}
		if statusErr := Run(statusArgs, &output, &output); statusErr == nil && json.Unmarshal(output.Bytes(), &target) == nil && target.Status == "pass" {
			targetReady = true
			return nil
		}
		output.Reset()
		deployArgs := []string{"lab", "target", "deploy", "--format", "json"}
		if labName != "" {
			deployArgs = append(deployArgs, "--lab", labName)
		}
		if err := Run(deployArgs, &output, &output); err != nil {
			return fmt.Errorf("deploy proof target: %w: %s", err, strings.TrimSpace(output.String()))
		}
		if err := json.Unmarshal(output.Bytes(), &target); err != nil {
			return fmt.Errorf("decode proof target: %w", err)
		}
		targetReady, targetOwned = true, true
		return nil
	}
	defer func() {
		if targetOwned {
			args := []string{"lab", "target", "remove", "--format", "json"}
			if labName != "" {
				args = append(args, "--lab", labName)
			}
			_ = Run(args, io.Discard, io.Discard)
		}
	}()
	for _, item := range items {
		for _, proof := range item.Document.ProofCases {
			if !containsString(proof.Via, via) {
				continue
			}
			result := packProofResult{Pack: item.Qualified, Case: proof.ID, Runtime: via, Status: "pass"}
			if proofUsesTarget(proof) {
				if err := ensureTarget(); err != nil {
					result.Status, result.Error, report.Status = "unavailable", err.Error(), "pass_with_unavailable"
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
			arguments, err := resolveProofArguments(proof.Arguments, target, report.RunID)
			if err != nil {
				result.Status, result.Error, report.Status = "fail", err.Error(), "fail"
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
			if runErr != nil || !matchesProofOutput(result.Output, proof.Expect) {
				if runErr != nil && unavailableCoverage(runErr) {
					result.Status, result.Error = "unavailable", runErr.Error()
					if report.Status != "fail" {
						report.Status = "pass_with_unavailable"
					}
				} else {
					result.Status, report.Status = "fail", "fail"
					if runErr != nil {
						result.Error = runErr.Error()
					} else {
						result.Error = "structured output did not match proof expectation"
					}
				}
			} else if proof.Cleanup {
				cleanupArgs := append([]string(nil), args...)
				cleanupArgs = append(cleanupArgs, "--cleanup")
				var cleanup bytes.Buffer
				if cleanupErr := Run(cleanupArgs, &cleanup, &cleanup); cleanupErr != nil {
					result.Status, result.Error, report.Status = "fail", "cleanup: "+cleanupErr.Error(), "fail"
				} else if verifyErr := verifyProofCleanup(ctx, via, labName, item, arguments); verifyErr != nil {
					result.Status, result.Error, report.Status = "fail", "cleanup verification: "+verifyErr.Error(), "fail"
				}
				result.Output = append(result.Output, nonemptyLines(cleanup.String())...)
			}
			report.Results = append(report.Results, result)
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

func verifyProofCleanup(ctx context.Context, via, labName string, item packsvc.Resolved, arguments map[string]string) error {
	if item.Document.ID != "startup-folder" || (via != "lab" && via != "sliver") {
		return nil
	}
	leaf := arguments["artifact_name"]
	if leaf == "" || strings.ContainsAny(leaf, `\/:`) {
		return fmt.Errorf("startup artifact name is not an exact leaf")
	}
	resolved, err := lab.ResolveProfile(labName, "", lab.ProfilesPath())
	if err != nil {
		return err
	}
	remote, err := lab.ResolveRemoteOptions(ctx, resolved.Name, resolved.Profile)
	if err != nil {
		return err
	}
	quotedLeaf := "'" + strings.ReplaceAll(leaf, "'", "''") + "'"
	script := `$ErrorActionPreference='Stop'; $leaf=` + quotedLeaf + `; $relative='Microsoft\Windows\Start Menu\Programs\Startup'; $roots=@(); if($env:APPDATA){$roots += $env:APPDATA}; $users=Join-Path $env:SystemDrive 'Users'; if(Test-Path -LiteralPath $users){$roots += @(Get-ChildItem -LiteralPath $users -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming' })}; $found=@($roots | ForEach-Object { Join-Path (Join-Path $_ $relative) $leaf } | Where-Object { Test-Path -LiteralPath $_ }); if($found.Count -gt 0){throw ('startup artifact remains: ' + ($found -join ', '))}; Write-Output 'absent'`
	stdout, stderr, err := lab.ExecutePowerShell(ctx, remote, script)
	if err != nil {
		return fmt.Errorf("independent path check failed: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	if !strings.Contains(string(stdout), "absent") {
		return fmt.Errorf("independent path check did not confirm absence")
	}
	return nil
}

func proofUsesTarget(proof packsvc.ProofCase) bool {
	for _, value := range proof.Arguments {
		if strings.Contains(value, "$TARGET_") || strings.Contains(value, "$MEMORY_") || strings.Contains(value, "$CANARY_PATH") || strings.Contains(value, "$DPAPI_") || strings.Contains(value, "$LAB_HOST") {
			return true
		}
	}
	return false
}

func resolveProofArguments(arguments map[string]string, target lab.TargetReport, runID string) (map[string]string, error) {
	values := map[string]string{
		"$TARGET_PID": strconv.FormatUint(uint64(target.State.PID), 10), "$TARGET_TID": strconv.FormatUint(uint64(target.State.AlertableTID), 10),
		"$MEMORY_ADDRESS": target.State.MemoryCanaryAddress, "$MEMORY_SIZE": strconv.FormatUint(uint64(target.State.MemoryCanarySize), 10),
		"$CANARY_PATH": target.State.CanaryFile, "$DPAPI_USER_PATH": target.Fixtures.DPAPIUserPath, "$DPAPI_MACHINE_PATH": target.Fixtures.DPAPIMachinePath,
		"$LAB_HOST": target.Host, "$TEMP": `C:\bofbench\proof\` + runID, "$RUN_ID": runID,
	}
	resolved := map[string]string{}
	for name, value := range arguments {
		for placeholder, replacement := range values {
			if !strings.Contains(value, placeholder) {
				continue
			}
			if replacement == "" || replacement == "0" {
				return nil, fmt.Errorf("proof placeholder %s is unavailable", placeholder)
			}
			value = strings.ReplaceAll(value, placeholder, replacement)
		}
		resolved[name] = value
	}
	return resolved, nil
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
