package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/argpack"
	"bofbench/internal/artifact"
	"bofbench/internal/buildsys"
	"bofbench/internal/capability"
	"bofbench/internal/config"
	"bofbench/internal/evidence"
	"bofbench/internal/recipe"
	"bofbench/internal/runlog"
	runtimesvc "bofbench/internal/runtime"
	"bofbench/internal/sourceaudit"
)

type devLoopReport struct {
	evidence.Header
	Project           string                    `json:"project"`
	Profile           string                    `json:"profile,omitempty"`
	Compiler          string                    `json:"compiler"`
	Runtime           string                    `json:"runtime"`
	StartedAt         string                    `json:"started_at"`
	CompletedAt       string                    `json:"completed_at"`
	Status            string                    `json:"status"`
	Build             buildsys.Result           `json:"build"`
	SourceAnalysis    *sourceaudit.Report       `json:"source_analysis,omitempty"`
	SourceJSONPath    string                    `json:"source_json_path,omitempty"`
	SourceMDPath      string                    `json:"source_md_path,omitempty"`
	Recipe            *recipe.Document          `json:"recipe,omitempty"`
	RecipePath        string                    `json:"recipe_path,omitempty"`
	RecipeFingerprint *evidence.FileFingerprint `json:"recipe_fingerprint,omitempty"`
	RecipeValidation  *recipe.Validation        `json:"recipe_validation,omitempty"`
	Analysis          *artifact.Analysis        `json:"analysis,omitempty"`
	AnalysisJSONPath  string                    `json:"analysis_json_path,omitempty"`
	AnalysisMDPath    string                    `json:"analysis_md_path,omitempty"`
	ImportCorrelation *devImportCorrelation     `json:"import_correlation,omitempty"`
	RuntimeState      string                    `json:"runtime_state"`
	RuntimeReason     string                    `json:"runtime_reason,omitempty"`
	Run               *runtimesvc.Result        `json:"run,omitempty"`
	Args              []argpack.Item            `json:"args,omitempty"`
	Error             string                    `json:"error,omitempty"`
	EvidencePath      string                    `json:"evidence_path"`
	MarkdownPath      string                    `json:"markdown_path"`
	Next              string                    `json:"next,omitempty"`
}

type devImportCorrelation struct {
	Status     string   `json:"status"`
	Declared   int      `json:"declared"`
	Emitted    int      `json:"emitted"`
	Matched    int      `json:"matched"`
	SourceOnly []string `json:"source_only,omitempty"`
	ObjectOnly []string `json:"object_only,omitempty"`
}

type devLoopOptions struct {
	Project            string
	Arch               string
	Compiler           string
	Runtime            string
	Profile            string
	SkipRun            bool
	VerifyReproducible bool
	Suppressions       []string
	ArgumentTokens     []string
}

func devCommand(stdout io.Writer) *cobra.Command {
	var opts devLoopOptions
	var format string
	cmd := &cobra.Command{
		Use:   "dev <project>",
		Short: "Build, analyze, preflight, and test a BOF in one developer loop",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" && format != "md" && format != "markdown" {
				return fmt.Errorf("unknown dev format %q", format)
			}
			opts.Project = args[0]
			report, devErr := executeDevLoop(opts)
			switch format {
			case "json":
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			case "md", "markdown":
				fmt.Fprint(stdout, devLoopMarkdown(report))
			case "text":
				fmt.Fprint(stdout, devLoopText(report))
			}
			if devErr != nil {
				return codedError{code: 1, err: devErr}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.Arch, "arch", "x64", "build architecture: x64 or x86")
	cmd.Flags().StringVar(&opts.Compiler, "compiler", "auto", "compiler profile: auto, mingw, or msvc")
	cmd.Flags().StringVar(&opts.Runtime, "runtime", "auto", "runtime: auto, windows-coff, linux-elf, or darwin-macho")
	cmd.Flags().StringVar(&opts.Profile, "profile", "", "bofbench.toml test profile")
	cmd.Flags().BoolVar(&opts.SkipRun, "skip-run", false, "stop after build, analysis, and loader preflight")
	cmd.Flags().BoolVar(&opts.VerifyReproducible, "verify-reproducible", false, "build twice and require identical object bytes")
	cmd.Flags().StringSliceVar(&opts.Suppressions, "suppress", nil, "analysis finding suppression; repeatable")
	cmd.Flags().StringArrayVar(&opts.ArgumentTokens, "arg-token", nil, "packed BOF argument token used by runtime adapters; repeatable")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	return cmd
}

func executeDevLoop(opts devLoopOptions) (devLoopReport, error) {
	started := time.Now().UTC()
	runDir, err := runlog.NewDir("dev-" + safeName(opts.Project))
	if err != nil {
		return devLoopReport{}, err
	}
	report := devLoopReport{
		Header:       evidence.New(evidence.SchemaDev, runlog.ID(runDir), ""),
		Project:      opts.Project,
		Profile:      opts.Profile,
		Compiler:     opts.Compiler,
		Runtime:      opts.Runtime,
		StartedAt:    started.Format(time.RFC3339),
		Status:       "fail",
		RuntimeState: "not_reached",
		EvidencePath: filepath.Join(runDir, "dev.json"),
		MarkdownPath: filepath.Join(runDir, "dev.md"),
	}
	finish := func(loopErr error) (devLoopReport, error) {
		report.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		if loopErr != nil {
			report.Status = "fail"
			report.Error = loopErr.Error()
		}
		if writeErr := writeJSON(report.EvidencePath, report); writeErr != nil && loopErr == nil {
			loopErr = writeErr
		}
		if writeErr := os.WriteFile(report.MarkdownPath, []byte(devLoopMarkdown(report)), 0o644); writeErr != nil && loopErr == nil {
			loopErr = writeErr
		}
		return report, loopErr
	}

	cfg, cfgPath, err := config.LoadFor(opts.Project)
	if err != nil {
		return finish(err)
	}
	cfg, err = config.ApplyProfile(cfg, opts.Profile)
	if err != nil {
		return finish(err)
	}
	entry := cfg.Entrypoint
	if entry == "" {
		entry = "go"
	}
	if sourceaudit.IsSourceInput(opts.Project) {
		sourcePersisted, sourceErr := sourceaudit.AnalyzeAndPersist(opts.Project, sourceaudit.Options{Entrypoint: entry})
		if sourceErr != nil {
			report.RuntimeReason = "source analysis failed"
			return finish(sourceErr)
		}
		report.SourceAnalysis = &sourcePersisted.Report
		report.SourceJSONPath = sourcePersisted.JSONPath
		report.SourceMDPath = sourcePersisted.MDPath
		if sourcePersisted.Report.Status == "fail" {
			report.RuntimeReason = "source analysis blocked the build"
			return finish(fmt.Errorf("BOF source analysis failed with %d error finding(s)", sourcePersisted.Report.Summary.Errors))
		}
		document, recipePath, recipeErr := recipe.LoadFor(opts.Project)
		if recipeErr == nil {
			report.Recipe = &document
			report.RecipePath = recipePath
			if fingerprint, fingerprintErr := evidence.FingerprintFile(recipePath); fingerprintErr == nil {
				report.RecipeFingerprint = &fingerprint
			}
			presentFeatures := make([]string, 0, len(sourcePersisted.Report.Features))
			for _, feature := range sourcePersisted.Report.Features {
				presentFeatures = append(presentFeatures, feature.Name)
			}
			validation := recipe.Validate(recipePath, document, presentFeatures)
			report.RecipeValidation = &validation
			if validation.Status == "fail" {
				report.RuntimeReason = "recipe validation blocked the build"
				return finish(fmt.Errorf("BOF recipe validation failed: %s", strings.Join(validation.Errors, "; ")))
			}
		} else if !os.IsNotExist(recipeErr) {
			report.RuntimeReason = "recipe parsing failed"
			return finish(recipeErr)
		}
	}
	build, err := buildsys.BuildWithOptions(opts.Project, buildsys.Options{
		Arch:               opts.Arch,
		Compiler:           opts.Compiler,
		ParentRunID:        report.RunID,
		VerifyReproducible: opts.VerifyReproducible,
	})
	report.Build = build
	if err != nil {
		report.RuntimeReason = "build failed before analysis"
		return finish(err)
	}

	persisted, err := artifact.AnalyzeAndPersistWithOptions(build.Object, artifact.AnalysisOptions{
		Entrypoint:   entry,
		Suppressions: opts.Suppressions,
	})
	if err != nil {
		report.RuntimeReason = "analysis failed"
		return finish(err)
	}
	report.Analysis = &persisted.Analysis
	report.AnalysisJSONPath = persisted.JSONPath
	report.AnalysisMDPath = persisted.MDPath
	if report.SourceAnalysis != nil {
		correlation := correlateImports(*report.SourceAnalysis, persisted.Analysis)
		report.ImportCorrelation = &correlation
	}
	if persisted.Analysis.LoaderCompatibility != nil && !persisted.Analysis.LoaderCompatibility.Compatible {
		report.RuntimeState = "blocked"
		report.RuntimeReason = fmt.Sprintf("loader preflight: %s", persisted.Analysis.LoaderCompatibility.Status)
		return finish(fmt.Errorf("BOF is not loader-compatible: %s", persisted.Analysis.LoaderCompatibility.Status))
	}

	if opts.SkipRun {
		report.Status = "pass"
		report.RuntimeState = "skipped"
		report.RuntimeReason = "disabled by --skip-run"
		report.Next = fmt.Sprintf("bofbench dev %s --runtime %s", shellQuote(opts.Project), shellQuote(effectiveRuntime(opts.Runtime, persisted.Analysis)))
		return finish(nil)
	}
	if !canRunHost(persisted.Analysis.Kind) {
		report.Status = "pass"
		report.RuntimeState = "deferred"
		report.RuntimeReason = persisted.Analysis.Runtime.Status
		report.Next = fmt.Sprintf("on %s/%s: bofbench dev %s --runtime %s", persisted.Analysis.Runtime.RequiredOS, persisted.Analysis.Runtime.RequiredArch, shellQuote(opts.Project), shellQuote(effectiveRuntime(opts.Runtime, persisted.Analysis)))
		return finish(nil)
	}

	argumentTokens := cfg.Args
	if len(opts.ArgumentTokens) > 0 {
		argumentTokens = append([]string(nil), opts.ArgumentTokens...)
	}
	packed, items, err := argpack.PackTokens(argumentTokens)
	if err != nil {
		return finish(err)
	}
	report.Args = items
	runResult, runErr := runtimesvc.Run(runtimesvc.Request{
		Path:      build.Object,
		Entry:     entry,
		ArgHex:    argpack.Hex(packed),
		Tokens:    argumentTokens,
		TimeoutMS: cfg.TimeoutMS,
		Runtime:   opts.Runtime,
	})
	if cfgPath != "" {
		if fingerprint, fingerprintErr := evidence.FingerprintFile(cfgPath); fingerprintErr == nil {
			runResult.ConfigFingerprint = &fingerprint
		}
	}
	expected, expectedErr := applyExpectedResult(&runResult, cfg)
	if expectedErr != nil {
		runErr = expectedErr
	}
	if runErr == nil || expected {
		if outputErr := applyOutputChecks(&runResult, cfg.Expect, cfg.Forbid); outputErr != nil {
			runErr = outputErr
		}
	}
	runResult.Header = evidence.New(evidence.SchemaRun, report.RunID+"/run", report.RunID)
	report.Run = &runResult
	if runErr != nil && !expected {
		report.RuntimeState = "fail"
		report.RuntimeReason = runResult.ExitState
		return finish(runErr)
	}
	if runResult.Status != "pass" && !expected {
		report.RuntimeState = "fail"
		report.RuntimeReason = runResult.ExitState
		return finish(fmt.Errorf("payload test failed: %s", runResult.ExitState))
	}
	report.Status = "pass"
	if expected {
		report.RuntimeState = "expected_pass"
		report.RuntimeReason = runResult.ExitState
	} else {
		report.RuntimeState = "pass"
	}
	report.Next = fmt.Sprintf("bofbench export %s --for raw", shellQuote(build.Object))
	return finish(nil)
}

func effectiveRuntime(requested string, analysis artifact.Analysis) string {
	if requested != "" && requested != "auto" {
		return requested
	}
	if analysis.Runtime.Runtime != "" {
		return analysis.Runtime.Runtime
	}
	return "auto"
}

func correlateImports(source sourceaudit.Report, object artifact.Analysis) devImportCorrelation {
	catalog := capability.WindowsCOFF()
	normalize := func(symbol string) string {
		normalized, _ := catalog.NormalizeImport(symbol)
		return normalized
	}
	declared := map[string]bool{}
	for _, imp := range source.DynamicImports {
		declared[normalize(imp.Symbol)] = true
	}
	for _, api := range source.BeaconAPIs {
		declared[normalize(api.Name)] = true
	}
	emitted := map[string]bool{}
	for _, imp := range object.Imports {
		emitted[normalize(imp.Symbol)] = true
	}
	result := devImportCorrelation{Status: "matched", Declared: len(declared), Emitted: len(emitted)}
	for symbol := range declared {
		if emitted[symbol] {
			result.Matched++
		} else {
			result.SourceOnly = append(result.SourceOnly, symbol)
		}
	}
	for symbol := range emitted {
		if !declared[symbol] {
			result.ObjectOnly = append(result.ObjectOnly, symbol)
		}
	}
	sort.Strings(result.SourceOnly)
	sort.Strings(result.ObjectOnly)
	if len(result.SourceOnly)+len(result.ObjectOnly) > 0 {
		result.Status = "review"
	}
	return result
}

func devLoopText(report devLoopReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "BOF DEV %s\n", strings.ToUpper(report.Status))
	fmt.Fprintf(&b, "project   %s\n", report.Project)
	if report.SourceAnalysis != nil {
		fmt.Fprintf(&b, "source    %-10s features=%d imports=%d review=%d errors=%d warnings=%d\n",
			report.SourceAnalysis.Status,
			report.SourceAnalysis.Summary.Features,
			report.SourceAnalysis.Summary.DynamicImports,
			report.SourceAnalysis.Summary.Review,
			report.SourceAnalysis.Summary.Errors,
			report.SourceAnalysis.Summary.Warnings,
		)
		shown := 0
		for _, finding := range report.SourceAnalysis.Findings {
			if finding.Severity != "error" && finding.Severity != "warning" {
				continue
			}
			location := finding.File
			if finding.Line > 0 {
				location += fmt.Sprintf(":%d", finding.Line)
			}
			fmt.Fprintf(&b, "source!   %-10s %s", finding.Category, finding.Detail)
			if location != "" {
				fmt.Fprintf(&b, " (%s)", location)
			}
			b.WriteByte('\n')
			if finding.Remediation != "" {
				fmt.Fprintf(&b, "          fix: %s\n", finding.Remediation)
			}
			shown++
			if shown == 5 {
				break
			}
		}
	}
	if report.Recipe != nil && report.RecipeValidation != nil {
		fmt.Fprintf(&b, "recipe    %-10s %s  impact=%s\n",
			report.RecipeValidation.Status,
			report.Recipe.Name,
			report.Recipe.Impact,
		)
		fmt.Fprintf(&b, "needs     privilege=%s network=%s domain=%s\n",
			report.Recipe.Privilege,
			report.Recipe.Network,
			report.Recipe.Domain,
		)
		for _, warning := range report.RecipeValidation.Warnings {
			fmt.Fprintf(&b, "recipe!   warning    %s\n", warning)
		}
		for _, problem := range report.RecipeValidation.Errors {
			fmt.Fprintf(&b, "recipe!   error      %s\n", problem)
		}
	}
	if report.Build.Status != "" {
		fmt.Fprintf(&b, "build     %-10s %s (%s/%s)\n", report.Build.Status, report.Build.Object, report.Build.Compiler.Profile, report.Build.Arch)
	}
	if report.Analysis != nil {
		compatibility := "not-applicable"
		blockers := 0
		warnings := 0
		if report.Analysis.LoaderCompatibility != nil {
			compatibility = report.Analysis.LoaderCompatibility.Status
			blockers = len(report.Analysis.LoaderCompatibility.Blockers)
			warnings = len(report.Analysis.LoaderCompatibility.Warnings)
		}
		fmt.Fprintf(&b, "analysis  %-10s entry=%s imports=%d relocs=%d findings=%d blockers=%d warnings=%d\n",
			compatibility,
			report.Analysis.EntrypointSymbol,
			len(report.Analysis.Imports),
			report.Analysis.Relocations,
			report.Analysis.FindingSummary.Active,
			blockers,
			warnings,
		)
	}
	if report.ImportCorrelation != nil {
		fmt.Fprintf(&b, "imports   %-10s matched=%d source-only=%d object-only=%d\n",
			report.ImportCorrelation.Status,
			report.ImportCorrelation.Matched,
			len(report.ImportCorrelation.SourceOnly),
			len(report.ImportCorrelation.ObjectOnly),
		)
		if len(report.ImportCorrelation.SourceOnly) > 0 {
			fmt.Fprintf(&b, "          source-only: %s\n", strings.Join(report.ImportCorrelation.SourceOnly, ", "))
		}
		if len(report.ImportCorrelation.ObjectOnly) > 0 {
			fmt.Fprintf(&b, "          object-only: %s\n", strings.Join(report.ImportCorrelation.ObjectOnly, ", "))
		}
	}
	fmt.Fprintf(&b, "runtime   %s", report.RuntimeState)
	if report.RuntimeReason != "" {
		fmt.Fprintf(&b, " (%s)", report.RuntimeReason)
	}
	b.WriteByte('\n')
	if report.Run != nil {
		fmt.Fprintf(&b, "output    %d line(s), exit=%s\n", len(report.Run.Output), report.Run.ExitState)
		for _, line := range report.Run.Output {
			fmt.Fprintf(&b, "          %s\n", line)
		}
	}
	if report.Error != "" {
		fmt.Fprintf(&b, "error     %s\n", report.Error)
	}
	fmt.Fprintf(&b, "reports   %s%c\n", filepath.Dir(report.EvidencePath), os.PathSeparator)
	if report.Next != "" {
		fmt.Fprintf(&b, "next      %s\n", report.Next)
	}
	return b.String()
}

func devLoopMarkdown(report devLoopReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# BOF Developer Loop: %s\n\n", strings.ToUpper(report.Status))
	fmt.Fprintf(&b, "- Project: `%s`\n", report.Project)
	if report.SourceAnalysis != nil {
		fmt.Fprintf(&b, "- Source: `%s`; %d files; %d dynamic imports; %d warnings; %d review findings\n",
			report.SourceAnalysis.Status,
			report.SourceAnalysis.Summary.Files,
			report.SourceAnalysis.Summary.DynamicImports,
			report.SourceAnalysis.Summary.Warnings,
			report.SourceAnalysis.Summary.Review,
		)
	}
	if report.Recipe != nil && report.RecipeValidation != nil {
		fmt.Fprintf(&b, "- Recipe: `%s` (`%s`); privilege `%s`; network `%s`; domain `%s`; impact `%s`\n",
			report.Recipe.Name,
			report.RecipeValidation.Status,
			report.Recipe.Privilege,
			report.Recipe.Network,
			report.Recipe.Domain,
			report.Recipe.Impact,
		)
	}
	fmt.Fprintf(&b, "- Build: `%s` (`%s`)\n", report.Build.Status, report.Build.Object)
	if report.Analysis != nil {
		compatibility := "not-applicable"
		if report.Analysis.LoaderCompatibility != nil {
			compatibility = report.Analysis.LoaderCompatibility.Status
		}
		fmt.Fprintf(&b, "- Analysis: `%s`; entry `%s`; %d imports; %d relocations; %d active findings\n",
			compatibility,
			report.Analysis.EntrypointSymbol,
			len(report.Analysis.Imports),
			report.Analysis.Relocations,
			report.Analysis.FindingSummary.Active,
		)
	}
	if report.ImportCorrelation != nil {
		fmt.Fprintf(&b, "- Import correlation: `%s`; %d matched; %d source-only; %d object-only\n",
			report.ImportCorrelation.Status,
			report.ImportCorrelation.Matched,
			len(report.ImportCorrelation.SourceOnly),
			len(report.ImportCorrelation.ObjectOnly),
		)
	}
	fmt.Fprintf(&b, "- Runtime: `%s`", report.RuntimeState)
	if report.RuntimeReason != "" {
		fmt.Fprintf(&b, " — %s", report.RuntimeReason)
	}
	b.WriteString("\n")
	if report.SourceAnalysis != nil && report.SourceAnalysis.Summary.Errors+report.SourceAnalysis.Summary.Warnings > 0 {
		b.WriteString("\n## Source Fixes\n\n| Severity | Category | Location | Fix |\n| --- | --- | --- | --- |\n")
		for _, finding := range report.SourceAnalysis.Findings {
			if finding.Severity != "error" && finding.Severity != "warning" {
				continue
			}
			location := finding.File
			if finding.Line > 0 {
				location += fmt.Sprintf(":%d", finding.Line)
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s |\n", finding.Severity, finding.Category, location, escapeMarkdownTable(finding.Remediation))
		}
		b.WriteByte('\n')
	}
	if report.Run != nil && len(report.Run.Output) > 0 {
		b.WriteString("\n## Output\n\n```text\n")
		for _, line := range report.Run.Output {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		b.WriteString("```\n")
	}
	if report.Error != "" {
		fmt.Fprintf(&b, "\n## Error\n\n%s\n", report.Error)
	}
	if report.Next != "" {
		fmt.Fprintf(&b, "\n## Next\n\n```sh\n%s\n```\n", report.Next)
	}
	return b.String()
}
