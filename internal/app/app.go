package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"bofbench/internal/argpack"
	"bofbench/internal/arsenal"
	"bofbench/internal/artifact"
	"bofbench/internal/buildsys"
	"bofbench/internal/capability"
	"bofbench/internal/config"
	"bofbench/internal/doctor"
	"bofbench/internal/evidence"
	"bofbench/internal/lab"
	preflightsvc "bofbench/internal/preflight"
	"bofbench/internal/runlog"
	runtimesvc "bofbench/internal/runtime"
	"bofbench/internal/stage"
	"bofbench/internal/tui"
)

type codedError struct {
	code int
	err  error
}

type arsenalTestReport struct {
	evidence.Header
	Root        string              `json:"root"`
	Selected    string              `json:"selected,omitempty"`
	Runtime     string              `json:"runtime"`
	Entrypoint  string              `json:"entrypoint"`
	Args        []string            `json:"args,omitempty"`
	StartedAt   string              `json:"started_at"`
	CompletedAt string              `json:"completed_at"`
	Status      string              `json:"status"`
	Summary     arsenalTestSummary  `json:"summary"`
	Results     []arsenalTestResult `json:"results"`
}

type arsenalTestSummary struct {
	Total       int `json:"total"`
	Passed      int `json:"passed"`
	AnalyzeOnly int `json:"analyze_only"`
	Failed      int `json:"failed"`
}

type arsenalTestResult struct {
	Name     string             `json:"name"`
	Path     string             `json:"path"`
	Object   string             `json:"object,omitempty"`
	Status   string             `json:"status"`
	Phase    string             `json:"phase"`
	Error    string             `json:"error,omitempty"`
	Build    *buildsys.Result   `json:"build,omitempty"`
	Analysis *artifact.Analysis `json:"analysis,omitempty"`
	Run      *runtimesvc.Result `json:"run,omitempty"`
	Args     []argpack.Item     `json:"args,omitempty"`
	Notes    []string           `json:"notes,omitempty"`
}

func (e codedError) Error() string { return e.err.Error() }
func (e codedError) Unwrap() error { return e.err }

func ExitCode(err error) int {
	var ce codedError
	if errors.As(err, &ce) {
		return ce.code
	}
	return 2
}

func Run(args []string, stdout, stderr io.Writer) error {
	root := rootCommand(stdout, stderr)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	return root.Execute()
}

func rootCommand(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "bofbench",
		Short:         "Offensive BOF build/load/test/stage workbench",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(
		newCommand(stdout),
		fetchCommand(stdout),
		listCommand(stdout),
		buildCommand(stdout),
		inspectCommand(stdout),
		analyzeCommand(stdout),
		preflightCommand(stdout),
		runCommand(stdout),
		testCommand(stdout),
		stageCommand(stdout),
		labCommand(stdout, stderr),
		doctorCommand(stdout),
		tuiCommand(stdout),
		docsCommand(stdout, stderr),
		versionCommand(stdout),
	)
	return cmd
}

func versionCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		RunE: func(cmd *cobra.Command, args []string) error {
			header := evidence.New(evidence.SchemaVersionInfo, "", "")
			switch format {
			case "text":
				fmt.Fprintf(stdout, "bofbench multi-platform version=%s commit=%s host=%s/%s\n", header.Tool.Version, header.Tool.Commit, header.Host.OS, header.Host.Arch)
				return nil
			case "json":
				return printJSON(stdout, header)
			default:
				return fmt.Errorf("unknown version format %q", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func newCommand(stdout io.Writer) *cobra.Command {
	var templateName string
	cmd := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a BOF payload workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := safeName(args[0])
			tpl, err := templateFor(templateName, name)
			if err != nil {
				return err
			}
			root := filepath.Join("bofs", name)
			if err := os.MkdirAll(root, 0o755); err != nil {
				return err
			}
			files := map[string]string{
				filepath.Join(root, name+".c"):       tpl.Source,
				filepath.Join(root, "beacon.h"):      tpl.Header,
				filepath.Join(root, "bofbench.toml"): tpl.Config,
				filepath.Join(root, "README.md"):     tpl.Readme,
			}
			for path, body := range files {
				if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
					return err
				}
			}
			fmt.Fprintf(stdout, "created BOF payload workspace %s\n", root)
			return nil
		},
	}
	cmd.Flags().StringVar(&templateName, "template", "args", "template: args, hello, winapi, unresolved, timeout")
	return cmd
}

func fetchCommand(stdout io.Writer) *cobra.Command {
	var opts arsenal.FetchOptions
	cmd := &cobra.Command{
		Use:   "fetch <alias|url>",
		Short: "Fetch a BOF arsenal or artifact from an alias, Git URL, zip URL, or raw URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Source = args[0]
			meta, err := arsenal.FetchWithOptions(opts)
			if err != nil {
				return err
			}
			return printJSON(stdout, meta)
		},
	}
	cmd.Flags().StringVar(&opts.Name, "name", "", "arsenal name under arsenal/")
	cmd.Flags().StringVar(&opts.Ref, "ref", "", "git ref, tag, branch, or sha")
	cmd.Flags().StringVar(&opts.Type, "type", "auto", "fetch type: git, zip, raw, auto")
	cmd.Flags().StringVar(&opts.Adapter, "adapter", "auto", "adapter: trustedsec-sa, generic, auto")
	return cmd
}

func listCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "list <dir>",
		Short: "List BOFs/artifacts in an arsenal-like directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := arsenal.List(args[0])
			if err != nil {
				return err
			}
			for _, entry := range entries {
				arch := "-"
				if entry.X64 != "" {
					arch = "x64"
				}
				if entry.X86 != "" {
					if arch == "-" {
						arch = "x86"
					} else {
						arch += ",x86"
					}
				}
				fmt.Fprintf(stdout, "%-32s %-8s %s\n", entry.Name, arch, entry.Path)
			}
			return nil
		},
	}
}

func buildCommand(stdout io.Writer) *cobra.Command {
	var arch string
	var compiler string
	var verifyReproducible bool
	cmd := &cobra.Command{
		Use:   "build <dir|file>",
		Short: "Build or copy a payload artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := buildsys.BuildWithOptions(args[0], buildsys.Options{
				Arch:               arch,
				Compiler:           compiler,
				VerifyReproducible: verifyReproducible,
			})
			if res.RunID != "" {
				if printErr := printJSON(stdout, res); printErr != nil {
					return printErr
				}
			}
			if err != nil {
				return codedError{code: 1, err: err}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&arch, "arch", "x64", "architecture: x64 or x86")
	cmd.Flags().StringVar(&compiler, "compiler", "", "compiler profile override: auto, mingw, or msvc")
	cmd.Flags().BoolVar(&verifyReproducible, "verify-reproducible", false, "build twice and require identical object bytes")
	return cmd
}

func inspectCommand(stdout io.Writer) *cobra.Command {
	var entry string
	var suppressions []string
	cmd := &cobra.Command{
		Use:   "inspect <artifact>",
		Short: "Print human-readable artifact analysis",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := artifact.AnalyzeWithOptions(args[0], artifact.AnalysisOptions{Entrypoint: entry, Suppressions: suppressions})
			if err != nil {
				return err
			}
			printAnalysis(stdout, a)
			return nil
		},
	}
	cmd.Flags().StringVar(&entry, "entry", "go", "entrypoint symbol")
	cmd.Flags().StringSliceVar(&suppressions, "suppress", nil, "mark finding category or category=evidence-glob as suppressed; repeatable")
	return cmd
}

func analyzeCommand(stdout io.Writer) *cobra.Command {
	var entry string
	var format string
	var baselinePath string
	var suppressions []string
	cmd := &cobra.Command{
		Use:   "analyze <artifact>",
		Short: "Analyze an artifact and write JSON/Markdown reports",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			persisted, err := artifact.AnalyzeAndPersistWithOptions(args[0], artifact.AnalysisOptions{Entrypoint: entry, Suppressions: suppressions})
			if err != nil {
				return err
			}
			var diff *artifact.DiffReport
			var diffJSONPath string
			var diffMDPath string
			if baselinePath != "" {
				baseline, err := artifact.LoadAnalysis(baselinePath)
				if err != nil {
					return err
				}
				report := artifact.CompareAnalysis(baseline, persisted.Analysis)
				report.Header = evidence.New(evidence.SchemaAnalysisDiff, persisted.Analysis.RunID+"/diff", persisted.Analysis.RunID)
				diff = &report
				diffJSONPath = filepath.Join(filepath.Dir(persisted.JSONPath), "diff.json")
				diffMDPath = filepath.Join(filepath.Dir(persisted.JSONPath), "diff.md")
				if err := writeJSON(diffJSONPath, report); err != nil {
					return err
				}
				if err := os.WriteFile(diffMDPath, []byte(artifact.DiffMarkdown(report)), 0o644); err != nil {
					return err
				}
			}
			if format == "md" || format == "markdown" {
				fmt.Fprint(stdout, artifact.Markdown(persisted.Analysis))
				if diff != nil {
					fmt.Fprint(stdout, "\n\n")
					fmt.Fprint(stdout, artifact.DiffMarkdown(*diff))
					fmt.Fprintf(stdout, "\nreports: %s %s %s %s\n", persisted.JSONPath, persisted.MDPath, diffJSONPath, diffMDPath)
				} else {
					fmt.Fprintf(stdout, "\nreports: %s %s\n", persisted.JSONPath, persisted.MDPath)
				}
			} else {
				if err := printJSON(stdout, struct {
					Analysis artifact.Analysis    `json:"analysis"`
					Diff     *artifact.DiffReport `json:"diff,omitempty"`
					JSONPath string               `json:"json_path"`
					MDPath   string               `json:"md_path"`
					DiffJSON string               `json:"diff_json_path,omitempty"`
					DiffMD   string               `json:"diff_md_path,omitempty"`
				}{Analysis: persisted.Analysis, Diff: diff, JSONPath: persisted.JSONPath, MDPath: persisted.MDPath, DiffJSON: diffJSONPath, DiffMD: diffMDPath}); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&entry, "entry", "go", "entrypoint symbol")
	cmd.Flags().StringVar(&format, "format", "json", "output format: json or md")
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "previous analysis.json to diff against")
	cmd.Flags().StringSliceVar(&suppressions, "suppress", nil, "mark finding category or category=evidence-glob as suppressed; repeatable")
	return cmd
}

func preflightCommand(stdout io.Writer) *cobra.Command {
	var selectList string
	var entry string
	var format string
	var strict bool
	var arch string
	var reportOnly bool
	cmd := &cobra.Command{
		Use:   "preflight <artifact|arsenal>",
		Short: "Predict Windows COFF loader compatibility without execution",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" && format != "md" && format != "markdown" {
				return fmt.Errorf("unknown preflight format %q", format)
			}
			persisted, err := preflightsvc.Run(preflightsvc.Options{
				Path:       args[0],
				Select:     selectList,
				Entrypoint: entry,
				Arch:       arch,
			})
			if err != nil {
				return err
			}
			switch format {
			case "text":
				fmt.Fprint(stdout, preflightsvc.Text(persisted.Report))
				fmt.Fprintf(stdout, "reports: %s %s\n", persisted.JSONPath, persisted.MDPath)
			case "json":
				if err := printJSON(stdout, struct {
					Report   preflightsvc.Report `json:"report"`
					JSONPath string              `json:"json_path"`
					MDPath   string              `json:"md_path"`
				}{Report: persisted.Report, JSONPath: persisted.JSONPath, MDPath: persisted.MDPath}); err != nil {
					return err
				}
			case "md", "markdown":
				fmt.Fprint(stdout, preflightsvc.Markdown(persisted.Report))
				fmt.Fprintf(stdout, "\nreports: %s %s\n", persisted.JSONPath, persisted.MDPath)
			}
			if !reportOnly && persisted.Report.HasProblems(strict) {
				return codedError{code: 1, err: fmt.Errorf("loader preflight gate failed with status %s", persisted.Report.Status)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&selectList, "select", "", "comma-separated arsenal selection")
	cmd.Flags().StringVar(&entry, "entry", "go", "entrypoint symbol")
	cmd.Flags().StringVar(&arch, "arch", "x64", "arsenal architecture: x64, x86, or all")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	cmd.Flags().BoolVar(&strict, "strict", false, "fail on runtime-lookup warnings as well as blockers")
	cmd.Flags().BoolVar(&reportOnly, "report-only", false, "always exit zero after writing the matrix")
	return cmd
}

func runCommand(stdout io.Writer) *cobra.Command {
	var entry string
	var timeout int
	var runtimeName string
	var argsMode bool
	cmd := &cobra.Command{
		Use:   "run <artifact> [--args z:hello i:3]",
		Short: "Run an artifact through a platform runtime",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			argTokens := args[1:]
			if !argsMode && len(argTokens) > 0 {
				return fmt.Errorf("unexpected trailing args; put BOF args after --args")
			}
			packed, items, err := argpack.PackTokens(argTokens)
			if err != nil {
				return err
			}
			runDir, err := runlog.NewDir("run-" + safeName(objectBase(args[0])))
			if err != nil {
				return err
			}
			res, err := runtimesvc.Run(runtimesvc.Request{
				Path:      args[0],
				Entry:     entry,
				ArgHex:    argpack.Hex(packed),
				Tokens:    argTokens,
				TimeoutMS: timeout,
				Runtime:   runtimeName,
			})
			res.Header = evidence.New(evidence.SchemaRun, runlog.ID(runDir), "")
			_ = os.WriteFile(filepath.Join(runDir, "result.md"), []byte(runMarkdown(res, items)), 0o644)
			_ = writeJSON(filepath.Join(runDir, "result.json"), res)
			_ = printJSON(stdout, res)
			if err != nil {
				return codedError{code: 1, err: err}
			}
			if res.Status != "pass" {
				return codedError{code: 1, err: fmt.Errorf("payload run failed: %s", res.ExitState)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&entry, "entry", "go", "entrypoint")
	cmd.Flags().IntVar(&timeout, "timeout", 5000, "timeout in milliseconds")
	cmd.Flags().StringVar(&runtimeName, "runtime", "auto", "runtime: auto, windows-coff, linux-elf, darwin-macho, wine-coff")
	cmd.Flags().BoolVar(&argsMode, "args", false, "treat remaining positional tokens as packed artifact args")
	return cmd
}

func testCommand(stdout io.Writer) *cobra.Command {
	var selectList string
	var entry string
	var argsMode bool
	var runtimeName string
	var timeout int
	var profile string
	cmd := &cobra.Command{
		Use:   "test <dir|object|arsenal> [--args ...]",
		Short: "Run arsenal or payload tests",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			argTokens := args[1:]
			if !argsMode && len(argTokens) > 0 {
				return fmt.Errorf("unexpected trailing args; put payload args after --args")
			}
			if _, _, err := argpack.PackTokens(argTokens); err != nil {
				return err
			}
			if entries, err := arsenal.List(args[0]); err == nil && len(entries) > 0 {
				return testArsenal(stdout, args[0], entries, selectList, entry, argTokens, runtimeName, timeout, profile)
			}
			cfg, cfgPath, err := config.LoadFor(args[0])
			if err != nil {
				return err
			}
			cfg, err = config.ApplyProfile(cfg, profile)
			if err != nil {
				return err
			}
			if cfg.Entrypoint != "" && entry == "go" {
				entry = cfg.Entrypoint
			}
			if len(argTokens) == 0 {
				argTokens = cfg.Args
			}
			object := args[0]
			if info, err := os.Stat(args[0]); err == nil && info.IsDir() {
				res, err := buildsys.Build(args[0], "x64")
				if err != nil {
					return err
				}
				object = res.Object
			}
			packed, items, err := argpack.PackTokens(argTokens)
			if err != nil {
				return err
			}
			effectiveTimeout := timeout
			if effectiveTimeout == 0 {
				effectiveTimeout = cfg.TimeoutMS
			}
			res, err := runtimesvc.Run(runtimesvc.Request{Path: object, Entry: entry, ArgHex: argpack.Hex(packed), Tokens: argTokens, Runtime: runtimeName, TimeoutMS: effectiveTimeout})
			if cfgPath != "" {
				if fingerprint, fingerprintErr := evidence.FingerprintFile(cfgPath); fingerprintErr == nil {
					res.ConfigFingerprint = &fingerprint
				}
			}
			expected, expectedErr := applyExpectedResult(&res, cfg)
			if expectedErr != nil {
				err = expectedErr
			}
			if err == nil || expected {
				err = applyOutputChecks(&res, cfg.Expect, cfg.Forbid)
			}
			runDir, runDirErr := runlog.NewDir("test-" + safeName(objectBase(object)))
			if runDirErr != nil {
				return runDirErr
			}
			res.Header = evidence.New(evidence.SchemaRun, runlog.ID(runDir), "")
			_ = os.WriteFile(filepath.Join(runDir, "result.md"), []byte(runMarkdown(res, items)), 0o644)
			_ = writeJSON(filepath.Join(runDir, "result.json"), res)
			_ = printJSON(stdout, res)
			if err != nil && !expected {
				return codedError{code: 1, err: err}
			}
			if res.Status != "pass" && !expected {
				return codedError{code: 1, err: fmt.Errorf("payload test failed: %s", res.ExitState)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&selectList, "select", "", "comma-separated arsenal selection")
	cmd.Flags().StringVar(&entry, "entry", "go", "entrypoint")
	cmd.Flags().StringVar(&runtimeName, "runtime", "auto", "runtime: auto, windows-coff, linux-elf, darwin-macho, wine-coff")
	cmd.Flags().IntVar(&timeout, "timeout", 0, "timeout in milliseconds; 0 uses config/default")
	cmd.Flags().BoolVar(&argsMode, "args", false, "treat remaining positional tokens as packed artifact args")
	cmd.Flags().StringVar(&profile, "profile", "", "bofbench.toml test profile to apply")
	return cmd
}

func stageCommand(stdout io.Writer) *cobra.Command {
	var target string
	var entry string
	var argsMode bool
	cmd := &cobra.Command{
		Use:   "stage <artifact> --target cobaltstrike|sliver|raw [--args ...]",
		Short: "Stage an artifact for an operator/C2 target",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("--target is required")
			}
			argTokens := args[1:]
			if !argsMode && len(argTokens) > 0 {
				return fmt.Errorf("unexpected trailing args; put staging args after --args")
			}
			_, items, err := argpack.PackTokens(argTokens)
			if err != nil {
				return err
			}
			res, err := stage.Stage(args[0], target, entry, items)
			if err != nil {
				return err
			}
			return printJSON(stdout, res)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "target: cobaltstrike, sliver, raw")
	cmd.Flags().StringVar(&entry, "entry", "go", "entrypoint")
	cmd.Flags().BoolVar(&argsMode, "args", false, "treat remaining positional tokens as packed artifact args")
	cmd.AddCommand(stageVerifyCommand(stdout))
	return cmd
}

func stageVerifyCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "verify <stage-directory-or-zip>",
		Short: "Verify a staged package and its manifest integrity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fmt.Errorf("unknown stage verification format %q", format)
			}
			report := stage.Verify(args[0])
			if format == "json" {
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			} else {
				fmt.Fprint(stdout, report.Text())
			}
			if !report.Passed() {
				return codedError{code: 1, err: fmt.Errorf("stage package verification failed")}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func doctorCommand(stdout io.Writer) *cobra.Command {
	var format string
	var strict bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local bofbench operator environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			report := doctor.Run()
			switch format {
			case "json":
				b, err := report.JSON()
				if err != nil {
					return err
				}
				_, err = stdout.Write(b)
				if err != nil {
					return err
				}
			case "text":
				fmt.Fprint(stdout, report.Text())
			default:
				return fmt.Errorf("unknown doctor format %q", format)
			}
			if report.HasProblems(strict) {
				return codedError{code: 1, err: fmt.Errorf("doctor found environment problems")}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit nonzero on warnings as well as failures")
	return cmd
}

func labCommand(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lab",
		Short: "Run and summarize local lab workflows",
	}
	cmd.AddCommand(labSmokeCommand(stdout, stderr), labSummaryCommand(stdout))
	return cmd
}

func labSmokeCommand(stdout, stderr io.Writer) *cobra.Command {
	var repoRoot string
	var selectList string
	var timeout int
	var skipFetch bool
	var script string
	var bofbenchExe string
	var printOnly bool
	cmd := &cobra.Command{
		Use:   "smoke",
		Short: "Run the Windows lab smoke workflow",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := lab.DefaultSmokeOptions(repoRoot)
			if selectList != "" {
				opts.Select = selectList
			}
			if timeout > 0 {
				opts.TimeoutMS = timeout
			}
			opts.SkipFetch = skipFetch
			if script != "" {
				opts.Script = script
			}
			if bofbenchExe != "" {
				opts.BofbenchExe = bofbenchExe
			}
			command := lab.SmokeArgs(opts)
			if printOnly {
				fmt.Fprintln(stdout, shellLine(command))
				return nil
			}
			if goruntime.GOOS != "windows" {
				fmt.Fprintln(stdout, shellLine(command))
				return codedError{code: 1, err: fmt.Errorf("lab smoke executes on Windows; run the printed command on the Windows lab host")}
			}
			if err := lab.RunSmoke(cmd.Context(), stdout, stderr, opts); err != nil {
				return codedError{code: 1, err: err}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&repoRoot, "repo-root", "", "repo root on the Windows lab host; default is current directory")
	cmd.Flags().StringVar(&selectList, "select", "whoami,ipconfig,env", "TrustedSec arsenal selection")
	cmd.Flags().IntVar(&timeout, "timeout", 5000, "TrustedSec arsenal timeout in milliseconds")
	cmd.Flags().BoolVar(&skipFetch, "skip-fetch", false, "skip fetching trustedsec-sa before smoke")
	cmd.Flags().StringVar(&script, "script", "", "path to windows-lab-smoke.ps1")
	cmd.Flags().StringVar(&bofbenchExe, "bofbench-exe", "", "temporary bofbench executable path used by the smoke script")
	cmd.Flags().BoolVar(&printOnly, "print", false, "print the PowerShell command without executing it")
	return cmd
}

func labSummaryCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "summary [lab-smoke.json]",
		Short: "Summarize the latest lab smoke report",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := ""
			if len(args) > 0 {
				path = args[0]
			}
			summary, err := lab.LoadSummary(path)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return printJSON(stdout, summary)
			case "text", "md", "markdown":
				fmt.Fprint(stdout, lab.Text(summary))
				return nil
			default:
				return fmt.Errorf("unknown lab summary format %q", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func tuiCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive operator TUI",
		RunE: func(cmd *cobra.Command, args []string) error {
			return tui.Run(stdout)
		},
	}
}

func docsCommand(stdout, stderr io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "docs serve|build",
		Short: "Serve or build MkDocs documentation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] != "serve" && args[0] != "build" {
				return fmt.Errorf("usage: bofbench docs serve|build")
			}
			cmdArgs := []string{args[0]}
			if args[0] == "serve" {
				cmdArgs = append(cmdArgs, "-a", "127.0.0.1:8000")
			}
			mkdocs := exec.Command("mkdocs", cmdArgs...)
			mkdocs.Stdout = stdout
			mkdocs.Stderr = stderr
			return mkdocs.Run()
		},
	}
	return cmd
}

func testArsenal(stdout io.Writer, root string, entries []arsenal.Entry, selectList, entry string, args []string, runtimeName string, timeout int, profile string) error {
	selected := arsenal.Select(entries, selectList)
	if len(selected) == 0 {
		return fmt.Errorf("no arsenal entries selected")
	}
	if runtimeName == "" {
		runtimeName = "auto"
	}
	runDir, err := runlog.NewDir("test-arsenal-" + safeName(filepath.Base(root)))
	if err != nil {
		return err
	}
	report := arsenalTestReport{
		Header:     evidence.New(evidence.SchemaArsenalTest, runlog.ID(runDir), ""),
		Root:       root,
		Selected:   selectList,
		Runtime:    runtimeName,
		Entrypoint: entry,
		Args:       append([]string(nil), args...),
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
		Status:     "pass",
	}
	failed := false
	for _, item := range selected {
		itemResult := arsenalTestResult{Name: item.Name, Path: item.Path, Status: "pass", Phase: "start"}
		object := item.X64
		if object == "" {
			res, err := buildsys.Build(item.Path, "x64")
			res.ParentRunID = report.RunID
			itemResult.Build = &res
			if err != nil {
				fmt.Fprintf(stdout, "%s: build fail: %v\n", item.Name, err)
				itemResult.Status = "fail"
				itemResult.Phase = "build"
				itemResult.Error = err.Error()
				report.Results = append(report.Results, itemResult)
				failed = true
				continue
			}
			object = res.Object
		}
		itemResult.Object = object
		a, err := artifact.Analyze(object, entry)
		a.Header = evidence.New(evidence.SchemaAnalysis, report.RunID+"/"+safeName(item.Name)+"/analysis", report.RunID)
		itemResult.Analysis = &a
		if err != nil {
			fmt.Fprintf(stdout, "%s: analyze fail: %v\n", item.Name, err)
			itemResult.Status = "fail"
			itemResult.Phase = "analyze"
			itemResult.Error = err.Error()
			report.Results = append(report.Results, itemResult)
			failed = true
			continue
		}
		if a.Kind == artifact.KindCOFF && a.LoaderCompatibility != nil && !a.LoaderCompatibility.Compatible {
			itemResult.Status = "fail"
			itemResult.Phase = "preflight"
			itemResult.Error = appCompatibilityMessage(*a.LoaderCompatibility)
			fmt.Fprintf(stdout, "%s: preflight fail: %s\n", item.Name, itemResult.Error)
			report.Results = append(report.Results, itemResult)
			failed = true
			continue
		}
		selectedRuntime := runtimeName
		if selectedRuntime == "" || selectedRuntime == "auto" {
			selectedRuntime = runtimesvc.SelectRuntime(a.Kind)
		}
		if runtimeName == "auto" && !canRunHost(a.Kind) {
			note := fmt.Sprintf("run requires %s", selectedRuntime)
			fmt.Fprintf(stdout, "%s: analyze pass kind=%s arch=%s relocs=%d (%s)\n", item.Name, a.Kind, a.Arch, a.Relocations, note)
			itemResult.Status = "analyze_pass"
			itemResult.Phase = "analyze"
			itemResult.Notes = append(itemResult.Notes, note)
			report.Results = append(report.Results, itemResult)
			continue
		}
		itemEntry := entry
		cfg, cfgPath, err := config.LoadFor(item.Path)
		if err != nil {
			fmt.Fprintf(stdout, "%s: config fail: %v\n", item.Name, err)
			itemResult.Status = "fail"
			itemResult.Phase = "config"
			itemResult.Error = err.Error()
			report.Results = append(report.Results, itemResult)
			failed = true
			continue
		}
		cfg, err = config.ApplyProfile(cfg, profile)
		if err != nil {
			fmt.Fprintf(stdout, "%s: profile fail: %v\n", item.Name, err)
			itemResult.Status = "fail"
			itemResult.Phase = "config"
			itemResult.Error = err.Error()
			report.Results = append(report.Results, itemResult)
			failed = true
			continue
		}
		if cfg.Entrypoint != "" && itemEntry == "go" {
			itemEntry = cfg.Entrypoint
		}
		argTokens := append([]string(nil), args...)
		if len(argTokens) == 0 {
			argTokens = cfg.Args
		}
		packed, packedItems, err := argpack.PackTokens(argTokens)
		if err != nil {
			return err
		}
		itemResult.Args = packedItems
		effectiveTimeout := timeout
		if effectiveTimeout == 0 {
			effectiveTimeout = cfg.TimeoutMS
		}
		if effectiveTimeout == 0 {
			effectiveTimeout = 5000
		}
		res, err := runtimesvc.Run(runtimesvc.Request{Path: object, Entry: itemEntry, ArgHex: argpack.Hex(packed), Tokens: argTokens, Runtime: runtimeName, TimeoutMS: effectiveTimeout})
		res.Header = evidence.New(evidence.SchemaRun, report.RunID+"/"+safeName(item.Name)+"/run", report.RunID)
		if cfgPath != "" {
			if fingerprint, fingerprintErr := evidence.FingerprintFile(cfgPath); fingerprintErr == nil {
				res.ConfigFingerprint = &fingerprint
			}
		}
		expected, expectedErr := applyExpectedResult(&res, cfg)
		if expectedErr != nil {
			err = expectedErr
		}
		if err == nil || expected {
			err = applyOutputChecks(&res, cfg.Expect, cfg.Forbid)
		}
		itemResult.Run = &res
		if (err != nil || res.Status != "pass") && !expected {
			fmt.Fprintf(stdout, "%s: run fail %s\n", item.Name, res.ExitState)
			itemResult.Status = "fail"
			itemResult.Phase = "run"
			if len(res.Errors) > 0 {
				itemResult.Error = strings.Join(res.Errors, "; ")
			} else if err != nil {
				itemResult.Error = err.Error()
			} else {
				itemResult.Error = res.ExitState
			}
			failed = true
		} else {
			if expected {
				fmt.Fprintf(stdout, "%s: run expected %s\n", item.Name, res.ExitState)
			} else {
				fmt.Fprintf(stdout, "%s: run pass\n", item.Name)
			}
			itemResult.Status = "pass"
			itemResult.Phase = "run"
		}
		report.Results = append(report.Results, itemResult)
	}
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	report.Summary = summarizeArsenalResults(report.Results)
	report.Status = arsenalReportStatus(report.Summary)
	jsonPath := filepath.Join(runDir, "result.json")
	mdPath := filepath.Join(runDir, "result.md")
	_ = writeJSON(jsonPath, report)
	_ = os.WriteFile(mdPath, []byte(arsenalTestMarkdown(report)), 0o644)
	fmt.Fprintf(stdout, "reports: %s %s\n", jsonPath, mdPath)
	if failed {
		return codedError{code: 1, err: fmt.Errorf("one or more arsenal tests failed")}
	}
	return nil
}

func appCompatibilityMessage(compatibility capability.Compatibility) string {
	issues := compatibility.Blockers
	if len(issues) == 0 {
		issues = compatibility.Warnings
	}
	if len(issues) == 0 {
		return compatibility.Status
	}
	parts := make([]string, 0, len(issues))
	for _, issue := range issues {
		value := issue.Category
		if issue.Symbol != "" {
			value += ": " + issue.Symbol
		} else if issue.Relocation != "" {
			value += ": " + issue.Relocation
		} else if issue.Diagnostic != "" {
			value += ": " + issue.Diagnostic
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, "; ")
}

func summarizeArsenalResults(results []arsenalTestResult) arsenalTestSummary {
	var summary arsenalTestSummary
	summary.Total = len(results)
	for _, result := range results {
		switch result.Status {
		case "pass":
			summary.Passed++
		case "analyze_pass":
			summary.AnalyzeOnly++
		case "fail":
			summary.Failed++
		}
	}
	return summary
}

func arsenalReportStatus(summary arsenalTestSummary) string {
	if summary.Failed > 0 {
		return "fail"
	}
	if summary.Passed > 0 && summary.AnalyzeOnly > 0 {
		return "mixed_pass"
	}
	if summary.Passed > 0 {
		return "pass"
	}
	if summary.AnalyzeOnly > 0 {
		return "analyze_pass"
	}
	return "empty"
}

func arsenalTestMarkdown(report arsenalTestReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Arsenal Test\n\n")
	fmt.Fprintf(&b, "- Schema: `%s` version `%d`\n", report.Schema, report.SchemaVersion)
	fmt.Fprintf(&b, "- Run ID: `%s`\n", report.RunID)
	fmt.Fprintf(&b, "- Root: `%s`\n", report.Root)
	fmt.Fprintf(&b, "- Selection: `%s`\n", report.Selected)
	fmt.Fprintf(&b, "- Runtime: `%s`\n", report.Runtime)
	fmt.Fprintf(&b, "- Entrypoint: `%s`\n", report.Entrypoint)
	fmt.Fprintf(&b, "- Status: `%s`\n", report.Status)
	fmt.Fprintf(&b, "- Summary: `%d pass`, `%d analyze-only`, `%d fail`, `%d total`\n", report.Summary.Passed, report.Summary.AnalyzeOnly, report.Summary.Failed, report.Summary.Total)
	fmt.Fprintf(&b, "- Started: `%s`\n", report.StartedAt)
	fmt.Fprintf(&b, "- Completed: `%s`\n\n", report.CompletedAt)
	b.WriteString("| Name | Status | Phase | Kind | Arch | Relocs | Exit | Detail |\n")
	b.WriteString("| --- | --- | --- | --- | --- | ---: | --- | --- |\n")
	for _, result := range report.Results {
		kind := ""
		arch := ""
		relocs := 0
		if result.Analysis != nil {
			kind = string(result.Analysis.Kind)
			arch = result.Analysis.Arch
			relocs = result.Analysis.Relocations
		}
		exit := ""
		if result.Run != nil {
			exit = result.Run.ExitState
		}
		detail := result.Error
		if detail == "" && len(result.Notes) > 0 {
			detail = strings.Join(result.Notes, "; ")
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%s` | %d | `%s` | %s |\n",
			result.Name, result.Status, result.Phase, kind, arch, relocs, exit, escapeMarkdownTable(detail))
	}
	return b.String()
}

func escapeMarkdownTable(s string) string {
	s = strings.ReplaceAll(s, "\n", "<br>")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func applyOutputChecks(res *runtimesvc.Result, expect, forbid []string) error {
	if res.Status != "pass" || len(expect)+len(forbid) == 0 {
		return nil
	}
	output := strings.Join(res.Output, "\n")
	var problems []string
	for _, needle := range expect {
		if strings.TrimSpace(needle) == "" {
			continue
		}
		if !strings.Contains(output, needle) {
			problems = append(problems, fmt.Sprintf("missing expected output %q", needle))
		}
	}
	for _, needle := range forbid {
		if strings.TrimSpace(needle) == "" {
			continue
		}
		if strings.Contains(output, needle) {
			problems = append(problems, fmt.Sprintf("forbidden output appeared %q", needle))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	res.Status = "fail"
	res.ExitState = "output_contract_failed"
	res.Errors = append(res.Errors, problems...)
	for _, problem := range problems {
		runtimesvc.AddEvent(res, "api_event", "fail", problem)
	}
	runtimesvc.AddEvent(res, "exit", "fail", "exit_state=output_contract_failed")
	return errors.New(strings.Join(problems, "; "))
}

func applyExpectedResult(res *runtimesvc.Result, cfg config.Project) (bool, error) {
	expected := false
	var problems []string
	if cfg.ExpectedExit != "" {
		expected = true
		if res.ExitState != cfg.ExpectedExit {
			problems = append(problems, fmt.Sprintf("expected exit %q, got %q", cfg.ExpectedExit, res.ExitState))
		}
	}
	if cfg.ExpectedStatus != "" {
		expected = true
		if res.Status != cfg.ExpectedStatus {
			problems = append(problems, fmt.Sprintf("expected status %q, got %q", cfg.ExpectedStatus, res.Status))
		}
	}
	if len(problems) == 0 {
		return expected, nil
	}
	res.Status = "fail"
	res.ExitState = "output_contract_failed"
	res.Errors = append(res.Errors, problems...)
	for _, problem := range problems {
		runtimesvc.AddEvent(res, "api_event", "fail", problem)
	}
	runtimesvc.AddEvent(res, "exit", "fail", "exit_state=output_contract_failed")
	return false, errors.New(strings.Join(problems, "; "))
}

func canRunHost(kind artifact.Kind) bool {
	switch kind {
	case artifact.KindCOFF:
		return goruntime.GOOS == "windows"
	case artifact.KindELF:
		return goruntime.GOOS == "linux"
	case artifact.KindMachO:
		return goruntime.GOOS == "darwin"
	default:
		return false
	}
}

func printAnalysis(w io.Writer, a artifact.Analysis) {
	fmt.Fprintf(w, "object: %s\n", a.Path)
	fmt.Fprintf(w, "kind: %s\n", a.Kind)
	fmt.Fprintf(w, "arch: %s\n", a.Arch)
	if a.Toolchain.Family != "" {
		fmt.Fprintf(w, "toolchain: %s confidence=%s compiler=%s\n", a.Toolchain.Family, a.Toolchain.Confidence, a.Toolchain.Compiler)
	}
	fmt.Fprintf(w, "size: %d\n", a.Size)
	if a.SHA256 != "" {
		fmt.Fprintf(w, "sha256: %s\n", a.SHA256)
	}
	fmt.Fprintf(w, "entry %q: %s\n", a.Entrypoint, yesNo(a.EntrypointOK))
	if a.EntrypointSymbol != "" {
		fmt.Fprintf(w, "  symbol=%s section=%s offset=0x%x\n", a.EntrypointSymbol, a.EntrypointSection, a.EntrypointOffset)
	}
	if a.Runtime.Runtime != "" {
		fmt.Fprintf(w, "runtime compatibility:\n")
		fmt.Fprintf(w, "  runtime=%s status=%s can_run=%s host=%s/%s required=%s/%s\n",
			a.Runtime.Runtime,
			a.Runtime.Status,
			yesNo(a.Runtime.CanRun),
			a.Runtime.HostOS,
			a.Runtime.HostArch,
			a.Runtime.RequiredOS,
			a.Runtime.RequiredArch,
		)
		if a.Runtime.RunCommand != "" {
			fmt.Fprintf(w, "  run: %s\n", a.Runtime.RunCommand)
		}
		if a.Runtime.Note != "" {
			fmt.Fprintf(w, "  note: %s\n", a.Runtime.Note)
		}
	}
	if a.LoaderCompatibility != nil {
		compatibility := a.LoaderCompatibility
		fmt.Fprintf(w, "loader preflight:\n")
		fmt.Fprintf(w, "  catalog=%s status=%s compatible=%s blockers=%d warnings=%d\n", compatibility.CatalogVersion, compatibility.Status, yesNo(compatibility.Compatible), len(compatibility.Blockers), len(compatibility.Warnings))
		for _, issue := range compatibility.Blockers {
			fmt.Fprintf(w, "  blocker %-28s %s", issue.Category, issue.Detail)
			if issue.Symbol != "" {
				fmt.Fprintf(w, " (%s)", issue.Symbol)
			}
			fmt.Fprintln(w)
		}
		for _, issue := range compatibility.Warnings {
			fmt.Fprintf(w, "  warning %-28s %s", issue.Category, issue.Detail)
			if issue.Symbol != "" {
				fmt.Fprintf(w, " (%s)", issue.Symbol)
			}
			fmt.Fprintln(w)
		}
	}
	if len(a.COFFDiagnostics) > 0 {
		fmt.Fprintf(w, "COFF diagnostics:\n")
		for _, diagnostic := range a.COFFDiagnostics {
			location := diagnostic.Section
			if diagnostic.Symbol != "" {
				if location != "" {
					location += "/"
				}
				location += diagnostic.Symbol
			}
			fmt.Fprintf(w, "  %-7s %-30s %s", diagnostic.Severity, diagnostic.Code, diagnostic.Detail)
			if location != "" {
				fmt.Fprintf(w, " (%s)", location)
			}
			fmt.Fprintln(w)
		}
	}
	if len(a.Findings) > 0 {
		fmt.Fprintf(w, "findings: active=%d suppressed=%d total=%d\n", a.FindingSummary.Active, a.FindingSummary.Suppressed, a.FindingSummary.Total)
		for _, finding := range a.Findings {
			state := "active"
			if finding.Suppressed {
				state = "suppressed"
			}
			fmt.Fprintf(w, "  %-10s %-7s %-18s %s", state, finding.Severity, finding.Category, finding.Detail)
			if finding.Evidence != "" {
				fmt.Fprintf(w, " (%s)", finding.Evidence)
			}
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintf(w, "sections:\n")
	for _, section := range a.Sections {
		storage := "file"
		if section.Uninitialized {
			storage = "zero-fill"
		}
		fmt.Fprintf(w, "  %-18s size=%-8d relocs=%-4d align=%-5d storage=%-9s flags=%s\n", section.Name, section.Size, section.Relocations, section.Alignment, storage, section.Flags)
	}
	if len(a.Imports) > 0 {
		fmt.Fprintf(w, "imports:\n")
		for _, imp := range a.Imports {
			target := imp.Symbol
			if imp.Library != "" || imp.API != "" {
				target = strings.TrimSpace(imp.Library + " " + imp.API)
			}
			fmt.Fprintf(w, "  %-18s %s\n", imp.Category, target)
		}
	}
	if len(a.Unresolved) > 0 {
		fmt.Fprintf(w, "unresolved externals:\n")
		for _, sym := range a.Unresolved {
			fmt.Fprintf(w, "  %s\n", sym)
		}
	}
	if len(a.RelocationDetails) > 0 {
		fmt.Fprintf(w, "relocations:\n")
		limit := min(len(a.RelocationDetails), 12)
		for i := 0; i < limit; i++ {
			rel := a.RelocationDetails[i]
			fmt.Fprintf(w, "  %-18s off=0x%-6x type=%-12s symbol=%s\n", rel.Section, rel.Offset, rel.Type, rel.Symbol)
		}
		if len(a.RelocationDetails) > limit {
			fmt.Fprintf(w, "  ... %d more relocations in analysis report\n", len(a.RelocationDetails)-limit)
		}
	}
	if len(a.Strings) > 0 {
		fmt.Fprintf(w, "visible strings:\n")
		limit := min(len(a.Strings), 12)
		for i := 0; i < limit; i++ {
			s := a.Strings[i]
			fmt.Fprintf(w, "  %-12s %s\n", s.Category, s.Value)
		}
		if len(a.Strings) > limit {
			fmt.Fprintf(w, "  ... %d more strings in analysis report\n", len(a.Strings)-limit)
		}
	}
	if len(a.Warnings) > 0 {
		fmt.Fprintf(w, "warnings:\n")
		for _, warning := range a.Warnings {
			fmt.Fprintf(w, "  %s\n", warning)
		}
	}
}

func runMarkdown(res runtimesvc.Result, items []argpack.Item) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Artifact Run\n\n")
	fmt.Fprintf(&b, "- Schema: `%s` version `%d`\n", res.Schema, res.SchemaVersion)
	if res.RunID != "" {
		fmt.Fprintf(&b, "- Run ID: `%s`\n", res.RunID)
	}
	if res.ParentRunID != "" {
		fmt.Fprintf(&b, "- Parent Run ID: `%s`\n", res.ParentRunID)
	}
	fmt.Fprintf(&b, "- Object: `%s`\n", res.Object)
	fmt.Fprintf(&b, "- Kind: `%s`\n", res.Kind)
	fmt.Fprintf(&b, "- Runtime: `%s`\n", res.Runtime)
	fmt.Fprintf(&b, "- Entry: `%s`\n", res.Entry)
	fmt.Fprintf(&b, "- Status: `%s`\n", res.Status)
	fmt.Fprintf(&b, "- Exit: `%s`\n", res.ExitState)
	fmt.Fprintf(&b, "- Args: `%v`\n", items)
	fmt.Fprintf(&b, "- Duration: `%dms`\n", res.DurationMS)
	if res.Loader != "" {
		fmt.Fprintf(&b, "- Loader: `%s`\n", res.Loader)
	}
	if res.ObjectFingerprint != nil {
		fmt.Fprintf(&b, "- Object SHA-256: `%s`\n", res.ObjectFingerprint.SHA256)
	}
	if res.LoaderFingerprint != nil {
		fmt.Fprintf(&b, "- Loader SHA-256: `%s`\n", res.LoaderFingerprint.SHA256)
	}
	if len(res.Events) > 0 {
		b.WriteString("\n## Events\n\n| Time | Type | Status | Message |\n| ---: | --- | --- | --- |\n")
		for _, event := range res.Events {
			fmt.Fprintf(&b, "| `%dms` | `%s` | `%s` | %s |\n", event.TimeMS, event.Type, event.Status, escapeMarkdownTable(event.Message))
		}
	}
	fmt.Fprintf(&b, "\n## Output\n\n%s\n\n## Errors\n\n%s\n", strings.Join(res.Output, "\n"), strings.Join(res.Errors, "\n"))
	return b.String()
}

func printJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func safeName(s string) string {
	s = strings.ToLower(filepath.Base(s))
	s = strings.TrimSuffix(s, filepath.Ext(s))
	return strings.NewReplacer(" ", "-", "_", "-", ".", "-").Replace(s)
}

func objectBase(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	return base
}

func shellLine(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if strings.ContainsAny(arg, " \t\n\r\"'`$&|;<>()[]{}*?!") {
		return "'" + strings.ReplaceAll(arg, "'", "''") + "'"
	}
	return arg
}

type payloadTemplate struct {
	Source string
	Header string
	Config string
	Readme string
}

func templateFor(templateName, name string) (payloadTemplate, error) {
	if templateName == "" {
		templateName = "args"
	}
	switch templateName {
	case "args", "arg_echo":
		return payloadTemplate{
			Source: templateArgsC(name),
			Header: templateBeaconHeader(),
			Config: fmt.Sprintf(`name = "%s"
entry = "go"
args = ["z:hello-from-%s", "i:3"]
expect = ["%s: hello-from-%s count=3"]
timeout_ms = 5000

[profile.alt]
args = ["z:profile-message", "i:9"]
expect = ["%s: profile-message count=9"]
forbid = ["panic"]
`, name, name, name, name, name),
			Readme: templateReadme(name, "args", "bofbench test bofs/"+name+" --profile alt"),
		}, nil
	case "hello", "noargs", "no-arg":
		return payloadTemplate{
			Source: templateHelloC(name),
			Header: templateBeaconHeader(),
			Config: fmt.Sprintf(`name = "%s"
entry = "go"
args = []
expect = ["hello from %s"]
timeout_ms = 5000
`, name, name),
			Readme: templateReadme(name, "hello", "bofbench test bofs/"+name),
		}, nil
	case "winapi":
		return payloadTemplate{
			Source: templateWinAPIC(name),
			Header: templateBeaconHeader(),
			Config: fmt.Sprintf(`name = "%s"
entry = "go"
args = []
expect = ["%s pid="]
timeout_ms = 5000
`, name, name),
			Readme: templateReadme(name, "winapi", "bofbench inspect dist/"+name+".x64.o"),
		}, nil
	case "unresolved", "missing-import":
		return payloadTemplate{
			Source: templateUnresolvedC(),
			Header: templateUnresolvedHeader(),
			Config: fmt.Sprintf(`name = "%s"
entry = "go"
args = []
expect_exit = "relocation_error"
timeout_ms = 5000
operator_notes = ["negative fixture: expected to fail before entrypoint because MissingExternal is unresolved"]
`, name),
			Readme: templateReadme(name, "unresolved", "bofbench test bofs/"+name+" --runtime windows-coff"),
		}, nil
	case "timeout":
		return payloadTemplate{
			Source: templateTimeoutC(),
			Header: templateBeaconHeader(),
			Config: fmt.Sprintf(`name = "%s"
entry = "go"
args = []
expect_exit = "timeout"
timeout_ms = 250
operator_notes = ["negative fixture: expected to time out in the local lab runner"]
`, name),
			Readme: templateReadme(name, "timeout", "bofbench test bofs/"+name+" --runtime windows-coff"),
		}, nil
	default:
		return payloadTemplate{}, fmt.Errorf("unknown template %q; choose args, hello, winapi, unresolved, or timeout", templateName)
	}
}

func templateReadme(name, templateName, extra string) string {
	return fmt.Sprintf("# %s\n\nTemplate: `%s`\n\n```sh\nbofbench build bofs/%s\nbofbench inspect dist/%s.x64.o\nbofbench test bofs/%s\n%s\nbofbench stage dist/%s.x64.o --target raw\n```\n", name, templateName, name, name, name, extra, name)
}

func templateArgsC(name string) string {
	return fmt.Sprintf(`#include "beacon.h"

void go(char *args, int len) {
    datap parser;
    char *message;
    int message_len = 0;
    int count = 0;

    BeaconDataParse(&parser, args, len);
    message = BeaconDataExtract(&parser, &message_len);
    count = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "%s: %%.*s count=%%d", message_len, message, count);
}
`, name)
}

func templateHelloC(name string) string {
	return fmt.Sprintf(`#include "beacon.h"

void go(char *args, int len) {
    (void)args;
    (void)len;
    BeaconPrintf(CALLBACK_OUTPUT, "hello from %s");
}
`, name)
}

func templateWinAPIC(name string) string {
	return fmt.Sprintf(`#include <windows.h>
#include "beacon.h"

void go(char *args, int len) {
    (void)args;
    (void)len;
    BeaconPrintf(CALLBACK_OUTPUT, "%s pid=%%lu", GetCurrentProcessId());
}
`, name)
}

func templateUnresolvedC() string {
	return `#include "beacon.h"

void go(char *args, int len) {
    (void)args;
    (void)len;
    MissingExternal();
}
`
}

func templateTimeoutC() string {
	return `#include "beacon.h"

void go(char *args, int len) {
    volatile unsigned long long spin = (unsigned long long)len;
    (void)args;
    for (;;) {
        spin++;
    }
}
`
}

func templateUnresolvedHeader() string {
	return `#pragma once
void MissingExternal(void);
`
}

func templateBeaconHeader() string {
	return `#pragma once
#define CALLBACK_OUTPUT 0
typedef struct {
    char *buffer;
    int length;
    int offset;
} datap;
void BeaconDataParse(datap *parser, char *buffer, int size);
int BeaconDataInt(datap *parser);
short BeaconDataShort(datap *parser);
int BeaconDataLength(datap *parser);
char *BeaconDataExtract(datap *parser, int *size);
void BeaconPrintf(int type, const char *fmt, ...);
void BeaconOutput(int type, char *data, int len);
`
}
