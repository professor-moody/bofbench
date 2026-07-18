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
	"sort"
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
	matrixsvc "bofbench/internal/matrix"
	packsvc "bofbench/internal/pack"
	preflightsvc "bofbench/internal/preflight"
	"bofbench/internal/recipe"
	"bofbench/internal/runlog"
	runtimesvc "bofbench/internal/runtime"
	"bofbench/internal/runtimeadapter"
	"bofbench/internal/scaffold"
	"bofbench/internal/sourceaudit"
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
		Short:         "Build, analyze, run, and deliver BOFs",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddGroup(
		&cobra.Group{ID: "create", Title: "Create and develop:"},
		&cobra.Group{ID: "analyze", Title: "Analyze and check:"},
		&cobra.Group{ID: "operate", Title: "Run and deliver:"},
		&cobra.Group{ID: "arsenal", Title: "External BOFs:"},
		&cobra.Group{ID: "interface", Title: "Interface and help:"},
		&cobra.Group{ID: "system", Title: "System:"},
	)
	cmd.AddCommand(
		commandGroup("create", newCommand(stdout)),
		commandGroup("create", catalogCommand(stdout)),
		commandGroup("create", packCommand(stdout)),
		commandGroup("create", addCommand(stdout)),
		commandGroup("create", featureCommand(stdout)),
		commandGroup("create", recipeCommand(stdout)),
		commandGroup("create", devCommand(stdout)),
		commandGroup("create", buildCommand(stdout)),
		commandGroup("create", matrixCommand(stdout)),
		commandGroup("analyze", inspectCommand(stdout)),
		commandGroup("analyze", analyzeCommand(stdout)),
		commandGroup("analyze", preflightCommand(stdout)),
		commandGroup("operate", runCommand(stdout)),
		commandGroup("operate", operationCommand(stdout)),
		commandGroup("operate", testCommand(stdout)),
		commandGroup("operate", exportCommand(stdout)),
		commandGroup("operate", sliverCommand(stdout)),
		commandGroup("operate", runtimeCommand(stdout)),
		commandGroup("operate", labCommand(stdout, stderr)),
		commandGroup("arsenal", fetchCommand(stdout)),
		commandGroup("arsenal", listCommand(stdout)),
		commandGroup("arsenal", arsenalCommand(stdout)),
		commandGroup("interface", tuiCommand(stdout)),
		commandGroup("interface", docsCommand(stdout, stderr)),
		commandGroup("system", doctorCommand(stdout)),
		commandGroup("system", versionCommand(stdout)),
	)
	return cmd
}

func commandGroup(group string, cmd *cobra.Command) *cobra.Command {
	cmd.GroupID = group
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
				fmt.Fprintf(stdout, "BOFBENCH %s\n", header.Tool.Version)
				fmt.Fprintf(stdout, "build -> analyze -> run -> hand off\n")
				fmt.Fprintf(stdout, "commit=%s  host=%s/%s\n", header.Tool.Commit, header.Host.OS, header.Host.Arch)
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
	var featureNames []string
	var packNames []string
	var catalogPaths []string
	var recipeName string
	var force bool
	cmd := &cobra.Command{
		Use:   "new <name>",
		Short: "Create a BOF payload workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := safeName(args[0])
			if recipeName != "" {
				if _, ok := recipe.Builtin(recipeName); !ok {
					return fmt.Errorf("unknown recipe %q; use 'bofbench recipe list'", recipeName)
				}
			}
			if recipeName != "" || len(packNames) > 0 {
				if !cmd.Flags().Changed("template") {
					templateName = "hello"
				}
			}
			tpl, err := templateFor(templateName, name)
			if err != nil {
				return err
			}
			root := filepath.Join("bofs", name)
			if _, err := os.Stat(root); err == nil && !force {
				return fmt.Errorf("BOF workspace %s already exists; use --force to replace generated files", root)
			} else if err != nil && !os.IsNotExist(err) {
				return err
			}
			if err := os.MkdirAll(root, 0o755); err != nil {
				return err
			}
			if force {
				if err := os.Remove(filepath.Join(root, "bofbench_features.h")); err != nil && !os.IsNotExist(err) {
					return err
				}
				if err := os.Remove(filepath.Join(root, recipe.SidecarName)); err != nil && !os.IsNotExist(err) {
					return err
				}
				if err := os.Remove(filepath.Join(root, packsvc.LockName)); err != nil && !os.IsNotExist(err) {
					return err
				}
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
			if len(featureNames) > 0 {
				result, err := scaffold.AddFeatures(root, featureNames)
				if err != nil {
					return err
				}
				fmt.Fprintf(stdout, "added features: %s\n", strings.Join(result.Added, ", "))
			}
			if recipeName != "" {
				result, err := recipe.Apply(root, recipeName, false)
				if err != nil {
					return err
				}
				fmt.Fprintf(stdout, "applied recipe: %s (%s)\n", result.Recipe.Name, result.Recipe.Title)
			}
			if len(packNames) > 0 {
				registry, err := packsvc.Load(packsvc.LoadOptions{Project: root, ExtraCatalogs: catalogPaths})
				if err != nil {
					return err
				}
				result, err := registry.Apply(root, packNames)
				if err != nil {
					return err
				}
				fmt.Fprintf(stdout, "added packs: %s\n", strings.Join(result.Added, ", "))
			}
			fmt.Fprintf(stdout, "created BOF payload workspace %s\n", root)
			fmt.Fprintf(stdout, "next: bofbench build %s\n", root)
			fmt.Fprintf(stdout, "then: bofbench analyze %s\n", root)
			fmt.Fprintf(stdout, "compat: bofbench dev %s\n", root)
			return nil
		},
	}
	cmd.Flags().StringVar(&templateName, "template", "args", "template: args, hello, winapi, unresolved, timeout")
	cmd.Flags().StringSliceVar(&featureNames, "feature", nil, "add a composable BOF feature; repeatable")
	cmd.Flags().StringSliceVar(&packNames, "pack", nil, "add a capability pack; repeatable or comma-separated")
	cmd.Flags().StringSliceVar(&catalogPaths, "catalog", nil, "additional pack catalog path; repeatable")
	cmd.Flags().StringVar(&recipeName, "recipe", "", "compose a built-in operational recipe")
	cmd.Flags().BoolVar(&force, "force", false, "replace generated files in an existing BOF workspace")
	return cmd
}

func featureCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "feature",
		Short: "List or add BOF capability modules",
	}
	packCommand := &cobra.Command{
		Use:   "pack",
		Short: "List or add curated feature packs",
	}
	packCommand.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List curated BOF feature packs",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				for _, pack := range scaffold.FeaturePacks() {
					fmt.Fprintf(stdout, "%-18s effects=%-14s features=%-2d %s\n", pack.Name, pack.Impact, len(pack.Features), pack.Description)
					fmt.Fprintf(stdout, "  %s\n", strings.Join(pack.Features, ","))
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "add <project|source.c> <pack>",
			Short: "Add every capability in a curated feature pack",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				result, err := scaffold.AddFeaturePack(args[0], args[1])
				if err != nil {
					return err
				}
				return printJSON(stdout, result)
			},
		},
	)
	cmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List reusable capability modules for BOF projects",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				printFeatureList(stdout, scaffold.Features())
				return nil
			},
		},
		&cobra.Command{
			Use:   "add <project|source.c> <feature> [feature...]",
			Short: "Add loader-compatible feature code to a BOF workspace",
			Args:  cobra.MinimumNArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				result, err := scaffold.AddFeatures(args[0], args[1:])
				if err != nil {
					return err
				}
				return printJSON(stdout, result)
			},
		},
		packCommand,
	)
	return cmd
}

func printFeatureList(stdout io.Writer, features []scaffold.Feature) {
	discovery := make([]scaffold.Feature, 0, len(features))
	actions := make([]scaffold.Feature, 0, len(features))
	cleanup := make([]scaffold.Feature, 0, 1)
	for _, feature := range features {
		switch {
		case feature.Name == "lab-cleanup":
			cleanup = append(cleanup, feature)
		case strings.HasPrefix(feature.Name, "lab-"):
			actions = append(actions, feature)
		default:
			discovery = append(discovery, feature)
		}
	}

	fmt.Fprintln(stdout, "BOF CAPABILITY MODULES")
	fmt.Fprintln(stdout, "Reusable source modules injected into a BOF project.")
	fmt.Fprintln(stdout, "add: bofbench feature add bofs/<project> <capability...>")
	printFeatureGroup(stdout, "READ-ONLY DISCOVERY", discovery)
	printFeatureGroup(stdout, "STATE-CHANGING LAB ACTIONS", actions)
	printFeatureGroup(stdout, "CLEANUP", cleanup)
}

func printFeatureGroup(stdout io.Writer, title string, features []scaffold.Feature) {
	if len(features) == 0 {
		return
	}
	fmt.Fprintf(stdout, "\n%s\n", title)
	for _, feature := range features {
		fmt.Fprintf(stdout, "  %-20s %s\n", feature.Name, feature.Description)
	}
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
	var format string
	cmd := &cobra.Command{
		Use:   "build <dir|file>",
		Short: "Build or copy a payload artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fmt.Errorf("unknown build format %q", format)
			}
			res, err := buildsys.BuildWithOptions(args[0], buildsys.Options{
				Arch:               arch,
				Compiler:           compiler,
				VerifyReproducible: verifyReproducible,
			})
			if res.RunID != "" {
				if format == "json" {
					if printErr := printJSON(stdout, res); printErr != nil {
						return printErr
					}
				} else {
					printBuildSummary(stdout, res)
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
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func printBuildSummary(stdout io.Writer, result buildsys.Result) {
	status := strings.ToUpper(result.Status)
	if status == "" {
		status = "ERROR"
	}
	fmt.Fprintf(stdout, "BOF BUILD %s\n", status)
	fmt.Fprintf(stdout, "object    %s (%s)\n", result.Object, result.Arch)
	if result.Compiler.Profile != "" {
		fmt.Fprintf(stdout, "compiler  %s", result.Compiler.Profile)
		if result.Compiler.Version != "" {
			fmt.Fprintf(stdout, "  %s", result.Compiler.Version)
		}
		fmt.Fprintln(stdout)
	}
	if result.ObjectFingerprint != nil {
		fmt.Fprintf(stdout, "file      %d bytes  sha256=%s\n", result.ObjectFingerprint.Size, shortHash(result.ObjectFingerprint.SHA256))
	}
	if result.Reproducibility != nil && result.Reproducibility.Checked {
		fmt.Fprintf(stdout, "rebuild   match=%t\n", result.Reproducibility.Reproducible)
	}
	for _, diagnostic := range result.Diagnostics {
		if diagnostic.Severity == "error" || diagnostic.Severity == "warning" {
			fmt.Fprintf(stdout, "%-8s %s: %s\n", diagnostic.Severity, diagnostic.Code, diagnostic.Message)
		}
	}
	if result.Error != "" {
		fmt.Fprintf(stdout, "error     %s\n", result.Error)
	}
	fmt.Fprintf(stdout, "reports   %s%c\n", filepath.Dir(result.EvidencePath), os.PathSeparator)
}

func matrixCommand(stdout io.Writer) *cobra.Command {
	var compilers []string
	var optimizations []string
	var architecture string
	var execution string
	var runtimeName string
	var profile string
	var format string
	var verifyReproducible bool
	cmd := &cobra.Command{
		Use:   "matrix <dir|source.c>",
		Short: "Exercise compiler, optimization, architecture, and runtime combinations",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "summary" && format != "text" && format != "json" && format != "md" && format != "markdown" {
				return fmt.Errorf("unknown matrix format %q", format)
			}
			persisted, matrixErr := matrixsvc.Run(matrixsvc.Options{
				Path:               args[0],
				Compilers:          compilers,
				Optimizations:      optimizations,
				Architecture:       architecture,
				Execution:          execution,
				Runtime:            runtimeName,
				Profile:            profile,
				VerifyReproducible: verifyReproducible,
			})
			if persisted.Report.RunID != "" {
				switch format {
				case "summary", "text":
					fmt.Fprint(stdout, matrixsvc.Text(persisted.Report))
					fmt.Fprintf(stdout, "reports: %s %s\n", persisted.JSONPath, persisted.MDPath)
				case "md", "markdown":
					fmt.Fprint(stdout, matrixsvc.Markdown(persisted.Report))
					fmt.Fprintf(stdout, "\nreports: %s %s\n", persisted.JSONPath, persisted.MDPath)
				case "json":
					if err := printJSON(stdout, struct {
						Report   matrixsvc.Report `json:"report"`
						JSONPath string           `json:"json_path"`
						MDPath   string           `json:"md_path"`
					}{Report: persisted.Report, JSONPath: persisted.JSONPath, MDPath: persisted.MDPath}); err != nil {
						return err
					}
				}
			}
			if matrixErr != nil {
				return codedError{code: 1, err: matrixErr}
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&compilers, "compiler", []string{"mingw", "msvc"}, "compiler profiles: mingw, msvc; repeatable")
	cmd.Flags().StringSliceVar(&optimizations, "optimization", []string{"debug", "size", "speed"}, "optimization modes: debug, size, speed; repeatable")
	cmd.Flags().StringVar(&architecture, "arch", "all", "architecture: x64, x86, or all")
	cmd.Flags().StringVar(&execution, "execute", "auto", "runtime execution: auto, always, or never")
	cmd.Flags().StringVar(&runtimeName, "runtime", "windows-coff", "runtime for executable x64 cells")
	cmd.Flags().StringVar(&profile, "profile", "", "bofbench.toml test profile for runtime arguments and contracts")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	cmd.Flags().BoolVar(&verifyReproducible, "verify-reproducible", true, "build every available cell twice and require identical bytes")
	cmd.AddCommand(matrixReplayCommand(stdout))
	return cmd
}

func matrixReplayCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "replay <matrix.json>",
		Short: "Replay preserved x64 matrix artifacts through the Windows runtime",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "summary" && format != "text" && format != "json" && format != "md" && format != "markdown" {
				return fmt.Errorf("unknown matrix replay format %q", format)
			}
			persisted, replayErr := matrixsvc.Replay(args[0])
			if persisted.Report.RunID != "" {
				switch format {
				case "summary", "text":
					fmt.Fprint(stdout, matrixsvc.Text(persisted.Report))
					fmt.Fprintf(stdout, "reports: %s %s\n", persisted.JSONPath, persisted.MDPath)
				case "md", "markdown":
					fmt.Fprint(stdout, matrixsvc.Markdown(persisted.Report))
					fmt.Fprintf(stdout, "\nreports: %s %s\n", persisted.JSONPath, persisted.MDPath)
				case "json":
					if err := printJSON(stdout, struct {
						Report   matrixsvc.Report `json:"report"`
						JSONPath string           `json:"json_path"`
						MDPath   string           `json:"md_path"`
					}{Report: persisted.Report, JSONPath: persisted.JSONPath, MDPath: persisted.MDPath}); err != nil {
						return err
					}
				}
			}
			if replayErr != nil {
				return codedError{code: 1, err: replayErr}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
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
			if err := applyConfiguredSignatures(&a, args[0]); err != nil {
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
	var comparePath string
	var suppressions []string
	var compiler string
	var explain string
	cmd := &cobra.Command{
		Use:   "analyze <project|source.c|artifact>",
		Short: "Analyze BOF source or a compiled artifact and write reports",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "summary" && format != "text" && format != "json" && format != "md" && format != "markdown" {
				return fmt.Errorf("unknown analysis format %q", format)
			}
			if baselinePath != "" && comparePath != "" {
				return fmt.Errorf("use either --baseline or --compare, not both")
			}
			if explain != "" && (baselinePath != "" || comparePath != "") {
				return fmt.Errorf("--explain cannot be combined with --baseline or --compare")
			}
			analysisInput := args[0]
			projectInput := ""
			if info, statErr := os.Stat(args[0]); statErr == nil && info.IsDir() {
				if baselinePath != "" || comparePath != "" {
					return fmt.Errorf("--baseline and --compare require compiled objects; build the project and pass its object")
				}
				cfg, _, err := config.LoadFor(args[0])
				if err != nil {
					return err
				}
				effectiveEntry := entry
				if effectiveEntry == "go" && cfg.Entrypoint != "" {
					effectiveEntry = cfg.Entrypoint
				}
				sourceResult, sourceErr := sourceaudit.AnalyzeAndPersist(args[0], sourceaudit.Options{Entrypoint: effectiveEntry})
				if sourceErr != nil || sourceResult.Report.Status == "fail" {
					switch format {
					case "json":
						if err := printJSON(stdout, sourceResult); err != nil {
							return err
						}
					case "md", "markdown":
						fmt.Fprint(stdout, sourceaudit.Markdown(sourceResult.Report))
					default:
						fmt.Fprint(stdout, sourceaudit.Text(sourceResult.Report))
						fmt.Fprintf(stdout, "reports: %s %s\n", sourceResult.JSONPath, sourceResult.MDPath)
					}
					if sourceErr != nil {
						return sourceErr
					}
					return codedError{code: 1, err: fmt.Errorf("BOF source analysis failed with %d error finding(s)", sourceResult.Report.Summary.Errors)}
				}
				build, err := buildsys.BuildWithOptions(args[0], buildsys.Options{Arch: "x64", Compiler: compiler})
				if err != nil {
					return codedError{code: 1, err: err}
				}
				analysisInput = build.Object
				projectInput = args[0]
				entry = effectiveEntry
			}
			if sourceaudit.IsSourceInput(analysisInput) {
				if baselinePath != "" || comparePath != "" {
					return fmt.Errorf("--baseline and --compare require compiled objects; build the project and pass its object")
				}
				if len(suppressions) > 0 {
					return fmt.Errorf("--suppress applies to compiled artifact findings")
				}
				cfg, _, err := config.LoadFor(args[0])
				if err != nil {
					return err
				}
				effectiveEntry := entry
				if effectiveEntry == "go" && cfg.Entrypoint != "" {
					effectiveEntry = cfg.Entrypoint
				}
				persisted, err := sourceaudit.AnalyzeAndPersist(args[0], sourceaudit.Options{Entrypoint: effectiveEntry})
				if err != nil {
					return err
				}
				switch format {
				case "summary", "text":
					fmt.Fprint(stdout, sourceaudit.Text(persisted.Report))
					fmt.Fprintf(stdout, "reports: %s %s\n", persisted.JSONPath, persisted.MDPath)
				case "md", "markdown":
					fmt.Fprint(stdout, sourceaudit.Markdown(persisted.Report))
					fmt.Fprintf(stdout, "\nreports: %s %s\n", persisted.JSONPath, persisted.MDPath)
				case "json":
					if err := printJSON(stdout, persisted); err != nil {
						return err
					}
				}
				if persisted.Report.Status == "fail" {
					return codedError{code: 1, err: fmt.Errorf("BOF source analysis failed with %d error finding(s)", persisted.Report.Summary.Errors)}
				}
				return nil
			}
			persisted, err := artifact.AnalyzeAndPersistWithOptions(analysisInput, artifact.AnalysisOptions{Entrypoint: entry, Suppressions: suppressions})
			if err != nil {
				return err
			}
			if projectInput != "" {
				if err := applyProjectPackMetadata(&persisted.Analysis, projectInput); err != nil {
					return err
				}
			} else if err := applyConfiguredSignatures(&persisted.Analysis, analysisInput); err != nil {
				return err
			}
			if err := writeJSON(persisted.JSONPath, persisted.Analysis); err != nil {
				return err
			}
			if err := os.WriteFile(persisted.MDPath, []byte(artifact.Markdown(persisted.Analysis)), 0o644); err != nil {
				return err
			}
			if explain != "" {
				explanation, explainErr := artifact.Explain(persisted.Analysis, explain)
				if explainErr != nil {
					return explainErr
				}
				switch format {
				case "json":
					return printJSON(stdout, struct {
						Explanation artifact.Explanation `json:"explanation"`
						JSONPath    string               `json:"json_path"`
						MDPath      string               `json:"md_path"`
					}{explanation, persisted.JSONPath, persisted.MDPath})
				case "md", "markdown":
					fmt.Fprint(stdout, artifact.ExplanationMarkdown(explanation))
				default:
					fmt.Fprint(stdout, artifact.ExplanationText(explanation))
				}
				fmt.Fprintf(stdout, "reports: %s %s\n", persisted.JSONPath, persisted.MDPath)
				return nil
			}
			var diff *artifact.DiffReport
			var diffJSONPath string
			var diffMDPath string
			if baselinePath != "" || comparePath != "" {
				var baseline artifact.Analysis
				if baselinePath != "" {
					baseline, err = artifact.LoadAnalysis(baselinePath)
				} else {
					baseline, err = artifact.AnalyzeWithOptions(comparePath, artifact.AnalysisOptions{Entrypoint: entry})
				}
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
			if format == "summary" {
				printAnalysisSummary(stdout, persisted.Analysis)
				fmt.Fprintf(stdout, "reports   %s%c\n", filepath.Dir(persisted.JSONPath), os.PathSeparator)
			} else if format == "text" {
				printAnalysis(stdout, persisted.Analysis)
				fmt.Fprintf(stdout, "reports: %s %s\n", persisted.JSONPath, persisted.MDPath)
			} else if format == "md" || format == "markdown" {
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
	cmd.Flags().StringVar(&format, "format", "summary", "output format: summary, text, json, or md")
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "previous analysis.json to diff against")
	cmd.Flags().StringVar(&comparePath, "compare", "", "other compiled object to compare capabilities against")
	cmd.Flags().StringSliceVar(&suppressions, "suppress", nil, "mark finding category or category=evidence-glob as suppressed; repeatable")
	cmd.Flags().StringVar(&compiler, "compiler", "auto", "compiler profile for project input: auto, mingw, or msvc")
	cmd.Flags().StringVar(&explain, "explain", "", "focus terminal output on one inferred capability or behavior-chain ID")
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
			if format != "summary" && format != "text" && format != "json" && format != "md" && format != "markdown" {
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
			case "summary":
				printPreflightSummary(stdout, persisted.Report)
				fmt.Fprintf(stdout, "reports   %s%c\n", filepath.Dir(persisted.JSONPath), os.PathSeparator)
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
				return codedError{code: 1, err: fmt.Errorf("loader support blocked execution with status %s", persisted.Report.Status)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&selectList, "select", "", "comma-separated arsenal selection")
	cmd.Flags().StringVar(&entry, "entry", "go", "entrypoint symbol")
	cmd.Flags().StringVar(&arch, "arch", "x64", "arsenal architecture: x64, x86, or all")
	cmd.Flags().StringVar(&format, "format", "summary", "output format: summary, text, json, or md")
	cmd.Flags().BoolVar(&strict, "strict", false, "fail on runtime-lookup warnings as well as blockers")
	cmd.Flags().BoolVar(&reportOnly, "report-only", false, "always exit zero after writing the matrix")
	return cmd
}

func printPreflightSummary(w io.Writer, report preflightsvc.Report) {
	status := "PASS"
	if report.Status != "pass" {
		status = "REVIEW"
	}
	fmt.Fprintf(w, "BOF PREFLIGHT %s\n", status)
	if len(report.Results) == 1 {
		printPreflightObjectSummary(w, report.Results[0])
		return
	}

	fmt.Fprintf(w, "objects   %d from %s\n", report.Summary.Total, report.Root)
	fmt.Fprintf(w, "loader    compatible=%d  warnings=%d  blocked=%d  failed=%d\n", report.Summary.Compatible, report.Summary.RuntimeLookup, report.Summary.Blocked, report.Summary.AnalyzeFailed)
	for _, result := range report.Results {
		imports := preflightImportCount(result)
		detail := preflightIssueCategories(result)
		if detail == "" {
			detail = result.Status
		}
		fmt.Fprintf(w, "  %-20s %-7s arch=%-3s toolchain=%-10s imports=%-3s relocs=%-4d %s\n",
			result.Name,
			preflightResultLabel(result),
			emptyText(result.Arch, "?"),
			emptyText(result.Toolchain, "unknown"),
			imports,
			result.Relocations,
			detail,
		)
	}
}

func printPreflightObjectSummary(w io.Writer, result preflightsvc.Result) {
	object := result.Object
	if object == "" {
		object = result.Path
	}
	blockers, warnings := 0, 0
	loader := "not checked"
	if result.Compatibility != nil {
		blockers = len(result.Compatibility.Blockers)
		warnings = len(result.Compatibility.Warnings)
		switch {
		case !result.Compatibility.Compatible:
			loader = "blocked"
		case warnings > 0:
			loader = "compatible (runtime lookup)"
		default:
			loader = "compatible"
		}
	} else if result.Status == "analyze_failed" {
		loader = "analysis failed"
	}
	fmt.Fprintf(w, "object    %s\n", object)
	fmt.Fprintf(w, "target    arch=%s  toolchain=%s  entry=%s  executable=%t\n", emptyText(result.Arch, "unknown"), emptyText(result.Toolchain, "unknown"), emptyText(result.Entrypoint, "go"), result.EntrypointOK)
	fmt.Fprintf(w, "loader    %s  blockers=%d  warnings=%d\n", emptyText(loader, "not checked"), blockers, warnings)
	fmt.Fprintf(w, "shape     imports=%s  relocs=%d\n", preflightImportCount(result), result.Relocations)
	if result.Error != "" {
		fmt.Fprintf(w, "error     %s\n", result.Error)
	}
	if result.Compatibility != nil && len(result.Compatibility.Blockers) > 0 {
		fmt.Fprintf(w, "blockers  %s\n", preflightIssueCategoriesFrom(result.Compatibility.Blockers))
	}
	if result.Compatibility != nil && len(result.Compatibility.Warnings) > 0 {
		fmt.Fprintf(w, "warnings  %s\n", preflightIssueCategoriesFrom(result.Compatibility.Warnings))
	}
}

func preflightImportCount(result preflightsvc.Result) string {
	if result.Object == "" {
		return "?"
	}
	analysis, err := artifact.Analyze(result.Object, emptyText(result.Entrypoint, "go"))
	if err != nil {
		return "?"
	}
	return fmt.Sprintf("%d", len(analysis.Imports))
}

func preflightResultLabel(result preflightsvc.Result) string {
	if result.Status == "compatible" {
		return "PASS"
	}
	if result.Status == "compatible_runtime_lookup" {
		return "WARN"
	}
	return "BLOCKED"
}

func preflightIssueCategories(result preflightsvc.Result) string {
	if result.Error != "" {
		return result.Error
	}
	if result.Compatibility == nil {
		return ""
	}
	if len(result.Compatibility.Blockers) > 0 {
		return "blockers=" + preflightIssueCategoriesFrom(result.Compatibility.Blockers)
	}
	if len(result.Compatibility.Warnings) > 0 {
		return "warnings=" + preflightIssueCategoriesFrom(result.Compatibility.Warnings)
	}
	return ""
}

func preflightIssueCategoriesFrom(issues []capability.Issue) string {
	seen := map[string]bool{}
	categories := make([]string, 0, len(issues))
	for _, issue := range issues {
		if issue.Category == "" || seen[issue.Category] {
			continue
		}
		seen[issue.Category] = true
		categories = append(categories, issue.Category)
	}
	sort.Strings(categories)
	return strings.Join(categories, ", ")
}

func runCommand(stdout io.Writer) *cobra.Command {
	var entry string
	var timeout int
	var runtimeName string
	var argsMode bool
	var via string
	var namedArgs []string
	var compiler string
	var arch string
	var sliverClient string
	var sliverSession string
	var labName string
	var labProfiles string
	var labHost string
	var labRoot string
	var labExecutable string
	var transportTimeout time.Duration
	var bootstrapMode string
	var cleanup bool
	var topologyName string
	var observe string
	cmd := &cobra.Command{
		Use:   "run <project|artifact> [--via native|lab|sliver|cobaltstrike] [--arg name=value]",
		Short: "Build if needed and execute a BOF through the selected runtime",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			observe = strings.ToLower(strings.TrimSpace(observe))
			if observe != "standard" && observe != "full" && observe != "off" {
				return fmt.Errorf("--observe must be standard, full, or off")
			}
			if cleanup {
				sourceProject := args[0]
				if !sourceaudit.IsSourceInput(args[0]) {
					return fmt.Errorf("--cleanup requires a BOF project with a pack lock")
				}
				cleanupProject, cleanupPacks, remove, err := prepareCleanupProject(args[0])
				if err != nil {
					return err
				}
				defer remove()
				args[0] = cleanupProject
				namedArgs = cleanupNamedArguments(sourceProject, cleanupProject, namedArgs)
				fmt.Fprintf(stdout, "cleanup   %s\n", strings.Join(cleanupPacks, ", "))
			}
			argTokens := args[1:]
			if !argsMode && len(argTokens) > 0 {
				return fmt.Errorf("unexpected trailing args; put BOF args after --args")
			}
			projectInput := sourceaudit.IsSourceInput(args[0])
			if topologyName != "" {
				if !projectInput {
					return fmt.Errorf("--topology requires a BOF project with pack metadata")
				}
				topology, err := resolveTopologyRuntimeValues(cmd.Context(), topologyName, labProfiles)
				if err != nil {
					return err
				}
				labName = topology.Topology.Execution.Name
				namedArgs, err = topologyNamedArguments(cmd.Context(), args[0], topology, namedArgs)
				if err != nil {
					return err
				}
			}
			if projectInput && len(namedArgs) == 0 && len(argTokens) == 0 {
				cfg, _, err := config.LoadFor(args[0])
				if err != nil {
					return err
				}
				argTokens = append([]string(nil), cfg.Args...)
			}
			resolved, err := resolveRunArguments(args[0], namedArgs, argTokens)
			if err != nil {
				return err
			}
			packed, items, err := argpack.PackTokens(resolved.Tokens)
			if err != nil {
				return err
			}
			run := &runtimeRunContext{
				stdout: stdout, input: args[0], projectInput: projectInput, entry: entry, timeout: timeout,
				runtimeName: runtimeName, compiler: compiler, arch: arch, resolved: resolved, packed: packed, items: items,
				labName: labName, labProfiles: labProfiles, labHost: labHost, labRoot: labRoot, labExecutable: labExecutable,
				transportTimeout: transportTimeout, bootstrapMode: bootstrapMode, sliverClient: sliverClient, sliverSession: sliverSession,
				interactiveLab: requiresInteractiveLabSession(args[0]),
				observe:        observe,
			}
			run.sensitiveOutputFields, run.sensitiveArgumentNames, run.sensitiveValues = runtimeSensitivity(args[0], resolved)
			registry, err := runtimeAdapterRegistry(run)
			if err != nil {
				return err
			}
			adapter, err := registry.Resolve(via)
			if err != nil {
				return fmt.Errorf("--via: %w", err)
			}
			availability, err := adapter.Detect(cmd.Context())
			if err != nil {
				return fmt.Errorf("detect %s runtime: %w", adapter.Name(), err)
			}
			if !availability.Available {
				return fmt.Errorf("%s runtime is unavailable: %s", adapter.Name(), emptyText(availability.Detail, "no usable runtime was detected"))
			}
			request := runtimeadapter.Request{Input: args[0], Entrypoint: entry, Cleanup: cleanup}
			for index, item := range items {
				name := fmt.Sprintf("arg%d", index+1)
				if index < len(resolved.Names) {
					name = resolved.Names[index]
				}
				sensitive := index < len(resolved.Sensitive) && resolved.Sensitive[index]
				request.Arguments = append(request.Arguments, runtimeadapter.Argument{Name: name, Type: item.Kind, Value: item.Value, Sensitive: sensitive})
			}
			if _, err := adapter.ConvertArguments(request.Arguments); err != nil {
				return fmt.Errorf("convert %s arguments: %w", adapter.Name(), err)
			}
			prepared, err := adapter.Prepare(cmd.Context(), request)
			if err != nil {
				return err
			}
			if cleanup {
				_, err = adapter.Cleanup(cmd.Context(), prepared)
			} else {
				_, err = adapter.Execute(cmd.Context(), prepared)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&entry, "entry", "go", "entrypoint")
	cmd.Flags().IntVar(&timeout, "timeout", 5000, "timeout in milliseconds")
	cmd.Flags().StringVar(&runtimeName, "runtime", "auto", "runtime: auto, windows-coff, linux-elf, darwin-macho, wine-coff")
	cmd.Flags().BoolVar(&argsMode, "args", false, "treat remaining positional tokens as packed artifact args")
	cmd.Flags().StringVar(&via, "via", "native", "execution target: native, lab, sliver, or cobaltstrike")
	cmd.Flags().StringArrayVar(&namedArgs, "arg", nil, "named pack argument (name=value); repeatable")
	cmd.Flags().StringVar(&compiler, "compiler", "auto", "compiler profile for project input: auto, mingw, or msvc")
	cmd.Flags().StringVar(&arch, "arch", "x64", "project build architecture: x64 or x86")
	cmd.Flags().StringVar(&sliverClient, "sliver-client", "", "Sliver client binary; discovered automatically when omitted")
	cmd.Flags().StringVar(&sliverSession, "session", "", "Sliver session ID, name, or filter; defaults to the selected lab profile")
	cmd.Flags().StringVar(&labName, "lab", "", "named lab profile for lab or Sliver execution")
	cmd.Flags().StringVar(&topologyName, "topology", "", "named multi-host topology; its execution role selects the lab")
	cmd.Flags().StringVar(&labProfiles, "profiles", lab.ProfilesPath(), "global lab profiles file")
	cmd.Flags().StringVar(&labHost, "host", "", "compatibility lab host override; prefer --lab")
	cmd.Flags().StringVar(&labRoot, "remote-root", "", "compatibility remote-root override; prefer the lab profile")
	cmd.Flags().StringVar(&labExecutable, "remote-exe", "", "compatibility remote executable override")
	cmd.Flags().DurationVar(&transportTimeout, "transport-timeout", 3*time.Minute, "lab operation timeout")
	cmd.Flags().StringVar(&bootstrapMode, "bootstrap", "auto", "lab runtime bootstrap: auto, always, or never")
	cmd.Flags().BoolVar(&cleanup, "cleanup", false, "run the cleanup companion packs instead of the project's action packs")
	cmd.Flags().StringVar(&observe, "observe", "standard", "lab telemetry markers: standard, full, or off")
	cmd.MarkFlagsMutuallyExclusive("lab", "topology")
	return cmd
}

func requiresInteractiveLabSession(project string) bool {
	lock, _, err := packsvc.LoadLock(project)
	if err != nil {
		return false
	}
	for _, record := range lock.Packs {
		switch record.ID {
		case "credential-list", "credential-read":
			return true
		}
	}
	return false
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
	var profile string
	var compiler string
	var arch string
	var runtimeName string
	var verifyReproducible bool
	var skipRun bool
	var format string
	cmd := &cobra.Command{
		Use:   "stage <project-or-artifact> --target cobaltstrike|sliver|raw [--args ...]",
		Short: "Build if needed and create a self-verified operator/C2 handoff",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			legacyStage := cmd.CalledAs() == "stage"
			if format != "text" && format != "json" {
				return fmt.Errorf("unknown export format %q", format)
			}
			if target == "" {
				return fmt.Errorf("--for is required")
			}
			argTokens := args[1:]
			if !argsMode && len(argTokens) > 0 {
				return fmt.Errorf("unexpected trailing args; put packed arguments after --args")
			}
			options, err := prepareStageOptions(stageInputOptions{
				Input: args[0], Target: target, Entrypoint: entry, ArgumentTokens: argTokens, ArgumentsExplicit: argsMode,
				Profile: profile, Compiler: compiler, Arch: arch, Runtime: runtimeName, VerifyReproducible: verifyReproducible, SkipRun: skipRun,
			})
			if err != nil {
				return err
			}
			if !legacyStage {
				options.OutputRoot = "export"
			}
			res, err := stage.StageWithOptions(options)
			if err != nil {
				return err
			}
			if format == "json" {
				return printJSON(stdout, res)
			}
			printExportSummary(stdout, res, legacyStage)
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "target: cobaltstrike, sliver, raw")
	cmd.Flags().StringVar(&entry, "entry", "", "entrypoint; project config or go by default")
	cmd.Flags().BoolVar(&argsMode, "args", false, "treat remaining positional tokens as packed artifact args")
	cmd.Flags().StringVar(&profile, "profile", "", "project test/operator profile")
	cmd.Flags().StringVar(&compiler, "compiler", "auto", "project compiler profile: auto, mingw, or msvc")
	cmd.Flags().StringVar(&arch, "arch", "x64", "project build architecture: x64 or x86")
	cmd.Flags().StringVar(&runtimeName, "runtime", "auto", "project validation runtime")
	cmd.Flags().BoolVar(&verifyReproducible, "verify-reproducible", true, "double-build project input and require identical object bytes")
	cmd.Flags().BoolVar(&skipRun, "skip-run", false, "for project input, stop after build/analysis instead of native validation")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.AddCommand(stageVerifyCommand(stdout))
	return cmd
}

func exportCommand(stdout io.Writer) *cobra.Command {
	cmd := stageCommand(stdout)
	originalRun := cmd.RunE
	cmd.Use = "export <project-or-artifact> --for cobaltstrike|sliver|raw|edrlab [--args ...]"
	cmd.Aliases = []string{"stage"}
	cmd.Short = "Build if needed and export a BOF for native or C2 use"
	cmd.Flags().String("for", "", "export target: cobaltstrike, sliver, raw, edrlab")
	cmd.RunE = func(command *cobra.Command, args []string) error {
		requested, _ := command.Flags().GetString("for")
		if requested != "edrlab" {
			return originalRun(command, args)
		}
		if len(args) < 1 {
			return fmt.Errorf("project or artifact is required")
		}
		argsMode, _ := command.Flags().GetBool("args")
		if !argsMode && len(args) > 1 {
			return fmt.Errorf("unexpected trailing args; put packed arguments after --args")
		}
		entry, _ := command.Flags().GetString("entry")
		profile, _ := command.Flags().GetString("profile")
		compiler, _ := command.Flags().GetString("compiler")
		arch, _ := command.Flags().GetString("arch")
		runtimeName, _ := command.Flags().GetString("runtime")
		verify, _ := command.Flags().GetBool("verify-reproducible")
		skipRun, _ := command.Flags().GetBool("skip-run")
		bundle, err := exportEDRBundle(args[0], args[1:], argsMode, entry, profile, compiler, arch, runtimeName, verify, skipRun)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "EDR Lab bundle exported\nBundle     %s\nExecute    bofbench-loader.exe\nNext       edrlab artifact %s --target-set <targets.yml>\n", bundle, bundle)
		return nil
	}
	cmd.PreRunE = func(command *cobra.Command, args []string) error {
		value, err := command.Flags().GetString("for")
		if err != nil {
			return err
		}
		if value != "" {
			return command.Flags().Set("target", value)
		}
		return nil
	}
	return cmd
}

func stageVerifyCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "verify <export-directory-or-zip>",
		Short: "Verify an exported package and its manifest integrity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "summary" && format != "text" && format != "json" {
				return fmt.Errorf("unknown export verification format %q", format)
			}
			report := stage.Verify(args[0])
			if format == "json" {
				if err := printJSON(stdout, report); err != nil {
					return err
				}
			} else if format == "text" {
				fmt.Fprint(stdout, report.Text())
			} else {
				printExportVerifySummary(stdout, report, cmd.Parent() != nil && cmd.Parent().CalledAs() == "stage")
			}
			if !report.Passed() {
				return codedError{code: 1, err: fmt.Errorf("export package verification failed")}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "summary", "output format: summary, text, or json")
	return cmd
}

func printExportSummary(stdout io.Writer, result stage.Result, legacyStage bool) {
	status := "FAIL"
	if result.Verified {
		status = "PASS"
	}
	label := "EXPORT"
	command := "export"
	if legacyStage {
		label = "STAGE (compatibility alias for EXPORT)"
		command = "export"
	}
	fmt.Fprintf(stdout, "BOF %s %s\n", label, status)
	fmt.Fprintf(stdout, "target    %s\n", result.Target)
	fmt.Fprintf(stdout, "object    %s\n", result.Object)
	fmt.Fprintf(stdout, "package   %s\n", result.Output)
	for _, verification := range result.Verification {
		fmt.Fprintf(stdout, "verify    %-9s %-18s warnings=%d\n", verification.Kind, verification.Status, verification.Warnings)
	}
	fmt.Fprintf(stdout, "next      bofbench %s verify %s\n", command, result.Output)
}

func printExportVerifySummary(stdout io.Writer, report stage.Verification, legacyStage bool) {
	status := strings.ToUpper(report.Status)
	label := "Export Package Verification"
	if legacyStage {
		label = "Stage Alias / Export Package Verification"
	}
	fmt.Fprintf(stdout, "%s: %s\n", label, status)
	fmt.Fprintf(stdout, "package   %s  target=%s\n", report.Name, report.Target)
	fmt.Fprintf(stdout, "input     %s (%s)\n", report.Input, report.Kind)
	fmt.Fprintf(stdout, "files     %d  bytes=%d\n", report.Summary.Files, report.Summary.Bytes)
	fmt.Fprintf(stdout, "checks    pass=%d  warnings=%d  fail=%d\n", report.Summary.Passed, report.Summary.Warnings, report.Summary.Failed)
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
	cmd.AddCommand(
		labAddCommand(stdout),
		labListCommand(stdout),
		labShowCommand(stdout),
		labUseCommand(stdout),
		labRemoveCommand(stdout),
		labImportCommand(stdout),
		labSetupScriptCommand(stdout),
		labMediaCommand(stdout),
		labTemplateCommand(stdout),
		labTopologyCommand(stdout),
		labTargetCommand(stdout),
		labInitCommand(stdout),
		labBootstrapCommand(stdout),
		labProviderRootCommand(stdout),
		labProviderCommand(stdout, "up"),
		labProviderCommand(stdout, "down"),
		labProviderCommand(stdout, "stop"),
		labProviderCommand(stdout, "snapshot"),
		labProviderCommand(stdout, "restore"),
		labProviderCommand(stdout, "clone"),
		labProviderCommand(stdout, "destroy"),
		labRemoteStatusCommand(stdout),
		labRemoteSyncCommand(stdout),
		labRemoteRunCommand(stdout),
		labRemoteCollectCommand(stdout),
		labRemoteResetCommand(stdout),
		labStateCommand(stdout),
		labSmokeCommand(stdout, stderr),
		labSummaryCommand(stdout),
	)
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
			} else {
				cmdArgs = append(cmdArgs, "--strict")
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
	printAnalysisSummary(w, a)
	fmt.Fprintln(w, "\nLoader and object details")
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
		fmt.Fprintf(w, "loader support:\n")
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

func printAnalysisSummary(w io.Writer, a artifact.Analysis) {
	loader := "not checked"
	blockers := 0
	if a.LoaderCompatibility != nil {
		loader = a.LoaderCompatibility.Status
		blockers = len(a.LoaderCompatibility.Blockers)
	}
	fmt.Fprintln(w, "Can do")
	if len(a.BehaviorChains) == 0 && len(a.Capabilities) == 0 {
		fmt.Fprintln(w, "  - No operator capability identified with useful confidence")
	}
	for _, chain := range a.BehaviorChains {
		location := ""
		if chain.Function != "" {
			location = " in " + chain.Function
		}
		fmt.Fprintf(w, "  - %s — %s%s\n", chain.Name, chain.Confidence, location)
		fmt.Fprintf(w, "    %s\n", chain.Summary)
	}
	for _, capability := range a.Capabilities {
		fmt.Fprintf(w, "  - %s — %s\n", shortCapabilityName(capability), emptyText(capability.Confidence, "confirmed primitive"))
	}

	fmt.Fprintln(w, "Effects")
	if len(a.Effects) == 0 {
		fmt.Fprintln(w, "  - No material effect inferred")
	} else {
		for _, effect := range a.Effects {
			fmt.Fprintf(w, "  - %s\n", effect)
		}
	}

	fmt.Fprintln(w, "Needs")
	needs := analysisNeeds(a)
	if len(needs) == 0 {
		fmt.Fprintln(w, "  - No special privilege, network, or host condition inferred")
	} else {
		for _, need := range needs {
			fmt.Fprintf(w, "  - %s\n", need)
		}
	}
	if len(a.Arguments) > 0 {
		fmt.Fprintln(w, "Arguments")
		for _, argument := range a.Arguments {
			required := "optional"
			if argument.Required {
				required = "required"
			}
			fmt.Fprintf(w, "  - %s (%s, %s; from %s)\n", argument.Name, argument.Type, required, argument.Source)
		}
	}

	fmt.Fprintln(w, "Works with")
	if len(a.WorksWith) == 0 {
		fmt.Fprintln(w, "  - No supported runtime identified")
	} else {
		fmt.Fprintf(w, "  - %s\n", strings.Join(a.WorksWith, ", "))
	}
	if len(a.Observed) > 0 {
		fmt.Fprintln(w, "Observed")
		for _, observed := range a.Observed {
			fmt.Fprintf(w, "  - %s — %s\n", observed.Capability, observed.Status)
		}
	}
	fmt.Fprintf(w, "Object      %s\n", a.Path)
	fmt.Fprintf(w, "Format      %s %s; toolchain=%s; bytes=%d; imports=%d; relocs=%d\n", a.Format, a.Arch, emptyText(a.Toolchain.Family, "unknown"), a.Size, len(a.Imports), a.Relocations)
	fmt.Fprintf(w, "Entry       %s; executable=%t\n", a.Entrypoint, a.EntrypointOK && a.EntrypointExecutable)
	fmt.Fprintf(w, "Loader      %s; blockers=%d\n", loader, blockers)
	if a.FindingSummary.Active > 0 || a.FindingSummary.Suppressed > 0 {
		fmt.Fprintf(w, "Details     findings=%d; suppressed=%d (use --format text or --format json)\n", a.FindingSummary.Active, a.FindingSummary.Suppressed)
	}
}

func analysisNeeds(a artifact.Analysis) []string {
	var values []string
	values = append(values, a.Requirements.Privilege...)
	values = append(values, a.Requirements.Network...)
	values = append(values, a.Requirements.Host...)
	for _, capability := range a.Capabilities {
		values = append(values, capability.Needs...)
	}
	for _, chain := range a.BehaviorChains {
		values = append(values, chain.Needs...)
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func printAnalysisCapabilities(w io.Writer, capabilities []artifact.Capability) {
	if len(capabilities) == 0 {
		fmt.Fprintln(w, "can do    no high-confidence capability inference")
		return
	}
	names := make([]string, 0, len(capabilities))
	evidence := map[string]bool{}
	usesStrings := false
	for _, item := range capabilities {
		names = append(names, shortCapabilityName(item))
		for _, value := range item.Evidence {
			evidence[value] = true
			if strings.HasPrefix(value, "string: ") {
				usesStrings = true
			}
		}
	}
	printWrappedValues(w, "can do", names, 78)
	fmt.Fprintf(w, "effects   %s\n", analysisCapabilityImpact(capabilities))
	basis := "imported APIs"
	if usesStrings {
		basis = "imported APIs + visible strings"
	}
	fmt.Fprintf(w, "evidence  inferred from %d %s; not execution proof\n", len(evidence), basis)
}

func shortCapabilityName(item artifact.Capability) string {
	if names := map[string]string{
		"identity_account_sid":  "identity/account/SID lookup",
		"token_context":         "token inspection",
		"process_inventory":     "process inventory",
		"process_access":        "process access/manipulation",
		"service_inventory":     "service inventory",
		"service_control":       "service control",
		"network_tcp":           "network/TCP access",
		"domain_context":        "domain/join context",
		"registry_read":         "registry read",
		"registry_write":        "registry write",
		"file_read":             "file read",
		"file_write":            "file write",
		"memory_operations":     "memory allocation/protection",
		"process_launch":        "process launch",
		"dynamic_loading":       "dynamic API loading",
		"persistence_mechanism": "persistence mechanism",
	}; names[item.ID] != "" {
		return names[item.ID]
	}
	return strings.ToLower(item.Name)
}

func printWrappedValues(w io.Writer, label string, values []string, width int) {
	prefix := fmt.Sprintf("%-10s", label)
	line := prefix
	for index, value := range values {
		piece := value
		if index < len(values)-1 {
			piece += "; "
		}
		if len(line)+len(piece) > width && line != prefix {
			fmt.Fprintln(w, strings.TrimRight(line, " "))
			line = strings.Repeat(" ", len(prefix))
		}
		line += piece
	}
	fmt.Fprintln(w, strings.TrimRight(line, " "))
}

func analysisCapabilityImpact(capabilities []artifact.Capability) string {
	flags := map[string]bool{}
	for _, item := range capabilities {
		impact := strings.ToLower(item.Impact)
		switch {
		case strings.Contains(impact, "persistent"):
			flags["persistence"] = true
		case strings.Contains(impact, "state change"):
			flags["changes state"] = true
		}
		if strings.Contains(impact, "code execution") {
			flags["launches code"] = true
		}
		if strings.Contains(impact, "cross-process") {
			flags["cross-process access"] = true
		}
		if strings.Contains(impact, "network") {
			flags["network access"] = true
		}
		if strings.Contains(impact, "discovery") {
			flags["read-only discovery"] = true
		}
		if strings.Contains(impact, "data access") {
			flags["data access"] = true
		}
	}
	ordered := []string{"persistence", "changes state", "launches code", "cross-process access", "network access", "data access", "read-only discovery"}
	var values []string
	for _, value := range ordered {
		if flags[value] {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return "review inferred APIs"
	}
	return strings.Join(values, " + ")
}

func emptyText(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func shortHash(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
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
	if res.LoaderErrorCode != "" {
		fmt.Fprintf(&b, "- Loader error code: `%s`\n", res.LoaderErrorCode)
	}
	if res.LoaderProcess != nil {
		if res.LoaderProcess.ExitCode != nil {
			fmt.Fprintf(&b, "- Loader process exit code: `%d`\n", *res.LoaderProcess.ExitCode)
		}
		if res.LoaderProcess.ExceptionCode != "" {
			fmt.Fprintf(&b, "- Windows exception: `%s`\n", res.LoaderProcess.ExceptionCode)
		}
		if res.LoaderProcess.StdoutTruncated || res.LoaderProcess.StderrTruncated {
			fmt.Fprintf(&b, "- Loader process streams truncated: `stdout=%t stderr=%t`\n", res.LoaderProcess.StdoutTruncated, res.LoaderProcess.StderrTruncated)
		}
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
	if res.LoaderMemory != nil {
		fmt.Fprintf(&b, "\n## Loader Memory\n\n- Initial protection: `%s`\n", res.LoaderMemory.InitialProtection)
		fmt.Fprintf(&b, "- Writable/executable sections: `%d`\n", res.LoaderMemory.WritableExecutableSections)
		b.WriteString("\n### Sections\n\n| Index | Name | Offset | Mapped | Allocation | Characteristics | Protection |\n| ---: | --- | ---: | ---: | ---: | ---: | --- |\n")
		for _, section := range res.LoaderMemory.Sections {
			fmt.Fprintf(&b, "| %d | `%s` | `0x%x` | %d | %d | `0x%08x` | `%s` |\n", section.Index, escapeMarkdownTable(section.Name), section.Offset, section.MappedSize, section.AllocationSize, section.Characteristics, section.Protection)
		}
		fmt.Fprintf(&b, "\n### Stub Region\n\n- Offset: `0x%x`\n- Allocation: `%d`\n- Protection: `%s`\n", res.LoaderMemory.StubRegion.Offset, res.LoaderMemory.StubRegion.AllocationSize, res.LoaderMemory.StubRegion.Protection)
	}
	if res.LoaderProcess != nil && (len(res.LoaderProcess.Stdout) > 0 || len(res.LoaderProcess.Stderr) > 0) {
		fmt.Fprintf(&b, "\n## Loader Process Streams\n\n### Stdout\n\n%s\n\n### Stderr\n\n%s\n", strings.Join(res.LoaderProcess.Stdout, "\n"), strings.Join(res.LoaderProcess.Stderr, "\n"))
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
	return fmt.Sprintf("# %s\n\nTemplate: `%s`\n\n```sh\nbofbench build bofs/%s\nbofbench analyze dist/%s.x64.o\nbofbench run bofs/%s --via native\n%s\nbofbench export bofs/%s --for raw\n```\n", name, templateName, name, name, name, extra, name)
}

func templateArgsC(name string) string {
	return fmt.Sprintf(`#include "beacon.h"
/* bofbench:feature-includes */

void go(char *args, int len) {
    datap parser;
    char *message;
    int message_len = 0;
    int count = 0;

    BeaconDataParse(&parser, args, len);
    message = BeaconDataExtract(&parser, &message_len);
    count = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "%s: %%.*s count=%%d\n", message_len, message, count);
    /* bofbench:feature-calls */
}
`, name)
}

func templateHelloC(name string) string {
	return fmt.Sprintf(`#include "beacon.h"
/* bofbench:feature-includes */

void go(char *args, int len) {
    (void)args;
    (void)len;
    BeaconPrintf(CALLBACK_OUTPUT, "hello from %s\n");
    /* bofbench:feature-calls */
}
`, name)
}

func templateWinAPIC(name string) string {
	return fmt.Sprintf(`#include <windows.h>
#include "beacon.h"
/* bofbench:feature-includes */

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentProcessId(void);

void go(char *args, int len) {
    (void)args;
    (void)len;
    BeaconPrintf(CALLBACK_OUTPUT, "%s pid=%%lu\n", KERNEL32$GetCurrentProcessId());
    /* bofbench:feature-calls */
}
`, name)
}

func templateUnresolvedC() string {
	return `#include "beacon.h"
/* bofbench:feature-includes */

void go(char *args, int len) {
    (void)args;
    (void)len;
    MissingExternal();
    /* bofbench:feature-calls */
}
`
}

func templateTimeoutC() string {
	return `#include "beacon.h"
/* bofbench:feature-includes */

void go(char *args, int len) {
    volatile unsigned long long spin = (unsigned long long)len;
    (void)args;
    for (;;) {
        spin++;
    }
    /* bofbench:feature-calls */
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
#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif
typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} datap;
typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} formatp;
DECLSPEC_IMPORT void BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT void BeaconPrintf(int type, const char *fmt, ...);
DECLSPEC_IMPORT void BeaconOutput(int type, char *data, int len);
DECLSPEC_IMPORT void BeaconFormatAlloc(formatp *format, int maxsz);
DECLSPEC_IMPORT void BeaconFormatReset(formatp *format);
DECLSPEC_IMPORT void BeaconFormatFree(formatp *format);
DECLSPEC_IMPORT void BeaconFormatAppend(formatp *format, char *text, int len);
DECLSPEC_IMPORT void BeaconFormatPrintf(formatp *format, const char *fmt, ...);
DECLSPEC_IMPORT char *BeaconFormatToString(formatp *format, int *size);
DECLSPEC_IMPORT void BeaconFormatInt(formatp *format, int value);
`
}
