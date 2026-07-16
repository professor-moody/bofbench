package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"bofbench/internal/arsenal"
	"bofbench/internal/artifact"
	packsvc "bofbench/internal/pack"
)

func arsenalCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "arsenal", Short: "Acquire, search, compare, and run external BOFs"}
	cmd.AddCommand(arsenalAcquireCommand(stdout), arsenalListCommand(stdout), arsenalInventoryCommand(stdout), arsenalSearchCommand(stdout), arsenalMatrixCommand(stdout), arsenalCompareCommand(stdout), arsenalLockCommand(stdout), arsenalVerifyCommand(stdout), arsenalDiffCommand(stdout), arsenalRegressionCommand(stdout))
	return cmd
}

func arsenalAcquireCommand(stdout io.Writer) *cobra.Command {
	var opts arsenal.FetchOptions
	cmd := &cobra.Command{
		Use: "acquire <alias|url>", Short: "Acquire a Git, ZIP, raw, or known public BOF arsenal", Args: cobra.ExactArgs(1),
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
	cmd.Flags().StringVar(&opts.Ref, "ref", "", "Git ref, tag, branch, or commit")
	cmd.Flags().StringVar(&opts.Type, "type", "auto", "source type: git, zip, raw, or auto")
	cmd.Flags().StringVar(&opts.Adapter, "adapter", "auto", "layout adapter: trustedsec-sa, generic, or auto")
	return cmd
}

func arsenalListCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use: "list <root>", Short: "List source and object variants in an arsenal", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := arsenal.List(args[0])
			if err != nil {
				return err
			}
			for _, entry := range entries {
				var architectures []string
				if entry.X64 != "" {
					architectures = append(architectures, "x64")
				}
				if entry.X86 != "" {
					architectures = append(architectures, "x86")
				}
				fmt.Fprintf(stdout, "%-32s %-8s %s\n", entry.Name, strings.Join(architectures, ","), entry.Path)
			}
			return nil
		},
	}
}

func arsenalRegressionCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use: "regression <baseline-report.json> <current-report.json>", Short: "Compare arsenal preflight or test evidence and fail on regressions", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" && format != "md" && format != "markdown" {
				return fmt.Errorf("arsenal regression format must be text, json, or md")
			}
			report, err := arsenal.CompareRegressionEvidence(args[0], args[1])
			if err != nil {
				return err
			}
			report, err = arsenal.PersistRegression(report)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				err = printJSON(stdout, report)
			case "md", "markdown":
				fmt.Fprint(stdout, arsenal.RegressionMarkdown(report))
				fmt.Fprintf(stdout, "\nreports: %s %s\n", report.EvidencePath, report.MarkdownPath)
			default:
				fmt.Fprint(stdout, arsenal.RegressionText(report))
			}
			if err != nil {
				return err
			}
			if report.Status == "fail" {
				return codedError{code: 1, err: fmt.Errorf("arsenal regression detected %d regression(s)", report.Summary.Regressions)}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	return cmd
}

func arsenalInventoryCommand(stdout io.Writer) *cobra.Command {
	var query string
	var format string
	cmd := &cobra.Command{
		Use: "inventory <root>", Short: "Analyze and inventory a BOF arsenal", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runArsenalInventory(stdout, args[0], query, format)
		},
	}
	cmd.Flags().StringVar(&query, "query", "", "filter by name, path, API, capability, compatibility, or visible string")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	return cmd
}

func arsenalSearchCommand(stdout io.Writer) *cobra.Command {
	var format string
	var filters arsenal.InventoryFilters
	var hasArgs bool
	cmd := &cobra.Command{
		Use: "search <root> [query]", Short: "Find external BOFs by capability, effect, requirements, or runtime", Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filters.Query = strings.Join(args[1:], " ")
			if cmd.Flags().Changed("has-args") {
				filters.HasArgs = &hasArgs
			}
			return runArsenalInventoryWithFilters(stdout, args[0], filters, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	cmd.Flags().StringVar(&filters.Can, "can", "", "capability or behavior, for example token or process injection")
	cmd.Flags().StringVar(&filters.API, "api", "", "imported API name or fragment, for example RpcBinding")
	cmd.Flags().StringVar(&filters.Chain, "chain", "", "behavior-chain name or fragment, for example remote_registry")
	cmd.Flags().StringVar(&filters.Effect, "effect", "", "effect, for example credentials, writes state, or starts execution")
	cmd.Flags().StringVar(&filters.WorksWith, "works-with", "", "runtime target: native, lab, sliver, or cobaltstrike")
	cmd.Flags().StringVar(&filters.Requires, "requires", "", "requirement, for example administrator, network, or target process")
	cmd.Flags().StringVar(&filters.Arch, "arch", "", "object architecture: x64 or x86")
	cmd.Flags().StringVar(&filters.Loader, "loader", "", "loader support, for example compatible or unsupported_relocation")
	cmd.Flags().StringVar(&filters.Confidence, "confidence", "", "analysis confidence: confirmed primitive, strong chain, or possible")
	cmd.Flags().BoolVar(&hasArgs, "has-args", false, "only show BOFs with typed or detected arguments")
	return cmd
}

func arsenalMatrixCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use: "matrix <root>", Short: "Compare every x64 and x86 object independently", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fmt.Errorf("arsenal matrix format must be text or json")
			}
			registry, err := packsvc.Load(packsvc.LoadOptions{Project: args[0]})
			if err != nil {
				return err
			}
			report, err := arsenal.BuildArchitectureMatrix(args[0], declarativeSignatures(registry.List()))
			if err != nil {
				return err
			}
			if format == "json" {
				return printJSON(stdout, report)
			}
			fmt.Fprint(stdout, arsenal.ArchitectureMatrixText(report))
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func arsenalCompareCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use: "compare <first.o> <second.o>", Short: "Compare external BOFs by capability and behavior", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" && format != "md" && format != "markdown" {
				return fmt.Errorf("arsenal compare format must be text, json, or md")
			}
			first, err := artifact.Analyze(args[0], "go")
			if err != nil {
				return err
			}
			second, err := artifact.Analyze(args[1], "go")
			if err != nil {
				return err
			}
			report := artifact.CompareAnalysis(first, second)
			switch format {
			case "json":
				return printJSON(stdout, report)
			case "md", "markdown":
				fmt.Fprint(stdout, artifact.DiffMarkdown(report))
			default:
				fmt.Fprintf(stdout, "Capability comparison\nfirst      %s\nsecond     %s\ncapability added=%d removed=%d\nbehavior   added=%d removed=%d\n", args[0], args[1], report.Summary.CapabilitiesAdded, report.Summary.CapabilitiesRemoved, report.Summary.BehaviorChainsAdded, report.Summary.BehaviorChainsRemoved)
				for _, change := range report.Changes {
					if change.Category == "capability" || change.Category == "behavior" {
						fmt.Fprintf(stdout, "  %-10s %-8s %s\n", change.Category, change.Change, change.Name)
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	return cmd
}

func arsenalLockCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use: "lock <root>", Short: "Pin source and every discovered object in an arsenal lock", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" {
				return fmt.Errorf("arsenal lock format must be text or json")
			}
			lock, err := arsenal.CreateLock(args[0])
			if err != nil {
				return err
			}
			lock, path, err := arsenal.WriteLock(args[0], lock)
			if err != nil {
				return err
			}
			switch format {
			case "text":
				fmt.Fprint(stdout, arsenal.LockText(lock, path))
				return nil
			case "json":
				return printJSON(stdout, struct {
					Path string       `json:"path"`
					Lock arsenal.Lock `json:"lock"`
				}{Path: path, Lock: lock})
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	return cmd
}

func arsenalVerifyCommand(stdout io.Writer) *cobra.Command {
	var lockPath string
	var format string
	cmd := &cobra.Command{
		Use: "verify <root>", Short: "Verify the current arsenal against its lock", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateArsenalDiffFormat(format); err != nil {
				return err
			}
			root := args[0]
			if lockPath == "" {
				lockPath = filepath.Join(root, arsenal.LockFileName)
			}
			baseline, err := arsenal.LoadLock(lockPath)
			if err != nil {
				return err
			}
			current, err := arsenal.CreateLock(root)
			if err != nil {
				return err
			}
			report, err := arsenal.PersistLockDiff(arsenal.CompareLocks(lockPath, root, baseline, current))
			if err != nil {
				return err
			}
			if err := printArsenalDiff(stdout, report, format); err != nil {
				return err
			}
			if report.Status != "same" {
				return codedError{code: 1, err: fmt.Errorf("arsenal differs from lock")}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&lockPath, "lock", "", "lock file; default <root>/arsenal.lock.json")
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	return cmd
}

func arsenalDiffCommand(stdout io.Writer) *cobra.Command {
	var format string
	var check bool
	cmd := &cobra.Command{
		Use: "diff <baseline-lock> <current-lock|root>", Short: "Explain object and source changes between arsenal states", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateArsenalDiffFormat(format); err != nil {
				return err
			}
			baseline, err := arsenal.LoadLock(args[0])
			if err != nil {
				return err
			}
			current, currentLabel, err := loadCurrentArsenalState(args[1])
			if err != nil {
				return err
			}
			report, err := arsenal.PersistLockDiff(arsenal.CompareLocks(args[0], currentLabel, baseline, current))
			if err != nil {
				return err
			}
			if err := printArsenalDiff(stdout, report, format); err != nil {
				return err
			}
			if check && report.Status != "same" {
				return codedError{code: 1, err: fmt.Errorf("arsenal diff detected changes")}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	cmd.Flags().BoolVar(&check, "check", false, "exit nonzero when changes are present")
	return cmd
}

func runArsenalInventory(stdout io.Writer, root, query, format string) error {
	return runArsenalInventoryWithFilters(stdout, root, arsenal.InventoryFilters{Query: query}, format)
}

func runArsenalInventoryWithFilters(stdout io.Writer, root string, filters arsenal.InventoryFilters, format string) error {
	if format != "text" && format != "json" && format != "md" && format != "markdown" {
		return fmt.Errorf("arsenal inventory format must be text, json, or md")
	}
	registry, err := packsvc.Load(packsvc.LoadOptions{Project: root})
	if err != nil {
		return err
	}
	report, err := arsenal.BuildInventoryWithSignatures(root, filters, declarativeSignatures(registry.List()))
	if err != nil {
		return err
	}
	report, err = arsenal.PersistInventory(report)
	if err != nil {
		return err
	}
	switch format {
	case "json":
		return printJSON(stdout, report)
	case "md", "markdown":
		fmt.Fprint(stdout, arsenal.InventoryMarkdown(report))
		fmt.Fprintf(stdout, "\nreports: %s %s\n", report.JSONPath, report.MarkdownPath)
	default:
		fmt.Fprint(stdout, arsenal.InventoryText(report))
	}
	return nil
}

func loadCurrentArsenalState(path string) (arsenal.Lock, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return arsenal.Lock{}, path, err
	}
	if info.IsDir() {
		lock, err := arsenal.CreateLock(path)
		return lock, path, err
	}
	lock, err := arsenal.LoadLock(path)
	return lock, path, err
}

func printArsenalDiff(stdout io.Writer, report arsenal.LockDiff, format string) error {
	switch format {
	case "json":
		return printJSON(stdout, report)
	case "md", "markdown":
		fmt.Fprint(stdout, arsenal.LockDiffMarkdown(report))
		fmt.Fprintf(stdout, "\nreports: %s %s\n", report.EvidencePath, report.MarkdownPath)
	default:
		fmt.Fprint(stdout, arsenal.LockDiffText(report))
	}
	return nil
}

func validateArsenalDiffFormat(format string) error {
	if format != "text" && format != "json" && format != "md" && format != "markdown" {
		return fmt.Errorf("arsenal diff format must be text, json, or md")
	}
	return nil
}
