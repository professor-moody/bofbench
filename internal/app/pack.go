package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	packsvc "bofbench/internal/pack"
)

func catalogCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "catalog", Short: "Configure local, private, or Git-backed capability pack catalogs"}
	cmd.AddCommand(catalogListCommand(stdout), catalogAddCommand(stdout), catalogRemoveCommand(stdout), catalogUpdateCommand(stdout))
	return cmd
}

func catalogListCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List configured capability pack catalogs", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := packsvc.LoadCatalogConfig()
			if err != nil {
				return err
			}
			fmt.Fprintln(stdout, "builtin  embedded public capability packs")
			for _, item := range config.Catalogs {
				fmt.Fprintf(stdout, "%-8s %s\n", item.Name, item.Path)
			}
			return nil
		},
	}
}

func catalogAddCommand(stdout io.Writer) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use: "add <directory|git-url>", Short: "Add a local, private, or Git-backed pack catalog", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref, err := packsvc.AddCatalog(args[0], name)
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "catalog   %s\npath      %s\nnext      bofbench pack list\n", ref.Name, ref.Path)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "catalog name; defaults to the directory or repository name")
	return cmd
}

func catalogRemoveCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use: "remove <name>", Short: "Remove a configured catalog reference", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := packsvc.RemoveCatalog(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "removed catalog %s\n", args[0])
			return nil
		},
	}
}

func catalogUpdateCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use: "update <name>", Short: "Fast-forward a configured Git-backed catalog", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := packsvc.UpdateCatalog(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "updated catalog %s\n", args[0])
			return nil
		},
	}
}

func packCommand(stdout io.Writer) *cobra.Command {
	var project string
	var catalogs []string
	cmd := &cobra.Command{Use: "pack", Short: "List, inspect, search, and validate BOF capability packs"}
	cmd.PersistentFlags().StringVar(&project, "project", ".", "project used for project-local pack discovery")
	cmd.PersistentFlags().StringSliceVar(&catalogs, "catalog", nil, "additional pack catalog path; repeatable")
	load := func() (*packsvc.Registry, error) {
		return packsvc.Load(packsvc.LoadOptions{Project: project, ExtraCatalogs: catalogs})
	}
	cmd.AddCommand(
		&cobra.Command{
			Use: "list", Short: "List available capability packs", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				registry, err := load()
				if err != nil {
					return err
				}
				printPacks(stdout, registry.List())
				return nil
			},
		},
		&cobra.Command{
			Use: "search <terms...>", Short: "Search pack names, capabilities, and effects", Args: cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				registry, err := load()
				if err != nil {
					return err
				}
				printPacks(stdout, registry.Search(strings.Join(args, " ")))
				return nil
			},
		},
		packShowCommand(stdout, load),
		packDocsCommand(stdout, load, func() []string { return append([]string(nil), catalogs...) }),
		packTestCommand(stdout, load, func() []string { return append([]string(nil), catalogs...) }),
		packProveCommand(stdout, load, func() []string { return append([]string(nil), catalogs...) }),
		&cobra.Command{
			Use: "validate <pack.json>", Short: "Validate a pack manifest and its source paths", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				document, err := packsvc.ValidateFile(args[0])
				if err != nil {
					return err
				}
				fmt.Fprintf(stdout, "PACK VALID\nid        %s\nversion   %s\ntier      %s\n", document.ID, document.Version, document.Tier)
				return nil
			},
		},
	)
	return cmd
}

func packDocsCommand(stdout io.Writer, load func() (*packsvc.Registry, error), catalogSelectors func() []string) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use: "docs", Short: "Generate Markdown reference from resolved pack manifests", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			registry, err := load()
			if err != nil {
				return err
			}
			items, err := selectedPacks(registry, nil, true, catalogSelectors())
			if err != nil {
				return err
			}
			body := packReferenceMarkdown(items)
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
			fmt.Fprintf(stdout, "pack reference written to %s\n", output)
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "Markdown output path; default stdout")
	return cmd
}

func packReferenceMarkdown(items []packsvc.Resolved) string {
	items = append([]packsvc.Resolved(nil), items...)
	sort.Slice(items, func(i, j int) bool { return items[i].Qualified < items[j].Qualified })
	var b strings.Builder
	b.WriteString("# Capability Pack Reference\n\n")
	b.WriteString("This page is generated from the resolved `pack.json` contracts. Use `bofbench pack docs --output docs/pack-reference.md` to refresh it.\n\n")
	for _, item := range items {
		document := item.Document
		fmt.Fprintf(&b, "## `%s`\n\n%s\n\n", item.Qualified, document.Summary)
		fmt.Fprintf(&b, "- Can do: %s\n", strings.Join(document.Capabilities, "; "))
		fmt.Fprintf(&b, "- Effects: %s\n", strings.Join(document.Effects, "; "))
		fmt.Fprintf(&b, "- Needs: privilege=%s; network=%s; platform=%s/%s\n", document.Privilege, document.Network, strings.Join(document.Platforms, ","), strings.Join(document.Architecture, ","))
		fmt.Fprintf(&b, "- Works with: %s\n", strings.Join(document.TargetSupport, ", "))
		fmt.Fprintf(&b, "- Version: `%s`\n", document.Version)
		if document.CleanupPack != "" {
			fmt.Fprintf(&b, "- Cleanup: `%s`\n", document.CleanupPack)
		}
		if len(document.AnalysisSignatures) > 0 {
			var signatures []string
			for _, signature := range document.AnalysisSignatures {
				signatures = append(signatures, signature.ID)
			}
			fmt.Fprintf(&b, "- Analyzer signatures: `%s`\n", strings.Join(signatures, "`, `"))
		}
		if len(document.ProofCases) > 0 {
			var proofs []string
			for _, proof := range document.ProofCases {
				proofs = append(proofs, proof.ID+" ("+strings.Join(proof.Via, ", ")+")")
			}
			fmt.Fprintf(&b, "- Live proofs: %s\n", strings.Join(proofs, "; "))
		}
		if len(document.Arguments) > 0 {
			b.WriteString("\n| Argument | Type | Required | Default | Description |\n| --- | --- | --- | --- | --- |\n")
			for _, argument := range document.Arguments {
				required := "no"
				if argument.Required && argument.Default == "" {
					required = "yes"
				}
				fmt.Fprintf(&b, "| `%s` | `%s` | %s | `%s` | %s |\n", argument.Name, argument.Type, required, argument.Default, strings.ReplaceAll(argument.Description, "|", "\\|"))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func packShowCommand(stdout io.Writer, load func() (*packsvc.Registry, error)) *cobra.Command {
	var format string
	var cleanup bool
	cmd := &cobra.Command{
		Use: "show <pack>", Short: "Show a capability pack, arguments, effects, and cleanup", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			registry, err := load()
			if err != nil {
				return err
			}
			item, err := registry.Resolve(args[0])
			if err != nil {
				return err
			}
			if cleanup {
				if item.Document.CleanupPack == "" {
					fmt.Fprintf(stdout, "%s has no cleanup pack\n", item.Qualified)
					return nil
				}
				item, err = registry.ResolveRelated(item, item.Document.CleanupPack)
				if err != nil {
					return err
				}
			}
			switch format {
			case "json":
				return printJSON(stdout, item)
			case "text":
				printPack(stdout, item)
				return nil
			default:
				return fmt.Errorf("pack format must be text or json")
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text or json")
	cmd.Flags().BoolVar(&cleanup, "cleanup", false, "show the pack's cleanup companion")
	return cmd
}

func addCommand(stdout io.Writer) *cobra.Command {
	var catalogs []string
	cmd := &cobra.Command{
		Use: "add <project> <pack...>", Short: "Add one or more capability packs to a BOF project", Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			registry, err := packsvc.Load(packsvc.LoadOptions{Project: args[0], ExtraCatalogs: catalogs})
			if err != nil {
				return err
			}
			result, err := registry.Apply(args[0], args[1:])
			if err != nil {
				return err
			}
			fmt.Fprintf(stdout, "PACKS ADDED\nproject   %s\n", result.Project)
			if len(result.Added) > 0 {
				fmt.Fprintf(stdout, "added     %s\n", strings.Join(result.Added, ", "))
			}
			if len(result.Existing) > 0 {
				fmt.Fprintf(stdout, "existing  %s\n", strings.Join(result.Existing, ", "))
			}
			if result.Migrated != "" {
				fmt.Fprintf(stdout, "migrated  %s\n", result.Migrated)
			}
			fmt.Fprintf(stdout, "lock      %s\nnext      bofbench build %s\n", result.LockPath, shellQuote(args[0]))
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&catalogs, "catalog", nil, "additional pack catalog path; repeatable")
	return cmd
}

func printPacks(stdout io.Writer, items []packsvc.Resolved) {
	if len(items) == 0 {
		fmt.Fprintln(stdout, "No capability packs matched.")
		return
	}
	fmt.Fprintln(stdout, "CAPABILITY PACKS")
	for _, item := range items {
		fmt.Fprintf(stdout, "%-34s tier=%-8s effects=%s\n", item.Qualified, item.Document.Tier, strings.Join(item.Document.Effects, ","))
		fmt.Fprintf(stdout, "  %s\n", item.Document.Summary)
	}
}

func printPack(stdout io.Writer, item packsvc.Resolved) {
	document := item.Document
	fmt.Fprintf(stdout, "%s\n", strings.ToUpper(document.Title))
	fmt.Fprintf(stdout, "pack       %s\nversion    %s\ntier       %s\n", item.Qualified, document.Version, document.Tier)
	fmt.Fprintf(stdout, "can do     %s\n", strings.Join(document.Capabilities, ", "))
	fmt.Fprintf(stdout, "effects    %s\n", strings.Join(document.Effects, ", "))
	fmt.Fprintf(stdout, "needs      privilege=%s network=%s platform=%s/%s\n", document.Privilege, document.Network, strings.Join(document.Platforms, ","), strings.Join(document.Architecture, ","))
	fmt.Fprintf(stdout, "works with %s\n", strings.Join(document.TargetSupport, ", "))
	if len(document.Arguments) > 0 {
		fmt.Fprintln(stdout, "arguments")
		for _, argument := range document.Arguments {
			required := "optional"
			if argument.Required {
				required = "required"
			}
			fmt.Fprintf(stdout, "  %-18s %-8s %-8s %s\n", argument.Name, argument.Type, required, argument.Description)
		}
	}
	if document.CleanupPack != "" {
		fmt.Fprintf(stdout, "cleanup    %s\n", document.CleanupPack)
	}
	if item.Manifest != "" {
		fmt.Fprintf(stdout, "manifest   %s\n", filepath.Clean(item.Manifest))
	}
}
