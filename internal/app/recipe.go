package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"bofbench/internal/recipe"
	"bofbench/internal/sourceaudit"
)

func recipeCommand(stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "recipe", Short: "Compose and validate operational BOF scenario recipes"}
	cmd.AddCommand(recipeListCommand(stdout), recipeApplyCommand(stdout), recipeShowCommand(stdout), recipeValidateCommand(stdout))
	return cmd
}

func recipeListCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List built-in offensive development recipes", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, document := range recipe.Builtins() {
				fmt.Fprintf(stdout, "%-18s %-20s privilege=%-6s network=%-8s effects=%-10s features=%s\n", document.Name, document.Category, document.Privilege, document.Network, document.Impact, strings.Join(document.Features, ","))
			}
			return nil
		},
	}
}

func recipeApplyCommand(stdout io.Writer) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use: "apply <project> <recipe>", Short: "Compose recipe features and write operational metadata", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := recipe.Apply(args[0], args[1], force)
			if err != nil {
				return err
			}
			if err := printJSON(stdout, result); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "next: bofbench recipe validate %s\n", shellQuote(args[0]))
			fmt.Fprintf(stdout, "then: bofbench dev %s\n", shellQuote(args[0]))
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing recipe sidecar")
	return cmd
}

func recipeShowCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use: "show <recipe|project>", Short: "Show a built-in or project recipe", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" && format != "md" && format != "markdown" {
				return fmt.Errorf("recipe format must be text, json, or md")
			}
			document, ok := recipe.Builtin(args[0])
			if !ok {
				var err error
				document, _, err = recipe.LoadFor(args[0])
				if err != nil {
					return err
				}
			}
			switch format {
			case "json":
				return printJSON(stdout, document)
			case "md", "markdown":
				fmt.Fprint(stdout, recipe.Markdown(document))
			default:
				fmt.Fprint(stdout, recipe.Text(document))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	return cmd
}

func recipeValidateCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use: "validate <project>", Short: "Validate recipe metadata against the project source", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "text" && format != "json" && format != "md" && format != "markdown" {
				return fmt.Errorf("recipe validation format must be text, json, or md")
			}
			document, recipePath, err := recipe.LoadFor(args[0])
			if err != nil {
				return err
			}
			source, err := sourceaudit.Analyze(args[0], sourceaudit.Options{})
			if err != nil {
				return err
			}
			features := make([]string, 0, len(source.Features))
			for _, feature := range source.Features {
				features = append(features, feature.Name)
			}
			validation := recipe.Validate(recipePath, document, features)
			if source.Status == "fail" {
				validation.Status = "fail"
				validation.Errors = append(validation.Errors, fmt.Sprintf("source analysis has %d error finding(s)", source.Summary.Errors))
			}
			validation, err = recipe.PersistValidation(validation)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				if err := printJSON(stdout, validation); err != nil {
					return err
				}
			case "md", "markdown":
				fmt.Fprint(stdout, recipe.ValidationMarkdown(validation))
				fmt.Fprintf(stdout, "\nreports: %s %s\n", validation.EvidencePath, validation.MarkdownPath)
			default:
				fmt.Fprint(stdout, recipe.ValidationText(validation))
			}
			if validation.Status == "fail" {
				return codedError{code: 1, err: fmt.Errorf("recipe validation failed")}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	return cmd
}
