package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

const (
	commandCompatibilitySchema        = "bofbench.command-compatibility"
	commandCompatibilitySchemaVersion = 1
)

type commandCompatibilityPolicy struct {
	Schema                string                  `json:"schema"`
	SchemaVersion         int                     `json:"schema_version"`
	ReviewedAt            string                  `json:"reviewed_at"`
	SupportedThrough      string                  `json:"supported_through"`
	RemovalNotBefore      string                  `json:"removal_not_before"`
	RemovalReady          bool                    `json:"removal_ready"`
	Commands              []legacyCommandContract `json:"commands"`
	CommonRemovalCriteria []string                `json:"common_removal_criteria"`
}

type legacyCommandContract struct {
	Command             string          `json:"command"`
	ReplacementCoverage string          `json:"replacement_coverage"`
	RemovalReady        bool            `json:"removal_ready"`
	Summary             string          `json:"summary"`
	Mappings            []legacyMapping `json:"mappings"`
	OpenGaps            []string        `json:"open_gaps,omitempty"`
	RemovalCriteria     []string        `json:"removal_criteria"`
}

type legacyMapping struct {
	Legacy      string `json:"legacy"`
	Replacement string `json:"replacement"`
	Notes       string `json:"notes,omitempty"`
}

func compatibilityPolicy() commandCompatibilityPolicy {
	return commandCompatibilityPolicy{
		Schema:           commandCompatibilitySchema,
		SchemaVersion:    commandCompatibilitySchemaVersion,
		ReviewedAt:       "2026-08-30",
		SupportedThrough: "0.x",
		RemovalNotBefore: "1.0.0",
		RemovalReady:     false,
		Commands: []legacyCommandContract{
			{
				Command:             "feature",
				ReplacementCoverage: "complete",
				RemovalReady:        false,
				Summary:             "Individual features and curated feature packs are versioned built-in packs.",
				Mappings: []legacyMapping{
					{Legacy: "bofbench feature list", Replacement: "bofbench pack list", Notes: "Use pack search and pack show to narrow or inspect results."},
					{Legacy: "bofbench feature add <project> <feature...>", Replacement: "bofbench add <project> <pack...>", Notes: "Every supported feature ID resolves as a built-in pack."},
					{Legacy: "bofbench feature pack list", Replacement: "bofbench pack list"},
					{Legacy: "bofbench feature pack add <project> <pack>", Replacement: "bofbench add <project> <pack>"},
					{Legacy: "bofbench new <project> --feature <feature>", Replacement: "bofbench new <project> --pack <pack>"},
				},
				RemovalCriteria: []string{
					"keep a registry test proving every supported feature and curated feature pack resolves as a built-in pack",
					"prove generated source and lockfile behavior through the replacement commands",
				},
			},
			{
				Command:             "recipe",
				ReplacementCoverage: "partial",
				RemovalReady:        false,
				Summary:             "Built-in recipes resolve as packs, but standalone legacy recipe-sidecar validation has no evidence-equivalent replacement.",
				Mappings: []legacyMapping{
					{Legacy: "bofbench recipe list", Replacement: "bofbench pack list", Notes: "Recipe IDs are retained as built-in pack IDs."},
					{Legacy: "bofbench recipe show <recipe>", Replacement: "bofbench pack show <recipe>"},
					{Legacy: "bofbench recipe apply <project> <recipe>", Replacement: "bofbench add <project> <recipe>", Notes: "Use new --pack <recipe> when creating a project."},
					{Legacy: "bofbench recipe validate <project>", Replacement: "bofbench build <project>; bofbench analyze <project>", Notes: "This validates the resolved project, not the legacy recipe sidecar itself."},
				},
				OpenGaps: []string{
					"no primary command emits the legacy bofbench.recipe-validation evidence document",
					"existing bofbench.recipe.json migration must remain readable and preserve its original sidecar",
				},
				RemovalCriteria: []string{
					"replace or explicitly retire standalone recipe-sidecar validation evidence",
					"test first-use migration for every built-in recipe ID",
				},
			},
			{
				Command:             "dev",
				ReplacementCoverage: "partial",
				RemovalReady:        false,
				Summary:             "The primary workflow is an explicit build, analyze, and run sequence; its individual evidence is richer, but it does not yet replace the unified dev receipt.",
				Mappings: []legacyMapping{
					{Legacy: "bofbench dev <project>", Replacement: "bofbench build <project>; bofbench analyze <project>; bofbench run <project> --via <runtime>"},
					{Legacy: "bofbench dev <project> --skip-run", Replacement: "bofbench build <project>; bofbench analyze <project>"},
					{Legacy: "bofbench dev <project> --verify-reproducible", Replacement: "bofbench build <project> --verify-reproducible", Notes: "Follow with analyze and run when those phases are required."},
				},
				OpenGaps: []string{
					"no aggregate primary report preserves the dev receipt's build, source, object, import-correlation, recipe, and runtime views together",
					"replacement commands do not emit the same unified next-action field",
				},
				RemovalCriteria: []string{
					"define an aggregate evidence contract with equal or richer immutable phase references",
					"prove failure and suppression semantics match the explicit command sequence",
				},
			},
			{
				Command:             "preflight",
				ReplacementCoverage: "partial",
				RemovalReady:        false,
				Summary:             "Analyze replaces single-object loader inspection; arsenal matrix is the nearest corpus replacement but does not preserve all preflight controls or evidence.",
				Mappings: []legacyMapping{
					{Legacy: "bofbench preflight <object>", Replacement: "bofbench analyze <object> --format text", Notes: "Text, JSON, and Markdown analysis already include loader support."},
					{Legacy: "bofbench preflight <arsenal> --arch all", Replacement: "bofbench arsenal matrix <arsenal> --format text", Notes: "Use JSON when machine-readable matrix output is required."},
				},
				OpenGaps: []string{
					"arsenal matrix has no exact equivalents for preflight --select, --strict, or --report-only",
					"arsenal matrix does not emit the persisted bofbench.preflight evidence contract",
				},
				RemovalCriteria: []string{
					"replace the selection, strict-exit, report-only, and persisted-matrix workflows",
					"prove single-object analyze reports every loader blocker represented by preflight",
				},
			},
			{
				Command:             "stage",
				ReplacementCoverage: "complete",
				RemovalReady:        false,
				Summary:             "Stage is a Cobra alias of export and shares the same implementation.",
				Mappings: []legacyMapping{
					{Legacy: "bofbench stage <project-or-artifact> --target <target>", Replacement: "bofbench export <project-or-artifact> --for <target>"},
					{Legacy: "bofbench stage verify <directory-or-zip>", Replacement: "bofbench export verify <directory-or-zip>"},
				},
				RemovalCriteria: []string{
					"keep integration coverage proving stage and export accept equivalent inputs and produce equivalent packages",
				},
			},
		},
		CommonRemovalCriteria: []string{
			"do not remove a compatibility command before version 1.0.0",
			"ship its complete replacement mapping for at least one minor release",
			"remove legacy invocations from current documentation and examples outside the compatibility reference",
			"keep historical receipt and sidecar schemas readable after command removal",
			"require integration tests showing replacement evidence is equal or richer for every supported workflow",
		},
	}
}

func compatibilityCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "compatibility",
		Short: "Show legacy command replacements and removal gates",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			policy := compatibilityPolicy()
			switch format {
			case "text":
				fmt.Fprint(stdout, compatibilityText(policy))
				return nil
			case "json":
				return printJSON(stdout, policy)
			case "md", "markdown":
				fmt.Fprint(stdout, compatibilityMarkdown(policy))
				return nil
			default:
				return fmt.Errorf("compatibility format must be text, json, or md")
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text, json, or md")
	return cmd
}

func legacyCommand(cmd *cobra.Command, name string) *cobra.Command {
	contract, ok := compatibilityContract(name)
	if !ok {
		return cmd
	}
	description := strings.TrimSpace(cmd.Long)
	if description == "" {
		description = strings.TrimSpace(cmd.Short)
	}
	cmd.Long = fmt.Sprintf("%s\n\nCompatibility command through 0.x; removal is not permitted before 1.0.0. %s Run 'bofbench compatibility' for exact replacements and open gates.", description, contract.Summary)
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations["bofbench.io/compatibility"] = name
	return cmd
}

func compatibilityContract(name string) (legacyCommandContract, bool) {
	for _, contract := range compatibilityPolicy().Commands {
		if contract.Command == name {
			return contract, true
		}
	}
	return legacyCommandContract{}, false
}

func compatibilityText(policy commandCompatibilityPolicy) string {
	var out strings.Builder
	fmt.Fprintf(&out, "BOFBENCH COMMAND COMPATIBILITY v%d\n", policy.SchemaVersion)
	fmt.Fprintf(&out, "supported through %s; removal not before %s; removal ready: %t\n\n", policy.SupportedThrough, policy.RemovalNotBefore, policy.RemovalReady)
	for _, contract := range policy.Commands {
		fmt.Fprintf(&out, "%-10s coverage=%-8s removal_ready=%t\n", contract.Command, contract.ReplacementCoverage, contract.RemovalReady)
		for _, mapping := range contract.Mappings {
			fmt.Fprintf(&out, "  %s\n    -> %s\n", mapping.Legacy, mapping.Replacement)
		}
		for _, gap := range contract.OpenGaps {
			fmt.Fprintf(&out, "  gap: %s\n", gap)
		}
	}
	return out.String()
}

func compatibilityMarkdown(policy commandCompatibilityPolicy) string {
	var out strings.Builder
	fmt.Fprintln(&out, "# Legacy command compatibility")
	fmt.Fprintln(&out)
	fmt.Fprintf(&out, "This is the generated human-readable view of `%s` schema version %d, reviewed %s. Compatibility commands are supported through `%s`; none may be removed before `%s`.\n\n", policy.Schema, policy.SchemaVersion, policy.ReviewedAt, policy.SupportedThrough, policy.RemovalNotBefore)
	fmt.Fprintln(&out, "| Command | Replacement coverage | Removal ready |")
	fmt.Fprintln(&out, "| --- | --- | --- |")
	for _, contract := range policy.Commands {
		fmt.Fprintf(&out, "| `%s` | %s | %t |\n", contract.Command, contract.ReplacementCoverage, contract.RemovalReady)
	}
	for _, contract := range policy.Commands {
		fmt.Fprintf(&out, "\n## `%s`\n\n%s\n\n", contract.Command, contract.Summary)
		fmt.Fprintln(&out, "| Legacy workflow | Primary replacement | Notes |")
		fmt.Fprintln(&out, "| --- | --- | --- |")
		for _, mapping := range contract.Mappings {
			fmt.Fprintf(&out, "| `%s` | `%s` | %s |\n", mapping.Legacy, mapping.Replacement, mapping.Notes)
		}
		if len(contract.OpenGaps) > 0 {
			fmt.Fprintln(&out, "\nOpen gaps:")
			for _, gap := range contract.OpenGaps {
				fmt.Fprintf(&out, "\n- %s\n", gap)
			}
		}
		fmt.Fprintln(&out, "\nCommand-specific removal criteria:")
		for _, criterion := range contract.RemovalCriteria {
			fmt.Fprintf(&out, "\n- %s\n", criterion)
		}
	}
	fmt.Fprintln(&out, "\n## Common removal criteria")
	for _, criterion := range policy.CommonRemovalCriteria {
		fmt.Fprintf(&out, "\n- %s\n", criterion)
	}
	fmt.Fprintln(&out, "\n## Machine-readable contract")
	fmt.Fprintln(&out)
	fmt.Fprintln(&out, "The checked-in JSON contract is `docs/evidence/command-compatibility-v1.json`. Regenerate both files with `bofbench compatibility --format md` and `bofbench compatibility --format json`; the documentation check rejects drift.")
	return out.String()
}
