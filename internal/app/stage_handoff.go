package app

import (
	"fmt"
	"strings"

	"bofbench/internal/argpack"
	"bofbench/internal/artifact"
	"bofbench/internal/config"
	packsvc "bofbench/internal/pack"
	"bofbench/internal/sourceaudit"
	"bofbench/internal/stage"
)

type stageInputOptions struct {
	Input              string
	Target             string
	Entrypoint         string
	ArgumentTokens     []string
	ArgumentNames      []string
	ArgumentOptional   []bool
	ArgumentsExplicit  bool
	Profile            string
	Compiler           string
	Arch               string
	Runtime            string
	VerifyReproducible bool
	SkipRun            bool
}

func prepareStageOptions(input stageInputOptions) (stage.Options, error) {
	options := stage.Options{
		Object: input.Input, Target: input.Target, Entrypoint: input.Entrypoint,
		SourceInput: input.Input, Profile: input.Profile,
	}
	argumentTokens := append([]string(nil), input.ArgumentTokens...)
	if sourceaudit.IsSourceInput(input.Input) {
		arch := strings.ToLower(strings.TrimSpace(input.Arch))
		if arch == "" {
			arch = "x64"
		}
		development, err := executeDevLoop(devLoopOptions{
			Project: input.Input, Arch: arch, Compiler: input.Compiler, Runtime: input.Runtime,
			Profile: input.Profile, SkipRun: input.SkipRun, VerifyReproducible: input.VerifyReproducible,
		})
		if err != nil {
			return stage.Options{}, fmt.Errorf("export preparation failed: %w", err)
		}
		cfg, _, err := config.LoadFor(input.Input)
		if err != nil {
			return stage.Options{}, err
		}
		cfg, err = config.ApplyProfile(cfg, input.Profile)
		if err != nil {
			return stage.Options{}, err
		}
		if options.Entrypoint == "" {
			options.Entrypoint = cfg.Entrypoint
		}
		if !input.ArgumentsExplicit {
			argumentTokens = append([]string(nil), cfg.Args...)
		}
		options.Object = development.Build.Object
		options.Project = input.Input
		options.OperatorNotes = append([]string(nil), cfg.OperatorNotes...)
		options.Recipe = development.Recipe
		options.RecipeValidation = development.RecipeValidation
		options.Evidence = stageEvidenceFromDevelopment(development)
	} else {
		analysis, err := artifact.Analyze(input.Input, fallbackStageEntrypoint(options.Entrypoint))
		if err != nil {
			return stage.Options{}, fmt.Errorf("artifact handoff analysis failed: %w", err)
		}
		if input.Target != "raw" && analysis.Kind != artifact.KindCOFF {
			return stage.Options{}, fmt.Errorf("%s handoff requires a Windows COFF BOF; got %s", input.Target, analysis.Kind)
		}
		if analysis.Kind == artifact.KindCOFF && (analysis.LoaderCompatibility == nil || !analysis.LoaderCompatibility.Compatible) {
			status := "analysis_failed"
			if analysis.LoaderCompatibility != nil {
				status = analysis.LoaderCompatibility.Status
			}
			return stage.Options{}, fmt.Errorf("artifact handoff blocked by loader preflight: %s", status)
		}
	}
	if options.Entrypoint == "" {
		options.Entrypoint = "go"
	}
	_, items, err := argpack.PackTokens(argumentTokens)
	if err != nil {
		return stage.Options{}, err
	}
	options.ArgumentNames = append([]string(nil), input.ArgumentNames...)
	options.ArgumentOptional = append([]bool(nil), input.ArgumentOptional...)
	if len(options.ArgumentNames) == 0 && options.Project != "" {
		if lock, _, lockErr := packsvc.LoadLock(options.Project); lockErr == nil {
			seen := map[string]bool{}
			for _, record := range lock.Packs {
				for _, argument := range record.Arguments {
					key := strings.ToLower(argument.Name)
					if !seen[key] {
						seen[key] = true
						options.ArgumentNames = append(options.ArgumentNames, argument.Name)
						options.ArgumentOptional = append(options.ArgumentOptional, !argument.Required || argument.Default != "")
						if len(argumentTokens) == 0 {
							item, itemErr := exportContractItem(argument)
							if itemErr != nil {
								return stage.Options{}, fmt.Errorf("pack argument %s: %w", argument.Name, itemErr)
							}
							items = append(items, item)
						}
					}
				}
			}
		}
	}
	if len(options.ArgumentNames) > len(items) && len(argumentTokens) > 0 {
		options.ArgumentNames = options.ArgumentNames[:len(items)]
		options.ArgumentOptional = options.ArgumentOptional[:len(items)]
	}
	options.Arguments = items
	return options, nil
}

func exportContractItem(argument packsvc.Argument) (argpack.Item, error) {
	value := argument.Default
	switch normalizedPackArgumentType(argument.Type) {
	case "string":
		return argpack.Item{Kind: "z", Value: value}, nil
	case "wstring":
		return argpack.Item{Kind: "Z", Value: value}, nil
	case "integer":
		if value == "" {
			value = "0"
		}
		return argpack.Item{Kind: "i", Value: value}, nil
	case "short":
		if value == "" {
			value = "0"
		}
		return argpack.Item{Kind: "s", Value: value}, nil
	case "bytes":
		return argpack.Item{Kind: "b", Value: value}, nil
	case "file":
		// Files are supplied at run time. An empty byte field preserves the
		// BOF argument position without reading or embedding a local file.
		return argpack.Item{Kind: "x", Value: ""}, nil
	default:
		return argpack.Item{}, fmt.Errorf("unsupported type %q", argument.Type)
	}
}

func stageEvidenceFromDevelopment(report devLoopReport) []stage.EvidenceInput {
	add := func(values *[]stage.EvidenceInput, kind, path, destination string) {
		if path != "" {
			*values = append(*values, stage.EvidenceInput{Kind: kind, Path: path, Destination: destination})
		}
	}
	var result []stage.EvidenceInput
	add(&result, "developer_json", report.EvidencePath, "reports/dev.json")
	add(&result, "developer_markdown", report.MarkdownPath, "reports/dev.md")
	add(&result, "source_analysis_json", report.SourceJSONPath, "reports/source.json")
	add(&result, "source_analysis_markdown", report.SourceMDPath, "reports/source.md")
	add(&result, "build_json", report.Build.EvidencePath, "reports/build.json")
	add(&result, "build_log", report.Build.LogPath, "reports/build.log")
	add(&result, "developer_analysis_json", report.AnalysisJSONPath, "reports/dev-analysis.json")
	add(&result, "developer_analysis_markdown", report.AnalysisMDPath, "reports/dev-analysis.md")
	return result
}

func fallbackStageEntrypoint(entrypoint string) string {
	if entrypoint == "" {
		return "go"
	}
	return entrypoint
}
