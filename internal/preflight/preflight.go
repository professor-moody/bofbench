package preflight

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/arsenal"
	"github.com/professor-moody/bofbench/internal/artifact"
	"github.com/professor-moody/bofbench/internal/buildsys"
	"github.com/professor-moody/bofbench/internal/capability"
	"github.com/professor-moody/bofbench/internal/config"
	"github.com/professor-moody/bofbench/internal/evidence"
	"github.com/professor-moody/bofbench/internal/runlog"
)

type Options struct {
	Path       string
	Select     string
	Entrypoint string
	Arch       string
}

type Report struct {
	evidence.Header
	Root            string                    `json:"root"`
	Selected        string                    `json:"selected,omitempty"`
	Entrypoint      string                    `json:"entrypoint"`
	Architecture    string                    `json:"architecture"`
	RootFingerprint *evidence.TreeFingerprint `json:"root_fingerprint,omitempty"`
	StartedAt       string                    `json:"started_at"`
	CompletedAt     string                    `json:"completed_at"`
	Status          string                    `json:"status"`
	Summary         Summary                   `json:"summary"`
	Results         []Result                  `json:"results"`
}

type Summary struct {
	Total          int            `json:"total"`
	Compatible     int            `json:"compatible"`
	RuntimeLookup  int            `json:"runtime_lookup"`
	Blocked        int            `json:"blocked"`
	NotApplicable  int            `json:"not_applicable"`
	AnalyzeFailed  int            `json:"analyze_failed"`
	Built          int            `json:"built"`
	ByArchitecture map[string]int `json:"by_architecture"`
	ByStatus       map[string]int `json:"by_status"`
	ByBlocker      map[string]int `json:"by_blocker"`
	ByToolchain    map[string]int `json:"by_toolchain"`
	ByArgumentNeed map[string]int `json:"by_argument_need"`
}

type Result struct {
	Name              string                    `json:"name"`
	Path              string                    `json:"path"`
	Object            string                    `json:"object,omitempty"`
	Status            string                    `json:"status"`
	Error             string                    `json:"error,omitempty"`
	Built             bool                      `json:"built,omitempty"`
	Build             *buildsys.Result          `json:"build,omitempty"`
	Kind              artifact.Kind             `json:"kind,omitempty"`
	Arch              string                    `json:"arch,omitempty"`
	Toolchain         string                    `json:"toolchain,omitempty"`
	SHA256            string                    `json:"sha256,omitempty"`
	EntrypointOK      bool                      `json:"entrypoint_ok"`
	Entrypoint        string                    `json:"entrypoint,omitempty"`
	Relocations       int                       `json:"relocations"`
	ArgumentNeed      string                    `json:"argument_need,omitempty"`
	ArgumentAPIs      []string                  `json:"argument_apis,omitempty"`
	ConfiguredArgs    []string                  `json:"configured_args,omitempty"`
	ConfigPath        string                    `json:"config_path,omitempty"`
	ConfigFingerprint *evidence.FileFingerprint `json:"config_fingerprint,omitempty"`
	Compatibility     *capability.Compatibility `json:"loader_compatibility,omitempty"`
}

type Persisted struct {
	Report   Report
	JSONPath string
	MDPath   string
}

type target struct {
	name   string
	path   string
	object string
	arch   string
	build  bool
}

func Run(opts Options) (Persisted, error) {
	if opts.Path == "" {
		return Persisted{}, fmt.Errorf("preflight path is required")
	}
	if opts.Entrypoint == "" {
		opts.Entrypoint = "go"
	}
	if opts.Arch == "" {
		opts.Arch = "x64"
	}
	if opts.Arch != "x64" && opts.Arch != "x86" && opts.Arch != "all" {
		return Persisted{}, fmt.Errorf("unsupported preflight architecture %q; expected x64, x86, or all", opts.Arch)
	}
	targets, err := discoverTargets(opts.Path, opts.Select, opts.Arch)
	if err != nil {
		return Persisted{}, err
	}
	if len(targets) == 0 {
		return Persisted{}, fmt.Errorf("no preflight targets selected")
	}
	runDir, err := runlog.NewDir("preflight-" + safeName(filepath.Base(filepath.Clean(opts.Path))))
	if err != nil {
		return Persisted{}, err
	}
	report := Report{
		Header:       evidence.New(evidence.SchemaPreflight, runlog.ID(runDir), ""),
		Root:         opts.Path,
		Selected:     opts.Select,
		Entrypoint:   opts.Entrypoint,
		Architecture: opts.Arch,
		StartedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if info, statErr := os.Stat(opts.Path); statErr == nil && info.IsDir() {
		if fingerprint, fingerprintErr := evidence.FingerprintTree(opts.Path); fingerprintErr == nil {
			report.RootFingerprint = &fingerprint
		}
	}
	for _, item := range targets {
		result := Result{Name: item.name, Path: item.path, Object: item.object, Status: "analyze_failed", Entrypoint: opts.Entrypoint}
		object := item.object
		if object == "" {
			if !item.build {
				result.Error = fmt.Sprintf("%s object is not available and the entry has no buildable C source", emptyAs(item.arch, "requested"))
				report.Results = append(report.Results, result)
				continue
			}
			buildArch := item.arch
			if buildArch == "" {
				buildArch = "x64"
			}
			build, buildErr := buildsys.Build(item.path, buildArch)
			if buildErr != nil {
				result.Error = buildErr.Error()
				report.Results = append(report.Results, result)
				continue
			}
			build.ParentRunID = report.RunID
			object = build.Object
			result.Object = object
			result.Built = true
			result.Build = &build
		}
		cfg, cfgPath, configErr := config.LoadFor(item.path)
		if configErr != nil {
			result.Error = configErr.Error()
			report.Results = append(report.Results, result)
			continue
		}
		result.ConfigPath = cfgPath
		if cfgPath != "" {
			if fingerprint, fingerprintErr := evidence.FingerprintFile(cfgPath); fingerprintErr == nil {
				result.ConfigFingerprint = &fingerprint
			}
		}
		result.ConfiguredArgs = append([]string(nil), cfg.Args...)
		entrypoint := opts.Entrypoint
		if entrypoint == "go" && cfgPath != "" && cfg.Entrypoint != "" {
			entrypoint = cfg.Entrypoint
		}
		result.Entrypoint = entrypoint
		analysis, analyzeErr := artifact.Analyze(object, entrypoint)
		lineageName := item.name
		if item.arch != "" {
			lineageName += "-" + item.arch
		}
		analysis.Header = evidence.New(evidence.SchemaAnalysis, report.RunID+"/"+safeName(lineageName)+"/analysis", report.RunID)
		if analyzeErr != nil {
			result.Error = analyzeErr.Error()
			report.Results = append(report.Results, result)
			continue
		}
		result.Kind = analysis.Kind
		result.Arch = analysis.Arch
		result.Toolchain = analysis.Toolchain.Family
		result.SHA256 = analysis.SHA256
		result.EntrypointOK = analysis.EntrypointOK
		result.Relocations = analysis.Relocations
		result.ArgumentNeed, result.ArgumentAPIs = argumentProfile(analysis, cfg)
		result.Compatibility = analysis.LoaderCompatibility
		switch {
		case analysis.Kind != artifact.KindCOFF:
			result.Status = "not_applicable"
		case analysis.LoaderCompatibility == nil:
			result.Status = "analyze_failed"
			result.Error = "Windows COFF analysis did not produce a loader compatibility result"
		default:
			result.Status = analysis.LoaderCompatibility.Status
		}
		report.Results = append(report.Results, result)
	}
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	report.Summary = summarize(report.Results)
	report.Status = reportStatus(report.Summary)
	jsonPath := filepath.Join(runDir, "preflight.json")
	mdPath := filepath.Join(runDir, "preflight.md")
	if err := writeJSON(jsonPath, report); err != nil {
		return Persisted{}, err
	}
	if err := os.WriteFile(mdPath, []byte(Markdown(report)), 0o644); err != nil {
		return Persisted{}, err
	}
	return Persisted{Report: report, JSONPath: jsonPath, MDPath: mdPath}, nil
}

func discoverTargets(path, selectList, arch string) ([]target, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []target{{name: objectName(path), path: path, object: path}}, nil
	}
	entries, listErr := arsenal.List(path)
	if listErr == nil && len(entries) > 0 {
		selected := arsenal.Select(entries, selectList)
		if len(selected) == 0 {
			return nil, fmt.Errorf("no arsenal entries matched selection %q", selectList)
		}
		out := make([]target, 0, len(selected))
		for _, entry := range selected {
			buildable := directoryHasCSource(entry.Path)
			switch arch {
			case "x64":
				out = append(out, target{name: entry.Name, path: entry.Path, object: entry.X64, arch: "x64", build: buildable})
			case "x86":
				out = append(out, target{name: entry.Name, path: entry.Path, object: entry.X86, arch: "x86", build: buildable})
			case "all":
				out = append(out,
					target{name: entry.Name, path: entry.Path, object: entry.X64, arch: "x64", build: buildable},
					target{name: entry.Name, path: entry.Path, object: entry.X86, arch: "x86", build: buildable},
				)
			}
		}
		return out, nil
	}
	if selectList != "" {
		return nil, fmt.Errorf("--select requires an arsenal-like directory")
	}
	if arch == "all" {
		return []target{
			{name: filepath.Base(filepath.Clean(path)), path: path, arch: "x64", build: true},
			{name: filepath.Base(filepath.Clean(path)), path: path, arch: "x86", build: true},
		}, nil
	}
	return []target{{name: filepath.Base(filepath.Clean(path)), path: path, arch: arch, build: true}}, nil
}

func directoryHasCSource(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || found {
			return filepath.SkipAll
		}
		if entry.IsDir() {
			if path != root && (entry.Name() == ".git" || entry.Name() == "build" || entry.Name() == "dist") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".c") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func summarize(results []Result) Summary {
	summary := Summary{
		Total:          len(results),
		ByArchitecture: map[string]int{},
		ByStatus:       map[string]int{},
		ByBlocker:      map[string]int{},
		ByToolchain:    map[string]int{},
		ByArgumentNeed: map[string]int{},
	}
	for _, result := range results {
		summary.ByArchitecture[emptyAs(result.Arch, "unknown")]++
		summary.ByStatus[emptyAs(result.Status, "unknown")]++
		summary.ByToolchain[emptyAs(result.Toolchain, "unknown")]++
		summary.ByArgumentNeed[emptyAs(result.ArgumentNeed, "unknown")]++
		seenBlockers := map[string]bool{}
		if result.Compatibility != nil {
			for _, blocker := range result.Compatibility.Blockers {
				if !seenBlockers[blocker.Category] {
					summary.ByBlocker[blocker.Category]++
					seenBlockers[blocker.Category] = true
				}
			}
		}
		if result.Built {
			summary.Built++
		}
		switch result.Status {
		case "compatible":
			summary.Compatible++
		case "compatible_runtime_lookup":
			summary.RuntimeLookup++
		case "not_applicable":
			summary.NotApplicable++
		case "analyze_failed":
			summary.AnalyzeFailed++
		default:
			summary.Blocked++
		}
	}
	return summary
}

func argumentProfile(analysis artifact.Analysis, cfg config.Project) (string, []string) {
	if analysis.Kind != artifact.KindCOFF {
		return "not_applicable", nil
	}
	seen := map[string]bool{}
	var apis []string
	for _, imported := range analysis.Imports {
		if imported.Category != "beacon_api" || !strings.HasPrefix(imported.API, "BeaconData") || seen[imported.API] {
			continue
		}
		seen[imported.API] = true
		apis = append(apis, imported.API)
	}
	sort.Strings(apis)
	if len(cfg.Args) > 0 {
		return "configured", apis
	}
	if len(apis) > 0 {
		return "required_unconfigured", apis
	}
	return "none_observed", nil
}

func reportStatus(summary Summary) string {
	if summary.AnalyzeFailed > 0 {
		return "fail"
	}
	if summary.Blocked > 0 {
		return "blocked"
	}
	if summary.RuntimeLookup > 0 {
		return "warn"
	}
	return "pass"
}

func (r Report) HasProblems(strict bool) bool {
	return r.Summary.AnalyzeFailed > 0 || r.Summary.Blocked > 0 || (strict && r.Summary.RuntimeLookup > 0)
}

func Text(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "BOFBench loader preflight: %s\n", report.Status)
	fmt.Fprintf(&b, "catalog matrix: %d compatible, %d runtime-lookup, %d blocked, %d not-applicable, %d failed, %d total\n", report.Summary.Compatible, report.Summary.RuntimeLookup, report.Summary.Blocked, report.Summary.NotApplicable, report.Summary.AnalyzeFailed, report.Summary.Total)
	fmt.Fprintf(&b, "dimensions: arch=[%s] blocker=[%s] toolchain=[%s] args=[%s]\n", formatCounts(report.Summary.ByArchitecture), formatCounts(report.Summary.ByBlocker), formatCounts(report.Summary.ByToolchain), formatCounts(report.Summary.ByArgumentNeed))
	for _, result := range report.Results {
		detail := result.Error
		if detail == "" && result.Compatibility != nil {
			if len(result.Compatibility.Blockers) > 0 {
				detail = issueSummary(result.Compatibility.Blockers)
			} else if len(result.Compatibility.Warnings) > 0 {
				detail = issueSummary(result.Compatibility.Warnings)
			}
		}
		fmt.Fprintf(&b, "%-28s %-28s %-6s %-12s %-22s relocs=%-4d %s\n", result.Name, result.Status, emptyAs(result.Arch, "-"), emptyAs(result.Toolchain, "-"), emptyAs(result.ArgumentNeed, "-"), result.Relocations, detail)
	}
	return b.String()
}

func Markdown(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Loader Preflight\n\n- Schema: `%s` version `%d`\n- Run ID: `%s`\n- Root: `%s`\n- Selection: `%s`\n- Entrypoint: `%s`\n- Architecture request: `%s`\n- Status: `%s`\n- Summary: `%d compatible`, `%d runtime lookup`, `%d blocked`, `%d not applicable`, `%d failed`, `%d total`\n- By architecture: `%s`\n- By blocker: `%s`\n- By toolchain: `%s`\n- By argument need: `%s`\n\n", report.Schema, report.SchemaVersion, report.RunID, report.Root, report.Selected, report.Entrypoint, report.Architecture, report.Status, report.Summary.Compatible, report.Summary.RuntimeLookup, report.Summary.Blocked, report.Summary.NotApplicable, report.Summary.AnalyzeFailed, report.Summary.Total, formatCounts(report.Summary.ByArchitecture), formatCounts(report.Summary.ByBlocker), formatCounts(report.Summary.ByToolchain), formatCounts(report.Summary.ByArgumentNeed))
	b.WriteString("| Name | Status | Kind | Arch | Toolchain | Entry | Arguments | Relocations | SHA256 | Detail |\n| --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- |\n")
	for _, result := range report.Results {
		detail := result.Error
		if detail == "" && result.Compatibility != nil {
			if len(result.Compatibility.Blockers) > 0 {
				detail = issueSummary(result.Compatibility.Blockers)
			} else if len(result.Compatibility.Warnings) > 0 {
				detail = issueSummary(result.Compatibility.Warnings)
			}
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | %d | `%s` | %s |\n", escape(result.Name), result.Status, result.Kind, result.Arch, result.Toolchain, escape(result.Entrypoint), result.ArgumentNeed, result.Relocations, result.SHA256, escape(detail))
	}
	return b.String()
}

func formatCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, ", ")
}

func issueSummary(issues []capability.Issue) string {
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

func writeJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func objectName(path string) string {
	base := filepath.Base(path)
	for _, suffix := range []string{".x64.o", ".x86.o", ".o", ".obj"} {
		if strings.HasSuffix(strings.ToLower(base), suffix) {
			return base[:len(base)-len(suffix)]
		}
	}
	return base
}

func safeName(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func emptyAs(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func escape(value string) string {
	value = strings.ReplaceAll(value, "\n", "<br>")
	return strings.ReplaceAll(value, "|", "\\|")
}
