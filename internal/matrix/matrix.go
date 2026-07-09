package matrix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"bofbench/internal/argpack"
	"bofbench/internal/artifact"
	"bofbench/internal/buildsys"
	"bofbench/internal/config"
	"bofbench/internal/evidence"
	"bofbench/internal/runlog"
	runtimesvc "bofbench/internal/runtime"
)

const (
	cellPass     = "pass"
	cellExpected = "expected"
	cellSkip     = "skip"
	cellFail     = "fail"
)

type Options struct {
	Path               string
	Compilers          []string
	Optimizations      []string
	Architecture       string
	Execution          string
	Runtime            string
	Profile            string
	VerifyReproducible bool
}

type Report struct {
	evidence.Header
	ReplayOf              string                    `json:"replay_of,omitempty"`
	ReplaySource          *evidence.FileFingerprint `json:"replay_source,omitempty"`
	Path                  string                    `json:"path"`
	SourceFingerprint     *evidence.FileFingerprint `json:"source_fingerprint,omitempty"`
	SourceTreeFingerprint *evidence.TreeFingerprint `json:"source_tree_fingerprint,omitempty"`
	Config                string                    `json:"config,omitempty"`
	ConfigFingerprint     *evidence.FileFingerprint `json:"config_fingerprint,omitempty"`
	Entrypoint            string                    `json:"entrypoint"`
	Runtime               string                    `json:"runtime"`
	Execution             string                    `json:"execution"`
	VerifyReproducible    bool                      `json:"verify_reproducible"`
	Contract              RuntimeContract           `json:"runtime_contract"`
	StartedAt             string                    `json:"started_at"`
	CompletedAt           string                    `json:"completed_at"`
	Status                string                    `json:"status"`
	Summary               Summary                   `json:"summary"`
	Cells                 []Cell                    `json:"cells"`
}

type RuntimeContract struct {
	Args           []string `json:"args,omitempty"`
	Expect         []string `json:"expect,omitempty"`
	Forbid         []string `json:"forbid,omitempty"`
	TimeoutMS      int      `json:"timeout_ms"`
	ExpectedExit   string   `json:"expected_exit,omitempty"`
	ExpectedStatus string   `json:"expected_status,omitempty"`
}

type Summary struct {
	Total            int                     `json:"total"`
	Passed           int                     `json:"passed"`
	Expected         int                     `json:"expected"`
	Skipped          int                     `json:"skipped"`
	Failed           int                     `json:"failed"`
	ByCompiler       map[string]StatusCounts `json:"by_compiler"`
	ByOptimization   map[string]StatusCounts `json:"by_optimization"`
	ByArchitecture   map[string]StatusCounts `json:"by_architecture"`
	ByClassification map[string]int          `json:"by_classification"`
}

type StatusCounts struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Expected int `json:"expected"`
	Skipped  int `json:"skipped"`
	Failed   int `json:"failed"`
}

type Cell struct {
	ID                  string                    `json:"id"`
	Compiler            string                    `json:"compiler"`
	Optimization        string                    `json:"optimization"`
	Architecture        string                    `json:"architecture"`
	CFlags              []string                  `json:"cflags"`
	ExpectedOutcome     string                    `json:"expected_outcome"`
	Status              string                    `json:"status"`
	Classification      string                    `json:"classification"`
	Stage               string                    `json:"stage"`
	Error               string                    `json:"error,omitempty"`
	Artifact            string                    `json:"artifact,omitempty"`
	ArtifactFingerprint *evidence.FileFingerprint `json:"artifact_fingerprint,omitempty"`
	Build               *buildsys.Result          `json:"build,omitempty"`
	BuildEvidence       string                    `json:"build_evidence,omitempty"`
	BuildLog            string                    `json:"build_log,omitempty"`
	Analysis            *artifact.Analysis        `json:"analysis,omitempty"`
	RuntimeAttempted    bool                      `json:"runtime_attempted"`
	Run                 *runtimesvc.Result        `json:"run,omitempty"`
}

type Persisted struct {
	Report   Report
	JSONPath string
	MDPath   string
}

type plannedCell struct {
	Compiler     string
	Optimization string
	Architecture string
	CFlags       []string
}

func Run(options Options) (Persisted, error) {
	plan, err := normalizeOptions(&options)
	if err != nil {
		return Persisted{}, err
	}
	info, err := os.Stat(options.Path)
	if err != nil {
		return Persisted{}, fmt.Errorf("matrix source %s: %w", options.Path, err)
	}
	if !info.IsDir() && !strings.EqualFold(filepath.Ext(options.Path), ".c") {
		return Persisted{}, fmt.Errorf("compiler matrix requires a C source file or project directory")
	}
	cfg, cfgPath, err := config.LoadFor(options.Path)
	if err != nil {
		return Persisted{}, err
	}
	cfg, err = config.ApplyProfile(cfg, options.Profile)
	if err != nil {
		return Persisted{}, err
	}
	entrypoint := cfg.Entrypoint
	if entrypoint == "" {
		entrypoint = "go"
	}
	packedArgs, _, err := argpack.PackTokens(cfg.Args)
	if err != nil {
		return Persisted{}, fmt.Errorf("matrix arguments: %w", err)
	}
	runDir, err := runlog.NewDir("matrix-" + safeName(filepath.Base(filepath.Clean(options.Path))))
	if err != nil {
		return Persisted{}, err
	}
	report := Report{
		Header:             evidence.New(evidence.SchemaCompilerMatrix, runlog.ID(runDir), ""),
		Path:               options.Path,
		Config:             cfgPath,
		Entrypoint:         entrypoint,
		Runtime:            options.Runtime,
		Execution:          options.Execution,
		VerifyReproducible: options.VerifyReproducible,
		Contract:           contractFromConfig(cfg),
		StartedAt:          time.Now().UTC().Format(time.RFC3339Nano),
	}
	if info.IsDir() {
		fingerprint, fingerprintErr := evidence.FingerprintTree(options.Path)
		if fingerprintErr != nil {
			return Persisted{}, fmt.Errorf("fingerprint matrix source: %w", fingerprintErr)
		}
		report.SourceTreeFingerprint = &fingerprint
	} else if fingerprint, fingerprintErr := evidence.FingerprintFile(options.Path); fingerprintErr != nil {
		return Persisted{}, fmt.Errorf("fingerprint matrix source: %w", fingerprintErr)
	} else {
		report.SourceFingerprint = &fingerprint
	}
	if cfgPath != "" {
		fingerprint, fingerprintErr := evidence.FingerprintFile(cfgPath)
		if fingerprintErr != nil {
			return Persisted{}, fmt.Errorf("fingerprint matrix config: %w", fingerprintErr)
		}
		report.ConfigFingerprint = &fingerprint
	}
	objectsDir := filepath.Join(runDir, "objects")
	if err := os.MkdirAll(objectsDir, 0o755); err != nil {
		return Persisted{}, err
	}
	for _, planned := range plan {
		cell := runCell(report.RunID, runDir, options, report.Contract, packedArgs, entrypoint, planned)
		report.Cells = append(report.Cells, cell)
	}
	report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	report.Summary = summarize(report.Cells)
	report.Status = "pass"
	if report.Summary.Failed > 0 {
		report.Status = "fail"
	} else if report.Summary.Skipped > 0 {
		report.Status = "pass_with_skips"
	}
	jsonPath := filepath.Join(runDir, "matrix.json")
	mdPath := filepath.Join(runDir, "matrix.md")
	if err := writeJSON(jsonPath, report); err != nil {
		return Persisted{}, err
	}
	if err := os.WriteFile(mdPath, []byte(Markdown(report)), 0o644); err != nil {
		return Persisted{}, err
	}
	persisted := Persisted{Report: report, JSONPath: jsonPath, MDPath: mdPath}
	if report.Summary.Failed > 0 {
		return persisted, fmt.Errorf("compiler matrix has %d failed cell(s)", report.Summary.Failed)
	}
	return persisted, nil
}

func runCell(parentRunID, runDir string, options Options, contract RuntimeContract, packedArgs []byte, entrypoint string, planned plannedCell) Cell {
	id := strings.Join([]string{planned.Compiler, planned.Optimization, planned.Architecture}, "-")
	cell := Cell{
		ID:              id,
		Compiler:        planned.Compiler,
		Optimization:    planned.Optimization,
		Architecture:    planned.Architecture,
		CFlags:          append([]string(nil), planned.CFlags...),
		ExpectedOutcome: "success",
		Status:          cellFail,
		Classification:  "build_failed",
		Stage:           "build",
	}
	if planned.Architecture == "x86" {
		cell.ExpectedOutcome = "unsupported_arch"
	}
	build, buildErr := buildsys.BuildWithOptions(options.Path, buildsys.Options{
		Arch:               planned.Architecture,
		Compiler:           planned.Compiler,
		ExtraCFlags:        planned.CFlags,
		ParentRunID:        parentRunID,
		VerifyReproducible: options.VerifyReproducible,
	})
	cell.Build = &build
	if preserveErr := preserveBuildEvidence(runDir, id, build, &cell); preserveErr != nil {
		cell.Classification = "evidence_copy_failed"
		cell.Error = preserveErr.Error()
		return cell
	}
	if buildErr != nil {
		cell.Error = buildErr.Error()
		if planned.Compiler == "msvc" && planned.Architecture == "x86" {
			cell.Status = cellExpected
			cell.Classification = "unsupported_compiler_arch"
			cell.ExpectedOutcome = "unsupported_compiler_arch"
		} else if compilerUnavailable(build) {
			cell.Status = cellSkip
			cell.Classification = "compiler_unavailable"
			cell.ExpectedOutcome = "compiler_unavailable"
		}
		return cell
	}
	if build.Mode != "compile" {
		cell.Classification = "unsupported_build_mode"
		cell.Error = fmt.Sprintf("compiler matrix requires direct compile mode; build selected %s", build.Mode)
		return cell
	}
	artifactPath := filepath.Join(runDir, "objects", id+".o")
	if err := copyFile(build.Object, artifactPath); err != nil {
		cell.Classification = "artifact_copy_failed"
		cell.Error = err.Error()
		return cell
	}
	cell.Artifact = artifactPath
	fingerprint, fingerprintErr := evidence.FingerprintFile(artifactPath)
	if fingerprintErr != nil {
		cell.Classification = "artifact_fingerprint_failed"
		cell.Error = fingerprintErr.Error()
		return cell
	}
	cell.ArtifactFingerprint = &fingerprint
	cell.Stage = "analysis"
	analysis, analyzeErr := artifact.Analyze(artifactPath, entrypoint)
	analysis.Header = evidence.New(evidence.SchemaAnalysis, parentRunID+"/"+id+"/analysis", parentRunID)
	cell.Analysis = &analysis
	if analyzeErr != nil {
		cell.Classification = "analysis_failed"
		cell.Error = analyzeErr.Error()
		return cell
	}
	if planned.Architecture == "x86" {
		if analysis.Arch != "x86" || analysis.LoaderCompatibility == nil || analysis.LoaderCompatibility.Status != "unsupported_arch" {
			cell.Classification = "x86_classification_mismatch"
			cell.Error = fmt.Sprintf("expected unsupported_arch for x86 object; arch=%s compatibility=%+v", analysis.Arch, analysis.LoaderCompatibility)
			return cell
		}
		cell.Status = cellExpected
		cell.Classification = "expected_unsupported_arch"
		cell.Stage = "preflight"
		return cell
	}
	if analysis.Arch != "x64" || analysis.LoaderCompatibility == nil || !analysis.LoaderCompatibility.Compatible {
		cell.Classification = "loader_incompatible"
		cell.Error = fmt.Sprintf("x64 build is not loader compatible: arch=%s compatibility=%+v", analysis.Arch, analysis.LoaderCompatibility)
		return cell
	}
	shouldExecute := options.Execution == "always" || options.Execution == "auto" && runtime.GOOS == "windows" && runtime.GOARCH == "amd64"
	if !shouldExecute {
		cell.Status = cellPass
		cell.Stage = "preflight"
		if options.Execution == "never" {
			cell.Classification = "analysis_pass"
		} else {
			cell.Classification = "runtime_deferred"
		}
		return cell
	}
	cell.RuntimeAttempted = true
	cell.Stage = "runtime"
	run, runErr := runtimesvc.Run(runtimesvc.Request{
		Path:      artifactPath,
		Entry:     entrypoint,
		ArgHex:    argpack.Hex(packedArgs),
		Tokens:    contract.Args,
		TimeoutMS: contract.TimeoutMS,
		Runtime:   options.Runtime,
	})
	run.Header = evidence.New(evidence.SchemaRun, parentRunID+"/"+id+"/run", parentRunID)
	cell.Run = &run
	if err := validateRunContract(contract, run, runErr); err != nil {
		cell.Classification = "runtime_failed"
		cell.Error = err.Error()
		return cell
	}
	cell.Status = cellPass
	cell.Classification = "runtime_pass"
	return cell
}

func normalizeOptions(options *Options) ([]plannedCell, error) {
	if options == nil || strings.TrimSpace(options.Path) == "" {
		return nil, fmt.Errorf("matrix source path is required")
	}
	compilers, err := normalizeList(options.Compilers, []string{"mingw", "msvc"}, map[string]bool{"mingw": true, "msvc": true}, "compiler")
	if err != nil {
		return nil, err
	}
	optimizations, err := normalizeList(options.Optimizations, []string{"debug", "size", "speed"}, map[string]bool{"debug": true, "size": true, "speed": true}, "optimization")
	if err != nil {
		return nil, err
	}
	architecture := strings.ToLower(strings.TrimSpace(options.Architecture))
	if architecture == "" {
		architecture = "all"
	}
	var architectures []string
	switch architecture {
	case "x64", "x86":
		architectures = []string{architecture}
	case "all":
		architectures = []string{"x64", "x86"}
	default:
		return nil, fmt.Errorf("matrix architecture must be x64, x86, or all; got %q", architecture)
	}
	options.Architecture = architecture
	options.Execution = strings.ToLower(strings.TrimSpace(options.Execution))
	if options.Execution == "" {
		options.Execution = "auto"
	}
	if options.Execution != "auto" && options.Execution != "always" && options.Execution != "never" {
		return nil, fmt.Errorf("matrix execution must be auto, always, or never; got %q", options.Execution)
	}
	if strings.TrimSpace(options.Runtime) == "" {
		options.Runtime = "windows-coff"
	}
	var plan []plannedCell
	for _, compiler := range compilers {
		for _, optimization := range optimizations {
			for _, arch := range architectures {
				plan = append(plan, plannedCell{Compiler: compiler, Optimization: optimization, Architecture: arch, CFlags: optimizationFlags(compiler, optimization)})
			}
		}
	}
	return plan, nil
}

func normalizeList(input, defaults []string, allowed map[string]bool, label string) ([]string, error) {
	if len(input) == 0 {
		input = defaults
	}
	seen := map[string]bool{}
	var result []string
	for _, raw := range input {
		for _, value := range strings.Split(raw, ",") {
			value = strings.ToLower(strings.TrimSpace(value))
			if value == "" {
				continue
			}
			if !allowed[value] {
				return nil, fmt.Errorf("unsupported matrix %s %q", label, value)
			}
			if !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("matrix %s list is empty", label)
	}
	return result, nil
}

func optimizationFlags(compiler, optimization string) []string {
	if compiler == "msvc" {
		switch optimization {
		case "debug":
			return []string{"/Od"}
		case "size":
			return []string{"/O1"}
		default:
			return []string{"/O2"}
		}
	}
	switch optimization {
	case "debug":
		return []string{"-O0"}
	case "size":
		return []string{"-Os"}
	default:
		return []string{"-O2"}
	}
}

func compilerUnavailable(build buildsys.Result) bool {
	for _, diagnostic := range build.Diagnostics {
		if diagnostic.Code == "compiler_unavailable" || diagnostic.Code == "build_tool_unavailable" {
			return true
		}
	}
	return false
}

func validateRun(cfg config.Project, run runtimesvc.Result, runErr error) error {
	return validateRunContract(contractFromConfig(cfg), run, runErr)
}

func contractFromConfig(cfg config.Project) RuntimeContract {
	return RuntimeContract{
		Args:           append([]string(nil), cfg.Args...),
		Expect:         append([]string(nil), cfg.Expect...),
		Forbid:         append([]string(nil), cfg.Forbid...),
		TimeoutMS:      cfg.TimeoutMS,
		ExpectedExit:   cfg.ExpectedExit,
		ExpectedStatus: cfg.ExpectedStatus,
	}
}

func validateRunContract(contract RuntimeContract, run runtimesvc.Result, runErr error) error {
	if contract.ExpectedExit != "" && run.ExitState != contract.ExpectedExit {
		return fmt.Errorf("exit state %s; expected %s", run.ExitState, contract.ExpectedExit)
	}
	if contract.ExpectedStatus != "" && run.Status != contract.ExpectedStatus {
		return fmt.Errorf("status %s; expected %s", run.Status, contract.ExpectedStatus)
	}
	expectedTerminal := contract.ExpectedExit != "" || contract.ExpectedStatus != ""
	if runErr != nil && !expectedTerminal {
		return runErr
	}
	if run.Status != "pass" && !expectedTerminal {
		return fmt.Errorf("runtime status %s exit_state=%s", run.Status, run.ExitState)
	}
	output := strings.Join(run.Output, "\n")
	for _, expected := range contract.Expect {
		if !strings.Contains(output, expected) {
			return fmt.Errorf("missing expected output %q", expected)
		}
	}
	for _, forbidden := range contract.Forbid {
		if strings.Contains(output, forbidden) {
			return fmt.Errorf("forbidden output %q was present", forbidden)
		}
	}
	return nil
}

func summarize(cells []Cell) Summary {
	summary := Summary{
		ByCompiler:       map[string]StatusCounts{},
		ByOptimization:   map[string]StatusCounts{},
		ByArchitecture:   map[string]StatusCounts{},
		ByClassification: map[string]int{},
	}
	for _, cell := range cells {
		summary.Total++
		switch cell.Status {
		case cellPass:
			summary.Passed++
		case cellExpected:
			summary.Expected++
		case cellSkip:
			summary.Skipped++
		default:
			summary.Failed++
		}
		summary.ByCompiler[cell.Compiler] = addCount(summary.ByCompiler[cell.Compiler], cell.Status)
		summary.ByOptimization[cell.Optimization] = addCount(summary.ByOptimization[cell.Optimization], cell.Status)
		summary.ByArchitecture[cell.Architecture] = addCount(summary.ByArchitecture[cell.Architecture], cell.Status)
		summary.ByClassification[cell.Classification]++
	}
	return summary
}

func addCount(counts StatusCounts, status string) StatusCounts {
	counts.Total++
	switch status {
	case cellPass:
		counts.Passed++
	case cellExpected:
		counts.Expected++
	case cellSkip:
		counts.Skipped++
	default:
		counts.Failed++
	}
	return counts
}

func Text(report Report) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "BOFBench compiler/runtime matrix: %s\n", report.Status)
	fmt.Fprintf(&builder, "matrix: %d pass, %d expected, %d skipped, %d failed, %d total\n", report.Summary.Passed, report.Summary.Expected, report.Summary.Skipped, report.Summary.Failed, report.Summary.Total)
	for _, cell := range report.Cells {
		fmt.Fprintf(&builder, "%-24s %-8s %-10s %-4s %-8s %s", cell.ID, cell.Compiler, cell.Optimization, cell.Architecture, cell.Status, cell.Classification)
		if cell.Error != "" {
			fmt.Fprintf(&builder, " — %s", cell.Error)
		}
		builder.WriteByte('\n')
	}
	return builder.String()
}

func Markdown(report Report) string {
	var builder strings.Builder
	builder.WriteString("# Compiler/Runtime Matrix\n\n")
	fmt.Fprintf(&builder, "- Schema: `%s` version `%d`\n", report.Schema, report.SchemaVersion)
	fmt.Fprintf(&builder, "- Run: `%s`\n- Source: `%s`\n- Status: `%s`\n- Runtime: `%s` (`%s`)\n- Reproducibility: `%t`\n", report.RunID, report.Path, report.Status, report.Runtime, report.Execution, report.VerifyReproducible)
	if report.ReplayOf != "" {
		fmt.Fprintf(&builder, "- Replay of: `%s`\n", report.ReplayOf)
	}
	fmt.Fprintf(&builder, "\n%d cells: %d pass, %d expected, %d skipped, %d failed.\n", report.Summary.Total, report.Summary.Passed, report.Summary.Expected, report.Summary.Skipped, report.Summary.Failed)
	builder.WriteString("\n| Cell | Compiler | Optimization | Arch | Flags | Status | Classification | Artifact |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, cell := range report.Cells {
		fmt.Fprintf(&builder, "| `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` |\n", cell.ID, cell.Compiler, cell.Optimization, cell.Architecture, strings.Join(cell.CFlags, " "), cell.Status, cell.Classification, cell.Artifact)
		if cell.Error != "" {
			fmt.Fprintf(&builder, "\n> `%s`: %s\n", cell.ID, cell.Error)
		}
	}
	builder.WriteString("\n## Classification Counts\n\n")
	keys := make([]string, 0, len(report.Summary.ByClassification))
	for key := range report.Summary.ByClassification {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&builder, "- `%s`: %d\n", key, report.Summary.ByClassification[key])
	}
	return builder.String()
}

func copyFile(source, destination string) error {
	value, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, value, 0o644)
}

func preserveBuildEvidence(runDir, id string, build buildsys.Result, cell *Cell) error {
	if cell == nil {
		return fmt.Errorf("matrix cell is nil")
	}
	directory := filepath.Join(runDir, "builds", id)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	evidencePath := filepath.Join(directory, "build.json")
	logPath := filepath.Join(directory, "build.log")
	if err := copyFile(build.EvidencePath, evidencePath); err != nil {
		return fmt.Errorf("preserve build evidence for %s: %w", id, err)
	}
	if err := copyFile(build.LogPath, logPath); err != nil {
		return fmt.Errorf("preserve build log for %s: %w", id, err)
	}
	cell.BuildEvidence = evidencePath
	cell.BuildLog = logPath
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func safeName(value string) string {
	value = strings.ToLower(value)
	return strings.NewReplacer(" ", "-", "_", "-", ".", "-").Replace(value)
}
