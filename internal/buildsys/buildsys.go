package buildsys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"bofbench/internal/config"
	"bofbench/internal/evidence"
	"bofbench/internal/runlog"
)

const buildTimeout = 90 * time.Second

type Options struct {
	Arch               string
	Compiler           string
	ExtraCFlags        []string
	ParentRunID        string
	VerifyReproducible bool
}

type CompilerInfo struct {
	Requested  string `json:"requested"`
	Profile    string `json:"profile"`
	SelectedBy string `json:"selected_by"`
	Command    string `json:"command"`
	Path       string `json:"path,omitempty"`
	Version    string `json:"version,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

type Diagnostic struct {
	Severity string `json:"severity"`
	Tool     string `json:"tool"`
	Code     string `json:"code"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Message  string `json:"message"`
	Raw      string `json:"raw,omitempty"`
}

type Reproducibility struct {
	Checked      bool                     `json:"checked"`
	Reproducible bool                     `json:"reproducible"`
	Method       string                   `json:"method"`
	First        evidence.FileFingerprint `json:"first"`
	Second       evidence.FileFingerprint `json:"second"`
}

type Result struct {
	evidence.Header
	Source                string                    `json:"source"`
	SourceFingerprint     *evidence.FileFingerprint `json:"source_fingerprint,omitempty"`
	SourceTreeFingerprint *evidence.TreeFingerprint `json:"source_tree_fingerprint,omitempty"`
	Config                string                    `json:"config,omitempty"`
	ConfigFingerprint     *evidence.FileFingerprint `json:"config_fingerprint,omitempty"`
	ObjectFingerprint     *evidence.FileFingerprint `json:"object_fingerprint,omitempty"`
	Name                  string                    `json:"name"`
	Arch                  string                    `json:"arch"`
	Object                string                    `json:"object"`
	Mode                  string                    `json:"mode,omitempty"`
	Compiler              CompilerInfo              `json:"compiler"`
	CFlags                []string                  `json:"cflags,omitempty"`
	Deterministic         bool                      `json:"deterministic"`
	VerifyReproducible    bool                      `json:"verify_reproducible"`
	WorkingDirectory      string                    `json:"working_directory,omitempty"`
	Environment           map[string]string         `json:"environment,omitempty"`
	Command               []string                  `json:"command,omitempty"`
	ExitCode              *int                      `json:"exit_code,omitempty"`
	Diagnostics           []Diagnostic              `json:"diagnostics,omitempty"`
	Reproducibility       *Reproducibility          `json:"reproducibility,omitempty"`
	LogPath               string                    `json:"log_path"`
	EvidencePath          string                    `json:"evidence_path"`
	Status                string                    `json:"status"`
	Error                 string                    `json:"error,omitempty"`
	Duration              string                    `json:"duration"`
}

func Build(input, arch string) (Result, error) {
	return BuildWithOptions(input, Options{Arch: arch})
}

func BuildWithOptions(input string, opts Options) (res Result, returnErr error) {
	started := time.Now()
	arch := strings.ToLower(strings.TrimSpace(opts.Arch))
	if arch == "" {
		arch = "x64"
	}
	initialName := inferName(input)
	runDir, err := runlog.NewDir("build-" + safeName(initialName))
	if err != nil {
		return Result{}, err
	}
	res = Result{
		Header:             evidence.New(evidence.SchemaBuild, runlog.ID(runDir), opts.ParentRunID),
		Source:             input,
		Name:               initialName,
		Arch:               arch,
		Object:             filepath.Join("dist", fmt.Sprintf("%s.%s.o", initialName, arch)),
		VerifyReproducible: opts.VerifyReproducible,
		LogPath:            filepath.Join(runDir, "build.log"),
		EvidencePath:       filepath.Join(runDir, "build.json"),
		Status:             "error",
	}
	defer func() {
		res.Duration = time.Since(started).String()
		if returnErr != nil {
			res.Error = returnErr.Error()
		}
		if _, statErr := os.Stat(res.LogPath); os.IsNotExist(statErr) {
			message := res.Error
			if message == "" {
				message = "build stopped before command execution"
			}
			_ = os.WriteFile(res.LogPath, []byte(message+"\n"), 0o644)
		}
		if writeErr := writeBuildResult(res.EvidencePath, res); writeErr != nil && returnErr == nil {
			returnErr = fmt.Errorf("write build evidence: %w", writeErr)
		}
	}()

	if arch != "x64" && arch != "x86" {
		err := fmt.Errorf("unsupported build architecture %q; expected x64 or x86", arch)
		addDiagnostic(&res, "error", "bofbench", "unsupported_arch", err.Error(), "")
		return res, err
	}
	if err := fingerprintSource(&res, input); err != nil {
		addDiagnostic(&res, "error", "bofbench", "source_unavailable", err.Error(), "")
		return res, err
	}

	cfg, cfgPath, err := config.LoadFor(input)
	res.Config = cfgPath
	setConfigFingerprint(&res, cfgPath)
	if err != nil {
		var configErr *config.Error
		if errors.As(err, &configErr) {
			for _, diagnostic := range configErr.Diagnostics {
				res.Diagnostics = append(res.Diagnostics, Diagnostic{
					Severity: "error",
					Tool:     "config",
					Code:     diagnostic.Code,
					File:     configErr.Path,
					Line:     diagnostic.Line,
					Column:   diagnostic.Column,
					Message:  diagnostic.Detail,
				})
			}
		} else {
			addDiagnostic(&res, "error", "config", "config_read", err.Error(), "")
		}
		return res, err
	}
	if cfg.Name != "" {
		res.Name = cfg.Name
	}
	res.Object = filepath.Join("dist", fmt.Sprintf("%s.%s.o", res.Name, arch))
	res.CFlags = append([]string(nil), cfg.CFlags...)
	res.CFlags = append(res.CFlags, opts.ExtraCFlags...)
	res.Deterministic = cfg.Deterministic

	outAbs, err := filepath.Abs(res.Object)
	if err != nil {
		addDiagnostic(&res, "error", "bofbench", "output_path", err.Error(), "")
		return res, err
	}
	workingDirectory, err := filepath.Abs(commandDir(input))
	if err != nil {
		addDiagnostic(&res, "error", "bofbench", "working_directory", err.Error(), "")
		return res, err
	}
	res.WorkingDirectory = workingDirectory
	res.Environment = deterministicEnvironment(cfg.Deterministic)

	if isObject(input) {
		res.Mode = "copy"
		res.Compiler = CompilerInfo{Requested: "none", Profile: "copy", SelectedBy: "artifact", Command: "copy"}
		if err := copyFile(input, res.Object); err != nil {
			addDiagnostic(&res, "error", "bofbench", "copy_failed", err.Error(), "")
			return res, err
		}
		if err := os.WriteFile(res.LogPath, []byte("copied existing object\n"), 0o644); err != nil {
			return res, err
		}
		setObjectFingerprint(&res)
		if opts.VerifyReproducible && res.ObjectFingerprint != nil {
			res.Reproducibility = &Reproducibility{
				Checked:      true,
				Reproducible: true,
				Method:       "existing_object_copy",
				First:        *res.ObjectFingerprint,
				Second:       *res.ObjectFingerprint,
			}
		}
		res.Status = "copied"
		return res, nil
	}

	var cmd []string
	requestedCompiler, selectedBy, err := requestedCompiler(cfg.Compiler, opts.Compiler)
	if err != nil {
		addDiagnostic(&res, "error", "bofbench", "compiler_profile", err.Error(), "")
		return res, err
	}
	if strings.TrimSpace(opts.Compiler) == "" && !cfg.CompilerSet {
		selectedBy = "default"
	}
	switch {
	case cfg.BuildCommand != "":
		res.Mode = "custom"
		cmd = shellCommand(cfg.BuildCommand)
		res.Compiler = commandProvenance(requestedCompiler, "custom", "project", cmd[0])
		addDiagnostic(&res, "warning", "bofbench", "compiler_provenance_indirect", "custom build command controls compiler selection; provenance identifies the command dispatcher", "")
	case hasFile(input, "Makefile") || hasFile(input, "makefile"):
		res.Mode = "make"
		cmd = []string{"make"}
		res.Compiler = commandProvenance(requestedCompiler, "make", "project", cmd[0])
		addDiagnostic(&res, "warning", "bofbench", "compiler_provenance_indirect", "Makefile controls compiler selection; provenance identifies make", "")
	case hasFile(input, "CMakeLists.txt"):
		res.Mode = "cmake"
		cmd = []string{"cmake", "--build", "build"}
		res.Compiler = commandProvenance(requestedCompiler, "cmake", "project", cmd[0])
		addDiagnostic(&res, "warning", "bofbench", "compiler_provenance_indirect", "CMake project controls compiler selection; provenance identifies cmake", "")
	default:
		res.Mode = "compile"
		source, findErr := findCSource(input)
		if findErr != nil {
			addDiagnostic(&res, "error", "bofbench", "source_selection", findErr.Error(), "")
			return res, findErr
		}
		sourceAbs, absErr := filepath.Abs(source)
		if absErr != nil {
			addDiagnostic(&res, "error", "bofbench", "source_path", absErr.Error(), "")
			return res, absErr
		}
		res.Compiler = CompilerInfo{Requested: requestedCompiler, Profile: requestedCompiler, SelectedBy: selectedBy, Command: compilerFor(arch)}
		profile, executable, selectErr := selectCompiler(requestedCompiler, arch)
		if selectErr != nil {
			addDiagnostic(&res, "error", "bofbench", "compiler_unavailable", selectErr.Error(), "")
			return res, selectErr
		}
		res.Compiler = commandProvenance(requestedCompiler, profile, selectedBy, executable)
		seed := reproducibilitySeed(res)
		cmd = compileCommand(profile, arch, executable, sourceAbs, outAbs, filepath.Dir(sourceAbs), res.CFlags, cfg.Deterministic, seed)
	}
	res.Command = append([]string(nil), cmd...)
	if res.Compiler.Path == "" {
		err := fmt.Errorf("build command %q is not available on PATH", cmd[0])
		addDiagnostic(&res, "error", "bofbench", "build_tool_unavailable", err.Error(), "")
		return res, err
	}
	if err := os.MkdirAll(filepath.Dir(res.Object), 0o755); err != nil {
		addDiagnostic(&res, "error", "bofbench", "output_directory", err.Error(), "")
		return res, err
	}
	_ = os.Remove(res.Object)

	first := executeBuild(cmd, res.WorkingDirectory, res.Environment)
	res.ExitCode = intPointer(first.ExitCode)
	res.Diagnostics = append(res.Diagnostics, parseCompilerDiagnostics(first.Output, res.Compiler.Profile)...)
	logData := formatBuildLog(cmd, first, nil)
	if writeErr := os.WriteFile(res.LogPath, logData, 0o644); writeErr != nil {
		return res, writeErr
	}
	if first.Err != nil {
		if !hasErrorDiagnostic(res.Diagnostics) {
			addDiagnostic(&res, "error", res.Compiler.Profile, "execution_failed", first.Err.Error(), strings.TrimSpace(first.Output))
		}
		if first.TimedOut {
			res.Status = "timeout"
		}
		return res, fmt.Errorf("build failed: %w; log: %s", first.Err, res.LogPath)
	}
	if err := materializeObject(res.Object, outAbs, res.WorkingDirectory, arch); err != nil {
		addDiagnostic(&res, "error", "bofbench", "object_missing", err.Error(), "")
		return res, err
	}
	firstFingerprint, err := evidence.FingerprintFile(res.Object)
	if err != nil {
		addDiagnostic(&res, "error", "bofbench", "object_fingerprint", err.Error(), "")
		return res, err
	}

	if opts.VerifyReproducible {
		method := "repeat_command"
		if res.Mode == "compile" {
			method = "double_compile"
		}
		if err := os.Remove(res.Object); err != nil && !os.IsNotExist(err) {
			return res, err
		}
		second := executeBuild(cmd, res.WorkingDirectory, res.Environment)
		res.ExitCode = intPointer(second.ExitCode)
		secondDiagnostics := parseCompilerDiagnostics(second.Output, res.Compiler.Profile)
		res.Diagnostics = append(res.Diagnostics, secondDiagnostics...)
		logData = formatBuildLog(cmd, first, &second)
		if writeErr := os.WriteFile(res.LogPath, logData, 0o644); writeErr != nil {
			return res, writeErr
		}
		check := &Reproducibility{Checked: true, Method: method, First: firstFingerprint}
		res.Reproducibility = check
		if second.Err != nil {
			if !hasErrorDiagnostic(secondDiagnostics) {
				addDiagnostic(&res, "error", res.Compiler.Profile, "rebuild_failed", second.Err.Error(), strings.TrimSpace(second.Output))
			}
			return res, fmt.Errorf("reproducibility rebuild failed: %w; log: %s", second.Err, res.LogPath)
		}
		if err := materializeObject(res.Object, outAbs, res.WorkingDirectory, arch); err != nil {
			addDiagnostic(&res, "error", "bofbench", "rebuild_object_missing", err.Error(), "")
			return res, err
		}
		secondFingerprint, fingerprintErr := evidence.FingerprintFile(res.Object)
		if fingerprintErr != nil {
			return res, fingerprintErr
		}
		check.Second = secondFingerprint
		check.Reproducible = firstFingerprint.SHA256 == secondFingerprint.SHA256 && firstFingerprint.Size == secondFingerprint.Size
		res.ObjectFingerprint = &secondFingerprint
		if !check.Reproducible {
			res.Status = "non_reproducible"
			err := fmt.Errorf("reproducibility check failed: first sha256 %s, second sha256 %s", firstFingerprint.SHA256, secondFingerprint.SHA256)
			addDiagnostic(&res, "error", "bofbench", "non_reproducible", err.Error(), "")
			return res, err
		}
	} else {
		res.ObjectFingerprint = &firstFingerprint
	}

	res.Status = "built"
	return res, nil
}

type execution struct {
	Output   string
	ExitCode int
	TimedOut bool
	Err      error
}

func executeBuild(command []string, directory string, environment map[string]string) execution {
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = directory
	cmd.Env = mergeEnvironment(os.Environ(), environment)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}
	return execution{Output: combined.String(), ExitCode: exitCode, TimedOut: ctx.Err() == context.DeadlineExceeded, Err: err}
}

func formatBuildLog(command []string, first execution, second *execution) []byte {
	var log strings.Builder
	fmt.Fprintf(&log, "command: %s\n\n[build 1]\n%s", strings.Join(command, " "), first.Output)
	if first.Output != "" && !strings.HasSuffix(first.Output, "\n") {
		log.WriteByte('\n')
	}
	if second != nil {
		fmt.Fprintf(&log, "\n[build 2]\n%s", second.Output)
		if second.Output != "" && !strings.HasSuffix(second.Output, "\n") {
			log.WriteByte('\n')
		}
	}
	return []byte(log.String())
}

func fingerprintSource(result *Result, input string) error {
	info, err := os.Stat(input)
	if err != nil {
		return fmt.Errorf("source %s: %w", input, err)
	}
	if info.IsDir() {
		fingerprint, err := evidence.FingerprintTree(input)
		if err != nil {
			return fmt.Errorf("fingerprint source tree %s: %w", input, err)
		}
		result.SourceTreeFingerprint = &fingerprint
		return nil
	}
	fingerprint, err := evidence.FingerprintFile(input)
	if err != nil {
		return fmt.Errorf("fingerprint source %s: %w", input, err)
	}
	result.SourceFingerprint = &fingerprint
	return nil
}

func setConfigFingerprint(result *Result, path string) {
	if path == "" {
		return
	}
	if fingerprint, err := evidence.FingerprintFile(path); err == nil {
		result.ConfigFingerprint = &fingerprint
	}
}

func setObjectFingerprint(result *Result) {
	if result == nil || result.Object == "" {
		return
	}
	if fingerprint, err := evidence.FingerprintFile(result.Object); err == nil {
		result.ObjectFingerprint = &fingerprint
	}
}

func writeBuildResult(path string, result Result) error {
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func materializeObject(out, outAbs, root, arch string) error {
	if _, err := os.Stat(out); err == nil {
		return nil
	}
	if _, err := os.Stat(outAbs); err == nil {
		if filepath.Clean(outAbs) == filepath.Clean(out) {
			return nil
		}
		return copyFile(outAbs, out)
	}
	candidate := newestObject(root, arch)
	if candidate == "" {
		candidate = newestObject(root, "")
	}
	if candidate == "" {
		return fmt.Errorf("build completed but no object found at %s", out)
	}
	return copyFile(candidate, out)
}

func findCSource(input string) (string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		if strings.HasSuffix(strings.ToLower(input), ".c") {
			return input, nil
		}
		return "", fmt.Errorf("%s is not a .c source or object", input)
	}
	var sources []string
	err = filepath.WalkDir(input, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "build" || entry.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(entry.Name(), "._") {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(path), ".c") {
			sources = append(sources, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(sources)
	if len(sources) == 0 {
		return "", fmt.Errorf("no .c source found under %s", input)
	}
	if len(sources) > 1 {
		return "", fmt.Errorf("multiple .c sources found under %s; add bofbench.toml build override", input)
	}
	return sources[0], nil
}

func commandDir(input string) string {
	info, err := os.Stat(input)
	if err == nil && info.IsDir() {
		return input
	}
	return filepath.Dir(input)
}

func hasFile(dir, name string) bool {
	info, err := os.Stat(filepath.Join(dir, name))
	return err == nil && !info.IsDir()
}

func isObject(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".o") || strings.HasSuffix(lower, ".obj")
}

func inferName(input string) string {
	base := filepath.Base(input)
	ext := filepath.Ext(base)
	if ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	if base == "." || base == string(filepath.Separator) || base == "" {
		base = "payload"
	}
	return safeName(base)
}

func safeName(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer(" ", "-", "_", "-", ".", "-")
	return replacer.Replace(value)
}

func shellCommand(command string) []string {
	if os.Getenv("ComSpec") != "" {
		return []string{os.Getenv("ComSpec"), "/C", command}
	}
	return []string{"sh", "-c", command}
}

func newestObject(root, arch string) string {
	var best string
	var bestTime time.Time
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		if !(strings.HasSuffix(lower, ".o") || strings.HasSuffix(lower, ".obj")) {
			return nil
		}
		if arch != "" && !strings.Contains(lower, arch) {
			return nil
		}
		info, err := entry.Info()
		if err == nil && info.ModTime().After(bestTime) {
			best = path
			bestTime = info.ModTime()
		}
		return nil
	})
	return best
}

func copyFile(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0o644)
}

func intPointer(value int) *int {
	return &value
}

func addDiagnostic(result *Result, severity, tool, code, message, raw string) {
	result.Diagnostics = append(result.Diagnostics, Diagnostic{Severity: severity, Tool: tool, Code: code, Message: message, Raw: raw})
}

func hasErrorDiagnostic(diagnostics []Diagnostic) bool {
	for _, diagnostic := range diagnostics {
		if diagnostic.Severity == "error" {
			return true
		}
	}
	return false
}
