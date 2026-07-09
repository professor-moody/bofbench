package buildsys

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"bofbench/internal/evidence"
)

var (
	gccDiagnostic  = regexp.MustCompile(`^(.+?):([0-9]+):(?:([0-9]+):)?\s*(fatal error|error|warning|note):\s*(.*)$`)
	msvcDiagnostic = regexp.MustCompile(`^(.+)\(([0-9]+)(?:,([0-9]+))?\):\s*(fatal error|error|warning|note)\s*([A-Za-z]+[0-9]+)?:?\s*(.*)$`)
)

func requestedCompiler(configured, override string) (string, string, error) {
	configured = strings.ToLower(strings.TrimSpace(configured))
	override = strings.ToLower(strings.TrimSpace(override))
	if configured == "" {
		configured = "auto"
	}
	if override != "" {
		if !validCompilerProfile(override) {
			return "", "", fmt.Errorf("compiler must be auto, mingw, or msvc; got %q", override)
		}
		return override, "cli", nil
	}
	if !validCompilerProfile(configured) {
		return "", "", fmt.Errorf("compiler must be auto, mingw, or msvc; got %q", configured)
	}
	return configured, "config", nil
}

func validCompilerProfile(profile string) bool {
	return profile == "auto" || profile == "mingw" || profile == "msvc"
}

func selectCompiler(requested, arch string) (string, string, error) {
	mingw := compilerFor(arch)
	switch requested {
	case "mingw":
		if _, err := exec.LookPath(mingw); err != nil {
			return "", "", fmt.Errorf("MinGW %s compiler %q is unavailable on PATH", arch, mingw)
		}
		return "mingw", mingw, nil
	case "msvc":
		if arch != "x64" {
			return "", "", fmt.Errorf("MSVC profile currently supports x64 only; requested %s", arch)
		}
		if runtime.GOOS != "windows" {
			return "", "", fmt.Errorf("MSVC profile requires Windows; host is %s", runtime.GOOS)
		}
		if _, err := exec.LookPath("cl"); err != nil {
			return "", "", fmt.Errorf("MSVC compiler cl.exe is unavailable on PATH")
		}
		return "msvc", "cl", nil
	case "auto":
		if _, err := exec.LookPath(mingw); err == nil {
			return "mingw", mingw, nil
		}
		if runtime.GOOS == "windows" && arch == "x64" {
			if _, err := exec.LookPath("cl"); err == nil {
				return "msvc", "cl", nil
			}
		}
		return "", "", fmt.Errorf("no compiler available for %s: tried %q%s", arch, mingw, msvcAttempt(arch))
	default:
		return "", "", fmt.Errorf("unknown compiler profile %q", requested)
	}
}

func msvcAttempt(arch string) string {
	if runtime.GOOS == "windows" && arch == "x64" {
		return " and MSVC cl.exe"
	}
	return ""
}

func compilerFor(arch string) string {
	if arch == "x86" {
		return "i686-w64-mingw32-gcc"
	}
	return "x86_64-w64-mingw32-gcc"
}

func compileCommand(profile, arch, executable, sourceAbs, outAbs, includeDir string, cflags []string, deterministic bool, seed string) []string {
	if profile == "msvc" {
		command := []string{executable, "/nologo", "/c", sourceAbs, "/Fo:" + outAbs, "/I", includeDir, "/DBOF"}
		if deterministic {
			command = append(command, "/Brepro", "/experimental:deterministic")
			if pathMapRoot := commonDirectory(filepath.Dir(sourceAbs), filepath.Dir(outAbs)); pathMapRoot != "" {
				command = append(command, "/pathmap:"+pathMapRoot+"=.")
			}
		}
		return append(command, cflags...)
	}
	command := []string{executable, "-c", sourceAbs, "-o", outAbs, "-I", includeDir, "-DBOF"}
	if deterministic {
		command = append(command, "-frandom-seed="+seed, "-ffile-prefix-map="+includeDir+"=.")
	}
	return append(command, cflags...)
}

func commonDirectory(left, right string) string {
	candidate := filepath.Clean(left)
	right = filepath.Clean(right)
	for {
		relative, err := filepath.Rel(candidate, right)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return candidate
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return ""
		}
		candidate = parent
	}
}

func commandProvenance(requested, profile, selectedBy, command string) CompilerInfo {
	info := CompilerInfo{Requested: requested, Profile: profile, SelectedBy: selectedBy, Command: command}
	path, err := exec.LookPath(command)
	if err != nil {
		return info
	}
	if absolute, absErr := filepath.Abs(path); absErr == nil {
		path = absolute
	}
	info.Path = path
	if fingerprint, fingerprintErr := evidence.FingerprintFile(path); fingerprintErr == nil {
		info.SHA256 = fingerprint.SHA256
	}
	info.Version = commandVersion(path, profile)
	return info
}

func commandVersion(path, profile string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{"--version"}
	if profile == "msvc" {
		args = nil
	}
	output, _ := exec.CommandContext(ctx, path, args...).CombinedOutput()
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			return line
		}
	}
	return ""
}

func deterministicEnvironment(enabled bool) map[string]string {
	environment := map[string]string{}
	for _, key := range []string{"CC", "CFLAGS", "CPPFLAGS", "INCLUDE", "LIB", "LIBPATH", "LANG", "LC_ALL", "TMP", "TEMP"} {
		if value, ok := os.LookupEnv(key); ok {
			environment[key] = value
		}
	}
	if enabled {
		environment["SOURCE_DATE_EPOCH"] = "0"
		environment["ZERO_AR_DATE"] = "1"
	}
	if len(environment) == 0 {
		return nil
	}
	return environment
}

func mergeEnvironment(base []string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return base
	}
	replaced := make(map[string]bool, len(overrides))
	result := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		key, _, _ := strings.Cut(item, "=")
		if value, ok := overrides[key]; ok {
			if !replaced[key] {
				result = append(result, key+"="+value)
				replaced[key] = true
			}
			continue
		}
		result = append(result, item)
	}
	for key, value := range overrides {
		if !replaced[key] {
			result = append(result, key+"="+value)
		}
	}
	return result
}

func reproducibilitySeed(result Result) string {
	hash := "bofbench"
	if result.SourceFingerprint != nil {
		hash = result.SourceFingerprint.SHA256
	} else if result.SourceTreeFingerprint != nil {
		hash = result.SourceTreeFingerprint.SHA256
	}
	if len(result.CFlags) > 0 {
		digest := sha256.Sum256([]byte(hash + "\x00" + strings.Join(result.CFlags, "\x00")))
		hash = fmt.Sprintf("%x", digest[:])
	}
	if len(hash) <= 16 {
		return hash
	}
	return hash[:16]
}

func parseCompilerDiagnostics(output, profile string) []Diagnostic {
	var diagnostics []Diagnostic
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		if match := msvcDiagnostic.FindStringSubmatch(raw); match != nil {
			code := match[5]
			if code == "" {
				code = "compiler_" + normalizedSeverity(match[4])
			}
			diagnostics = append(diagnostics, Diagnostic{
				Severity: normalizedSeverity(match[4]),
				Tool:     toolName(profile, "msvc"),
				Code:     code,
				File:     match[1],
				Line:     parseNumber(match[2]),
				Column:   parseNumber(match[3]),
				Message:  strings.TrimSpace(match[6]),
				Raw:      raw,
			})
			continue
		}
		if match := gccDiagnostic.FindStringSubmatch(raw); match != nil {
			severity := normalizedSeverity(match[4])
			diagnostics = append(diagnostics, Diagnostic{
				Severity: severity,
				Tool:     toolName(profile, "gcc"),
				Code:     "compiler_" + severity,
				File:     match[1],
				Line:     parseNumber(match[2]),
				Column:   parseNumber(match[3]),
				Message:  strings.TrimSpace(match[5]),
				Raw:      raw,
			})
		}
	}
	return diagnostics
}

func normalizedSeverity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "fatal error" {
		return "error"
	}
	return value
}

func toolName(profile, fallback string) string {
	if profile != "" && profile != "auto" {
		return profile
	}
	return fallback
}

func parseNumber(value string) int {
	parsed, _ := strconv.Atoi(value)
	return parsed
}
