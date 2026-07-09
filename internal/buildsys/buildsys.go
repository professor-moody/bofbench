package buildsys

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"time"

	"bofbench/internal/config"
	"bofbench/internal/runlog"
)

type Result struct {
	Name     string   `json:"name"`
	Arch     string   `json:"arch"`
	Object   string   `json:"object"`
	Command  []string `json:"command,omitempty"`
	LogPath  string   `json:"log_path"`
	Status   string   `json:"status"`
	Duration string   `json:"duration"`
}

func Build(input, arch string) (Result, error) {
	start := time.Now()
	cfg, _, err := config.LoadFor(input)
	if err != nil {
		return Result{}, err
	}
	name := cfg.Name
	if name == "" {
		name = inferName(input)
	}
	out := filepath.Join("dist", fmt.Sprintf("%s.%s.o", name, arch))
	outAbs, err := filepath.Abs(out)
	if err != nil {
		return Result{}, err
	}
	runDir, err := runlog.NewDir("build-" + safeName(name))
	if err != nil {
		return Result{}, err
	}
	logPath := filepath.Join(runDir, "build.log")
	res := Result{Name: name, Arch: arch, Object: out, LogPath: logPath}
	if strings.HasSuffix(strings.ToLower(input), ".o") || strings.HasSuffix(strings.ToLower(input), ".obj") {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return res, err
		}
		if err := copyFile(input, out); err != nil {
			return res, err
		}
		_ = os.WriteFile(logPath, []byte("copied existing object\n"), 0o644)
		res.Status = "copied"
		res.Duration = time.Since(start).String()
		return res, nil
	}
	var cmd []string
	if cfg.BuildCommand != "" {
		cmd = shellCommand(cfg.BuildCommand)
	} else if hasFile(input, "Makefile") || hasFile(input, "makefile") {
		cmd = []string{"make"}
	} else if hasFile(input, "CMakeLists.txt") {
		cmd = []string{"cmake", "--build", "build"}
	} else {
		source, err := findCSource(input)
		if err != nil {
			return res, err
		}
		sourceAbs, err := filepath.Abs(source)
		if err != nil {
			return res, err
		}
		cmd = compileCommandFor(arch, sourceAbs, outAbs, filepath.Dir(sourceAbs))
	}
	res.Command = cmd
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return res, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	exe := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	exe.Dir = commandDir(input)
	var combined bytes.Buffer
	exe.Stdout = &combined
	exe.Stderr = &combined
	err = exe.Run()
	_ = os.WriteFile(logPath, combined.Bytes(), 0o644)
	if err != nil {
		res.Status = "error"
		res.Duration = time.Since(start).String()
		return res, fmt.Errorf("build failed: %w; log: %s", err, logPath)
	}
	if _, err := os.Stat(out); err != nil {
		if _, absErr := os.Stat(outAbs); absErr == nil {
			if err := copyFile(outAbs, out); err != nil {
				return res, err
			}
			res.Status = "built"
			res.Duration = time.Since(start).String()
			return res, nil
		}
		candidate := newestObject(commandDir(input), arch)
		if candidate == "" {
			res.Status = "error"
			res.Duration = time.Since(start).String()
			return res, fmt.Errorf("build completed but no object found at %s", out)
		}
		if err := copyFile(candidate, out); err != nil {
			return res, err
		}
	}
	res.Status = "built"
	res.Duration = time.Since(start).String()
	return res, nil
}

func compilerFor(arch string) string {
	if arch == "x86" {
		return "i686-w64-mingw32-gcc"
	}
	return "x86_64-w64-mingw32-gcc"
}

func compileCommandFor(arch, sourceAbs, outAbs, includeDir string) []string {
	cc := compilerFor(arch)
	if _, err := exec.LookPath(cc); err == nil {
		return []string{cc, "-c", sourceAbs, "-o", outAbs, "-I", includeDir, "-DBOF"}
	}
	if goruntime.GOOS == "windows" && arch == "x64" {
		if _, err := exec.LookPath("cl"); err == nil {
			return []string{"cl", "/nologo", "/c", sourceAbs, "/Fo:" + outAbs, "/I", includeDir, "/DBOF"}
		}
	}
	return []string{cc, "-c", sourceAbs, "-o", outAbs, "-I", includeDir, "-DBOF"}
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
	err = filepath.WalkDir(input, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "build" || d.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), "._") {
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

func safeName(s string) string {
	s = strings.ToLower(s)
	replacer := strings.NewReplacer(" ", "-", "_", "-", ".", "-")
	return replacer.Replace(s)
}

func shellCommand(cmd string) []string {
	if os.Getenv("ComSpec") != "" {
		return []string{os.Getenv("ComSpec"), "/C", cmd}
	}
	return []string{"sh", "-c", cmd}
}

func newestObject(root, arch string) string {
	var best string
	var bestTime time.Time
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		if !(strings.HasSuffix(lower, ".o") || strings.HasSuffix(lower, ".obj")) {
			return nil
		}
		if arch != "" && !strings.Contains(lower, arch) {
			return nil
		}
		info, err := d.Info()
		if err == nil && info.ModTime().After(bestTime) {
			best = path
			bestTime = info.ModTime()
		}
		return nil
	})
	return best
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}
