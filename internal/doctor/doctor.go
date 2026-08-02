package doctor

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/evidence"
)

type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

type Report struct {
	evidence.Header
	GeneratedAt string  `json:"generated_at"`
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	Checks      []Check `json:"checks"`
}

type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	Path   string `json:"path,omitempty"`
}

func Run() Report {
	generated := time.Now().UTC()
	r := Report{
		Header:      evidence.New(evidence.SchemaDoctor, "doctor-"+generated.Format("20060102T150405.000000000Z"), ""),
		GeneratedAt: generated.Format(time.RFC3339),
		OS:          goruntime.GOOS,
		Arch:        goruntime.GOARCH,
	}
	r.Checks = append(r.Checks,
		checkTool("go", "Go toolchain", true),
		checkTool("git", "Git client", true),
		checkCompiler(),
		checkOptionalTool("i686-w64-mingw32-gcc", "x86 MinGW compiler"),
		checkLoader(),
		checkWindowsRuntime(),
		checkOptionalTool("mkdocs", "MkDocs documentation builder"),
		checkDir("bofs", "bofs directory"),
		checkDir("arsenal", "arsenal directory"),
		checkDir("dist", "dist directory"),
		checkDir("runs", "runs directory"),
		checkDir("stage", "stage directory"),
	)
	return r
}

func (r Report) HasProblems(strict bool) bool {
	for _, check := range r.Checks {
		if check.Status == Fail {
			return true
		}
		if strict && check.Status == Warn {
			return true
		}
	}
	return false
}

func (r Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "bofbench doctor\n")
	fmt.Fprintf(&b, "schema: %s version %d\n", r.Schema, r.SchemaVersion)
	fmt.Fprintf(&b, "run: %s\n", r.RunID)
	fmt.Fprintf(&b, "host: %s/%s\n\n", r.OS, r.Arch)
	for _, check := range r.Checks {
		path := ""
		if check.Path != "" {
			path = " (" + check.Path + ")"
		}
		fmt.Fprintf(&b, "%-6s %-28s %s%s\n", strings.ToUpper(string(check.Status)), check.Name, check.Detail, path)
	}
	return b.String()
}

func checkTool(name, label string, required bool) Check {
	path, err := exec.LookPath(name)
	if err != nil {
		status := Warn
		if required {
			status = Fail
		}
		return Check{Name: label, Status: status, Detail: name + " not found on PATH"}
	}
	version := commandVersion(name)
	return Check{Name: label, Status: Pass, Detail: version, Path: path}
}

func checkOptionalTool(name, label string) Check {
	return checkTool(name, label, false)
}

func checkCompiler() Check {
	if path, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err == nil {
		return Check{Name: "x64 BOF compiler", Status: Pass, Detail: "MinGW-w64 x64 compiler", Path: path}
	}
	if goruntime.GOOS == "windows" {
		if path, err := exec.LookPath("cl"); err == nil {
			return Check{Name: "x64 BOF compiler", Status: Pass, Detail: "MSVC cl fallback", Path: path}
		}
	}
	return Check{Name: "x64 BOF compiler", Status: Warn, Detail: "x86_64-w64-mingw32-gcc not found; Windows x64 can also use cl.exe"}
}

func checkLoader() Check {
	path, source := findLoader()
	if path == "" {
		return Check{Name: "Windows COFF loader", Status: Warn, Detail: "bofbench-loader.exe not found; build native/loader or set BOFBENCH_LOADER"}
	}
	return Check{Name: "Windows COFF loader", Status: Pass, Detail: source, Path: path}
}

func checkWindowsRuntime() Check {
	path, _ := findLoader()
	if goruntime.GOOS != "windows" {
		return Check{Name: "windows-coff runtime", Status: Warn, Detail: "native execution requires Windows x64 host"}
	}
	if goruntime.GOARCH != "amd64" {
		return Check{Name: "windows-coff runtime", Status: Fail, Detail: "native execution requires amd64"}
	}
	if path == "" {
		return Check{Name: "windows-coff runtime", Status: Warn, Detail: "host is Windows x64 but loader is missing"}
	}
	return Check{Name: "windows-coff runtime", Status: Pass, Detail: "ready"}
}

func checkDir(path, label string) Check {
	info, err := os.Stat(path)
	if err != nil {
		return Check{Name: label, Status: Warn, Detail: path + " does not exist yet"}
	}
	if !info.IsDir() {
		return Check{Name: label, Status: Warn, Detail: path + " exists but is not a directory"}
	}
	return Check{Name: label, Status: Pass, Detail: "present", Path: path}
}

func findLoader() (string, string) {
	if p := os.Getenv("BOFBENCH_LOADER"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, "BOFBENCH_LOADER"
		}
		return "", ""
	}
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "bofbench-loader.exe")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, "next to bofbench binary"
		}
	}
	candidate := filepath.Join("native", "loader", "bofbench-loader.exe")
	if _, err := os.Stat(candidate); err == nil {
		return candidate, "native/loader"
	}
	return "", ""
}

func commandVersion(name string) string {
	args := []string{"--version"}
	if name == "cl" {
		args = nil
	}
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "available"
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if line == "" {
		return "available"
	}
	return line
}
