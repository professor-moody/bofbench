package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/professor-moody/bofbench/internal/evidence"
)

type SmokeOptions struct {
	RepoRoot    string
	Select      string
	TimeoutMS   int
	BofbenchExe string
	SkipFetch   bool
	Script      string
	Shell       string
}

type Summary struct {
	evidence.Header
	Path        string         `json:"path,omitempty"`
	GeneratedAt string         `json:"generated_at"`
	RepoRoot    string         `json:"repo_root"`
	Selection   string         `json:"selection"`
	TimeoutMS   int            `json:"timeout_ms"`
	Status      string         `json:"status"`
	Steps       []Step         `json:"steps"`
	Environment LabEnvironment `json:"environment"`
}

type LabEnvironment struct {
	ComputerName   string `json:"computer_name,omitempty"`
	OSVersion      string `json:"os_version,omitempty"`
	OSArchitecture string `json:"os_architecture,omitempty"`
	PowerShell     string `json:"powershell,omitempty"`
	GoVersion      string `json:"go_version,omitempty"`
	Compiler       string `json:"compiler,omitempty"`
	BofbenchSHA256 string `json:"bofbench_sha256,omitempty"`
	LoaderSHA256   string `json:"loader_sha256,omitempty"`
}

type Step struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	StartedAt  string `json:"started_at"`
	DurationMS int    `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

func DefaultSmokeOptions(repoRoot string) SmokeOptions {
	if repoRoot == "" {
		if cwd, err := os.Getwd(); err == nil {
			repoRoot = cwd
		} else {
			repoRoot = "."
		}
	}
	return SmokeOptions{
		RepoRoot:    repoRoot,
		Select:      "whoami,ipconfig,env",
		TimeoutMS:   5000,
		Script:      labScriptPath(repoRoot),
		BofbenchExe: labRunnerPath(repoRoot),
	}
}

func PowerShell() string {
	if p, err := exec.LookPath("pwsh"); err == nil {
		return p
	}
	if p, err := exec.LookPath("powershell"); err == nil {
		return p
	}
	return "pwsh"
}

func SmokeArgs(opts SmokeOptions) []string {
	shell := opts.Shell
	if shell == "" {
		shell = PowerShell()
	}
	script := opts.Script
	if script == "" {
		script = labScriptPath(opts.RepoRoot)
	}
	timeout := opts.TimeoutMS
	if timeout <= 0 {
		timeout = 5000
	}
	selectList := opts.Select
	if strings.TrimSpace(selectList) == "" {
		selectList = "whoami,ipconfig,env"
	}
	args := []string{shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, "-RepoRoot", opts.RepoRoot, "-Select", selectList, "-TimeoutMS", strconv.Itoa(timeout)}
	if opts.BofbenchExe != "" {
		args = append(args, "-BofbenchExe", opts.BofbenchExe)
	}
	if opts.SkipFetch {
		args = append(args, "-SkipFetch")
	}
	return args
}

func labScriptPath(repoRoot string) string {
	if looksWindowsPath(repoRoot) {
		return strings.TrimRight(repoRoot, `\/`) + `\scripts\windows-lab-smoke.ps1`
	}
	return filepath.Join(repoRoot, "scripts", "windows-lab-smoke.ps1")
}

func labRunnerPath(repoRoot string) string {
	if looksWindowsPath(repoRoot) {
		return `work\bin\bofbench-lab.exe`
	}
	return filepath.Join("work", "bin", "bofbench-lab.exe")
}

func looksWindowsPath(path string) bool {
	return strings.Contains(path, `\`) || (len(path) >= 2 && path[1] == ':')
}

func RunSmoke(ctx context.Context, stdout, stderr io.Writer, opts SmokeOptions) error {
	args := SmokeArgs(opts)
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func LatestSummaryPath(root string) (string, error) {
	if root == "" {
		root = "."
	}
	matches, err := filepath.Glob(filepath.Join(root, "runs", "*-lab-smoke", "lab-smoke.json"))
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no lab smoke summaries found under %s", filepath.Join(root, "runs"))
	}
	sort.Slice(matches, func(i, j int) bool {
		ii, ierr := os.Stat(matches[i])
		ji, jerr := os.Stat(matches[j])
		if ierr != nil || jerr != nil {
			return matches[i] > matches[j]
		}
		return ii.ModTime().After(ji.ModTime())
	})
	return matches[0], nil
}

func LoadSummary(path string) (Summary, error) {
	if path == "" {
		latest, err := LatestSummaryPath(".")
		if err != nil {
			return Summary{}, err
		}
		path = latest
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Summary{}, err
	}
	var summary Summary
	if err := json.Unmarshal(b, &summary); err != nil {
		return Summary{}, err
	}
	summary.Path = path
	return summary, nil
}

func Text(summary Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Lab Smoke Summary\n\n")
	if summary.Schema != "" {
		fmt.Fprintf(&b, "- Schema: `%s` version `%d`\n", summary.Schema, summary.SchemaVersion)
	}
	if summary.RunID != "" {
		fmt.Fprintf(&b, "- Run ID: `%s`\n", summary.RunID)
	}
	if summary.Path != "" {
		fmt.Fprintf(&b, "- Path: `%s`\n", summary.Path)
	}
	fmt.Fprintf(&b, "- Status: `%s`\n", summary.Status)
	fmt.Fprintf(&b, "- Generated: `%s`\n", summary.GeneratedAt)
	fmt.Fprintf(&b, "- Repo: `%s`\n", summary.RepoRoot)
	fmt.Fprintf(&b, "- Selection: `%s`\n", summary.Selection)
	fmt.Fprintf(&b, "- Timeout: `%dms`\n\n", summary.TimeoutMS)
	if summary.Environment.OSVersion != "" {
		fmt.Fprintf(&b, "- Lab OS: `%s` (`%s`)\n", summary.Environment.OSVersion, summary.Environment.OSArchitecture)
		fmt.Fprintf(&b, "- BOFBench SHA-256: `%s`\n", summary.Environment.BofbenchSHA256)
		fmt.Fprintf(&b, "- Loader SHA-256: `%s`\n\n", summary.Environment.LoaderSHA256)
	}
	b.WriteString("| Step | Status | Duration | Error |\n")
	b.WriteString("| --- | --- | ---: | --- |\n")
	for _, step := range summary.Steps {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%dms` | %s |\n", step.Name, step.Status, step.DurationMS, tableText(step.Error))
	}
	return b.String()
}

func tableText(s string) string {
	s = strings.ReplaceAll(s, "\n", "<br>")
	s = strings.ReplaceAll(s, "|", "\\|")
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return s
}
