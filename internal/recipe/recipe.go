package recipe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"bofbench/internal/evidence"
	"bofbench/internal/runlog"
	"bofbench/internal/scaffold"
)

const (
	Schema        = "bofbench.recipe"
	SchemaVersion = 1
	SidecarName   = "bofbench.recipe.json"
)

type Document struct {
	Schema          string   `json:"schema"`
	SchemaVersion   int      `json:"schema_version"`
	Name            string   `json:"name"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Category        string   `json:"category"`
	Features        []string `json:"features"`
	Privilege       string   `json:"privilege"`
	Platforms       []string `json:"platforms"`
	Network         string   `json:"network"`
	Domain          string   `json:"domain"`
	Impact          string   `json:"impact"`
	RecommendedArgs []string `json:"recommended_args,omitempty"`
	Prerequisites   []string `json:"prerequisites"`
	StateChanges    []string `json:"state_changes"`
	Artifacts       []string `json:"artifacts"`
	Cleanup         []string `json:"cleanup"`
	OperatorNotes   []string `json:"operator_notes,omitempty"`
	Project         string   `json:"project,omitempty"`
	GeneratedAt     string   `json:"generated_at,omitempty"`
}

type ApplyResult struct {
	Path     string             `json:"path"`
	Recipe   Document           `json:"recipe"`
	Features scaffold.AddResult `json:"feature_result"`
}

type Validation struct {
	evidence.Header
	Path               string   `json:"path"`
	Recipe             string   `json:"recipe"`
	Status             string   `json:"status"`
	RequiredFeatures   []string `json:"required_features,omitempty"`
	PresentFeatures    []string `json:"present_features,omitempty"`
	MissingFeatures    []string `json:"missing_features,omitempty"`
	UnexpectedFeatures []string `json:"unexpected_features,omitempty"`
	Errors             []string `json:"errors,omitempty"`
	Warnings           []string `json:"warnings,omitempty"`
	GeneratedAt        string   `json:"generated_at"`
	EvidencePath       string   `json:"evidence_path,omitempty"`
	MarkdownPath       string   `json:"markdown_path,omitempty"`
}

func Builtins() []Document {
	values := []Document{
		{
			Name: "host-survey", Title: "Host Context Survey", Description: "Collect process, host, user, and temporary-directory context from the current Windows session.",
			Category: "discovery", Features: []string{"process", "host", "identity", "filesystem"}, Privilege: "user", Platforms: []string{"windows-x64"}, Network: "none", Domain: "optional", Impact: "read_only",
			Prerequisites: []string{"interactive or service logon context on the lab host"},
			StateChanges:  []string{"none beyond the short-lived loader process and output buffers"},
			Artifacts:     []string{"Beacon output containing PID/TID, computer name, user name, and temporary path"},
			Cleanup:       []string{"none required; all buffers are stack-local"},
			OperatorNotes: []string{"use as a low-impact first proof of loader, identity, and environment context"},
		},
		{
			Name: "network-survey", Title: "Local Network Context Survey", Description: "Report the Windows computer name and Winsock host name from the current network context.",
			Category: "network-discovery", Features: []string{"host", "network"}, Privilege: "user", Platforms: []string{"windows-x64"}, Network: "local", Domain: "optional", Impact: "read_only",
			Prerequisites: []string{"Winsock 2 is available in the Windows lab"},
			StateChanges:  []string{"initializes Winsock state inside the loader process"},
			Artifacts:     []string{"Beacon output containing computer and Winsock host names", "short-lived Winsock initialization in the loader process"},
			Cleanup:       []string{"WSACleanup executes before the BOF returns"},
			OperatorNotes: []string{"does not initiate an outbound connection or enumerate remote systems"},
		},
		{
			Name: "registry-survey", Title: "Read-Only Registry Context Survey", Description: "Read Windows product context from HKLM and report the current user.",
			Category: "registry-discovery", Features: []string{"identity", "registry"}, Privilege: "user", Platforms: []string{"windows-x64"}, Network: "none", Domain: "none", Impact: "read_only",
			Prerequisites: []string{"read access to HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"},
			StateChanges:  []string{"none; the registry is opened with KEY_QUERY_VALUE"},
			Artifacts:     []string{"Beacon output containing user and Windows product names", "short-lived read-only registry handle"},
			Cleanup:       []string{"RegCloseKey executes before the BOF returns"},
			OperatorNotes: []string{"the recipe does not create or modify registry values"},
		},
		{
			Name: "full-survey", Title: "Full Local Context Survey", Description: "Exercise the six core read-only BOFBench capabilities in one native loader run.",
			Category: "discovery", Features: []string{"process", "host", "identity", "filesystem", "network", "registry"}, Privilege: "user", Platforms: []string{"windows-x64"}, Network: "local", Domain: "optional", Impact: "read_only",
			Prerequisites: []string{"Windows x64 lab with the BOFBench native loader", "read access to the Windows product-name registry value", "Winsock 2 available"},
			StateChanges:  []string{"initializes Winsock state inside the loader process", "opens a read-only registry handle"},
			Artifacts:     []string{"Beacon output for process, host, identity, filesystem, network, and registry context", "short-lived loader process state captured in run evidence"},
			Cleanup:       []string{"WSACleanup and RegCloseKey execute before the BOF returns", "all other buffers are stack-local"},
			OperatorNotes: []string{"intended as the comprehensive BOFBench developer/lab proof before adding custom behavior"},
		},
		{
			Name: "deep-survey", Title: "Deep Read-Only Discovery Survey", Description: "Combine bounded process, token, service, TCP endpoint, domain, host, identity, filesystem, network, and registry discovery in one BOF.",
			Category: "deep-discovery", Features: []string{"process", "host", "identity", "filesystem", "network", "registry", "process-list", "token-context", "service-list", "tcp-connections", "domain-context"}, Privilege: "user", Platforms: []string{"windows-x64"}, Network: "local", Domain: "optional", Impact: "read_only",
			Prerequisites: []string{"Windows x64 lab with the BOFBench native loader or a compatible COFF loader", "standard Toolhelp, token, Service Control Manager, IP Helper, NetAPI, Winsock, and registry APIs available", "read access to local process, service, TCP, join, and product-name metadata"},
			StateChanges:  []string{"creates a short-lived process snapshot", "opens read-only token, service-manager, and registry handles", "initializes Winsock state inside the loader process"},
			Artifacts:     []string{"Beacon output for eleven bounded discovery techniques", "short-lived loader process state and run evidence", "up to sixteen process, service, and TCP rows per technique"},
			Cleanup:       []string{"closes the process snapshot, token, service-manager, and registry handles", "frees the NetAPI join buffer and calls WSACleanup before return", "all enumeration buffers are stack-local"},
			OperatorNotes: []string{"read-only lab-safe depth profile; it performs no credential access, injection, persistence, remote scanning, or state modification", "use individual packs when the full eleven-technique output is unnecessary"},
		},
		{
			Name: "active-actions", Title: "Active Offensive Lab Actions", Description: "Execute four observable and reversible lab actions without the discovery output.",
			Category: "offensive-lab", Features: []string{"lab-file-write", "lab-registry-write", "lab-run-key", "lab-process-launch"}, Privilege: "user", Platforms: []string{"windows-x64"}, Network: "none", Domain: "none", Impact: "modifies_state",
			Prerequisites: []string{"authorized disposable Windows x64 lab", "permission to create files in the current temporary directory and values under the current-user registry hive"},
			StateChanges:  []string{"creates %TEMP%\\bofbench-active-marker.txt", "sets HKCU\\Software\\BOFBench\\LabMarker", "sets the inert HKCU Run value BOFBenchLab", "launches a bounded cmd.exe child that creates %TEMP%\\bofbench-process-marker.txt"},
			Artifacts:     []string{"two BOFBench-owned temporary marker files", "one BOFBench-owned current-user registry key", "one inert BOFBenchLab Run value", "short-lived child process and loader evidence"},
			Cleanup:       []string{"run the active-cleanup recipe through the same loader or Sliver session", "verify both marker files, HKCU\\Software\\BOFBench, and the BOFBenchLab Run value are absent"},
			OperatorNotes: []string{"authorized internal-lab use only", "the Run value executes only cmd.exe /d /c exit 0 and exists solely as a reversible persistence proof"},
		},
		{
			Name: "offensive-survey", Title: "Active Offensive Lab Survey", Description: "Combine deep discovery with observable file, registry, and child-process actions for an authorized lab operation.",
			Category: "offensive-lab", Features: []string{"process", "host", "identity", "filesystem", "network", "registry", "process-list", "token-context", "service-list", "tcp-connections", "domain-context", "lab-file-write", "lab-registry-write", "lab-run-key", "lab-process-launch"}, Privilege: "user", Platforms: []string{"windows-x64"}, Network: "local", Domain: "optional", Impact: "modifies_state",
			Prerequisites: []string{"authorized disposable Windows x64 lab", "BOFBench native loader or compatible COFF loader", "permission to create files in the current temporary directory and values under HKCU\\Software"},
			StateChanges:  []string{"creates %TEMP%\\bofbench-active-marker.txt", "sets HKCU\\Software\\BOFBench\\LabMarker", "sets the inert HKCU Run value BOFBenchLab", "launches a bounded cmd.exe child that creates %TEMP%\\bofbench-process-marker.txt"},
			Artifacts:     []string{"Beacon output for eleven discovery and four active techniques", "two BOFBench-owned temporary marker files", "one BOFBench-owned current-user registry key", "one inert BOFBenchLab Run value", "short-lived child process and loader evidence"},
			Cleanup:       []string{"run the active-cleanup recipe through the same loader or Sliver session", "verify both marker files, HKCU\\Software\\BOFBench, and the BOFBenchLab Run value are absent"},
			OperatorNotes: []string{"authorized internal-lab use only", "actions are intentionally observable and reversible; the only persistence value exits immediately and no injection, credential access, destructive behavior, or remote scanning is included"},
		},
		{
			Name: "active-cleanup", Title: "Active Offensive Lab Cleanup", Description: "Remove only the known temporary-file and registry artifacts created by the active offensive lab survey.",
			Category: "cleanup", Features: []string{"lab-cleanup"}, Privilege: "user", Platforms: []string{"windows-x64"}, Network: "none", Domain: "none", Impact: "modifies_state",
			Prerequisites: []string{"run in the same Windows user context used for offensive-survey"},
			StateChanges:  []string{"deletes the two known BOFBench temporary marker files if present", "deletes HKCU\\Software\\BOFBench if present", "deletes only the BOFBenchLab value from the current-user Run key if present"},
			Artifacts:     []string{"Beacon cleanup-status output", "native or Sliver run evidence"},
			Cleanup:       []string{"no further cleanup is required after verifying the known BOFBench markers are absent"},
			OperatorNotes: []string{"the cleanup BOF does not accept arbitrary paths or registry keys"},
		},
	}
	for i := range values {
		values[i].Schema = Schema
		values[i].SchemaVersion = SchemaVersion
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
	return values
}

func Builtin(name string) (Document, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, item := range Builtins() {
		if item.Name == name {
			return item, true
		}
	}
	return Document{}, false
}

func Apply(project, name string, force bool) (ApplyResult, error) {
	document, ok := Builtin(name)
	if !ok {
		return ApplyResult{}, fmt.Errorf("unknown recipe %q; choose %s", name, builtinNames())
	}
	info, err := os.Stat(project)
	if err != nil {
		return ApplyResult{}, err
	}
	if !info.IsDir() {
		return ApplyResult{}, fmt.Errorf("recipe project must be a directory: %s", project)
	}
	path := filepath.Join(project, SidecarName)
	if _, err := os.Stat(path); err == nil && !force {
		return ApplyResult{}, fmt.Errorf("recipe sidecar %s already exists; use --force to replace it", path)
	} else if err != nil && !os.IsNotExist(err) {
		return ApplyResult{}, err
	}
	featureResult, err := scaffold.AddFeatures(project, document.Features)
	if err != nil {
		return ApplyResult{}, err
	}
	document.Project = filepath.Base(filepath.Clean(project))
	document.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := marshal(document)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Path: path, Recipe: document, Features: featureResult}, nil
}

func LoadFor(path string) (Document, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Document{}, "", err
	}
	dir := path
	if !info.IsDir() {
		dir = filepath.Dir(path)
	}
	recipePath := filepath.Join(dir, SidecarName)
	data, err := os.ReadFile(recipePath)
	if err != nil {
		return Document{}, recipePath, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, recipePath, fmt.Errorf("parse %s: %w", recipePath, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("trailing JSON value")
		}
		return Document{}, recipePath, fmt.Errorf("parse %s: %w", recipePath, err)
	}
	return document, recipePath, nil
}

func Validate(path string, document Document, presentFeatures []string) Validation {
	report := Validation{
		Header: evidence.New(evidence.SchemaRecipeValidation, "", ""), Path: path, Recipe: document.Name, Status: "pass",
		RequiredFeatures: uniqueStrings(document.Features), PresentFeatures: uniqueStrings(presentFeatures), GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if document.Schema != Schema || document.SchemaVersion != SchemaVersion {
		report.Errors = append(report.Errors, fmt.Sprintf("recipe identity must be %s version %d", Schema, SchemaVersion))
	}
	for label, value := range map[string]string{"name": document.Name, "title": document.Title, "description": document.Description, "category": document.Category} {
		if strings.TrimSpace(value) == "" {
			report.Errors = append(report.Errors, label+" is required")
		}
	}
	if !containsString([]string{"any", "user", "admin", "system"}, document.Privilege) {
		report.Errors = append(report.Errors, "privilege must be any, user, admin, or system")
	}
	if !containsString(document.Platforms, "windows-x64") {
		report.Errors = append(report.Errors, "platforms must include windows-x64")
	}
	if !containsString([]string{"none", "local", "outbound", "domain"}, document.Network) {
		report.Errors = append(report.Errors, "network must be none, local, outbound, or domain")
	}
	if !containsString([]string{"none", "optional", "required"}, document.Domain) {
		report.Errors = append(report.Errors, "domain must be none, optional, or required")
	}
	if !containsString([]string{"read_only", "modifies_state", "destructive"}, document.Impact) {
		report.Errors = append(report.Errors, "impact must be read_only, modifies_state, or destructive")
	}
	for label, values := range map[string][]string{"features": document.Features, "prerequisites": document.Prerequisites, "state_changes": document.StateChanges, "artifacts": document.Artifacts, "cleanup": document.Cleanup} {
		if len(nonEmptyStrings(values)) == 0 {
			report.Errors = append(report.Errors, label+" must contain at least one explicit item")
		}
	}
	present := map[string]bool{}
	for _, feature := range report.PresentFeatures {
		present[feature] = true
	}
	for _, feature := range report.RequiredFeatures {
		if !present[feature] {
			report.MissingFeatures = append(report.MissingFeatures, feature)
		}
	}
	if len(report.MissingFeatures) > 0 {
		report.Errors = append(report.Errors, "source is missing required recipe features: "+strings.Join(report.MissingFeatures, ", "))
	}
	required := map[string]bool{}
	for _, feature := range report.RequiredFeatures {
		required[feature] = true
	}
	for _, feature := range report.PresentFeatures {
		if !required[feature] {
			report.UnexpectedFeatures = append(report.UnexpectedFeatures, feature)
		}
	}
	if len(report.UnexpectedFeatures) > 0 {
		report.Warnings = append(report.Warnings, "source contains features not declared by the recipe: "+strings.Join(report.UnexpectedFeatures, ", "))
	}
	known := map[string]bool{}
	for _, feature := range scaffold.Features() {
		known[feature.Name] = true
	}
	for _, feature := range report.RequiredFeatures {
		if !known[feature] {
			report.Warnings = append(report.Warnings, fmt.Sprintf("feature %q is custom and cannot be composed by 'recipe apply'", feature))
		}
	}
	if document.Impact != "read_only" && onlyNone(document.Cleanup) {
		report.Errors = append(report.Errors, "state-changing recipes require explicit cleanup or an irreversible-impact note")
	}
	if len(report.Errors) > 0 {
		report.Status = "fail"
	} else if len(report.Warnings) > 0 {
		report.Status = "pass_with_warnings"
	}
	return report
}

func PersistValidation(report Validation) (Validation, error) {
	runDir, err := runlog.NewDir("recipe-" + safeName(report.Recipe))
	if err != nil {
		return report, err
	}
	report.Header = evidence.New(evidence.SchemaRecipeValidation, runlog.ID(runDir), "")
	report.EvidencePath = filepath.Join(runDir, "recipe-validation.json")
	report.MarkdownPath = filepath.Join(runDir, "recipe-validation.md")
	data, err := marshal(report)
	if err != nil {
		return report, err
	}
	if err := os.WriteFile(report.EvidencePath, data, 0o644); err != nil {
		return report, err
	}
	if err := os.WriteFile(report.MarkdownPath, []byte(ValidationMarkdown(report)), 0o644); err != nil {
		return report, err
	}
	return report, nil
}

func Text(document Document) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s\n", document.Name, document.Title)
	fmt.Fprintf(&b, "category   %s\nprivilege  %s\nplatform   %s\nnetwork    %s\ndomain     %s\nimpact     %s\nfeatures   %s\n", document.Category, document.Privilege, strings.Join(document.Platforms, ","), document.Network, document.Domain, document.Impact, strings.Join(document.Features, ","))
	fmt.Fprintf(&b, "description %s\n", document.Description)
	appendTextList(&b, "prereq", document.Prerequisites)
	appendTextList(&b, "changes", document.StateChanges)
	appendTextList(&b, "artifacts", document.Artifacts)
	appendTextList(&b, "cleanup", document.Cleanup)
	return b.String()
}

func Markdown(document Document) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n%s\n\n- Recipe: `%s`\n- Category: `%s`\n- Privilege: `%s`\n- Platforms: `%s`\n- Network: `%s`\n- Domain: `%s`\n- Impact: `%s`\n- Features: `%s`\n", document.Title, document.Description, document.Name, document.Category, document.Privilege, strings.Join(document.Platforms, ", "), document.Network, document.Domain, document.Impact, strings.Join(document.Features, ", "))
	appendMarkdownList(&b, "Prerequisites", document.Prerequisites)
	appendMarkdownList(&b, "State Changes", document.StateChanges)
	appendMarkdownList(&b, "Observable Artifacts", document.Artifacts)
	appendMarkdownList(&b, "Cleanup", document.Cleanup)
	appendMarkdownList(&b, "Operator Notes", document.OperatorNotes)
	return b.String()
}

func ValidationText(report Validation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "BOF recipe validation: %s\nrecipe    %s\nrequired  %s\npresent   %s\n", report.Status, report.Recipe, strings.Join(report.RequiredFeatures, ","), strings.Join(report.PresentFeatures, ","))
	for _, problem := range report.Errors {
		fmt.Fprintf(&b, "ERROR     %s\n", problem)
	}
	for _, problem := range report.Warnings {
		fmt.Fprintf(&b, "WARNING   %s\n", problem)
	}
	if report.EvidencePath != "" {
		fmt.Fprintf(&b, "reports   %s %s\n", report.EvidencePath, report.MarkdownPath)
	}
	return b.String()
}

func ValidationMarkdown(report Validation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# BOF Recipe Validation: %s\n\n- Recipe: `%s`\n- Project: `%s`\n- Required features: `%s`\n- Present features: `%s`\n", strings.ToUpper(report.Status), report.Recipe, report.Path, strings.Join(report.RequiredFeatures, ", "), strings.Join(report.PresentFeatures, ", "))
	appendMarkdownList(&b, "Errors", report.Errors)
	appendMarkdownList(&b, "Warnings", report.Warnings)
	return b.String()
}

func builtinNames() string {
	var names []string
	for _, item := range Builtins() {
		names = append(names, item.Name)
	}
	return strings.Join(names, ", ")
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func nonEmptyStrings(values []string) []string {
	var out []string
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func onlyNone(values []string) bool {
	values = nonEmptyStrings(values)
	return len(values) == 0 || len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "none")
}

func marshal(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func safeName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.NewReplacer(" ", "-", "_", "-", ".", "-").Replace(value)
}

func appendTextList(b *strings.Builder, label string, values []string) {
	for _, value := range values {
		fmt.Fprintf(b, "%-10s %s\n", label, value)
	}
}

func appendMarkdownList(b *strings.Builder, title string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "\n## %s\n\n", title)
	for _, value := range values {
		fmt.Fprintf(b, "- %s\n", value)
	}
}
