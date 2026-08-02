package sourceaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/professor-moody/bofbench/internal/capability"
	"github.com/professor-moody/bofbench/internal/evidence"
	"github.com/professor-moody/bofbench/internal/runlog"
)

const (
	maxSourceFiles = 256
	maxSourceFile  = 2 << 20
	maxSourceBytes = 16 << 20
)

type Options struct {
	Entrypoint string
}

type Report struct {
	evidence.Header
	Path           string    `json:"path"`
	Entrypoint     string    `json:"entrypoint"`
	Status         string    `json:"status"`
	Files          []File    `json:"files"`
	Entrypoints    []Usage   `json:"entrypoints,omitempty"`
	BeaconAPIs     []Usage   `json:"beacon_apis,omitempty"`
	DynamicImports []Import  `json:"dynamic_imports,omitempty"`
	Features       []Usage   `json:"features,omitempty"`
	Findings       []Finding `json:"findings,omitempty"`
	Summary        Summary   `json:"summary"`
	GeneratedAt    string    `json:"generated_at"`
}

type File struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Lines  int    `json:"lines"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Usage struct {
	Name string `json:"name"`
	File string `json:"file"`
	Line int    `json:"line"`
}

type Import struct {
	Symbol  string `json:"symbol"`
	Library string `json:"library"`
	API     string `json:"api"`
	File    string `json:"file"`
	Line    int    `json:"line"`
}

type Finding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Symbol      string `json:"symbol,omitempty"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type Summary struct {
	Files          int `json:"files"`
	CFiles         int `json:"c_files"`
	HeaderFiles    int `json:"header_files"`
	Entrypoints    int `json:"entrypoints"`
	BeaconAPIs     int `json:"beacon_apis"`
	DynamicImports int `json:"dynamic_imports"`
	Features       int `json:"features"`
	Errors         int `json:"errors"`
	Warnings       int `json:"warnings"`
	Review         int `json:"review"`
	Info           int `json:"info"`
}

type Persisted struct {
	Report   Report `json:"source_analysis"`
	JSONPath string `json:"json_path"`
	MDPath   string `json:"md_path"`
}

var (
	dynamicImportPattern = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\$([A-Za-z_][A-Za-z0-9_]*)\b`)
	beaconCallPattern    = regexp.MustCompile(`\b(Beacon[A-Za-z0-9_]*)\s*\(`)
	featurePattern       = regexp.MustCompile(`bofbench:feature\s+([A-Za-z0-9_-]+)\s+begin`)
	mainPattern          = regexp.MustCompile(`\b(?:void|int)\s+main\s*\(`)
	pragmaLibPattern     = regexp.MustCompile(`(?i)#\s*pragma\s+comment\s*\(\s*lib\s*,`)
	crtCallPattern       = regexp.MustCompile(`\b(printf|fprintf|sprintf|snprintf|malloc|calloc|realloc|free|memcpy|memset|strlen|strcmp|strcpy|strncpy|atoi|strtol|time)\s*\(`)
)

var directWindowsAPIs = map[string]string{
	"CreateFileA":                 "KERNEL32",
	"CreateFileW":                 "KERNEL32",
	"CreateProcessA":              "KERNEL32",
	"CreateProcessW":              "KERNEL32",
	"CreateRemoteThread":          "KERNEL32",
	"CreateToolhelp32Snapshot":    "KERNEL32",
	"FreeLibrary":                 "KERNEL32",
	"GetComputerNameA":            "KERNEL32",
	"GetCurrentProcessId":         "KERNEL32",
	"GetCurrentThreadId":          "KERNEL32",
	"GetEnvironmentVariableA":     "KERNEL32",
	"GetModuleHandleA":            "KERNEL32",
	"GetProcAddress":              "KERNEL32",
	"GetTempPathA":                "KERNEL32",
	"LoadLibraryA":                "KERNEL32",
	"OpenProcess":                 "KERNEL32",
	"ReadProcessMemory":           "KERNEL32",
	"VirtualAlloc":                "KERNEL32",
	"VirtualAllocEx":              "KERNEL32",
	"VirtualProtect":              "KERNEL32",
	"WriteProcessMemory":          "KERNEL32",
	"RegCloseKey":                 "ADVAPI32",
	"RegOpenKeyExA":               "ADVAPI32",
	"RegQueryValueExA":            "ADVAPI32",
	"RegSetValueExA":              "ADVAPI32",
	"GetUserNameA":                "ADVAPI32",
	"LogonUserA":                  "ADVAPI32",
	"CredEnumerateA":              "ADVAPI32",
	"CredReadA":                   "ADVAPI32",
	"WSAStartup":                  "WS2_32",
	"WSACleanup":                  "WS2_32",
	"connect":                     "WS2_32",
	"getaddrinfo":                 "WS2_32",
	"gethostname":                 "WS2_32",
	"recv":                        "WS2_32",
	"send":                        "WS2_32",
	"socket":                      "WS2_32",
	"WinHttpOpen":                 "WINHTTP",
	"InternetOpenA":               "WININET",
	"NtAllocateVirtualMemory":     "NTDLL",
	"NtProtectVirtualMemory":      "NTDLL",
	"NtWriteVirtualMemory":        "NTDLL",
	"RtlAdjustPrivilege":          "NTDLL",
	"MiniDumpWriteDump":           "DBGHELP",
	"NetUserEnum":                 "NETAPI32",
	"DsGetDcNameA":                "NETAPI32",
	"LsaEnumerateLogonSessions":   "SECUR32",
	"LsaGetLogonSessionData":      "SECUR32",
	"OpenProcessToken":            "ADVAPI32",
	"LookupPrivilegeValueA":       "ADVAPI32",
	"AdjustTokenPrivileges":       "ADVAPI32",
	"DuplicateTokenEx":            "ADVAPI32",
	"ImpersonateLoggedOnUser":     "ADVAPI32",
	"RevertToSelf":                "ADVAPI32",
	"CreateProcessWithTokenW":     "ADVAPI32",
	"CreateProcessAsUserW":        "ADVAPI32",
	"GetTokenInformation":         "ADVAPI32",
	"LookupAccountSidA":           "ADVAPI32",
	"ConvertSidToStringSidA":      "ADVAPI32",
	"ConvertStringSidToSidA":      "ADVAPI32",
	"GetNamedSecurityInfoA":       "ADVAPI32",
	"SetNamedSecurityInfoA":       "ADVAPI32",
	"CryptUnprotectData":          "CRYPT32",
	"CoInitializeEx":              "OLE32",
	"CoCreateInstance":            "OLE32",
	"WTSQuerySessionInformationA": "WTSAPI32",
}

func IsSourceInput(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return true
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".c", ".h":
		return true
	default:
		return false
	}
}

func Analyze(path string, opts Options) (Report, error) {
	entry := strings.TrimSpace(opts.Entrypoint)
	if entry == "" {
		entry = capability.WindowsCOFF().DefaultEntrypoint
	}
	paths, err := sourcePaths(path)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		Header:      evidence.New(evidence.SchemaSourceAnalysis, "", ""),
		Path:        path,
		Entrypoint:  entry,
		Status:      "pass",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	catalog := capability.WindowsCOFF()
	beaconSupported := map[string]bool{}
	for _, api := range catalog.BeaconAPIs {
		beaconSupported[api] = true
	}
	var totalBytes int64
	for _, diskPath := range paths {
		info, err := os.Stat(diskPath)
		if err != nil {
			return Report{}, err
		}
		if info.Size() > maxSourceFile {
			return Report{}, fmt.Errorf("source file %s exceeds %d bytes", diskPath, maxSourceFile)
		}
		totalBytes += info.Size()
		if totalBytes > maxSourceBytes {
			return Report{}, fmt.Errorf("source input exceeds %d bytes", maxSourceBytes)
		}
		body, err := os.ReadFile(diskPath)
		if err != nil {
			return Report{}, err
		}
		rel := displayPath(path, diskPath)
		fingerprint, err := evidence.FingerprintFile(diskPath)
		if err != nil {
			return Report{}, err
		}
		kind := strings.TrimPrefix(strings.ToLower(filepath.Ext(diskPath)), ".")
		report.Files = append(report.Files, File{Path: rel, Kind: kind, Lines: lineCount(body), Size: info.Size(), SHA256: fingerprint.SHA256})
		if kind == "c" {
			report.Summary.CFiles++
		} else {
			report.Summary.HeaderFiles++
		}
		original := string(body)
		clean := sanitizeC(original)

		entryPattern := regexp.MustCompile(`\b(?:void|int)\s+` + regexp.QuoteMeta(entry) + `\s*\([^;{}]*\)\s*\{`)
		for _, match := range entryPattern.FindAllStringIndex(clean, -1) {
			report.Entrypoints = append(report.Entrypoints, Usage{Name: entry, File: rel, Line: lineAt(clean, match[0])})
		}
		for _, match := range beaconCallPattern.FindAllStringSubmatchIndex(clean, -1) {
			name := clean[match[2]:match[3]]
			if declarationPrefix(clean, match[0]) {
				continue
			}
			usage := Usage{Name: name, File: rel, Line: lineAt(clean, match[0])}
			report.BeaconAPIs = append(report.BeaconAPIs, usage)
			if !beaconSupported[name] {
				report.Findings = append(report.Findings, Finding{
					Severity: "error", Category: "unsupported_beacon_api", File: rel, Line: usage.Line, Symbol: name,
					Detail:      "Beacon API is not implemented by the native loader shim",
					Remediation: "use one of the Beacon APIs declared by the loader capability catalog or add the shim with a native fixture",
				})
			}
		}
		for _, match := range dynamicImportPattern.FindAllStringSubmatchIndex(clean, -1) {
			library := clean[match[2]:match[3]]
			api := clean[match[4]:match[5]]
			symbol := clean[match[0]:match[1]]
			imp := Import{Symbol: symbol, Library: library, API: api, File: rel, Line: lineAt(clean, match[0])}
			report.DynamicImports = append(report.DynamicImports, imp)
			if category := offensiveCategory(library, api); category != "" {
				report.Findings = append(report.Findings, Finding{
					Severity: "review", Category: category, File: rel, Line: imp.Line, Symbol: symbol,
					Detail:      offensiveDetail(category),
					Remediation: "confirm the lab prerequisites, expected artifacts, and cleanup for this capability",
				})
			}
		}
		for _, match := range featurePattern.FindAllStringSubmatchIndex(original, -1) {
			report.Features = append(report.Features, Usage{Name: original[match[2]:match[3]], File: rel, Line: lineAt(original, match[0])})
		}
		for _, match := range crtCallPattern.FindAllStringSubmatchIndex(clean, -1) {
			name := clean[match[2]:match[3]]
			report.Findings = append(report.Findings, Finding{
				Severity: "warning", Category: "crt_dependency", File: rel, Line: lineAt(clean, match[0]), Symbol: name,
				Detail:      "direct CRT use can emit an unresolved runtime dependency in a standalone BOF object",
				Remediation: crtRemediation(name),
			})
		}
		for name, library := range directWindowsAPIs {
			pattern := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\s*\(`)
			for _, match := range pattern.FindAllStringIndex(clean, -1) {
				if precededByDynamicPrefix(clean, match[0]) {
					continue
				}
				report.Findings = append(report.Findings, Finding{
					Severity: "warning", Category: "implicit_winapi_import", File: rel, Line: lineAt(clean, match[0]), Symbol: name,
					Detail:      "unqualified WinAPI use relies on compiler spelling or loader fallback lookup",
					Remediation: fmt.Sprintf("declare and call %s$%s so source intent and loader resolution are explicit", library, name),
				})
			}
		}
		for _, match := range mainPattern.FindAllStringIndex(clean, -1) {
			report.Findings = append(report.Findings, Finding{
				Severity: "warning", Category: "standalone_entrypoint", File: rel, Line: lineAt(clean, match[0]), Symbol: "main",
				Detail:      "standalone main entrypoint is not invoked by the BOF loader",
				Remediation: fmt.Sprintf("move BOF behavior behind the configured %s entrypoint", entry),
			})
		}
		for _, match := range pragmaLibPattern.FindAllStringIndex(clean, -1) {
			report.Findings = append(report.Findings, Finding{
				Severity: "warning", Category: "linker_dependency", File: rel, Line: lineAt(clean, match[0]),
				Detail:      "linker default-library directives do not resolve imports in the native BOF loader",
				Remediation: "replace linked-library assumptions with explicit LIBRARY$API imports",
			})
		}
	}
	report.Entrypoints = uniqueUsages(report.Entrypoints)
	report.BeaconAPIs = uniqueUsagesByName(report.BeaconAPIs)
	report.DynamicImports = uniqueImports(report.DynamicImports)
	report.Features = uniqueUsagesByName(report.Features)
	report.Findings = uniqueFindings(report.Findings)
	if len(report.Entrypoints) == 0 {
		report.Findings = append(report.Findings, Finding{
			Severity: "error", Category: "missing_entrypoint", Symbol: entry,
			Detail:      fmt.Sprintf("no definition of the configured %q entrypoint was found in C source", entry),
			Remediation: fmt.Sprintf("define void %s(char *args, int len) or set entry in bofbench.toml", entry),
		})
	} else if len(report.Entrypoints) > 1 {
		report.Findings = append(report.Findings, Finding{
			Severity: "error", Category: "duplicate_entrypoint", Symbol: entry,
			Detail:      fmt.Sprintf("%d definitions of the configured %q entrypoint were found", len(report.Entrypoints), entry),
			Remediation: "keep exactly one external BOF entrypoint definition",
		})
	}
	report.Summary.Files = len(report.Files)
	report.Summary.Entrypoints = len(report.Entrypoints)
	report.Summary.BeaconAPIs = len(report.BeaconAPIs)
	report.Summary.DynamicImports = len(report.DynamicImports)
	report.Summary.Features = len(report.Features)
	for _, finding := range report.Findings {
		switch finding.Severity {
		case "error":
			report.Summary.Errors++
		case "warning":
			report.Summary.Warnings++
		case "review":
			report.Summary.Review++
		default:
			report.Summary.Info++
		}
	}
	if report.Summary.Errors > 0 {
		report.Status = "fail"
	} else if report.Summary.Warnings > 0 {
		report.Status = "pass_with_warnings"
	}
	return report, nil
}

func AnalyzeAndPersist(path string, opts Options) (Persisted, error) {
	report, err := Analyze(path, opts)
	if err != nil {
		return Persisted{}, err
	}
	runDir, err := runlog.NewDir("source-" + safeBase(path))
	if err != nil {
		return Persisted{}, err
	}
	report.Header = evidence.New(evidence.SchemaSourceAnalysis, runlog.ID(runDir), "")
	jsonPath := filepath.Join(runDir, "source.json")
	mdPath := filepath.Join(runDir, "source.md")
	if err := writeJSON(jsonPath, report); err != nil {
		return Persisted{}, err
	}
	if err := os.WriteFile(mdPath, []byte(Markdown(report)), 0o644); err != nil {
		return Persisted{}, err
	}
	return Persisted{Report: report, JSONPath: jsonPath, MDPath: mdPath}, nil
}

func Text(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "BOF source analysis: %s\n", report.Status)
	fmt.Fprintf(&b, "source: %s\n", report.Path)
	fmt.Fprintf(&b, "summary: files=%d entrypoints=%d beacon=%d imports=%d features=%d errors=%d warnings=%d review=%d\n",
		report.Summary.Files, report.Summary.Entrypoints, report.Summary.BeaconAPIs, report.Summary.DynamicImports, report.Summary.Features,
		report.Summary.Errors, report.Summary.Warnings, report.Summary.Review)
	for _, imp := range report.DynamicImports {
		fmt.Fprintf(&b, "import  %-32s %s:%d\n", imp.Symbol, imp.File, imp.Line)
	}
	for _, finding := range report.Findings {
		location := finding.File
		if finding.Line > 0 {
			location += fmt.Sprintf(":%d", finding.Line)
		}
		fmt.Fprintf(&b, "%-7s %-24s %s", strings.ToUpper(finding.Severity), finding.Category, finding.Detail)
		if location != "" {
			fmt.Fprintf(&b, " (%s)", location)
		}
		b.WriteByte('\n')
		if finding.Remediation != "" {
			fmt.Fprintf(&b, "        fix: %s\n", finding.Remediation)
		}
	}
	return b.String()
}

func Markdown(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# BOF Source Analysis\n\n- Status: `%s`\n- Source: `%s`\n- Entrypoint: `%s`\n- Files: `%d`\n- Beacon APIs: `%d`\n- Dynamic imports: `%d`\n- Features: `%d`\n\n",
		report.Status, report.Path, report.Entrypoint, report.Summary.Files, report.Summary.BeaconAPIs, report.Summary.DynamicImports, report.Summary.Features)
	if len(report.DynamicImports) > 0 {
		b.WriteString("## Dynamic Imports\n\n| Symbol | File | Line |\n| --- | --- | ---: |\n")
		for _, imp := range report.DynamicImports {
			fmt.Fprintf(&b, "| `%s` | `%s` | %d |\n", imp.Symbol, imp.File, imp.Line)
		}
		b.WriteByte('\n')
	}
	if len(report.Findings) > 0 {
		b.WriteString("## Findings\n\n| Severity | Category | Location | Detail | Fix |\n| --- | --- | --- | --- | --- |\n")
		for _, finding := range report.Findings {
			location := finding.File
			if finding.Line > 0 {
				location += fmt.Sprintf(":%d", finding.Line)
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s | %s |\n", finding.Severity, finding.Category, location, escapeTable(finding.Detail), escapeTable(finding.Remediation))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func sourcePaths(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if !IsSourceInput(path) {
			return nil, fmt.Errorf("%s is not a C source or header", path)
		}
		return []string{path}, nil
	}
	var paths []string
	err = filepath.WalkDir(path, func(diskPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "build", "dist", "runs", "stage":
				if diskPath != path {
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".c" || ext == ".h" {
			paths = append(paths, diskPath)
			if len(paths) > maxSourceFiles {
				return fmt.Errorf("source input exceeds %d C/header files", maxSourceFiles)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no C source or header found under %s", path)
	}
	return paths, nil
}

func displayPath(root, diskPath string) string {
	info, err := os.Stat(root)
	if err == nil && info.IsDir() {
		if rel, relErr := filepath.Rel(root, diskPath); relErr == nil {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(diskPath)
}

func sanitizeC(source string) string {
	out := []byte(source)
	inBlock := false
	inString := byte(0)
	escaped := false
	for i := 0; i < len(out); i++ {
		if inBlock {
			if i+1 < len(out) && out[i] == '*' && out[i+1] == '/' {
				out[i], out[i+1] = ' ', ' '
				i++
				inBlock = false
			} else if out[i] != '\n' {
				out[i] = ' '
			}
			continue
		}
		if inString != 0 {
			if escaped {
				escaped = false
			} else if out[i] == '\\' {
				escaped = true
			} else if out[i] == inString {
				inString = 0
			}
			if out[i] != '\n' {
				out[i] = ' '
			}
			continue
		}
		if i+1 < len(out) && out[i] == '/' && out[i+1] == '*' {
			out[i], out[i+1] = ' ', ' '
			i++
			inBlock = true
			continue
		}
		if i+1 < len(out) && out[i] == '/' && out[i+1] == '/' {
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
			continue
		}
		if out[i] == '"' || out[i] == '\'' {
			inString = out[i]
			out[i] = ' '
		}
	}
	return string(out)
}

func precededByDynamicPrefix(source string, index int) bool {
	start := index - 48
	if start < 0 {
		start = 0
	}
	prefix := source[start:index]
	return strings.HasSuffix(strings.TrimSpace(prefix), "$")
}

func offensiveCategory(library, api string) string {
	library = strings.ToLower(library)
	apiLower := strings.ToLower(api)
	switch {
	case library == "ws2_32" || library == "wininet" || library == "winhttp" || library == "iphlpapi":
		return "network_capability"
	case strings.HasPrefix(apiLower, "reg"):
		return "registry_capability"
	case strings.Contains(apiLower, "process") || strings.Contains(apiLower, "thread") || strings.Contains(apiLower, "virtualalloc") || strings.Contains(apiLower, "writevirtualmemory"):
		return "process_capability"
	case strings.Contains(apiLower, "cred") || strings.Contains(apiLower, "logon") || strings.Contains(apiLower, "token") || strings.Contains(apiLower, "privilege") || strings.Contains(apiLower, "lsa"):
		return "identity_capability"
	default:
		return ""
	}
}

func offensiveDetail(category string) string {
	switch category {
	case "network_capability":
		return "source declares network-capable Windows APIs"
	case "registry_capability":
		return "source declares registry-capable Windows APIs"
	case "process_capability":
		return "source declares process, thread, or memory-operation APIs"
	case "identity_capability":
		return "source declares identity, credential, token, or privilege APIs"
	default:
		return "source declares an operational capability"
	}
}

func crtRemediation(name string) string {
	if name == "printf" || name == "fprintf" || name == "sprintf" || name == "snprintf" {
		return "use BeaconPrintf/BeaconOutput or declare the exact MSVCRT$ API intentionally"
	}
	if name == "malloc" || name == "calloc" || name == "realloc" || name == "free" {
		return "use an explicit Windows heap API or declare the exact MSVCRT$ API intentionally"
	}
	return "confirm the compiler inlines this operation or declare the exact MSVCRT$ dependency explicitly"
}

func uniqueUsages(values []Usage) []Usage {
	seen := map[string]bool{}
	out := make([]Usage, 0, len(values))
	for _, value := range values {
		key := fmt.Sprintf("%s\x00%s\x00%d", value.Name, value.File, value.Line)
		if !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	return out
}

func uniqueUsagesByName(values []Usage) []Usage {
	seen := map[string]bool{}
	out := make([]Usage, 0, len(values))
	for _, value := range values {
		if !seen[value.Name] {
			seen[value.Name] = true
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func uniqueImports(values []Import) []Import {
	seen := map[string]bool{}
	out := make([]Import, 0, len(values))
	for _, value := range values {
		if !seen[value.Symbol] {
			seen[value.Symbol] = true
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Symbol < out[j].Symbol })
	return out
}

func uniqueFindings(values []Finding) []Finding {
	seen := map[string]bool{}
	out := make([]Finding, 0, len(values))
	for _, value := range values {
		location := fmt.Sprintf("%s:%d", value.File, value.Line)
		if value.Symbol != "" {
			location = value.Symbol
		}
		key := fmt.Sprintf("%s\x00%s\x00%s", value.Severity, value.Category, location)
		if !seen[key] {
			seen[key] = true
			out = append(out, value)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func declarationPrefix(source string, index int) bool {
	lineStart := strings.LastIndex(source[:index], "\n") + 1
	for _, delimiter := range []string{";", "{", "}"} {
		if offset := strings.LastIndex(source[lineStart:index], delimiter); offset >= 0 {
			candidate := lineStart + offset + 1
			if candidate > lineStart {
				lineStart = candidate
			}
		}
	}
	prefix := strings.TrimSpace(source[lineStart:index])
	if prefix == "" {
		return false
	}
	typeWords := map[string]bool{"void": true, "int": true, "short": true, "char": true, "long": true, "bool": true, "dword": true, "winapi": true, "winbaseapi": true}
	for _, field := range strings.Fields(prefix) {
		field = strings.ToLower(strings.Trim(field, "*()"))
		if typeWords[field] {
			return true
		}
	}
	return false
}

func severityRank(value string) int {
	switch value {
	case "error":
		return 0
	case "warning":
		return 1
	case "review":
		return 2
	default:
		return 3
	}
}

func lineAt(source string, index int) int {
	if index <= 0 {
		return 1
	}
	return 1 + strings.Count(source[:index], "\n")
}

func lineCount(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	lines := 1 + strings.Count(string(body), "\n")
	if body[len(body)-1] == '\n' {
		lines--
	}
	return lines
}

func safeBase(path string) string {
	base := strings.TrimSuffix(filepath.Base(filepath.Clean(path)), filepath.Ext(path))
	base = strings.ToLower(base)
	return strings.NewReplacer(" ", "-", "_", "-", ".", "-").Replace(base)
}

func escapeTable(value string) string {
	value = strings.ReplaceAll(value, "\n", "<br>")
	return strings.ReplaceAll(value, "|", "\\|")
}

func writeJSON(path string, value any) error {
	data, err := evidenceJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
