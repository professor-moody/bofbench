package artifact

import (
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"time"

	"bofbench/internal/capability"
	"bofbench/internal/coff"
	"bofbench/internal/evidence"
	"bofbench/internal/runlog"
)

type Kind string

const (
	KindCOFF    Kind = "coff"
	KindELF     Kind = "elf"
	KindMachO   Kind = "macho"
	KindUnknown Kind = "unknown"
)

type Analysis struct {
	evidence.Header
	Path                string                    `json:"path"`
	Kind                Kind                      `json:"kind"`
	Arch                string                    `json:"arch,omitempty"`
	Format              string                    `json:"format,omitempty"`
	Entrypoint          string                    `json:"entrypoint,omitempty"`
	EntrypointOK        bool                      `json:"entrypoint_ok"`
	Size                int64                     `json:"size"`
	SHA256              string                    `json:"sha256,omitempty"`
	Sections            []Section                 `json:"sections,omitempty"`
	Symbols             []Symbol                  `json:"symbols,omitempty"`
	Unresolved          []string                  `json:"unresolved,omitempty"`
	Imports             []Import                  `json:"imports,omitempty"`
	Strings             []String                  `json:"strings,omitempty"`
	Findings            []Finding                 `json:"findings,omitempty"`
	Relocations         int                       `json:"relocations"`
	RelocationDetails   []Relocation              `json:"relocation_details,omitempty"`
	LoaderCompatibility *capability.Compatibility `json:"loader_compatibility,omitempty"`
	Runtime             RuntimeInfo               `json:"runtime_compatibility,omitempty"`
	GeneratedAt         string                    `json:"generated_at"`
	Warnings            []string                  `json:"warnings,omitempty"`
	AnalyzerNotes       []string                  `json:"analyzer_notes,omitempty"`
}

type Section struct {
	Name        string `json:"name"`
	Size        uint64 `json:"size"`
	Relocations int    `json:"relocations"`
	Flags       string `json:"flags,omitempty"`
}

type Symbol struct {
	Name      string `json:"name"`
	Section   string `json:"section,omitempty"`
	Undefined bool   `json:"undefined,omitempty"`
	External  bool   `json:"external,omitempty"`
}

type Import struct {
	Symbol   string `json:"symbol"`
	Library  string `json:"library,omitempty"`
	API      string `json:"api,omitempty"`
	Category string `json:"category"`
}

type String struct {
	Value    string `json:"value"`
	Category string `json:"category"`
}

type Finding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence,omitempty"`
}

type Relocation struct {
	Section string  `json:"section"`
	Offset  uint64  `json:"offset"`
	Type    string  `json:"type"`
	Code    *uint16 `json:"code,omitempty"`
	Symbol  string  `json:"symbol,omitempty"`
}

type RuntimeInfo struct {
	Runtime      string `json:"runtime,omitempty"`
	Status       string `json:"status,omitempty"`
	CanRun       bool   `json:"can_run"`
	RequiredOS   string `json:"required_os,omitempty"`
	RequiredArch string `json:"required_arch,omitempty"`
	HostOS       string `json:"host_os,omitempty"`
	HostArch     string `json:"host_arch,omitempty"`
	RunCommand   string `json:"run_command,omitempty"`
	TestCommand  string `json:"test_command,omitempty"`
	Note         string `json:"note,omitempty"`
}

type Persisted struct {
	JSONPath string
	MDPath   string
	Analysis Analysis
}

func Detect(path string) (Kind, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return KindUnknown, err
	}
	if len(b) < 4 {
		return KindUnknown, nil
	}
	if b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return KindELF, nil
	}
	magic := binary.BigEndian.Uint32(b[:4])
	switch magic {
	case 0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcafebabf:
		return KindMachO, nil
	}
	magic = binary.LittleEndian.Uint32(b[:4])
	switch magic {
	case 0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcafebabf:
		return KindMachO, nil
	}
	if len(b) >= 20 {
		machine := binary.LittleEndian.Uint16(b[0:2])
		optionalHeaderSize := binary.LittleEndian.Uint16(b[16:18])
		if optionalHeaderSize == 0 && (machine == coff.MachineX64 || machine == coff.MachineX86) {
			return KindCOFF, nil
		}
	}
	return KindUnknown, nil
}

func Analyze(path, entry string) (Analysis, error) {
	if entry == "" {
		entry = "go"
	}
	kind, err := Detect(path)
	if err != nil {
		return Analysis{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return Analysis{}, err
	}
	a := Analysis{
		Header:      evidence.New(evidence.SchemaAnalysis, "", ""),
		Path:        path,
		Kind:        kind,
		Entrypoint:  entry,
		Size:        info.Size(),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if sum, err := sha256File(path); err == nil {
		a.SHA256 = sum
	}
	var out Analysis
	switch kind {
	case KindCOFF:
		out, err = analyzeCOFF(path, entry, a)
	case KindELF:
		out, err = analyzeELF(path, entry, a)
	case KindMachO:
		out, err = analyzeMachO(path, entry, a)
	default:
		a.Warnings = append(a.Warnings, "unknown artifact type")
		out = a
	}
	if err != nil {
		return out, err
	}
	finishAnalysis(path, &out)
	return out, nil
}

func AnalyzeAndPersist(path, entry string) (Persisted, error) {
	a, err := Analyze(path, entry)
	if err != nil {
		return Persisted{}, err
	}
	runDir, err := runlog.NewDir("analysis-" + safeBase(path))
	if err != nil {
		return Persisted{}, err
	}
	a.Header = evidence.New(evidence.SchemaAnalysis, runlog.ID(runDir), "")
	jsonPath := filepath.Join(runDir, "analysis.json")
	mdPath := filepath.Join(runDir, "analysis.md")
	if err := writeJSON(jsonPath, a); err != nil {
		return Persisted{}, err
	}
	if err := os.WriteFile(mdPath, []byte(Markdown(a)), 0o644); err != nil {
		return Persisted{}, err
	}
	return Persisted{JSONPath: jsonPath, MDPath: mdPath, Analysis: a}, nil
}

func Markdown(a Analysis) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Artifact Analysis\n\n")
	fmt.Fprintf(&b, "- Schema: `%s` version `%d`\n", a.Schema, a.SchemaVersion)
	if a.RunID != "" {
		fmt.Fprintf(&b, "- Run ID: `%s`\n", a.RunID)
	}
	fmt.Fprintf(&b, "- Path: `%s`\n", a.Path)
	fmt.Fprintf(&b, "- Kind: `%s`\n", a.Kind)
	fmt.Fprintf(&b, "- Arch: `%s`\n", a.Arch)
	fmt.Fprintf(&b, "- Entry `%s`: `%t`\n", a.Entrypoint, a.EntrypointOK)
	fmt.Fprintf(&b, "- Size: `%d`\n", a.Size)
	fmt.Fprintf(&b, "- Relocations: `%d`\n\n", a.Relocations)
	if a.Runtime.Runtime != "" {
		b.WriteString("## Runtime Compatibility\n\n| Runtime | Status | Host | Required | Next |\n| --- | --- | --- | --- | --- |\n")
		host := strings.Trim(strings.TrimSpace(a.Runtime.HostOS+"/"+a.Runtime.HostArch), "/")
		required := strings.Trim(strings.TrimSpace(a.Runtime.RequiredOS+"/"+a.Runtime.RequiredArch), "/")
		next := a.Runtime.RunCommand
		if next == "" {
			next = a.Runtime.Note
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s |\n\n", a.Runtime.Runtime, a.Runtime.Status, host, required, escapeTable(next))
	}
	if a.LoaderCompatibility != nil {
		compatibility := a.LoaderCompatibility
		fmt.Fprintf(&b, "## Loader Preflight\n\n- Catalog: `%s`\n- Status: `%s`\n- Compatible: `%t`\n", compatibility.CatalogVersion, compatibility.Status, compatibility.Compatible)
		if len(compatibility.Blockers) > 0 {
			b.WriteString("\n### Blockers\n\n| Category | Symbol | Relocation | Detail |\n| --- | --- | --- | --- |\n")
			for _, issue := range compatibility.Blockers {
				fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | %s |\n", issue.Category, escapeTable(issue.Symbol), escapeTable(issue.Relocation), escapeTable(issue.Detail))
			}
		}
		if len(compatibility.Warnings) > 0 {
			b.WriteString("\n### Preflight Warnings\n\n| Category | Symbol | Detail |\n| --- | --- | --- |\n")
			for _, issue := range compatibility.Warnings {
				fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", issue.Category, escapeTable(issue.Symbol), escapeTable(issue.Detail))
			}
		}
		b.WriteString("\n")
	}
	if len(a.Findings) > 0 {
		b.WriteString("## Findings\n\n| Severity | Category | Detail | Evidence |\n| --- | --- | --- | --- |\n")
		for _, finding := range a.Findings {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | `%s` |\n", finding.Severity, finding.Category, escapeTable(finding.Detail), escapeTable(finding.Evidence))
		}
		b.WriteString("\n")
	}
	b.WriteString("## Sections\n\n| Name | Size | Relocations | Flags |\n| --- | ---: | ---: | --- |\n")
	for _, section := range a.Sections {
		fmt.Fprintf(&b, "| `%s` | %d | %d | `%s` |\n", section.Name, section.Size, section.Relocations, section.Flags)
	}
	if len(a.Imports) > 0 {
		b.WriteString("\n## Imports\n\n| Symbol | Library | API | Category |\n| --- | --- | --- | --- |\n")
		for _, imp := range a.Imports {
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` |\n", escapeTable(imp.Symbol), escapeTable(imp.Library), escapeTable(imp.API), imp.Category)
		}
	}
	if len(a.Unresolved) > 0 {
		b.WriteString("\n## Unresolved\n\n")
		for _, s := range a.Unresolved {
			fmt.Fprintf(&b, "- `%s`\n", s)
		}
	}
	if len(a.RelocationDetails) > 0 {
		b.WriteString("\n## Relocation Detail\n\n| Section | Offset | Type | Symbol |\n| --- | ---: | --- | --- |\n")
		limit := minInt(len(a.RelocationDetails), 120)
		for i := 0; i < limit; i++ {
			rel := a.RelocationDetails[i]
			fmt.Fprintf(&b, "| `%s` | `0x%x` | `%s` | `%s` |\n", rel.Section, rel.Offset, rel.Type, escapeTable(rel.Symbol))
		}
		if len(a.RelocationDetails) > limit {
			fmt.Fprintf(&b, "\n_%d additional relocations omitted from Markdown; see JSON report._\n", len(a.RelocationDetails)-limit)
		}
	}
	if len(a.Strings) > 0 {
		b.WriteString("\n## Visible Strings\n\n| Category | Value |\n| --- | --- |\n")
		for _, s := range a.Strings {
			fmt.Fprintf(&b, "| `%s` | `%s` |\n", s.Category, escapeTable(s.Value))
		}
	}
	if len(a.Warnings) > 0 {
		b.WriteString("\n## Warnings\n\n")
		for _, s := range a.Warnings {
			fmt.Fprintf(&b, "- %s\n", s)
		}
	}
	return b.String()
}

func analyzeCOFF(path, entry string, a Analysis) (Analysis, error) {
	info, err := coff.Inspect(path)
	if err != nil {
		return a, err
	}
	a.Arch = info.Machine
	a.Format = "COFF"
	a.SHA256 = info.SHA256
	for _, section := range info.Sections {
		a.Sections = append(a.Sections, Section{
			Name:        section.Name,
			Size:        uint64(section.Size),
			Relocations: len(section.Relocations),
			Flags:       coffFlags(section),
		})
		a.Relocations += len(section.Relocations)
		for _, rel := range section.Relocations {
			code := rel.Type
			a.RelocationDetails = append(a.RelocationDetails, Relocation{
				Section: rel.Section,
				Offset:  uint64(rel.VirtualAddress),
				Type:    rel.TypeName,
				Code:    &code,
				Symbol:  rel.SymbolName,
			})
		}
	}
	for _, sym := range info.Symbols {
		undefined := sym.External && sym.SectionNumber == 0
		a.Symbols = append(a.Symbols, Symbol{Name: sym.Name, Undefined: undefined, External: sym.External})
		if sym.Name == entry && sym.SectionNumber > 0 {
			a.EntrypointOK = true
		}
		if undefined {
			a.Unresolved = append(a.Unresolved, sym.Name)
		}
	}
	a.AnalyzerNotes = append(a.AnalyzerNotes, "Windows COFF execution requires windows-coff runtime")
	return a, nil
}

func finishAnalysis(path string, a *Analysis) {
	if a.Kind == KindCOFF {
		compatibility := assessLoaderCompatibility(*a)
		a.LoaderCompatibility = &compatibility
	}
	a.Runtime = runtimeInfo(*a)
	if !a.EntrypointOK && a.Entrypoint != "" && a.Kind != KindUnknown {
		a.Warnings = append(a.Warnings, fmt.Sprintf("entrypoint %q was not found", a.Entrypoint))
		addFinding(a, Finding{Severity: "high", Category: "entrypoint", Detail: "requested entrypoint was not found", Evidence: a.Entrypoint})
	}
	for _, section := range a.Sections {
		if strings.Contains(section.Flags, "W") && strings.Contains(section.Flags, "X") {
			addFinding(a, Finding{Severity: "high", Category: "section", Detail: "section is both writable and executable", Evidence: section.Name})
		}
	}
	for _, sym := range a.Unresolved {
		imp := classifyImport(sym)
		a.Imports = append(a.Imports, imp)
		for _, finding := range importFindings(imp) {
			addFinding(a, finding)
		}
	}
	sort.Slice(a.Imports, func(i, j int) bool { return a.Imports[i].Symbol < a.Imports[j].Symbol })
	if b, err := os.ReadFile(path); err == nil {
		a.Strings = classifyStrings(coff.ExtractStrings(b, 4))
		for _, s := range a.Strings {
			if s.Category != "visible" && s.Category != "toolchain" && s.Category != "source_file" {
				addFinding(a, Finding{Severity: "info", Category: "string", Detail: "notable visible string", Evidence: s.Value})
			}
		}
	}
	sortFindings(a.Findings)
}

func runtimeInfo(a Analysis) RuntimeInfo {
	info := RuntimeInfo{
		HostOS:   goruntime.GOOS,
		HostArch: goruntime.GOARCH,
	}
	switch a.Kind {
	case KindCOFF:
		info.Runtime = "windows-coff"
		info.RequiredOS = "windows"
		info.RequiredArch = "amd64"
		info.RunCommand = fmt.Sprintf("bofbench run %s --runtime windows-coff", a.Path)
		info.TestCommand = fmt.Sprintf("bofbench test %s --runtime windows-coff", a.Path)
		if a.LoaderCompatibility != nil && !a.LoaderCompatibility.Compatible {
			info.Status = a.LoaderCompatibility.Status
			info.Note = fmt.Sprintf("loader preflight found %d blocking compatibility issue(s)", len(a.LoaderCompatibility.Blockers))
			return info
		}
		if goruntime.GOOS == "windows" && goruntime.GOARCH == "amd64" {
			info.Status = "runnable"
			if a.LoaderCompatibility != nil && len(a.LoaderCompatibility.Warnings) > 0 {
				info.Status = "runnable_with_runtime_lookup"
			}
			info.CanRun = true
			info.Note = "native Windows COFF loader can run this artifact on the current host"
			return info
		}
		info.Status = "requires_windows_amd64"
		info.Note = "copy or sync the artifact to a Windows x64 lab and run the displayed command"
	case KindELF:
		info.Runtime = "linux-elf"
		info.RequiredOS = "linux"
		info.RequiredArch = hostArchFor(a.Arch)
		info.RunCommand = fmt.Sprintf("bofbench run %s --runtime linux-elf", a.Path)
		info.TestCommand = fmt.Sprintf("bofbench test %s --runtime linux-elf", a.Path)
		if goruntime.GOOS == "linux" && archMatches(info.RequiredArch, goruntime.GOARCH) {
			info.Status = "runnable"
			info.CanRun = true
			info.Note = "linked native ELF runner can run this artifact on the current host"
			return info
		}
		info.Status = "requires_linux"
		info.Note = "run this artifact on a matching Linux host"
	case KindMachO:
		info.Runtime = "darwin-macho"
		info.RequiredOS = "darwin"
		info.RequiredArch = hostArchFor(a.Arch)
		info.RunCommand = fmt.Sprintf("bofbench run %s --runtime darwin-macho", a.Path)
		info.TestCommand = fmt.Sprintf("bofbench test %s --runtime darwin-macho", a.Path)
		if goruntime.GOOS == "darwin" && archMatches(info.RequiredArch, goruntime.GOARCH) {
			info.Status = "runnable"
			info.CanRun = true
			info.Note = "linked native Mach-O runner can run this artifact on the current host"
			return info
		}
		info.Status = "requires_darwin"
		info.Note = "run this artifact on a matching macOS host"
	default:
		info.Status = "unknown_artifact"
		info.Note = "no runtime can be selected until the artifact type is recognized"
	}
	return info
}

func hostArchFor(artifactArch string) string {
	lower := strings.ToLower(artifactArch)
	switch {
	case strings.Contains(lower, "x86-64"), strings.Contains(lower, "amd64"), strings.Contains(lower, "x86_64"):
		return "amd64"
	case strings.Contains(lower, "arm64"), strings.Contains(lower, "aarch64"):
		return "arm64"
	default:
		return ""
	}
}

func archMatches(required, host string) bool {
	return required == "" || required == host
}

func classifyImport(symbol string) Import {
	original := symbol
	symbol, _ = capability.WindowsCOFF().NormalizeImport(symbol)
	imp := Import{Symbol: original, Category: "external"}
	if strings.HasPrefix(symbol, "Beacon") {
		imp.Category = "beacon_api"
		imp.API = symbol
		return imp
	}
	if lib, api, ok := strings.Cut(symbol, "$"); ok {
		imp.Library = strings.ToUpper(strings.TrimSuffix(lib, ".dll"))
		imp.API = api
		imp.Category = "winapi"
		return imp
	}
	trimmed := strings.TrimLeft(symbol, "_")
	if isCRTSymbol(trimmed) {
		imp.API = trimmed
		imp.Category = "crt"
		return imp
	}
	imp.API = trimmed
	return imp
}

func assessLoaderCompatibility(a Analysis) capability.Compatibility {
	relocations := make([]capability.RelocationUse, 0, len(a.RelocationDetails))
	for _, relocation := range a.RelocationDetails {
		if relocation.Code == nil {
			continue
		}
		relocations = append(relocations, capability.RelocationUse{
			Code:    *relocation.Code,
			Name:    relocation.Type,
			Section: relocation.Section,
			Symbol:  relocation.Symbol,
		})
	}
	return capability.AssessWindowsCOFF(capability.COFFInput{
		Arch:         a.Arch,
		Entrypoint:   a.Entrypoint,
		EntrypointOK: a.EntrypointOK,
		Relocations:  relocations,
		Unresolved:   a.Unresolved,
	})
}

func importFindings(imp Import) []Finding {
	api := strings.ToLower(imp.API)
	if api == "" {
		api = strings.ToLower(imp.Symbol)
	}
	var findings []Finding
	add := func(category, detail string) {
		findings = append(findings, Finding{Severity: "review", Category: category, Detail: detail, Evidence: imp.Symbol})
	}
	switch {
	case containsAny(api, "virtualalloc", "virtualprotect", "heapcreate", "ntallocatevirtualmemory", "ntprotectvirtualmemory"):
		add("memory_api", "memory allocation/protection API imported")
	case containsAny(api, "writeprocessmemory", "createremotethread", "openprocess", "queueuserapc", "ntwritevirtualmemory", "ntcreatethreadex"):
		add("process_api", "cross-process or thread-manipulation API imported")
	case containsAny(api, "winhttp", "internetopen", "internetconnect", "wsastartup", "connect", "send", "recv"):
		add("network_api", "network-capable API imported")
	case containsAny(api, "regopen", "regset", "regquery", "regdelete"):
		add("registry_api", "registry API imported")
	case containsAny(api, "loadlibrary", "getprocaddress", "ldrgetprocedureaddress"):
		add("dynamic_linking", "dynamic import resolution API imported")
	}
	if imp.Category == "external" && imp.API != "" && !strings.HasPrefix(imp.API, ".") {
		findings = append(findings, Finding{Severity: "info", Category: "external_symbol", Detail: "external symbol needs loader or linker support", Evidence: imp.Symbol})
	}
	return findings
}

func classifyStrings(values []string) []String {
	out := make([]String, 0, minInt(len(values), 80))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] || isNoiseString(value) {
			continue
		}
		seen[value] = true
		category := stringCategory(value)
		if category == "visible" && len(out) >= 40 {
			continue
		}
		out = append(out, String{Value: value, Category: category})
		if len(out) >= 80 {
			break
		}
	}
	return out
}

func stringCategory(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "gcc:") || strings.Contains(lower, "clang version") || strings.Contains(lower, "microsoft (r)"):
		return "toolchain"
	case strings.HasSuffix(lower, ".c") || strings.HasSuffix(lower, ".cc") || strings.HasSuffix(lower, ".cpp") || strings.HasSuffix(lower, ".h"):
		return "source_file"
	case strings.Contains(lower, "http://") || strings.Contains(lower, "https://"):
		return "url"
	case strings.Contains(lower, "powershell") || strings.Contains(lower, "cmd.exe") || strings.Contains(lower, "/bin/sh"):
		return "command"
	case strings.Contains(lower, "password") || strings.Contains(lower, "passwd") || strings.Contains(lower, "apikey") || strings.Contains(lower, "api_key") || strings.Contains(lower, "secret") || strings.Contains(lower, "token="):
		return "secret_like"
	case looksLikeWindowsPath(value):
		return "path"
	case looksLikeIPv4(value):
		return "ip_literal"
	default:
		return "visible"
	}
}

func isNoiseString(value string) bool {
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, ".debug"):
		return true
	case strings.HasPrefix(lower, ".rdata$") || strings.HasPrefix(lower, ".text$") || strings.HasPrefix(lower, ".pdata$") || strings.HasPrefix(lower, ".xdata$"):
		return true
	}
	switch lower {
	case ".text", ".data", ".bss", ".rdata", ".xdata", ".pdata", ".file", ".drectve", ".comment", ".llvm_addrsig":
		return true
	}
	if !strings.ContainsAny(value, " /\\:") && containsAny(lower, ".text", ".data", ".bss", ".rdata", ".xdata", ".pdata") {
		return true
	}
	if len(value) <= 5 && strings.ContainsAny(value, "@`") {
		return true
	}
	if len(value) <= 5 && punctuationRatio(value) > 0.4 {
		return true
	}
	return false
}

func isCRTSymbol(symbol string) bool {
	switch symbol {
	case "memcpy", "memset", "memcmp", "strlen", "strnlen", "strcmp", "strncmp", "sprintf", "snprintf", "printf", "malloc", "free", "realloc", "calloc":
		return true
	default:
		return strings.HasPrefix(symbol, "printf") || strings.HasPrefix(symbol, "sprintf")
	}
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func looksLikeWindowsPath(s string) bool {
	if len(s) >= 3 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		return true
	}
	return strings.HasPrefix(s, `\\`)
}

func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func addFinding(a *Analysis, finding Finding) {
	for _, existing := range a.Findings {
		if existing.Severity == finding.Severity && existing.Category == finding.Category && existing.Detail == finding.Detail && existing.Evidence == finding.Evidence {
			return
		}
	}
	a.Findings = append(a.Findings, finding)
}

func sortFindings(findings []Finding) {
	weight := map[string]int{"high": 0, "review": 1, "warn": 2, "info": 3}
	sort.SliceStable(findings, func(i, j int) bool {
		wi, ok := weight[findings[i].Severity]
		if !ok {
			wi = 9
		}
		wj, ok := weight[findings[j].Severity]
		if !ok {
			wj = 9
		}
		if wi != wj {
			return wi < wj
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].Evidence < findings[j].Evidence
	})
}

func analyzeELF(path, entry string, a Analysis) (Analysis, error) {
	f, err := elf.Open(path)
	if err != nil {
		return a, err
	}
	defer f.Close()
	a.Arch = f.Machine.String()
	a.Format = "ELF"
	syms, _ := f.Symbols()
	for _, section := range f.Sections {
		relocs := 0
		if section.Type == elf.SHT_RELA || section.Type == elf.SHT_REL {
			relocs = estimateELFRelocs(section)
			a.Relocations += relocs
			a.RelocationDetails = append(a.RelocationDetails, elfRelocations(f, section, syms)...)
		}
		a.Sections = append(a.Sections, Section{Name: section.Name, Size: section.Size, Relocations: relocs, Flags: section.Flags.String()})
	}
	for _, sym := range syms {
		undefined := sym.Section == elf.SHN_UNDEF
		a.Symbols = append(a.Symbols, Symbol{Name: sym.Name, Undefined: undefined, External: elf.ST_BIND(sym.Info) == elf.STB_GLOBAL})
		if sym.Name == entry && !undefined {
			a.EntrypointOK = true
		}
		if undefined && sym.Name != "" {
			a.Unresolved = append(a.Unresolved, sym.Name)
		}
	}
	a.AnalyzerNotes = append(a.AnalyzerNotes, "ELF runtime execution uses a linked native harness on matching Linux hosts")
	return a, nil
}

func analyzeMachO(path, entry string, a Analysis) (Analysis, error) {
	f, err := macho.Open(path)
	if err != nil {
		return a, err
	}
	defer f.Close()
	a.Arch = f.Cpu.String()
	a.Format = "Mach-O"
	for _, section := range f.Sections {
		relocs := len(section.Relocs)
		a.Relocations += relocs
		a.Sections = append(a.Sections, Section{Name: section.Name, Size: section.Size, Relocations: relocs, Flags: fmt.Sprintf("0x%x", section.Flags)})
		for _, rel := range section.Relocs {
			a.RelocationDetails = append(a.RelocationDetails, Relocation{
				Section: section.Name,
				Offset:  uint64(rel.Addr),
				Type:    fmt.Sprintf("type_%d_len_%d", rel.Type, rel.Len),
				Symbol:  machoRelocSymbol(f, rel),
			})
		}
	}
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			undefined := sym.Sect == 0
			a.Symbols = append(a.Symbols, Symbol{Name: sym.Name, Undefined: undefined})
			if (sym.Name == entry || sym.Name == "_"+entry) && !undefined {
				a.EntrypointOK = true
			}
			if undefined && sym.Name != "" {
				a.Unresolved = append(a.Unresolved, sym.Name)
			}
		}
	}
	a.AnalyzerNotes = append(a.AnalyzerNotes, "Mach-O runtime execution uses a linked native harness on matching macOS hosts")
	return a, nil
}

func elfRelocations(f *elf.File, section *elf.Section, syms []elf.Symbol) []Relocation {
	data, err := section.Data()
	if err != nil {
		return nil
	}
	var out []Relocation
	switch f.Class {
	case elf.ELFCLASS64:
		size := 16
		if section.Type == elf.SHT_RELA {
			size = 24
		}
		for off := 0; off+size <= len(data); off += size {
			offset := f.ByteOrder.Uint64(data[off : off+8])
			info := f.ByteOrder.Uint64(data[off+8 : off+16])
			out = append(out, Relocation{
				Section: section.Name,
				Offset:  offset,
				Type:    fmt.Sprintf("type_%d", uint32(info)),
				Symbol:  elfSymbolName(syms, int(info>>32)),
			})
		}
	case elf.ELFCLASS32:
		size := 8
		if section.Type == elf.SHT_RELA {
			size = 12
		}
		for off := 0; off+size <= len(data); off += size {
			offset := uint64(f.ByteOrder.Uint32(data[off : off+4]))
			info := f.ByteOrder.Uint32(data[off+4 : off+8])
			out = append(out, Relocation{
				Section: section.Name,
				Offset:  offset,
				Type:    fmt.Sprintf("type_%d", info&0xff),
				Symbol:  elfSymbolName(syms, int(info>>8)),
			})
		}
	}
	return out
}

func elfSymbolName(syms []elf.Symbol, idx int) string {
	if idx <= 0 || idx > len(syms) {
		return ""
	}
	return syms[idx-1].Name
}

func machoRelocSymbol(f *macho.File, rel macho.Reloc) string {
	if !rel.Extern || f.Symtab == nil {
		return ""
	}
	idx := int(rel.Value)
	if idx < 0 || idx >= len(f.Symtab.Syms) {
		return ""
	}
	return f.Symtab.Syms[idx].Name
}

func estimateELFRelocs(section *elf.Section) int {
	if section.Entsize == 0 {
		switch section.Type {
		case elf.SHT_RELA:
			return int(section.Size / 24)
		case elf.SHT_REL:
			return int(section.Size / 16)
		}
		return 0
	}
	return int(section.Size / section.Entsize)
}

func escapeTable(s string) string {
	s = strings.ReplaceAll(s, "\n", "<br>")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "'")
	return s
}

func punctuationRatio(s string) float64 {
	if s == "" {
		return 0
	}
	punctuation := 0
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			punctuation++
		}
	}
	return float64(punctuation) / float64(len(s))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func coffFlags(s coff.Section) string {
	var b strings.Builder
	if s.Readable {
		b.WriteByte('R')
	} else {
		b.WriteByte('-')
	}
	if s.Writable {
		b.WriteByte('W')
	} else {
		b.WriteByte('-')
	}
	if s.Executable {
		b.WriteByte('X')
	} else {
		b.WriteByte('-')
	}
	return b.String()
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func safeBase(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.NewReplacer(" ", "-", "_", "-", ".", "-").Replace(base)
	if base == "" {
		return "artifact"
	}
	return base
}
