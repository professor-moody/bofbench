package artifact

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type BehaviorStep struct {
	Action   string `json:"action"`
	API      string `json:"api"`
	Evidence string `json:"evidence"`
}

type BehaviorChain struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Summary    string         `json:"summary"`
	Confidence string         `json:"confidence"`
	Function   string         `json:"function,omitempty"`
	Effects    []string       `json:"effects"`
	Needs      []string       `json:"needs,omitempty"`
	Steps      []BehaviorStep `json:"steps"`
}

type Requirements struct {
	Platform  []string `json:"platform,omitempty"`
	Privilege []string `json:"privilege,omitempty"`
	Network   []string `json:"network,omitempty"`
	Host      []string `json:"host,omitempty"`
}

type ArgumentHint struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
	Source   string `json:"source"`
}

type ObservedCapability struct {
	Capability string   `json:"capability"`
	Status     string   `json:"status"`
	Evidence   []string `json:"evidence,omitempty"`
}

type SourceAndVersion struct {
	Repository   string `json:"repository,omitempty"`
	Ref          string `json:"ref,omitempty"`
	Commit       string `json:"commit,omitempty"`
	ObjectSHA256 string `json:"object_sha256"`
}

type chainRule struct {
	id              string
	name            string
	summary         string
	steps           []chainRuleStep
	effects         []string
	needs           []string
	requiredStrings []string
}

type chainRuleStep struct {
	action string
	apis   []string
}

var behaviorRules = []chainRule{
	{
		id: "process_injection_remote_thread", name: "Remote-thread process injection", summary: "Open another process, place executable content in it, and start a remote thread.",
		effects: []string{"accesses another process", "writes process memory", "starts execution"}, needs: []string{"a target PID", "sufficient access to the target process", "payload bytes"},
		steps: []chainRuleStep{
			{action: "open target process", apis: []string{"openprocess", "ntopenprocess"}},
			{action: "allocate target memory", apis: []string{"virtualallocex", "ntallocatevirtualmemory"}},
			{action: "write target memory", apis: []string{"writeprocessmemory", "ntwritevirtualmemory"}},
			{action: "start remote execution", apis: []string{"createremotethread", "createremotethreadex", "ntcreatethreadex"}},
		},
	},
	{
		id: "process_injection_apc", name: "APC process injection", summary: "Open another process, write content into it, and queue an asynchronous procedure call.",
		effects: []string{"accesses another process", "writes process memory", "starts execution"}, needs: []string{"a target PID and thread", "sufficient access to the target", "payload bytes"},
		steps: []chainRuleStep{
			{action: "open target process", apis: []string{"openprocess", "ntopenprocess"}},
			{action: "allocate target memory", apis: []string{"virtualallocex", "ntallocatevirtualmemory"}},
			{action: "write target memory", apis: []string{"writeprocessmemory", "ntwritevirtualmemory"}},
			{action: "queue execution", apis: []string{"queueuserapc", "ntqueueapcthread"}},
		},
	},
	{
		id: "token_impersonation", name: "Token duplication and impersonation", summary: "Open a token, duplicate it, and apply the duplicated security context to the current thread.",
		effects: []string{"accesses a security token", "changes security context"}, needs: []string{"a source process or thread token", "token duplication and impersonation rights"},
		steps: []chainRuleStep{
			{action: "open source token", apis: []string{"openprocesstoken", "openthreadtoken"}},
			{action: "duplicate token", apis: []string{"duplicatetoken", "duplicatetokenex"}},
			{action: "impersonate token", apis: []string{"impersonateloggedonuser", "setthreadtoken", "ntsetinformationthread"}},
		},
	},
	{
		id: "token_process_launch", name: "Process creation with another token", summary: "Duplicate an access token and start a process under that security context.",
		effects: []string{"accesses a security token", "starts execution", "changes security context"}, needs: []string{"a source token", "process creation rights for that token"},
		steps: []chainRuleStep{
			{action: "duplicate token", apis: []string{"duplicatetokenex"}},
			{action: "create process with token", apis: []string{"createprocesswithtokenw", "createprocessasusera", "createprocessasuserw"}},
		},
	},
	{
		id: "service_execution", name: "Service creation and execution", summary: "Connect to the Service Control Manager, create a service, and start it.",
		effects: []string{"writes system state", "starts execution", "persists"}, needs: []string{"service-control-manager access", "typically administrator rights"},
		steps: []chainRuleStep{
			{action: "open service manager", apis: []string{"openscmanagera", "openscmanagerw"}},
			{action: "create service", apis: []string{"createservicea", "createservicew"}},
			{action: "start service", apis: []string{"startservicea", "startservicew"}},
		},
	},
	{
		id: "run_key_persistence", name: "Registry Run-key persistence", summary: "Open or create an autorun registry location and set a value.",
		effects: []string{"writes system state", "persists"}, needs: []string{"write access to the selected registry hive"}, requiredStrings: []string{`currentversion\run`},
		steps: []chainRuleStep{
			{action: "open or create registry key", apis: []string{"regopenkeyexa", "regopenkeyexw", "regcreatekeyexa", "regcreatekeyexw"}},
			{action: "set autorun value", apis: []string{"regsetvalueexa", "regsetvalueexw"}},
		},
	},
	{
		id: "credential_process_memory", name: "Credential-process memory access", summary: "Open a credential-bearing process and read its memory.",
		effects: []string{"accesses another process", "accesses credential material"}, needs: []string{"a target PID", "process query and memory-read rights"}, requiredStrings: []string{"lsass"},
		steps: []chainRuleStep{
			{action: "open target process", apis: []string{"openprocess", "ntopenprocess"}},
			{action: "read process memory", apis: []string{"readprocessmemory", "ntreadvirtualmemory"}},
		},
	},
	{
		id: "process_minidump", name: "Process minidump collection", summary: "Open a process and write a minidump containing process state.",
		effects: []string{"accesses another process", "writes a file"}, needs: []string{"a target PID", "process query/read rights", "an output path"},
		steps: []chainRuleStep{
			{action: "open target process", apis: []string{"openprocess", "ntopenprocess"}},
			{action: "write process dump", apis: []string{"minidumpwritedump"}},
		},
	},
}

func enrichAnalysis(path string, analysis *Analysis) {
	for index := range analysis.Capabilities {
		analysis.Capabilities[index].Confidence = "confirmed primitive"
		analysis.Capabilities[index].Effects = capabilityEffects(analysis.Capabilities[index].Impact)
		analysis.Capabilities[index].Needs = capabilityNeeds(analysis.Capabilities[index].ID)
	}
	analysis.BehaviorChains = inferBehaviorChains(analysis.RelocationDetails, analysis.Strings)
	analysis.Arguments = inferArgumentHints(path)
	analysis.Effects = collectEffects(analysis.Capabilities, analysis.BehaviorChains)
	analysis.Requirements = inferRequirements(*analysis)
	analysis.WorksWith = inferWorksWith(*analysis)
	analysis.SourceAndVersion = sourceAndVersion(path, analysis.SHA256)
}

func applyObservedRuns(analysis *Analysis) {
	if analysis == nil || analysis.SHA256 == "" {
		return
	}
	paths, _ := filepath.Glob(filepath.Join("runs", "*", "result.json"))
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))
	seen := map[string]bool{}
	for _, receiptPath := range paths {
		data, err := os.ReadFile(receiptPath)
		if err != nil {
			continue
		}
		var receipt struct {
			Status            string `json:"status"`
			Runtime           string `json:"runtime"`
			ObjectFingerprint *struct {
				SHA256 string `json:"sha256"`
			} `json:"object_fingerprint"`
			Output []string `json:"output"`
		}
		if json.Unmarshal(data, &receipt) != nil || receipt.ObjectFingerprint == nil || !strings.EqualFold(receipt.ObjectFingerprint.SHA256, analysis.SHA256) {
			continue
		}
		status := receipt.Status
		if receipt.Runtime != "" {
			status = receipt.Runtime + "/" + status
		}
		if len(receipt.Output) == 0 {
			key := "object execution\x00" + status
			if !seen[key] {
				seen[key] = true
				analysis.Observed = append(analysis.Observed, ObservedCapability{Capability: "object execution", Status: status, Evidence: []string{receiptPath}})
			}
			continue
		}
		for _, line := range receipt.Output {
			capability := structuredOutputName(line)
			if capability == "" {
				capability = "object output"
			}
			key := capability + "\x00" + status
			if seen[key] {
				continue
			}
			seen[key] = true
			analysis.Observed = append(analysis.Observed, ObservedCapability{Capability: capability, Status: status, Evidence: []string{receiptPath, line}})
			if len(analysis.Observed) >= 24 {
				return
			}
		}
	}
}

func structuredOutputName(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[") {
		return ""
	}
	end := strings.IndexByte(line, ']')
	if end <= 1 || end > 80 {
		return ""
	}
	return line[1:end]
}

func inferBehaviorChains(relocations []Relocation, visibleStrings []String) []BehaviorChain {
	byFunction := map[string]map[string]string{}
	for _, relocation := range relocations {
		if relocation.Function == "" || relocation.Symbol == "" {
			continue
		}
		api := strings.ToLower(classifyImport(relocation.Symbol).API)
		if api == "" {
			continue
		}
		if byFunction[relocation.Function] == nil {
			byFunction[relocation.Function] = map[string]string{}
		}
		byFunction[relocation.Function][api] = relocation.Symbol
	}
	stringsLower := make([]string, 0, len(visibleStrings))
	for _, item := range visibleStrings {
		stringsLower = append(stringsLower, strings.ToLower(strings.ReplaceAll(item.Value, "/", `\`)))
	}
	var chains []BehaviorChain
	seen := map[string]bool{}
	functions := make([]string, 0, len(byFunction))
	for function := range byFunction {
		functions = append(functions, function)
	}
	sort.Strings(functions)
	for _, function := range functions {
		apis := byFunction[function]
		for _, rule := range behaviorRules {
			if !stringsMatch(stringsLower, rule.requiredStrings) {
				continue
			}
			steps, ok := matchRuleSteps(apis, rule.steps)
			if !ok {
				continue
			}
			key := rule.id + "@" + function
			if seen[key] {
				continue
			}
			seen[key] = true
			chains = append(chains, BehaviorChain{ID: rule.id, Name: rule.name, Summary: rule.summary, Confidence: "strong chain", Function: function, Effects: append([]string(nil), rule.effects...), Needs: append([]string(nil), rule.needs...), Steps: steps})
		}
	}
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].ID != chains[j].ID {
			return chains[i].ID < chains[j].ID
		}
		return chains[i].Function < chains[j].Function
	})
	return chains
}

func matchRuleSteps(apis map[string]string, rules []chainRuleStep) ([]BehaviorStep, bool) {
	steps := make([]BehaviorStep, 0, len(rules))
	for _, rule := range rules {
		matchedAPI := ""
		matchedEvidence := ""
		for _, candidate := range rule.apis {
			if evidence, ok := apis[candidate]; ok {
				matchedAPI = candidate
				matchedEvidence = evidence
				break
			}
		}
		if matchedAPI == "" {
			return nil, false
		}
		steps = append(steps, BehaviorStep{Action: rule.action, API: matchedAPI, Evidence: matchedEvidence})
	}
	return steps, true
}

func stringsMatch(values, required []string) bool {
	for _, needle := range required {
		found := false
		for _, value := range values {
			if strings.Contains(value, needle) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func capabilityEffects(impact string) []string {
	lower := strings.ToLower(impact)
	var effects []string
	if strings.Contains(lower, "read") || strings.Contains(lower, "discovery") || strings.Contains(lower, "access") {
		effects = append(effects, "reads data")
	}
	if strings.Contains(lower, "network") {
		effects = append(effects, "reaches network")
	}
	if strings.Contains(lower, "state change") || strings.Contains(lower, "write") {
		effects = append(effects, "writes state")
	}
	if strings.Contains(lower, "execution") || strings.Contains(lower, "code-loading") {
		effects = append(effects, "starts execution")
	}
	if strings.Contains(lower, "persistent") {
		effects = append(effects, "persists")
	}
	if strings.Contains(lower, "memory") || strings.Contains(lower, "cross-process") {
		effects = append(effects, "accesses another process")
	}
	if len(effects) == 0 {
		effects = append(effects, "supports execution")
	}
	return uniqueStrings(effects)
}

func capabilityNeeds(id string) []string {
	switch id {
	case "process_access":
		return []string{"a target process", "access rights required by the selected operation"}
	case "service_control":
		return []string{"service-control-manager access", "typically administrator rights"}
	case "network_tcp":
		return []string{"network availability for outbound operations"}
	case "persistence_mechanism":
		return []string{"write access to the selected persistence location"}
	default:
		return nil
	}
}

func collectEffects(capabilities []Capability, chains []BehaviorChain) []string {
	var out []string
	for _, capability := range capabilities {
		out = append(out, capability.Effects...)
	}
	for _, chain := range chains {
		out = append(out, chain.Effects...)
	}
	return uniqueStrings(out)
}

func inferRequirements(analysis Analysis) Requirements {
	requirements := Requirements{}
	if analysis.Kind == KindCOFF {
		requirements.Platform = []string{"windows-" + strings.ToLower(analysis.Arch)}
	}
	requirements.Privilege = []string{"current user"}
	for _, capability := range analysis.Capabilities {
		if capability.ID == "service_control" {
			requirements.Privilege = append(requirements.Privilege, "administrator rights may be required")
		}
		if capability.ID == "process_access" {
			requirements.Privilege = append(requirements.Privilege, "target process access rights")
		}
		if capability.ID == "network_tcp" {
			requirements.Network = append(requirements.Network, "local or outbound network depending on arguments")
		}
	}
	for _, chain := range analysis.BehaviorChains {
		requirements.Host = append(requirements.Host, chain.Needs...)
	}
	requirements.Privilege = uniqueStrings(requirements.Privilege)
	requirements.Network = uniqueStrings(requirements.Network)
	requirements.Host = uniqueStrings(requirements.Host)
	return requirements
}

func inferWorksWith(analysis Analysis) []string {
	var targets []string
	if analysis.Kind == KindCOFF && analysis.EntrypointOK && (analysis.Arch == "x64" || analysis.Arch == "x86") {
		targets = append(targets, "cobaltstrike", "sliver")
		if analysis.LoaderCompatibility != nil && analysis.LoaderCompatibility.Compatible {
			targets = append(targets, "native", "lab")
		}
	} else if analysis.Runtime.CanRun {
		targets = append(targets, "native")
	}
	return uniqueStrings(targets)
}

func inferArgumentHints(path string) []ArgumentHint {
	dir := filepath.Dir(path)
	if hints := sliverArgumentHints(filepath.Join(dir, "extension.json")); len(hints) > 0 {
		return hints
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.cna"))
	for _, match := range matches {
		if hints := cnaArgumentHints(match); len(hints) > 0 {
			return hints
		}
	}
	return nil
}

func sliverArgumentHints(path string) []ArgumentHint {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var manifest struct {
		Arguments []struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Optional bool   `json:"optional"`
		} `json:"arguments"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return nil
	}
	var out []ArgumentHint
	for _, argument := range manifest.Arguments {
		out = append(out, ArgumentHint{Name: argument.Name, Type: argument.Type, Required: !argument.Optional, Source: filepath.Base(path)})
	}
	return out
}

var bofPackPattern = regexp.MustCompile(`bof_pack\s*\([^\n]*?["']([zZisbx]+)["']`)

func cnaArgumentHints(path string) []ArgumentHint {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	match := bofPackPattern.FindSubmatch(data)
	if len(match) != 2 {
		return nil
	}
	types := map[byte]string{'z': "string", 'Z': "wstring", 'i': "int", 's': "short", 'b': "bytes", 'x': "file"}
	var out []ArgumentHint
	for index, value := range match[1] {
		out = append(out, ArgumentHint{Name: "arg" + itoa(index+1), Type: types[byte(value)], Required: true, Source: filepath.Base(path)})
	}
	return out
}

func sourceAndVersion(path, hash string) SourceAndVersion {
	result := SourceAndVersion{ObjectSHA256: hash}
	dir := filepath.Dir(path)
	for {
		gitDir := filepath.Join(dir, ".git")
		if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
			result.Repository = gitRemote(filepath.Join(gitDir, "config"))
			head, _ := os.ReadFile(filepath.Join(gitDir, "HEAD"))
			value := strings.TrimSpace(string(head))
			if strings.HasPrefix(value, "ref: ") {
				result.Ref = strings.TrimPrefix(value, "ref: ")
				commit, _ := os.ReadFile(filepath.Join(gitDir, filepath.FromSlash(result.Ref)))
				result.Commit = strings.TrimSpace(string(commit))
			} else {
				result.Commit = value
			}
			return result
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return result
		}
		dir = parent
	}
}

func gitRemote(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	section := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if strings.HasPrefix(section, `[remote "origin"]`) && strings.HasPrefix(line, "url") {
			_, value, ok := strings.Cut(line, "=")
			if ok {
				return strings.TrimSpace(value)
			}
		}
	}
	return ""
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
