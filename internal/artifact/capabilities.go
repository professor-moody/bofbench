package artifact

import (
	"sort"
	"strings"
)

// Capability is an operator-readable static-analysis inference. It describes
// what an object appears equipped to do based on concrete imports (and, for a
// small number of mechanisms, corroborating visible strings). It is not an
// execution claim.
type Capability struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Summary    string   `json:"summary"`
	Impact     string   `json:"impact"`
	Inference  string   `json:"inference"`
	Confidence string   `json:"confidence,omitempty"`
	Effects    []string `json:"effects,omitempty"`
	Needs      []string `json:"needs,omitempty"`
	Evidence   []string `json:"evidence"`
}

type capabilityRule struct {
	id      string
	name    string
	summary string
	impact  string
	apis    map[string]bool
}

type accumulatedCapability struct {
	rule     capabilityRule
	evidence map[string]bool
}

var capabilityRules = []capabilityRule{
	{
		id:      "identity_account_sid",
		name:    "Identity, account, and SID lookup",
		summary: "Resolve the current user, account names, security identifiers, or privilege names.",
		impact:  "read-only discovery",
		apis: apiSet(
			"GetUserNameA", "GetUserNameW", "GetUserNameExA", "GetUserNameExW",
			"LookupAccountNameA", "LookupAccountNameW", "LookupAccountSidA", "LookupAccountSidW",
			"ConvertSidToStringSidA", "ConvertSidToStringSidW", "LookupPrivilegeNameA", "LookupPrivilegeNameW",
			"LookupPrivilegeDisplayNameA", "LookupPrivilegeDisplayNameW", "LsaLookupSids", "LsaLookupNames2",
			"NetUserGetInfo", "NetUserEnum",
		),
	},
	{
		id:      "token_context",
		name:    "Access-token inspection",
		summary: "Open and inspect process or thread tokens, including elevation, integrity, groups, and privileges.",
		impact:  "security-context discovery",
		apis: apiSet(
			"OpenProcessToken", "OpenThreadToken", "GetTokenInformation", "GetSidSubAuthority",
			"GetSidSubAuthorityCount", "PrivilegeCheck", "CheckTokenMembership", "GetTokenInformation",
		),
	},
	{
		id:      "process_inventory",
		name:    "Process inventory",
		summary: "Enumerate local processes and collect process identifiers or metadata.",
		impact:  "read-only discovery",
		apis: apiSet(
			"Process32First", "Process32FirstW", "Process32Next", "Process32NextW", "EnumProcesses",
			"K32EnumProcesses", "NtQuerySystemInformation", "WTSEnumerateProcessesA", "WTSEnumerateProcessesW",
		),
	},
	{
		id:      "process_access",
		name:    "Process access and manipulation",
		summary: "Open another process or read, write, or start execution in its address space.",
		impact:  "cross-process access",
		apis: apiSet(
			"OpenProcess", "NtOpenProcess", "ReadProcessMemory", "NtReadVirtualMemory", "WriteProcessMemory",
			"NtWriteVirtualMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC",
		),
	},
	{
		id:      "service_inventory",
		name:    "Service inventory",
		summary: "Enumerate services or query service configuration and state.",
		impact:  "read-only discovery",
		apis: apiSet(
			"EnumServicesStatusA", "EnumServicesStatusW", "EnumServicesStatusExA", "EnumServicesStatusExW",
			"QueryServiceConfigA", "QueryServiceConfigW", "QueryServiceConfig2A", "QueryServiceConfig2W",
			"QueryServiceStatus", "QueryServiceStatusEx", "GetServiceDisplayNameA", "GetServiceDisplayNameW",
		),
	},
	{
		id:      "service_control",
		name:    "Service control",
		summary: "Create, reconfigure, start, stop, or delete a Windows service.",
		impact:  "system state change",
		apis: apiSet(
			"CreateServiceA", "CreateServiceW", "ChangeServiceConfigA", "ChangeServiceConfigW",
			"ChangeServiceConfig2A", "ChangeServiceConfig2W", "StartServiceA", "StartServiceW",
			"ControlService", "DeleteService",
		),
	},
	{
		id:      "network_tcp",
		name:    "Network and TCP access",
		summary: "Initialize networking, inspect adapters or TCP endpoints, resolve names, or open network connections.",
		impact:  "network access",
		apis: apiSet(
			"WSAStartup", "socket", "connect", "WSAConnect", "send", "recv", "getaddrinfo", "GetAddrInfoW",
			"gethostbyname", "gethostname", "GetAdaptersInfo", "GetAdaptersAddresses", "GetTcpTable",
			"GetTcpTable2", "GetExtendedTcpTable", "WinHttpOpen", "WinHttpConnect", "InternetOpenA",
			"InternetOpenW", "InternetConnectA", "InternetConnectW", "DnsQuery_A", "DnsQuery_W",
		),
	},
	{
		id:      "domain_context",
		name:    "Domain and join context",
		summary: "Determine domain membership, locate a domain controller, or query workstation/domain context.",
		impact:  "read-only discovery",
		apis: apiSet(
			"NetGetJoinInformation", "DsGetDcNameA", "DsGetDcNameW", "NetWkstaGetInfo", "NetWkstaUserEnum",
			"DsRoleGetPrimaryDomainInformation", "LsaQueryInformationPolicy",
		),
	},
	{
		id:      "registry_read",
		name:    "Registry read",
		summary: "Query or enumerate Windows Registry keys and values.",
		impact:  "read-only discovery",
		apis: apiSet(
			"RegQueryValueA", "RegQueryValueW", "RegQueryValueExA", "RegQueryValueExW", "RegGetValueA",
			"RegGetValueW", "RegEnumKeyA", "RegEnumKeyW", "RegEnumKeyExA", "RegEnumKeyExW",
			"RegEnumValueA", "RegEnumValueW", "NtQueryKey", "NtQueryValueKey",
		),
	},
	{
		id:      "registry_write",
		name:    "Registry write",
		summary: "Create, modify, rename, or delete Windows Registry keys or values.",
		impact:  "system state change",
		apis: apiSet(
			"RegCreateKeyA", "RegCreateKeyW", "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueA",
			"RegSetValueW", "RegSetValueExA", "RegSetValueExW", "RegDeleteKeyA", "RegDeleteKeyW",
			"RegDeleteKeyExA", "RegDeleteKeyExW", "RegDeleteValueA", "RegDeleteValueW", "RegRenameKey",
			"NtCreateKey", "NtSetValueKey", "NtDeleteKey", "NtDeleteValueKey",
		),
	},
	{
		id:      "file_read",
		name:    "File read",
		summary: "Read file contents from the local or remote filesystem.",
		impact:  "data access",
		apis:    apiSet("ReadFile", "ReadFileEx", "NtReadFile", "ZwReadFile"),
	},
	{
		id:      "file_write",
		name:    "File write",
		summary: "Write, copy, move, or delete files and directories.",
		impact:  "filesystem state change",
		apis: apiSet(
			"WriteFile", "WriteFileEx", "NtWriteFile", "ZwWriteFile", "DeleteFileA", "DeleteFileW",
			"MoveFileA", "MoveFileW", "MoveFileExA", "MoveFileExW", "CopyFileA", "CopyFileW",
			"CopyFileExA", "CopyFileExW", "CreateDirectoryA", "CreateDirectoryW", "RemoveDirectoryA", "RemoveDirectoryW",
		),
	},
	{
		id:      "memory_operations",
		name:    "Memory allocation and protection",
		summary: "Allocate virtual memory or change page protections, including executable-memory preparation.",
		impact:  "memory state change",
		apis: apiSet(
			"VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "NtAllocateVirtualMemory",
			"NtProtectVirtualMemory", "MapViewOfFile", "MapViewOfFileEx", "NtMapViewOfSection",
		),
	},
	{
		id:      "process_launch",
		name:    "Process launch",
		summary: "Start a new process or invoke an executable command.",
		impact:  "code execution",
		apis: apiSet(
			"CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW",
			"CreateProcessWithTokenW", "CreateProcessWithLogonW", "WinExec", "ShellExecuteA", "ShellExecuteW",
			"ShellExecuteExA", "ShellExecuteExW", "NtCreateUserProcess",
		),
	},
	{
		id:      "dynamic_loading",
		name:    "Dynamic library and API loading",
		summary: "Load modules or resolve API addresses at runtime.",
		impact:  "code-loading support",
		apis: apiSet(
			"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress",
			"LdrLoadDll", "LdrGetProcedureAddress",
		),
	},
	{
		id:      "handle_inventory",
		name:    "System-handle inventory",
		summary: "Enumerate system handles or inspect a duplicated handle's object type.",
		impact:  "security-context discovery",
		apis:    apiSet("NtQuerySystemInformation", "NtQueryObject", "DuplicateHandle"),
	},
	{
		id:      "privilege_adjustment",
		name:    "Token privilege adjustment",
		summary: "Resolve and enable a named privilege in the current access token.",
		impact:  "security-context state change",
		apis:    apiSet("LookupPrivilegeValueA", "LookupPrivilegeValueW", "AdjustTokenPrivileges"),
	},
	{
		id:      "credential_manager_access",
		name:    "Credential Manager access",
		summary: "Enumerate Credential Manager entries or read an explicitly selected entry.",
		impact:  "credential access",
		apis:    apiSet("CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW"),
	},
	{
		id:      "dpapi_access",
		name:    "DPAPI protected-material access",
		summary: "Protect or unprotect data using the current Windows user or machine context.",
		impact:  "protected material access",
		apis:    apiSet("CryptProtectData", "CryptUnprotectData"),
	},
	{
		id:      "wmi_access",
		name:    "Windows Management Instrumentation",
		summary: "Connect to WMI for a query or an explicitly targeted management operation.",
		impact:  "system management access",
		apis:    apiSet("CoCreateInstance", "CoSetProxyBlanket"),
	},
	{
		id:      "module_inventory",
		name:    "Process-module inventory",
		summary: "Enumerate modules loaded by an explicitly selected process.",
		impact:  "read-only discovery",
		apis:    apiSet("Module32First", "Module32FirstW", "Module32Next", "Module32NextW", "EnumProcessModules", "K32EnumProcessModules"),
	},
	{
		id:      "driver_inventory",
		name:    "Loaded-driver inventory",
		summary: "Enumerate loaded kernel driver addresses and names.",
		impact:  "read-only discovery",
		apis:    apiSet("EnumDeviceDrivers", "GetDeviceDriverBaseNameA", "GetDeviceDriverBaseNameW"),
	},
	{
		id:      "task_inventory",
		name:    "Scheduled-task inventory",
		summary: "Enumerate scheduled-task definitions from the selected task location.",
		impact:  "read-only discovery",
		apis:    apiSet("FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW"),
	},
	{
		id:      "session_inventory",
		name:    "Interactive-session inventory",
		summary: "Enumerate Windows sessions and their logged-on identities.",
		impact:  "read-only discovery",
		apis:    apiSet("WTSEnumerateSessionsA", "WTSEnumerateSessionsW", "WTSQuerySessionInformationA", "WTSQuerySessionInformationW"),
	},
	{
		id:      "share_inventory",
		name:    "Network-share inventory",
		summary: "Enumerate shares on one explicitly supplied local or remote host.",
		impact:  "network discovery",
		apis:    apiSet("NetShareEnum", "NetShareGetInfo"),
	},
}

func inferCapabilities(imports []Import, visibleStrings []String) []Capability {
	found := map[string]*accumulatedCapability{}
	for _, imp := range imports {
		api := strings.ToLower(strings.TrimSpace(imp.API))
		if api == "" {
			api = strings.ToLower(strings.TrimSpace(imp.Symbol))
		}
		for _, rule := range capabilityRules {
			if !rule.apis[api] {
				continue
			}
			item := found[rule.id]
			if item == nil {
				item = &accumulatedCapability{rule: rule, evidence: map[string]bool{}}
				found[rule.id] = item
			}
			item.evidence[capabilityAPIEvidence(imp)] = true
		}
	}

	addPersistenceCapabilities(found, imports, visibleStrings)

	out := make([]Capability, 0, len(found))
	for _, item := range found {
		evidence := make([]string, 0, len(item.evidence))
		for value := range item.evidence {
			evidence = append(evidence, value)
		}
		sort.Strings(evidence)
		basis := "import analysis"
		for _, value := range evidence {
			if strings.HasPrefix(value, "string: ") {
				basis = "imports + visible strings"
				break
			}
		}
		out = append(out, Capability{
			ID: item.rule.id, Name: item.rule.name, Summary: item.rule.summary, Impact: item.rule.impact,
			Inference: basis, Evidence: evidence,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func addPersistenceCapabilities(found map[string]*accumulatedCapability, imports []Import, visibleStrings []String) {
	registryWrite := matchingImportEvidence(imports, capabilityRulesByID("registry_write").apis)
	fileWrite := matchingImportEvidence(imports, capabilityRulesByID("file_write").apis)
	processLaunch := matchingImportEvidence(imports, capabilityRulesByID("process_launch").apis)
	serviceCreate := matchingImportEvidence(imports, apiSet("CreateServiceA", "CreateServiceW"))

	evidence := map[string]bool{}
	for _, value := range serviceCreate {
		evidence[value] = true
	}
	for _, item := range visibleStrings {
		lower := strings.ToLower(strings.ReplaceAll(item.Value, "/", `\`))
		switch {
		case len(registryWrite) > 0 && (strings.Contains(lower, `\microsoft\windows\currentversion\run`) || strings.Contains(lower, `\microsoft\windows\currentversion\runonce`)):
			for _, value := range registryWrite {
				evidence[value] = true
			}
			evidence["string: "+item.Value] = true
		case len(fileWrite) > 0 && strings.Contains(lower, `\start menu\programs\startup`):
			for _, value := range fileWrite {
				evidence[value] = true
			}
			evidence["string: "+item.Value] = true
		case len(processLaunch) > 0 && strings.Contains(lower, "schtasks") && strings.Contains(lower, "/create"):
			for _, value := range processLaunch {
				evidence[value] = true
			}
			evidence["string: "+item.Value] = true
		}
	}
	if len(evidence) == 0 {
		return
	}
	found["persistence_mechanism"] = &accumulatedCapability{
		rule: capabilityRule{
			id:      "persistence_mechanism",
			name:    "Persistence mechanism",
			summary: "Create a service or establish an explicit autorun mechanism through the Registry, Startup folder, or Task Scheduler.",
			impact:  "persistent system change",
		},
		evidence: evidence,
	}
}

func capabilityRulesByID(id string) capabilityRule {
	for _, rule := range capabilityRules {
		if rule.id == id {
			return rule
		}
	}
	return capabilityRule{}
}

func matchingImportEvidence(imports []Import, apis map[string]bool) []string {
	var out []string
	for _, imp := range imports {
		if apis[strings.ToLower(strings.TrimSpace(imp.API))] {
			out = append(out, capabilityAPIEvidence(imp))
		}
	}
	return out
}

func apiSet(apis ...string) map[string]bool {
	out := make(map[string]bool, len(apis))
	for _, api := range apis {
		out[strings.ToLower(api)] = true
	}
	return out
}

func capabilityAPIEvidence(imp Import) string {
	if imp.Library != "" && imp.API != "" {
		return strings.ToUpper(imp.Library) + "$" + imp.API
	}
	if imp.API != "" {
		return imp.API
	}
	return imp.Symbol
}
