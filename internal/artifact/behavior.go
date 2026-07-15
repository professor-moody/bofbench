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
	id                string
	name              string
	summary           string
	confidence        string
	steps             []chainRuleStep
	effects           []string
	needs             []string
	requiredStrings   []string
	requiredFunctions []string
}

type chainRuleStep struct {
	action string
	apis   []string
}

// DeclarativeSignature is the catalog-safe form of a behavior rule. It is
// intentionally data-only: catalogs can describe evidence, but cannot execute
// analyzer code.
type DeclarativeSignature struct {
	ID              string
	Name            string
	Summary         string
	Catalog         string
	Steps           []DeclarativeSignatureStep
	RequiredStrings []string
	Effects         []string
	Requirements    []string
}

type DeclarativeSignatureStep struct {
	Action string
	APIs   []string
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
		effects: []string{"writes system state", "persists"}, needs: []string{"write access to the selected registry hive"}, requiredStrings: []string{"[run-key]"},
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
	{
		id: "handle_duplicate_query", name: "Handle duplication and object query", summary: "Open a process, duplicate one selected handle, and query the duplicated object's type.",
		effects: []string{"accesses another process", "reads handle metadata"}, needs: []string{"a source PID", "an exact handle value", "process handle-duplication rights"},
		steps: []chainRuleStep{
			{action: "open source process", apis: []string{"openprocess", "ntopenprocess"}},
			{action: "duplicate selected handle", apis: []string{"duplicatehandle"}},
			{action: "query duplicated object", apis: []string{"ntqueryobject"}},
		},
	},
	{
		id: "token_inventory", name: "Process-token inventory", summary: "Enumerate processes, open their tokens, and inspect identity, elevation, and integrity details.",
		effects: []string{"reads process metadata", "reads security token metadata"}, needs: []string{"a process filter", "token query rights for matching processes"},
		steps: []chainRuleStep{
			{action: "enumerate processes", apis: []string{"createtoolhelp32snapshot", "enumprocesses", "k32enumprocesses"}},
			{action: "open process token", apis: []string{"openprocesstoken"}},
			{action: "inspect token", apis: []string{"gettokeninformation"}},
		},
	},
	{
		id: "privilege_adjustment", name: "Current-token privilege adjustment", summary: "Resolve one named privilege and request that it be enabled in the current token.",
		effects: []string{"changes current process token state"}, needs: []string{"the named privilege must already be present in the token"},
		steps: []chainRuleStep{
			{action: "resolve privilege identifier", apis: []string{"lookupprivilegevaluea", "lookupprivilegevaluew"}},
			{action: "adjust token privilege", apis: []string{"adjusttokenprivileges"}},
		},
	},
	{
		id: "process_memory_read", name: "Bounded process-memory read", summary: "Open one explicitly selected process and read bytes from a supplied address.",
		effects: []string{"accesses another process", "reads memory"}, needs: []string{"a target PID", "an exact address and byte limit", "process memory-read rights"},
		steps: []chainRuleStep{
			{action: "open target process", apis: []string{"openprocess", "ntopenprocess"}},
			{action: "read target memory", apis: []string{"readprocessmemory", "ntreadvirtualmemory"}},
		},
	},
	{
		id: "dpapi_file_unprotect", name: "DPAPI file recovery", summary: "Read an explicit protected blob and ask DPAPI to recover it in the current user or machine context.",
		effects: []string{"reads a file", "accesses protected material"}, needs: []string{"an exact DPAPI blob path", "the matching user or machine context", "an output byte limit"},
		steps: []chainRuleStep{
			{action: "read protected blob", apis: []string{"readfile", "ntreadfile"}},
			{action: "unprotect material", apis: []string{"cryptunprotectdata"}},
		},
	},
	{
		id: "module_inventory", name: "Process-module inventory", summary: "Create a module snapshot for one process and enumerate the loaded modules.",
		effects: []string{"reads process metadata"}, needs: []string{"a target PID", "module snapshot access"},
		steps: []chainRuleStep{
			{action: "create module snapshot", apis: []string{"createtoolhelp32snapshot"}},
			{action: "enumerate modules", apis: []string{"module32first", "module32firstw"}},
		},
	},
	{
		id: "driver_inventory", name: "Loaded-driver inventory", summary: "Enumerate loaded driver addresses and resolve their base names.",
		effects: []string{"reads system metadata"}, needs: []string{"driver enumeration access"},
		steps: []chainRuleStep{
			{action: "enumerate driver addresses", apis: []string{"enumdevicedrivers"}},
			{action: "resolve driver names", apis: []string{"getdevicedriverbasenamea", "getdevicedriverbasenamew"}},
		},
	},
	{
		id: "logged_on_users", name: "Logged-on user inventory", summary: "Enumerate interactive sessions and query the identity associated with each session.",
		effects: []string{"reads session metadata"}, needs: []string{"session enumeration access"},
		steps: []chainRuleStep{
			{action: "enumerate sessions", apis: []string{"wtsenumeratesessionsa", "wtsenumeratesessionsw"}},
			{action: "query session identity", apis: []string{"wtsquerysessioninformationa", "wtsquerysessioninformationw"}},
		},
	},
	{
		id: "wmi_query", name: "WMI query", summary: "Create a WMI client and authenticate it for an explicit bounded query.",
		effects: []string{"reads system management data"}, needs: []string{"a namespace", "a WQL query", "a property and result limit", "WMI access"},
		steps: []chainRuleStep{
			{action: "create WMI client", apis: []string{"cocreateinstance"}},
			{action: "apply WMI security context", apis: []string{"cosetproxyblanket"}},
		},
	},
	{
		id: "wmi_process_creation", name: "WMI process creation", summary: "Create a WMI client and invoke Win32_Process.Create on one supplied host.",
		effects: []string{"reaches a supplied host", "starts execution"}, needs: []string{"one target host", "one command", "WMI process-create rights"}, requiredStrings: []string{"[wmi-process-create]"},
		steps: []chainRuleStep{
			{action: "create WMI client", apis: []string{"cocreateinstance"}},
			{action: "apply WMI security context", apis: []string{"cosetproxyblanket"}},
		},
	},
	{
		id: "remote_host_information", name: "Exact-host Windows information", summary: "Query workstation identity and server role/version details for one supplied Windows host.",
		effects: []string{"reaches a supplied host", "reads host metadata"}, needs: []string{"one exact target host", "workstation and server information RPC access"},
		steps: []chainRuleStep{{action: "query workstation identity", apis: []string{"netwkstagetinfo"}}, {action: "query server role and version", apis: []string{"netservergetinfo"}}},
	},
	{
		id: "remote_service_inventory", name: "Remote service inventory", summary: "Open the Service Control Manager on one host and enumerate bounded service process state.",
		effects: []string{"reaches a supplied host", "reads service metadata"}, needs: []string{"one exact target host", "remote SCM enumeration access"},
		steps: []chainRuleStep{{action: "open remote service manager", apis: []string{"openscmanagera", "openscmanagerw"}}, {action: "enumerate service state", apis: []string{"enumservicesstatusexa", "enumservicesstatusexw"}}},
	},
	{
		id: "remote_session_inventory", name: "Remote SMB session inventory", summary: "Enumerate bounded SMB session metadata from one supplied host.", confidence: "confirmed primitive",
		effects: []string{"reaches a supplied host", "reads SMB session metadata"}, needs: []string{"one exact target host", "session enumeration access"},
		steps: []chainRuleStep{{action: "enumerate SMB sessions", apis: []string{"netsessionenum"}}},
	},
	{
		id: "remote_registry_read", name: "Remote registry value read", summary: "Connect to a supplied host registry, open one exact key, and read one exact value.",
		effects: []string{"reaches a supplied host", "reads registry data"}, needs: []string{"one exact target host", "an exact hive, key, and value", "Remote Registry access"},
		steps: []chainRuleStep{{action: "connect to remote registry", apis: []string{"regconnectregistrya", "regconnectregistryw"}}, {action: "open exact key", apis: []string{"regopenkeyexa", "regopenkeyexw"}}, {action: "read exact value", apis: []string{"regqueryvalueexa", "regqueryvalueexw"}}},
	},
	{
		id: "remote_wmi_query", name: "Remote WMI query", summary: "Create a WMI client, authenticate its proxy, and issue a WQL query against a supplied namespace.",
		effects: []string{"reaches a supplied host", "reads remote management data"}, needs: []string{"one exact target host and namespace", "a bounded WQL query", "DCOM/WMI access"}, requiredStrings: []string{"[remote-wmi-query]"},
		steps: []chainRuleStep{{action: "create WMI client", apis: []string{"cocreateinstance"}}, {action: "apply WMI security context", apis: []string{"cosetproxyblanket"}}, {action: "prepare WQL query", apis: []string{"sysallocstring"}}},
	},
	{
		id: "remote_file_stage", name: "Hash-guarded SMB file staging", summary: "Validate supplied content and write it to one exact UNC destination.",
		effects: []string{"reaches a supplied host", "writes remote filesystem state"}, needs: []string{"one exact host/share/path", "supplied content and matching SHA-256", "SMB write access"}, requiredStrings: []string{"[remote-file-stage]"},
		steps: []chainRuleStep{{action: "hash supplied content", apis: []string{"cryptcreatehash"}}, {action: "open exact destination", apis: []string{"createfilew"}}, {action: "write supplied content", apis: []string{"writefile"}}},
	},
	{
		id: "remote_file_cleanup", name: "Hash-guarded SMB file cleanup", summary: "Hash one exact UNC file and remove it only when the expected digest matches.",
		effects: []string{"reaches a supplied host", "removes exact remote filesystem state"}, needs: []string{"one exact host/share/path", "the expected SHA-256", "SMB delete access"}, requiredStrings: []string{"[remote-file-remove]"},
		steps: []chainRuleStep{{action: "read exact destination", apis: []string{"createfilew"}}, {action: "hash existing content", apis: []string{"cryptcreatehash"}}, {action: "remove matching file", apis: []string{"deletefilew"}}},
	},
	{
		id: "remote_task_execution", name: "Native remote scheduled-task execution", summary: "Connect to Task Scheduler on one supplied host, register one exact task, and start it.",
		effects: []string{"reaches a supplied host", "writes remote task state", "starts remote execution"}, needs: []string{"one exact host and task name", "Task Scheduler administration rights"}, requiredStrings: []string{"[remote-task-execute]"},
		steps: []chainRuleStep{{action: "create Task Scheduler client", apis: []string{"cocreateinstance"}}, {action: "prepare exact task definition", apis: []string{"sysallocstring"}}},
	},
	{
		id: "remote_task_cleanup", name: "Native remote scheduled-task cleanup", summary: "Connect to Task Scheduler on one supplied host and delete only one exact task.",
		effects: []string{"reaches a supplied host", "removes exact remote task state"}, needs: []string{"one exact host and task name", "Task Scheduler administration rights"}, requiredStrings: []string{"[remote-task-cleanup]"},
		steps: []chainRuleStep{{action: "create Task Scheduler client", apis: []string{"cocreateinstance"}}, {action: "prepare exact task name", apis: []string{"sysallocstring"}}},
	},
	{
		id: "remote_task_inventory", name: "Remote scheduled-task inventory", summary: "Connect to Task Scheduler on one supplied host and enumerate bounded task state.",
		effects: []string{"reaches a supplied host", "reads scheduled-task metadata"}, needs: []string{"one exact host", "Task Scheduler query access"}, requiredStrings: []string{"task scheduler interface"},
		steps: []chainRuleStep{{action: "create Task Scheduler client", apis: []string{"cocreateinstance"}}, {action: "prepare remote folder path", apis: []string{"sysallocstring"}}},
	},
	{
		id: "credential_manager_inventory", name: "Credential Manager inventory", summary: "Enumerate bounded Credential Manager metadata in the current user context.", confidence: "confirmed primitive",
		effects: []string{"reads credential metadata"}, needs: []string{"the matching Credential Manager user context", "a result limit"}, requiredStrings: []string{"[credential-list]"},
		steps: []chainRuleStep{{action: "enumerate credential metadata", apis: []string{"credenumeratea", "credenumeratew"}}},
	},
	{
		id: "credential_manager_read", name: "Targeted Credential Manager read", summary: "Read one exact Credential Manager entry and return only the requested bounded bytes.", confidence: "confirmed primitive",
		effects: []string{"accesses credential material"}, needs: []string{"the matching Credential Manager user context", "an exact target name", "an output byte limit"}, requiredStrings: []string{"[credential-read]"},
		steps: []chainRuleStep{{action: "read exact credential", apis: []string{"credreada", "credreadw"}}},
	},
	{
		id: "scheduled_task_persistence", name: "Scheduled-task persistence", summary: "Create one explicitly named logon task through the native Task Scheduler interfaces.",
		effects: []string{"writes system state", "persists", "starts execution"}, needs: []string{"an exact task name", "a command", "task creation rights"}, requiredStrings: []string{"[scheduled-task]"},
		steps: []chainRuleStep{{action: "create Task Scheduler client", apis: []string{"cocreateinstance"}}, {action: "prepare exact task definition", apis: []string{"sysallocstring"}}},
	},
	{
		id: "scheduled_task_cleanup", name: "Scheduled-task cleanup", summary: "Delete one explicitly named task through the native Task Scheduler interfaces.",
		effects: []string{"writes system state"}, needs: []string{"an exact task name", "task deletion rights"}, requiredStrings: []string{"[scheduled-task-cleanup]"},
		steps: []chainRuleStep{{action: "create Task Scheduler client", apis: []string{"cocreateinstance"}}, {action: "prepare exact task name", apis: []string{"sysallocstring"}}},
	},
	{
		id: "security_package_inventory", name: "Windows authentication-package inventory", summary: "Enumerate installed SSPI authentication and security-support packages.",
		confidence: "confirmed primitive", effects: []string{"reads authentication package metadata"}, needs: []string{"local SSPI availability", "a result limit"},
		steps: []chainRuleStep{{action: "enumerate security packages", apis: []string{"enumeratesecuritypackagesa", "enumeratesecuritypackagesw"}}},
	},
	{
		id: "certificate_store_inventory", name: "Certificate-store inventory", summary: "Open a Windows certificate store and enumerate identity, validity, thumbprint, and private-key metadata.",
		effects: []string{"reads certificate metadata", "reads private-key availability metadata"}, needs: []string{"a certificate store scope and name", "store read access"},
		steps: []chainRuleStep{{action: "open certificate store", apis: []string{"certopenstore", "certopensystemstorea", "certopensystemstorew"}}, {action: "enumerate certificates", apis: []string{"certenumcertificatesinstore"}}, {action: "inspect certificate properties", apis: []string{"certgetcertificatecontextproperty", "certgetnamestringa", "certgetnamestringw"}}},
	},
	{
		id: "logon_session_details", name: "Logon-session context inventory", summary: "Enumerate logon identifiers and resolve account, session, logon type, and authentication-package context.",
		effects: []string{"reads security context metadata"}, needs: []string{"visibility of the selected logon session", "a result limit"},
		steps: []chainRuleStep{{action: "enumerate logon identifiers", apis: []string{"lsaenumeratelogonsessions"}}, {action: "read logon-session data", apis: []string{"lsagetlogonsessiondata"}}},
	},
	{
		id: "kerberos_cache_inventory", name: "Kerberos ticket-cache inventory", summary: "Connect to LSA, resolve the Kerberos package, and request ticket-cache metadata.",
		effects: []string{"reads authentication cache metadata"}, needs: []string{"a visible logon context", "Kerberos package availability"},
		steps: []chainRuleStep{{action: "connect to LSA", apis: []string{"lsaconnectuntrusted", "lsaregisterlogonprocess"}}, {action: "resolve Kerberos package", apis: []string{"lsalookupauthenticationpackage"}}, {action: "query ticket cache", apis: []string{"lsacallauthenticationpackage"}}},
	},
	{
		id: "vault_inventory", name: "Windows Vault metadata inventory", summary: "Enumerate available Vaults and list bounded stored-item metadata.",
		effects: []string{"reads credential metadata"}, needs: []string{"current-user Vault access", "a result limit"},
		steps: []chainRuleStep{{action: "enumerate Vaults", apis: []string{"vaultenumeratevaults"}}, {action: "open selected Vault", apis: []string{"vaultopenvault"}}, {action: "enumerate Vault items", apis: []string{"vaultenumerateitems"}}},
	},
	{
		id: "vault_exact_read", name: "Exact Windows Vault secret read", summary: "Open one Vault, identify an exact resource and identity, and request its stored authenticator.",
		effects: []string{"accesses credential material"}, needs: []string{"an exact Vault GUID", "an exact resource and identity", "current-user Vault access", "an output byte limit"},
		steps: []chainRuleStep{{action: "open selected Vault", apis: []string{"vaultopenvault"}}, {action: "locate exact item", apis: []string{"vaultenumerateitems"}}, {action: "read item authenticator", apis: []string{"vaultgetitem"}}},
	},
	{
		id: "dpapi_file_reprotect", name: "DPAPI material re-protection", summary: "Recover one protected blob, protect it under a selected DPAPI scope, and write the new blob.",
		effects: []string{"reads protected material", "writes a protected file"}, needs: []string{"matching source DPAPI context", "an output path", "a target DPAPI scope"},
		steps: []chainRuleStep{{action: "read protected blob", apis: []string{"readfile", "ntreadfile"}}, {action: "recover protected material", apis: []string{"cryptunprotectdata"}}, {action: "protect for selected scope", apis: []string{"cryptprotectdata"}}, {action: "write protected output", apis: []string{"writefile", "ntwritefile"}}},
	},
	{
		id: "certificate_pfx_export", name: "Selected certificate and private-key PFX export", summary: "Select an exact certificate, export its available private key into a PFX blob, and write one exact file.",
		effects: []string{"accesses private-key material", "writes a PFX file"}, needs: []string{"an exact certificate thumbprint", "an exportable private key", "a PFX password", "an output path"},
		steps: []chainRuleStep{{action: "open certificate store", apis: []string{"certopenstore", "certopensystemstorea", "certopensystemstorew"}}, {action: "select certificate", apis: []string{"certfindcertificateinstore"}}, {action: "export certificate and key", apis: []string{"pfxexportcertstoreex"}}, {action: "write PFX file", apis: []string{"writefile", "ntwritefile"}}},
	},
	{
		id: "thread_hijack_execute", name: "Thread-context hijack execution", summary: "Write content into another process, suspend a selected thread, replace its instruction pointer, and resume execution.",
		effects: []string{"accesses another process", "writes process memory", "starts execution"}, needs: []string{"a target PID and TID", "payload bytes", "process VM and thread-context access"},
		steps: []chainRuleStep{{action: "write remote execution bytes", apis: []string{"virtualallocex", "writeprocessmemory"}}, {action: "capture selected thread context", apis: []string{"suspendthread", "getthreadcontext"}}, {action: "redirect selected thread", apis: []string{"setthreadcontext", "resumethread"}}},
	},
	{
		id: "module_stomp_execute", name: "Module-backed byte replacement and execution", summary: "Read a selected process image range, replace its bytes, and optionally begin execution at that address.",
		effects: []string{"accesses another process", "writes process memory", "starts execution"}, needs: []string{"a target process and module range", "payload bytes", "process VM access"}, requiredStrings: []string{"[module-stomp-execute]"},
		steps: []chainRuleStep{{action: "read selected image range", apis: []string{"readprocessmemory"}}, {action: "replace selected image bytes", apis: []string{"virtualprotectex", "writeprocessmemory"}}, {action: "optionally start execution", apis: []string{"createremotethread"}}},
	},
	{
		id: "process_hollow_spawn", name: "Suspended-process execution replacement", summary: "Create a selected process suspended, write replacement execution bytes, and redirect its primary thread.",
		effects: []string{"starts a process", "writes process memory", "starts execution"}, needs: []string{"a host image", "replacement bytes", "process creation rights"},
		steps: []chainRuleStep{{action: "create host process suspended", apis: []string{"createprocessa", "createprocessw"}}, {action: "write replacement execution bytes", apis: []string{"virtualallocex", "writeprocessmemory"}}, {action: "redirect primary thread", apis: []string{"getthreadcontext", "setthreadcontext"}}},
	},
	{
		id: "process_library_load", name: "Remote library loading", summary: "Write a DLL path into a selected process and invoke its loader through a remote thread.",
		effects: []string{"accesses another process", "writes process memory", "starts execution"}, needs: []string{"a target PID", "a DLL path", "process VM and create-thread access"}, requiredStrings: []string{"loadlibraryw"},
		steps: []chainRuleStep{{action: "write remote DLL path", apis: []string{"virtualallocex", "writeprocessmemory"}}, {action: "resolve library loader", apis: []string{"getprocaddress"}}, {action: "start remote library load", apis: []string{"createremotethread"}}},
	},
	{
		id: "kerberos_service_ticket_request", name: "Kerberos service-ticket request", summary: "Acquire outbound Kerberos credentials and initialize a security context for a selected SPN.",
		effects: []string{"accesses authentication material", "reaches a domain controller"}, needs: []string{"an SPN", "a usable Kerberos logon context"}, requiredStrings: []string{"kerberos"},
		steps: []chainRuleStep{{action: "acquire Kerberos credentials", apis: []string{"acquirecredentialshandlea", "acquirecredentialshandlew"}}, {action: "request service context", apis: []string{"initializesecuritycontexta", "initializesecuritycontextw"}}},
	},
	{
		id: "remote_winrm_execute", name: "Remote WinRM execution", summary: "Start an exact-host WinRM operation and collect bounded command output.",
		effects: []string{"reaches a supplied host", "starts remote execution"}, needs: []string{"a target host and command", "WinRM authorization"}, requiredStrings: []string{"[remote-winrm-execute]"},
		steps: []chainRuleStep{{action: "create captured child output", apis: []string{"createpipe"}}, {action: "start WinRM client", apis: []string{"createprocessa", "createprocessw", "createprocesswithlogonw"}}, {action: "collect command output", apis: []string{"readfile"}}},
	},
	{
		id: "process_library_unload", name: "Remote library unloading", summary: "Resolve FreeLibrary and invoke it in a selected process for a supplied module base.",
		effects: []string{"accesses another process", "starts execution", "changes loaded modules"}, needs: []string{"a target PID and module base", "process create-thread access"}, requiredStrings: []string{"[process-library-unload]"},
		steps: []chainRuleStep{{action: "resolve library unload routine", apis: []string{"getprocaddress"}}, {action: "start remote unload", apis: []string{"createremotethread"}}},
	},
	{
		id: "kerberos_ticket_purge", name: "Kerberos ticket-cache purge", summary: "Resolve the Kerberos authentication package and submit an exact or broad cache-purge request.",
		effects: []string{"changes authentication cache state"}, needs: []string{"an exact ticket selection or explicit broad scope"}, requiredStrings: []string{"[kerberos-ticket-purge]"},
		steps: []chainRuleStep{{action: "resolve Kerberos authentication package", apis: []string{"lsaconnectuntrusted", "lsalookupauthenticationpackage"}}, {action: "submit purge request", apis: []string{"lsacallauthenticationpackage"}}},
	},
	{
		id: "process_access_check", name: "Selected process access check", summary: "Attempt explicitly selected process access rights and report which handles Windows grants.",
		effects: []string{"reads process access metadata"}, needs: []string{"a target PID", "the current Windows security context"}, requiredStrings: []string{"[process-access-check]"},
		steps: []chainRuleStep{{action: "open selected process with requested rights", apis: []string{"openprocess"}}, {action: "release granted handles", apis: []string{"closehandle"}}},
	},
	{
		id: "module_export_inventory", name: "Selected module export inventory", summary: "Select one loaded process module and enumerate its PE export names and addresses.",
		effects: []string{"reads process module metadata"}, needs: []string{"a target PID", "process query and VM-read access"}, requiredStrings: []string{"[module-export-inventory]"},
		steps: []chainRuleStep{{action: "select loaded module", apis: []string{"createtoolhelp32snapshot"}}, {action: "read mapped PE export data", apis: []string{"readprocessmemory"}}},
	},
	{
		id: "local_account_policy_inventory", name: "Local account policy inventory", summary: "Read local password, authentication-role, and lockout policy metadata.", confidence: "confirmed primitive",
		effects: []string{"reads local authentication policy metadata"}, needs: []string{"local NetAPI policy query access"}, requiredStrings: []string{"[local-account-policy-inventory]"},
		steps: []chainRuleStep{{action: "read local account policy", apis: []string{"netusermodalsget"}}},
	},
	{
		id: "network_neighbor_inventory", name: "Network neighbor inventory", summary: "Enumerate bounded IPv4 and IPv6 neighbor-cache metadata.",
		effects: []string{"reads local network neighbor metadata"}, needs: []string{"local IP Helper access"}, requiredStrings: []string{"[network-neighbor-inventory]"},
		steps: []chainRuleStep{{action: "read neighbor table", apis: []string{"getipnettable2"}}, {action: "release neighbor table", apis: []string{"freemibtable"}}},
	},
	{id: "process_handle_duplicate", name: "Selected process handle duplication", summary: "Duplicate an exact supplied handle between operator-selected process contexts.", effects: []string{"accesses another process", "creates a process handle"}, needs: []string{"source PID and handle", "PROCESS_DUP_HANDLE access"}, requiredStrings: []string{"[process-handle-duplicate]"}, steps: []chainRuleStep{{action: "open selected process contexts", apis: []string{"openprocess"}}, {action: "duplicate supplied handle", apis: []string{"duplicatehandle"}}}},
	{id: "process_handle_close", name: "Selected process handle closure", summary: "Close an exact supplied handle in an operator-selected process.", effects: []string{"accesses another process", "closes a process handle"}, needs: []string{"target PID and handle", "PROCESS_DUP_HANDLE access"}, requiredStrings: []string{"[process-handle-close]"}, steps: []chainRuleStep{{action: "open selected process", apis: []string{"openprocess"}}, {action: "close supplied handle", apis: []string{"duplicatehandle"}}}},
	{id: "process_command_line_set", name: "Process command-line mutation", summary: "Locate process parameters through the PEB and replace the selected command line.", effects: []string{"accesses another process", "writes process parameters"}, needs: []string{"target PID and replacement command line"}, requiredStrings: []string{"[process-command-line-set]"}, steps: []chainRuleStep{{action: "locate process parameters", apis: []string{"ntqueryinformationprocess", "readprocessmemory"}}, {action: "replace command line", apis: []string{"writeprocessmemory"}}}},
	{id: "process_command_line_restore", name: "Process command-line restoration", summary: "Restore a selected process command line from an explicit value or backup.", effects: []string{"accesses another process", "writes process parameters"}, needs: []string{"target PID and restore data"}, requiredStrings: []string{"[process-command-line-restore]"}, steps: []chainRuleStep{{action: "locate process parameters", apis: []string{"ntqueryinformationprocess", "readprocessmemory"}}, {action: "restore command line", apis: []string{"writeprocessmemory"}}}},
	{id: "threadpool_wait_execute", name: "Threadpool wait callback execution", summary: "Dispatch operator-supplied bytes through a native threadpool wait callback.", effects: []string{"allocates executable memory", "starts execution"}, needs: []string{"payload bytes in the BOF host context"}, requiredStrings: []string{"[threadpool-wait-execute]"}, steps: []chainRuleStep{{action: "prepare callback memory", apis: []string{"virtualalloc", "virtualprotect"}}, {action: "register wait callback", apis: []string{"createthreadpoolwait", "setthreadpoolwait"}}, {action: "signal callback", apis: []string{"setevent"}}}},
	{id: "service_config_set", name: "Service configuration mutation", summary: "Query and modify selected Windows service configuration fields.", effects: []string{"writes service configuration"}, needs: []string{"service name and SERVICE_CHANGE_CONFIG access"}, requiredStrings: []string{"[service-config-set]"}, steps: []chainRuleStep{{action: "inspect selected service", apis: []string{"openservicew", "queryserviceconfigw"}}, {action: "change selected configuration", apis: []string{"changeserviceconfigw", "changeserviceconfig2w"}}}},
	{id: "service_config_restore", name: "Service configuration restoration", summary: "Restore selected Windows service configuration from backup or explicit values.", effects: []string{"writes service configuration"}, needs: []string{"service name and restore values"}, requiredStrings: []string{"[service-config-restore]"}, steps: []chainRuleStep{{action: "open selected service", apis: []string{"openservicew"}}, {action: "restore selected configuration", apis: []string{"changeserviceconfigw", "changeserviceconfig2w"}}}},
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
			ObjectSHA256      string `json:"object_sha256"`
			ObjectFingerprint *struct {
				SHA256 string `json:"sha256"`
			} `json:"object_fingerprint"`
			Output []string `json:"output"`
		}
		if json.Unmarshal(data, &receipt) != nil {
			continue
		}
		objectSHA256 := receipt.ObjectSHA256
		if objectSHA256 == "" && receipt.ObjectFingerprint != nil {
			objectSHA256 = receipt.ObjectFingerprint.SHA256
		}
		if !strings.EqualFold(objectSHA256, analysis.SHA256) {
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
		hasStructured := false
		for _, line := range receipt.Output {
			if structuredOutputName(line) != "" {
				hasStructured = true
				break
			}
		}
		for _, line := range receipt.Output {
			capability := structuredOutputName(line)
			if capability == "" {
				if hasStructured {
					continue
				}
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
	for _, char := range line[1:end] {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return ""
		}
	}
	return line[1:end]
}

func inferBehaviorChains(relocations []Relocation, visibleStrings []String) []BehaviorChain {
	return inferBehaviorChainsWithRules(relocations, visibleStrings, behaviorRules)
}

func inferBehaviorChainsWithRules(relocations []Relocation, visibleStrings []String, rules []chainRule) []BehaviorChain {
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
		for _, rule := range rules {
			if rule.id == "process_memory_read" && seen["credential_process_memory@"+function] {
				continue
			}
			if !stringsMatch(stringsLower, rule.requiredStrings) {
				continue
			}
			if !functionsMatch(functions, rule.requiredFunctions) {
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
			confidence := rule.confidence
			if confidence == "" {
				confidence = "strong chain"
			}
			chains = append(chains, BehaviorChain{ID: rule.id, Name: rule.name, Summary: rule.summary, Confidence: confidence, Function: function, Effects: append([]string(nil), rule.effects...), Needs: append([]string(nil), rule.needs...), Steps: steps})
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

func functionsMatch(functions, required []string) bool {
	for _, needle := range required {
		needle = strings.ToLower(strings.TrimSpace(needle))
		found := false
		for _, function := range functions {
			if strings.Contains(strings.ToLower(function), needle) {
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

// ApplyDeclarativeSignatures adds catalog-provided behavior matches while
// preserving the built-in analyzer results. Conflicting IDs are expected to be
// qualified by the caller before they reach this boundary.
func ApplyDeclarativeSignatures(analysis *Analysis, signatures []DeclarativeSignature) {
	if analysis == nil || len(signatures) == 0 {
		return
	}
	rules := make([]chainRule, 0, len(signatures))
	for _, signature := range signatures {
		rule := chainRule{
			id: signature.ID, name: signature.Name, summary: signature.Summary,
			effects: append([]string(nil), signature.Effects...), needs: append([]string(nil), signature.Requirements...),
			requiredStrings: append([]string(nil), signature.RequiredStrings...),
		}
		if len(signature.Steps) == 1 {
			rule.confidence = "confirmed primitive"
		}
		for _, step := range signature.Steps {
			apis := make([]string, 0, len(step.APIs))
			for _, api := range step.APIs {
				apis = append(apis, strings.ToLower(strings.TrimSpace(api)))
			}
			rule.steps = append(rule.steps, chainRuleStep{action: step.Action, apis: apis})
		}
		rules = append(rules, rule)
	}
	additional := inferBehaviorChainsWithRules(analysis.RelocationDetails, analysis.Strings, rules)
	seen := map[string]bool{}
	for _, chain := range analysis.BehaviorChains {
		seen[chain.ID+"@"+chain.Function] = true
	}
	for _, chain := range additional {
		key := chain.ID + "@" + chain.Function
		if !seen[key] {
			seen[key] = true
			analysis.BehaviorChains = append(analysis.BehaviorChains, chain)
		}
	}
	sort.Slice(analysis.BehaviorChains, func(i, j int) bool {
		if analysis.BehaviorChains[i].ID != analysis.BehaviorChains[j].ID {
			return analysis.BehaviorChains[i].ID < analysis.BehaviorChains[j].ID
		}
		return analysis.BehaviorChains[i].Function < analysis.BehaviorChains[j].Function
	})
	analysis.Effects = collectEffects(analysis.Capabilities, analysis.BehaviorChains)
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
	if strings.Contains(lower, "credential") {
		effects = append(effects, "accesses credential material")
	}
	if strings.Contains(lower, "protected material") {
		effects = append(effects, "accesses protected material")
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
	case "handle_inventory":
		return []string{"an exact target PID or handle for targeted operations"}
	case "privilege_adjustment":
		return []string{"a privilege name already present in the current token"}
	case "credential_manager_access":
		return []string{"the matching Credential Manager user context", "an exact target name and byte limit for secret reads"}
	case "dpapi_access":
		return []string{"the matching DPAPI user or machine context", "an exact protected blob and byte limit"}
	case "wmi_access":
		return []string{"an explicit namespace or target host", "WMI access in the current security context"}
	case "share_inventory":
		return []string{"one explicitly supplied host"}
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
	if hints := packLockArgumentHints(path); len(hints) > 0 {
		return hints
	}
	return nil
}

func packLockArgumentHints(path string) []ArgumentHint {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	base := filepath.Base(absolute)
	for _, suffix := range []string{".x64.o", ".x86.o", ".o"} {
		if strings.HasSuffix(strings.ToLower(base), suffix) {
			base = base[:len(base)-len(suffix)]
			break
		}
	}
	objectDir := filepath.Dir(absolute)
	workspace := objectDir
	if strings.EqualFold(filepath.Base(objectDir), "dist") {
		workspace = filepath.Dir(objectDir)
	}
	candidates := []string{
		filepath.Join(workspace, "bofs", base, "bofbench.lock.json"),
		filepath.Join(objectDir, "bofbench.lock.json"),
		filepath.Join(filepath.Dir(objectDir), "bofbench.lock.json"),
	}
	seenPath := map[string]bool{}
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if seenPath[candidate] {
			continue
		}
		seenPath[candidate] = true
		data, readErr := os.ReadFile(candidate)
		if readErr != nil {
			continue
		}
		var lock struct {
			Schema string `json:"schema"`
			Packs  []struct {
				Arguments []struct {
					Name     string `json:"name"`
					Type     string `json:"type"`
					Required bool   `json:"required"`
				} `json:"arguments"`
			} `json:"packs"`
		}
		if json.Unmarshal(data, &lock) != nil || lock.Schema != "bofbench.pack-lock" {
			continue
		}
		var hints []ArgumentHint
		seen := map[string]bool{}
		for _, item := range lock.Packs {
			for _, argument := range item.Arguments {
				key := argument.Name + "\x00" + argument.Type
				if argument.Name == "" || argument.Type == "" || seen[key] {
					continue
				}
				seen[key] = true
				hints = append(hints, ArgumentHint{Name: argument.Name, Type: argument.Type, Required: argument.Required, Source: "pack lock"})
			}
		}
		return hints
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
