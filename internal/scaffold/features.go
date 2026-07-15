package scaffold

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	includeMarker = "/* bofbench:feature-includes */"
	callMarker    = "    /* bofbench:feature-calls */"
)

type Feature struct {
	Name        string
	Description string
	Declaration string
	Call        string
}

type FeaturePack struct {
	Name        string
	Description string
	Impact      string
	Features    []string
}

type AddResult struct {
	Project  string   `json:"project"`
	Source   string   `json:"source"`
	Header   string   `json:"header"`
	Added    []string `json:"added,omitempty"`
	Existing []string `json:"existing,omitempty"`
}

var features = []Feature{
	{
		Name:        "process",
		Description: "report the current process and thread identifiers",
		Declaration: `DWORD WINAPI KERNEL32$GetCurrentProcessId(void);
DWORD WINAPI KERNEL32$GetCurrentThreadId(void);

static void bofbench_feature_process(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "[process] pid=%lu tid=%lu",
        KERNEL32$GetCurrentProcessId(), KERNEL32$GetCurrentThreadId());
}`,
		Call: "bofbench_feature_process();",
	},
	{
		Name:        "host",
		Description: "report the local computer name",
		Declaration: `BOOL WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);

static void bofbench_feature_host(void) {
	char value[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(value);
	value[0] = '\0';
    if (KERNEL32$GetComputerNameA(value, &size)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[host] name=%s", value);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[host] GetComputerNameA failed");
    }
}`,
		Call: "bofbench_feature_host();",
	},
	{
		Name:        "identity",
		Description: "report the current Windows user name",
		Declaration: `BOOL WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);

static void bofbench_feature_identity(void) {
	char value[UNLEN + 1];
    DWORD size = sizeof(value);
	value[0] = '\0';
    if (ADVAPI32$GetUserNameA(value, &size)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[identity] user=%s", value);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[identity] GetUserNameA failed");
    }
}`,
		Call: "bofbench_feature_identity();",
	},
	{
		Name:        "filesystem",
		Description: "report the current Windows temporary directory",
		Declaration: `DWORD WINAPI KERNEL32$GetTempPathA(DWORD, LPSTR);

static void bofbench_feature_filesystem(void) {
	char value[MAX_PATH + 1];
	value[0] = '\0';
    DWORD size = KERNEL32$GetTempPathA(sizeof(value), value);
    if (size > 0 && size < sizeof(value)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[filesystem] temp=%s", value);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[filesystem] GetTempPathA failed");
    }
}`,
		Call: "bofbench_feature_filesystem();",
	},
	{
		Name:        "network",
		Description: "initialize Winsock and report the local host name",
		Declaration: `int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
int WSAAPI WS2_32$gethostname(char *, int);
int WSAAPI WS2_32$WSACleanup(void);

static void bofbench_feature_network(void) {
    WSADATA data;
	char value[256];
	value[0] = '\0';
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[network] WSAStartup failed");
        return;
    }
    if (WS2_32$gethostname(value, sizeof(value)) == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[network] hostname=%s", value);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[network] gethostname failed");
    }
    WS2_32$WSACleanup();
}`,
		Call: "bofbench_feature_network();",
	},
	{
		Name:        "registry",
		Description: "read the Windows product name from the local registry",
		Declaration: `LSTATUS WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
LSTATUS WINAPI ADVAPI32$RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);

static void bofbench_feature_registry(void) {
    HKEY key = NULL;
	char value[256];
    DWORD type = 0;
    DWORD size = sizeof(value);
	value[0] = '\0';
    LSTATUS status = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0,
        KEY_QUERY_VALUE,
        &key);
    if (status == ERROR_SUCCESS) {
        status = ADVAPI32$RegQueryValueExA(key, "ProductName", NULL, &type, (LPBYTE)value, &size);
        ADVAPI32$RegCloseKey(key);
    }
    if (status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        value[sizeof(value) - 1] = '\0';
        BeaconPrintf(CALLBACK_OUTPUT, "[registry] product=%s", value);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[registry] product query failed status=%ld", status);
    }
}`,
		Call: "bofbench_feature_registry();",
	},
	{
		Name:        "process-list",
		Description: "enumerate a bounded snapshot of local processes",
		Declaration: `HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static void bofbench_feature_process_list(void) {
    HANDLE snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    DWORD shown = 0;
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[process-list] CreateToolhelp32Snapshot failed");
        return;
    }
    entry.dwSize = sizeof(entry);
    if (!KERNEL32$Process32First(snapshot, &entry)) {
        BeaconPrintf(CALLBACK_ERROR, "[process-list] Process32First failed");
        KERNEL32$CloseHandle(snapshot);
        return;
    }
    do {
        BeaconPrintf(CALLBACK_OUTPUT, "[process-list] pid=%lu ppid=%lu threads=%lu image=%s",
            entry.th32ProcessID, entry.th32ParentProcessID, entry.cntThreads, entry.szExeFile);
        shown++;
    } while (shown < 16 && KERNEL32$Process32Next(snapshot, &entry));
    BeaconPrintf(CALLBACK_OUTPUT, "[process-list] shown=%lu limit=16", shown);
    KERNEL32$CloseHandle(snapshot);
}`,
		Call: "bofbench_feature_process_list();",
	},
	{
		Name:        "process-search",
		Description: "enumerate local processes with a runtime name filter and result limit",
		Declaration: `HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static void bofbench_feature_process_search(datap *parser) {
    int filter_length = 0;
    char *filter = BeaconDataExtract(parser, &filter_length);
    int requested_limit = BeaconDataInt(parser);
    int filter_chars = filter_length > 0 ? filter_length - 1 : 0;
    DWORD limit = requested_limit > 0 ? (DWORD)requested_limit : 25;
    HANDLE snapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 entry;
    DWORD matched = 0;
    DWORD examined = 0;
    if (limit > 256) limit = 256;
    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[process-discovery] status=error api=CreateToolhelp32Snapshot");
        return;
    }
    entry.dwSize = sizeof(entry);
    if (!KERNEL32$Process32First(snapshot, &entry)) {
        BeaconPrintf(CALLBACK_ERROR, "[process-discovery] status=error api=Process32First");
        KERNEL32$CloseHandle(snapshot);
        return;
    }
    do {
        BOOL selected = filter == NULL || filter_chars <= 0;
        int start = 0;
        examined++;
        while (!selected && entry.szExeFile[start] != '\0') {
            int index = 0;
            while (index < filter_chars && entry.szExeFile[start + index] != '\0') {
                char left = entry.szExeFile[start + index];
                char right = filter[index];
                if (left >= 'A' && left <= 'Z') left = (char)(left + ('a' - 'A'));
                if (right >= 'A' && right <= 'Z') right = (char)(right + ('a' - 'A'));
                if (left != right) break;
                index++;
            }
            if (index == filter_chars) selected = TRUE;
            start++;
        }
        if (!selected) continue;
        BeaconPrintf(CALLBACK_OUTPUT, "[process-discovery] pid=%lu ppid=%lu threads=%lu image=%s",
            entry.th32ProcessID, entry.th32ParentProcessID, entry.cntThreads, entry.szExeFile);
        matched++;
    } while (matched < limit && KERNEL32$Process32Next(snapshot, &entry));
    BeaconPrintf(CALLBACK_OUTPUT, "[process-discovery] status=ok matched=%lu examined=%lu limit=%lu filter=%s",
        matched, examined, limit, (filter != NULL && filter_length > 0) ? filter : "*");
    KERNEL32$CloseHandle(snapshot);
}`,
		Call: "bofbench_feature_process_search($PARSER);",
	},
	{
		Name:        "token-context",
		Description: "report token elevation and integrity context",
		Declaration: `HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
PUCHAR WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID);
PDWORD WINAPI ADVAPI32$GetSidSubAuthority(PSID, DWORD);

static const char *bofbench_integrity_name(DWORD rid) {
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) return "system";
    if (rid >= SECURITY_MANDATORY_HIGH_RID) return "high";
    if (rid >= SECURITY_MANDATORY_MEDIUM_RID) return "medium";
    if (rid >= SECURITY_MANDATORY_LOW_RID) return "low";
    return "untrusted";
}

static void bofbench_feature_token_context(void) {
    HANDLE token = NULL;
    TOKEN_ELEVATION elevation;
    BYTE integrity_buffer[256];
    PTOKEN_MANDATORY_LABEL label = (PTOKEN_MANDATORY_LABEL)integrity_buffer;
    DWORD returned = 0;
    DWORD rid = 0;
    PUCHAR count = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &token)) {
        BeaconPrintf(CALLBACK_ERROR, "[token-context] OpenProcessToken failed");
        return;
    }
    if (!ADVAPI32$GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned)) {
        BeaconPrintf(CALLBACK_ERROR, "[token-context] TokenElevation query failed");
        KERNEL32$CloseHandle(token);
        return;
    }
    if (!ADVAPI32$GetTokenInformation(token, TokenIntegrityLevel, integrity_buffer, sizeof(integrity_buffer), &returned)) {
        BeaconPrintf(CALLBACK_ERROR, "[token-context] TokenIntegrityLevel query failed");
        KERNEL32$CloseHandle(token);
        return;
    }
    count = ADVAPI32$GetSidSubAuthorityCount(label->Label.Sid);
    if (count != NULL && *count > 0) {
        rid = *ADVAPI32$GetSidSubAuthority(label->Label.Sid, (DWORD)(*count - 1));
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[token-context] elevated=%lu integrity=%s rid=0x%lx",
        elevation.TokenIsElevated, bofbench_integrity_name(rid), rid);
    KERNEL32$CloseHandle(token);
}`,
		Call: "bofbench_feature_token_context();",
	},
	{
		Name:        "service-list",
		Description: "enumerate a bounded set of local Windows services",
		Declaration: `SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR, LPCSTR, DWORD);
BOOL WINAPI ADVAPI32$EnumServicesStatusExA(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCSTR);
BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
HANDLE WINAPI KERNEL32$GetProcessHeap(void);
LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

static void bofbench_feature_service_list(void) {
    SC_HANDLE manager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    HANDLE heap = KERNEL32$GetProcessHeap();
    LPBYTE buffer = NULL;
    DWORD needed = 0;
    DWORD count = 0;
    DWORD resume = 0;
    DWORD shown = 0;
    LPENUM_SERVICE_STATUS_PROCESSA entries = NULL;
    if (manager == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[service-list] OpenSCManagerA failed");
        return;
    }
    ADVAPI32$EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &needed, &count, &resume, NULL);
    if (needed == 0 || needed > 1048576 || heap == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[service-list] invalid buffer requirement=%lu", needed);
        ADVAPI32$CloseServiceHandle(manager);
        return;
    }
    buffer = (LPBYTE)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, needed);
    if (buffer == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[service-list] allocation failed bytes=%lu", needed);
        ADVAPI32$CloseServiceHandle(manager);
        return;
    }
    resume = 0;
    count = 0;
    if (!ADVAPI32$EnumServicesStatusExA(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_STATE_ALL, buffer, needed, &needed, &count, &resume, NULL) && count == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[service-list] enumeration failed required=%lu", needed);
        KERNEL32$HeapFree(heap, 0, buffer);
        ADVAPI32$CloseServiceHandle(manager);
        return;
    }
    entries = (LPENUM_SERVICE_STATUS_PROCESSA)buffer;
    while (shown < count && shown < 16) {
        BeaconPrintf(CALLBACK_OUTPUT, "[service-list] name=%s state=%lu pid=%lu",
            entries[shown].lpServiceName,
            entries[shown].ServiceStatusProcess.dwCurrentState,
            entries[shown].ServiceStatusProcess.dwProcessId);
        shown++;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[service-list] shown=%lu returned=%lu limit=16", shown, count);
    KERNEL32$HeapFree(heap, 0, buffer);
    ADVAPI32$CloseServiceHandle(manager);
}`,
		Call: "bofbench_feature_service_list();",
	},
	{
		Name:        "tcp-connections",
		Description: "inventory a bounded set of local IPv4 TCP endpoints and owning PIDs",
		Declaration: `DWORD WINAPI IPHLPAPI$GetExtendedTcpTable(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
HANDLE WINAPI KERNEL32$GetProcessHeap(void);
LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

static DWORD bofbench_tcp_port(DWORD value) {
    return ((value & 0x000000ffUL) << 8) | ((value & 0x0000ff00UL) >> 8);
}

static void bofbench_feature_tcp_connections(void) {
    HANDLE heap = KERNEL32$GetProcessHeap();
    LPBYTE buffer = NULL;
    DWORD size = 0;
    DWORD status = IPHLPAPI$GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    PMIB_TCPTABLE_OWNER_PID table = NULL;
    DWORD shown = 0;
    if (size == 0 || size > 1048576 || heap == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[tcp-connections] invalid buffer requirement=%lu status=%lu", size, status);
        return;
    }
    buffer = (LPBYTE)KERNEL32$HeapAlloc(heap, HEAP_ZERO_MEMORY, size);
    if (buffer == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[tcp-connections] allocation failed bytes=%lu", size);
        return;
    }
    status = IPHLPAPI$GetExtendedTcpTable(buffer, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (status != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[tcp-connections] GetExtendedTcpTable failed status=%lu required=%lu", status, size);
        KERNEL32$HeapFree(heap, 0, buffer);
        return;
    }
    table = (PMIB_TCPTABLE_OWNER_PID)buffer;
    while (shown < table->dwNumEntries && shown < 16) {
        PMIB_TCPROW_OWNER_PID row = &table->table[shown];
        DWORD local = row->dwLocalAddr;
        DWORD remote = row->dwRemoteAddr;
        BeaconPrintf(CALLBACK_OUTPUT,
            "[tcp-connections] pid=%lu state=%lu local=%lu.%lu.%lu.%lu:%lu remote=%lu.%lu.%lu.%lu:%lu",
            row->dwOwningPid, row->dwState,
            local & 0xff, (local >> 8) & 0xff, (local >> 16) & 0xff, (local >> 24) & 0xff, bofbench_tcp_port(row->dwLocalPort),
            remote & 0xff, (remote >> 8) & 0xff, (remote >> 16) & 0xff, (remote >> 24) & 0xff, bofbench_tcp_port(row->dwRemotePort));
        shown++;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[tcp-connections] shown=%lu total=%lu limit=16", shown, table->dwNumEntries);
    KERNEL32$HeapFree(heap, 0, buffer);
}`,
		Call: "bofbench_feature_tcp_connections();",
	},
	{
		Name:        "domain-context",
		Description: "report local workgroup or domain join context",
		Declaration: `NET_API_STATUS NET_API_FUNCTION NETAPI32$NetGetJoinInformation(LPCWSTR, LPWSTR *, PNETSETUP_JOIN_STATUS);
NET_API_STATUS NET_API_FUNCTION NETAPI32$NetApiBufferFree(LPVOID);

static void bofbench_feature_domain_context(void) {
    LPWSTR wide_name = NULL;
    NETSETUP_JOIN_STATUS join_status = NetSetupUnknownStatus;
    NET_API_STATUS status = NETAPI32$NetGetJoinInformation(NULL, &wide_name, &join_status);
    char name[128];
    DWORD index = 0;
    name[0] = '\0';
    if (status != NERR_Success) {
        BeaconPrintf(CALLBACK_ERROR, "[domain-context] NetGetJoinInformation failed status=%lu", status);
        return;
    }
    if (wide_name != NULL) {
        while (index < sizeof(name) - 1 && wide_name[index] != L'\0') {
            WCHAR value = wide_name[index];
            name[index] = value < 128 ? (char)value : '?';
            index++;
        }
        name[index] = '\0';
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[domain-context] status=%lu name=%s", (DWORD)join_status, name);
    if (wide_name != NULL) {
        NETAPI32$NetApiBufferFree(wide_name);
    }
}`,
		Call: "bofbench_feature_domain_context();",
	},
	{
		Name:        "process-tree",
		Description: "enumerate a bounded process tree with session and architecture context",
		Declaration: `HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
BOOL WINAPI KERNEL32$ProcessIdToSessionId(DWORD, DWORD *);
HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
BOOL WINAPI KERNEL32$IsWow64Process(HANDLE, PBOOL);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static BOOL bofbench_process_tree_match(const char *value, const char *filter, int length) {
    int start = 0;
    if (filter == NULL || length <= 0) return TRUE;
    while (value[start] != '\0') {
        int index = 0;
        while (index < length && value[start + index] != '\0') {
            char left = value[start + index];
            char right = filter[index];
            if (left >= 'A' && left <= 'Z') left = (char)(left + 32);
            if (right >= 'A' && right <= 'Z') right = (char)(right + 32);
            if (left != right) break;
            index++;
        }
        if (index == length) return TRUE;
        start++;
    }
    return FALSE;
}

static void bofbench_feature_process_tree(datap *parser) {
    int filter_length = 0;
    char *filter = BeaconDataExtract(parser, &filter_length);
    int requested = BeaconDataInt(parser);
    DWORD limit = requested > 0 ? (DWORD)requested : 25;
    DWORD shown = 0;
    PROCESSENTRY32 entry;
    HANDLE snapshot;
    if (limit > 256) limit = 256;
    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[process-tree] status=error api=CreateToolhelp32Snapshot");
        return;
    }
    entry.dwSize = sizeof(entry);
    if (!KERNEL32$Process32First(snapshot, &entry)) {
        KERNEL32$CloseHandle(snapshot);
        BeaconPrintf(CALLBACK_ERROR, "[process-tree] status=error api=Process32First");
        return;
    }
    do {
        DWORD session = 0;
        BOOL wow64 = FALSE;
        HANDLE process = NULL;
        if (!bofbench_process_tree_match(entry.szExeFile, filter, filter_length > 0 ? filter_length - 1 : 0)) continue;
        KERNEL32$ProcessIdToSessionId(entry.th32ProcessID, &session);
        process = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
        if (process != NULL) {
            KERNEL32$IsWow64Process(process, &wow64);
            KERNEL32$CloseHandle(process);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[process-tree] pid=%lu ppid=%lu session=%lu arch=%s image=%s",
            entry.th32ProcessID, entry.th32ParentProcessID, session, wow64 ? "x86" : "x64", entry.szExeFile);
        shown++;
    } while (shown < limit && KERNEL32$Process32Next(snapshot, &entry));
    KERNEL32$CloseHandle(snapshot);
    BeaconPrintf(CALLBACK_OUTPUT, "[process-tree] status=complete shown=%lu limit=%lu filter=%s", shown, limit, filter_length > 1 ? filter : "*");
}`,
		Call: "bofbench_feature_process_tree($PARSER);",
	},
	{
		Name:        "thread-inventory",
		Description: "enumerate bounded thread identifiers and priorities for one process",
		Declaration: `HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Thread32First(HANDLE, LPTHREADENTRY32);
BOOL WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static void bofbench_feature_thread_inventory(datap *parser) {
    DWORD target_pid = (DWORD)BeaconDataInt(parser);
    int requested = BeaconDataInt(parser);
    DWORD limit = requested > 0 ? (DWORD)requested : 64;
    DWORD shown = 0;
    THREADENTRY32 entry;
    HANDLE snapshot;
    if (limit > 512) limit = 512;
    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[thread-inventory] status=error api=CreateToolhelp32Snapshot");
        return;
    }
    entry.dwSize = sizeof(entry);
    if (!KERNEL32$Thread32First(snapshot, &entry)) {
        KERNEL32$CloseHandle(snapshot);
        BeaconPrintf(CALLBACK_ERROR, "[thread-inventory] status=error api=Thread32First");
        return;
    }
    do {
        if (entry.th32OwnerProcessID != target_pid) continue;
        BeaconPrintf(CALLBACK_OUTPUT, "[thread-inventory] pid=%lu tid=%lu base_priority=%ld delta_priority=%ld",
            target_pid, entry.th32ThreadID, entry.tpBasePri, entry.tpDeltaPri);
        shown++;
    } while (shown < limit && KERNEL32$Thread32Next(snapshot, &entry));
    KERNEL32$CloseHandle(snapshot);
    BeaconPrintf(CALLBACK_OUTPUT, "[thread-inventory] status=complete pid=%lu shown=%lu limit=%lu", target_pid, shown, limit);
}`,
		Call: "bofbench_feature_thread_inventory($PARSER);",
	},
	{
		Name:        "process-mitigation-inventory",
		Description: "report bounded mitigation-policy flags for one explicitly selected process",
		Declaration: `BOOL WINAPI KERNEL32$GetProcessMitigationPolicy(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static void bofbench_feature_process_mitigation_inventory(datap *parser) {
    DWORD target_pid = (DWORD)BeaconDataInt(parser);
    HANDLE process;
    DWORD dep[2] = {0, 0};
    DWORD aslr = 0, dynamic_code = 0, cfg = 0, signature = 0, child = 0;
    DWORD available = 0;
    process = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
    if (process == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[process-mitigation-inventory] status=failed target_pid=%lu error=%lu", target_pid, KERNEL32$GetLastError());
        return;
    }
    if (KERNEL32$GetProcessMitigationPolicy(process, (PROCESS_MITIGATION_POLICY)0, dep, sizeof(dep))) available++;
    if (KERNEL32$GetProcessMitigationPolicy(process, (PROCESS_MITIGATION_POLICY)1, &aslr, sizeof(aslr))) available++;
    if (KERNEL32$GetProcessMitigationPolicy(process, (PROCESS_MITIGATION_POLICY)2, &dynamic_code, sizeof(dynamic_code))) available++;
    if (KERNEL32$GetProcessMitigationPolicy(process, (PROCESS_MITIGATION_POLICY)7, &cfg, sizeof(cfg))) available++;
    if (KERNEL32$GetProcessMitigationPolicy(process, (PROCESS_MITIGATION_POLICY)8, &signature, sizeof(signature))) available++;
    if (KERNEL32$GetProcessMitigationPolicy(process, (PROCESS_MITIGATION_POLICY)13, &child, sizeof(child))) available++;
    BeaconPrintf(CALLBACK_OUTPUT, "[process-mitigation-inventory] target_pid=%lu dep=0x%08lx aslr=0x%08lx dynamic_code=0x%08lx cfg=0x%08lx signature=0x%08lx child_process=0x%08lx",
        target_pid, dep[0], aslr, dynamic_code, cfg, signature, child);
    BeaconPrintf(CALLBACK_OUTPUT, "[process-mitigation-inventory] status=complete target_pid=%lu policies=%lu", target_pid, available);
    KERNEL32$CloseHandle(process);
}`,
		Call: "bofbench_feature_process_mitigation_inventory($PARSER);",
	},
	{
		Name:        "process-memory-map",
		Description: "enumerate bounded committed virtual-memory regions for one explicitly selected process",
		Declaration: `#include <psapi.h>
HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
SIZE_T WINAPI KERNEL32$VirtualQueryEx(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DWORD WINAPI PSAPI$GetMappedFileNameA(HANDLE, LPVOID, LPSTR, DWORD);

static void bofbench_feature_process_memory_map(datap *parser) {
    DWORD target_pid = (DWORD)BeaconDataInt(parser);
    int requested = BeaconDataInt(parser);
    DWORD limit = requested > 0 ? (DWORD)requested : 64;
    DWORD shown = 0;
    HANDLE process;
    ULONG_PTR cursor = 0;
    MEMORY_BASIC_INFORMATION region;
    if (limit > 512) limit = 512;
    process = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_pid);
    if (process == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[process-memory-map] status=failed target_pid=%lu error=%lu", target_pid, KERNEL32$GetLastError());
        return;
    }
    while (shown < limit && KERNEL32$VirtualQueryEx(process, (LPCVOID)cursor, &region, sizeof(region)) == sizeof(region)) {
        ULONG_PTR next = (ULONG_PTR)region.BaseAddress + (ULONG_PTR)region.RegionSize;
        if (region.State == MEM_COMMIT) {
            char mapped[MAX_PATH + 1];
            DWORD mapped_length;
            mapped[0] = '\0';
            mapped_length = PSAPI$GetMappedFileNameA(process, region.BaseAddress, mapped, MAX_PATH);
            if (mapped_length >= MAX_PATH) mapped[MAX_PATH] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "[process-memory-map] target_pid=%lu base=0x%llx size=%llu protect=0x%08lx type=0x%08lx mapped=%s",
                target_pid, (unsigned long long)(ULONG_PTR)region.BaseAddress, (unsigned long long)region.RegionSize,
                region.Protect, region.Type, mapped_length > 0 ? mapped : "-");
            shown++;
        }
        if (next <= cursor) break;
        cursor = next;
    }
    KERNEL32$CloseHandle(process);
    BeaconPrintf(CALLBACK_OUTPUT, "[process-memory-map] status=complete target_pid=%lu shown=%lu limit=%lu", target_pid, shown, limit);
}`,
		Call: "bofbench_feature_process_memory_map($PARSER);",
	},
	{
		Name:        "thread-start-inventory",
		Description: "enumerate bounded thread start addresses and containing process regions for one selected process",
		Declaration: `#include <psapi.h>
HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Thread32First(HANDLE, LPTHREADENTRY32);
BOOL WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);
HANDLE WINAPI KERNEL32$OpenThread(DWORD, BOOL, DWORD);
HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
SIZE_T WINAPI KERNEL32$VirtualQueryEx(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DWORD WINAPI PSAPI$GetMappedFileNameA(HANDLE, LPVOID, LPSTR, DWORD);
NTSTATUS NTAPI NTDLL$NtQueryInformationThread(HANDLE, ULONG, PVOID, ULONG, PULONG);

static void bofbench_feature_thread_start_inventory(datap *parser) {
    DWORD target_pid = (DWORD)BeaconDataInt(parser);
    int requested = BeaconDataInt(parser);
    DWORD limit = requested > 0 ? (DWORD)requested : 64;
    DWORD shown = 0;
    HANDLE snapshot, process;
    THREADENTRY32 entry;
    if (limit > 512) limit = 512;
    process = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_pid);
    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (process == NULL || snapshot == INVALID_HANDLE_VALUE) {
        if (process != NULL) KERNEL32$CloseHandle(process);
        if (snapshot != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(snapshot);
        BeaconPrintf(CALLBACK_ERROR, "[thread-start-inventory] status=failed target_pid=%lu error=%lu", target_pid, KERNEL32$GetLastError());
        return;
    }
    entry.dwSize = sizeof(entry);
    if (KERNEL32$Thread32First(snapshot, &entry)) do {
        HANDLE thread;
        PVOID start = NULL;
        MEMORY_BASIC_INFORMATION region;
        char mapped[MAX_PATH + 1];
        DWORD mapped_length = 0;
        NTSTATUS status;
        if (entry.th32OwnerProcessID != target_pid) continue;
        thread = KERNEL32$OpenThread(THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID);
        if (thread == NULL) continue;
        status = NTDLL$NtQueryInformationThread(thread, 9, &start, sizeof(start), NULL);
        mapped[0] = '\0';
        if (status >= 0 && KERNEL32$VirtualQueryEx(process, start, &region, sizeof(region)) == sizeof(region)) {
            mapped_length = PSAPI$GetMappedFileNameA(process, region.BaseAddress, mapped, MAX_PATH);
        } else {
            region.Protect = 0;
            region.Type = 0;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[thread-start-inventory] target_pid=%lu tid=%lu start=0x%llx state=%s protect=0x%08lx type=0x%08lx mapped=%s",
            target_pid, entry.th32ThreadID, (unsigned long long)(ULONG_PTR)start, status >= 0 ? "queryable" : "unavailable",
            region.Protect, region.Type, mapped_length > 0 ? mapped : "-");
        KERNEL32$CloseHandle(thread);
        shown++;
    } while (shown < limit && KERNEL32$Thread32Next(snapshot, &entry));
    KERNEL32$CloseHandle(snapshot);
    KERNEL32$CloseHandle(process);
    BeaconPrintf(CALLBACK_OUTPUT, "[thread-start-inventory] status=complete target_pid=%lu shown=%lu limit=%lu", target_pid, shown, limit);
}`,
		Call: "bofbench_feature_thread_start_inventory($PARSER);",
	},
	{
		Name:        "named-pipe-inventory",
		Description: "enumerate bounded named-pipe entries with an optional prefix filter",
		Declaration: `HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
BOOL WINAPI KERNEL32$FindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
BOOL WINAPI KERNEL32$FindClose(HANDLE);

static BOOL bofbench_pipe_prefix(const char *value, const char *prefix, int length) {
    int index = 0;
    if (prefix == NULL || length <= 0) return TRUE;
    while (index < length && value[index] != '\0') {
        char left = value[index];
        char right = prefix[index];
        if (left >= 'A' && left <= 'Z') left = (char)(left + 32);
        if (right >= 'A' && right <= 'Z') right = (char)(right + 32);
        if (left != right) return FALSE;
        index++;
    }
    return index == length;
}

static void bofbench_feature_named_pipe_inventory(datap *parser) {
    int prefix_length = 0;
    char *prefix = BeaconDataExtract(parser, &prefix_length);
    int requested = BeaconDataInt(parser);
    DWORD limit = requested > 0 ? (DWORD)requested : 64;
    DWORD shown = 0;
    WIN32_FIND_DATAA entry;
    HANDLE search;
    if (limit > 512) limit = 512;
    search = KERNEL32$FindFirstFileA("\\\\.\\pipe\\*", &entry);
    if (search == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[named-pipe-inventory] status=error api=FindFirstFileA");
        return;
    }
    do {
        if (!bofbench_pipe_prefix(entry.cFileName, prefix, prefix_length > 0 ? prefix_length - 1 : 0)) continue;
        BeaconPrintf(CALLBACK_OUTPUT, "[named-pipe-inventory] name=%s", entry.cFileName);
        shown++;
    } while (shown < limit && KERNEL32$FindNextFileA(search, &entry));
    KERNEL32$FindClose(search);
    BeaconPrintf(CALLBACK_OUTPUT, "[named-pipe-inventory] status=complete shown=%lu limit=%lu prefix=%s", shown, limit, prefix_length > 1 ? prefix : "*");
}`,
		Call: "bofbench_feature_named_pipe_inventory($PARSER);",
	},
	{
		Name:        "ldap-query",
		Description: "run a bounded LDAP query with an explicit base, filter, and attribute list",
		Declaration: `#include <winldap.h>
#include <dsgetdc.h>
DWORD WINAPI NETAPI32$DsGetDcNameA(LPCSTR, LPCSTR, GUID *, LPCSTR, ULONG, PDOMAIN_CONTROLLER_INFOA *);
NET_API_STATUS NET_API_FUNCTION NETAPI32$NetApiBufferFree(LPVOID);
LDAP * LDAPAPI WLDAP32$ldap_initA(PCHAR, ULONG);
ULONG LDAPAPI WLDAP32$ldap_set_optionA(LDAP *, int, const void *);
ULONG LDAPAPI WLDAP32$ldap_connect(LDAP *, struct l_timeval *);
ULONG LDAPAPI WLDAP32$ldap_bind_sA(LDAP *, PCHAR, PCHAR, ULONG);
ULONG LDAPAPI WLDAP32$ldap_search_sA(LDAP *, PCHAR, ULONG, PCHAR, PCHAR *, ULONG, LDAPMessage **);
LDAPMessage * LDAPAPI WLDAP32$ldap_first_entry(LDAP *, LDAPMessage *);
LDAPMessage * LDAPAPI WLDAP32$ldap_next_entry(LDAP *, LDAPMessage *);
PCHAR LDAPAPI WLDAP32$ldap_get_dnA(LDAP *, LDAPMessage *);
PCHAR * LDAPAPI WLDAP32$ldap_get_valuesA(LDAP *, LDAPMessage *, PCHAR);
ULONG LDAPAPI WLDAP32$ldap_value_freeA(PCHAR *);
VOID LDAPAPI WLDAP32$ldap_memfreeA(PCHAR);
ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage *);
ULONG LDAPAPI WLDAP32$ldap_unbind_s(LDAP *);

static void bofbench_domain_to_base(const char *domain, char *base, DWORD capacity) {
    DWORD used = 0;
    DWORD index = 0;
    while (domain != NULL && domain[index] != '\0' && used + 4 < capacity) {
        if (index == 0 || domain[index - 1] == '.') {
            if (used > 0) base[used++] = ',';
            base[used++] = 'D'; base[used++] = 'C'; base[used++] = '=';
        }
        if (domain[index] != '.') base[used++] = domain[index];
        index++;
    }
    base[used] = '\0';
}

static void bofbench_feature_ldap_query(datap *parser) {
    int server_length = 0, base_length = 0, filter_length = 0, attributes_length = 0;
    char *server = BeaconDataExtract(parser, &server_length);
    char *base = BeaconDataExtract(parser, &base_length);
    char *filter = BeaconDataExtract(parser, &filter_length);
    char *attributes_text = BeaconDataExtract(parser, &attributes_length);
    int requested = BeaconDataInt(parser);
    DWORD limit = requested > 0 ? (DWORD)requested : 25;
    PDOMAIN_CONTROLLER_INFOA dc = NULL;
    LDAP *ldap = NULL;
    LDAPMessage *message = NULL;
    LDAPMessage *entry = NULL;
    char base_buffer[512];
    char *attributes[9];
    DWORD attribute_count = 0;
    DWORD shown = 0;
    ULONG version = LDAP_VERSION3;
    ULONG status;
    DWORD index;
    if (limit > 100) limit = 100;
    if (NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &dc) != ERROR_SUCCESS || dc == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[ldap-query] status=error api=DsGetDcNameA");
        return;
    }
    if (server_length <= 1) server = dc->DomainControllerName + 2;
    if (base_length <= 1) {
        bofbench_domain_to_base(dc->DomainName, base_buffer, sizeof(base_buffer));
        base = base_buffer;
    }
    if (filter_length <= 1) filter = "(objectClass=*)";
    if (attributes_length <= 1) attributes_text = "distinguishedName";
    attributes[attribute_count++] = attributes_text;
    for (index = 0; attributes_text[index] != '\0' && attribute_count < 8; index++) {
        if (attributes_text[index] == ',') {
            attributes_text[index] = '\0';
            attributes[attribute_count++] = &attributes_text[index + 1];
        }
    }
    attributes[attribute_count] = NULL;
    ldap = WLDAP32$ldap_initA(server, LDAP_PORT);
    if (ldap == NULL) {
        NETAPI32$NetApiBufferFree(dc);
        BeaconPrintf(CALLBACK_ERROR, "[ldap-query] status=error api=ldap_initA");
        return;
    }
    WLDAP32$ldap_set_optionA(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
    status = WLDAP32$ldap_connect(ldap, NULL);
    if (status == LDAP_SUCCESS) status = WLDAP32$ldap_bind_sA(ldap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (status == LDAP_SUCCESS) status = WLDAP32$ldap_search_sA(ldap, base, LDAP_SCOPE_SUBTREE, filter, attributes, 0, &message);
    if (status != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[ldap-query] status=error ldap_status=%lu server=%s base=%s", status, server, base);
        if (message != NULL) WLDAP32$ldap_msgfree(message);
        WLDAP32$ldap_unbind_s(ldap);
        NETAPI32$NetApiBufferFree(dc);
        return;
    }
    entry = WLDAP32$ldap_first_entry(ldap, message);
    while (entry != NULL && shown < limit) {
        PCHAR dn = WLDAP32$ldap_get_dnA(ldap, entry);
        DWORD attribute_index;
        BeaconPrintf(CALLBACK_OUTPUT, "[ldap-query] row=%lu dn=%s", shown + 1, dn != NULL ? dn : "");
        for (attribute_index = 0; attribute_index < attribute_count; attribute_index++) {
            PCHAR *values = WLDAP32$ldap_get_valuesA(ldap, entry, attributes[attribute_index]);
            if (values != NULL && values[0] != NULL) {
                BeaconPrintf(CALLBACK_OUTPUT, "[ldap-query] row=%lu attribute=%s value=%s", shown + 1, attributes[attribute_index], values[0]);
                WLDAP32$ldap_value_freeA(values);
            }
        }
        if (dn != NULL) WLDAP32$ldap_memfreeA(dn);
        shown++;
        entry = WLDAP32$ldap_next_entry(ldap, entry);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[ldap-query] status=complete shown=%lu limit=%lu server=%s base=%s filter=%s", shown, limit, server, base, filter);
    WLDAP32$ldap_msgfree(message);
    WLDAP32$ldap_unbind_s(ldap);
    NETAPI32$NetApiBufferFree(dc);
}`,
		Call: "bofbench_feature_ldap_query($PARSER);",
	},
	{
		Name:        "security-package-inventory",
		Description: "enumerate bounded Windows authentication and security-support packages",
		Declaration: `#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <sspi.h>
SECURITY_STATUS WINAPI SECUR32$EnumerateSecurityPackagesW(PULONG, PSecPkgInfoW *);
SECURITY_STATUS WINAPI SECUR32$FreeContextBuffer(PVOID);

static void bofbench_security_wide_text(const WCHAR *source, char *target, DWORD capacity) {
    DWORD index = 0;
    if (capacity == 0) return;
    while (source != NULL && source[index] != L'\0' && index + 1 < capacity) {
        target[index] = source[index] < 128 ? (char)source[index] : '?';
        index++;
    }
    target[index] = '\0';
}

static BOOL bofbench_security_match(const char *value, const char *filter, int length) {
    int start = 0;
    if (filter == NULL || length <= 0) return TRUE;
    while (value[start] != '\0') {
        int index = 0;
        while (index < length && value[start + index] != '\0') {
            char left = value[start + index], right = filter[index];
            if (left >= 'A' && left <= 'Z') left = (char)(left + 32);
            if (right >= 'A' && right <= 'Z') right = (char)(right + 32);
            if (left != right) break;
            index++;
        }
        if (index == length) return TRUE;
        start++;
    }
    return FALSE;
}

static void bofbench_feature_security_package_inventory(datap *parser) {
    int filter_length = 0;
    char *filter = BeaconDataExtract(parser, &filter_length);
    int requested = BeaconDataInt(parser);
    ULONG count = 0, index, shown = 0;
    DWORD limit = requested > 0 ? (DWORD)requested : 25;
    PSecPkgInfoW packages = NULL;
    SECURITY_STATUS status;
    if (limit > 128) limit = 128;
    status = SECUR32$EnumerateSecurityPackagesW(&count, &packages);
    if (status != SEC_E_OK || packages == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[security-package-inventory] status=error security_status=0x%08lx", status);
        return;
    }
    for (index = 0; index < count && shown < limit; index++) {
        char name[128], comment[256];
        bofbench_security_wide_text(packages[index].Name, name, sizeof(name));
        if (!bofbench_security_match(name, filter, filter_length > 0 ? filter_length - 1 : 0)) continue;
        bofbench_security_wide_text(packages[index].Comment, comment, sizeof(comment));
        BeaconPrintf(CALLBACK_OUTPUT, "[security-package-inventory] name=%s capabilities=0x%08lx max_token=%lu comment=%s",
            name, packages[index].fCapabilities, packages[index].cbMaxToken, comment);
        shown++;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[security-package-inventory] status=complete shown=%lu total=%lu limit=%lu filter=%s",
        shown, count, limit, filter_length > 1 ? filter : "*");
    SECUR32$FreeContextBuffer(packages);
}`,
		Call: "bofbench_feature_security_package_inventory($PARSER);",
	},
	{
		Name:        "certificate-store-inventory",
		Description: "enumerate bounded certificate metadata from one explicit Windows certificate store",
		Declaration: `#include <wincrypt.h>
HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void *);
PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT);
BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);
DWORD WINAPI CRYPT32$CertGetNameStringW(PCCERT_CONTEXT, DWORD, DWORD, void *, LPWSTR, DWORD);
BOOL WINAPI CRYPT32$CertGetCertificateContextProperty(PCCERT_CONTEXT, DWORD, void *, DWORD *);
BOOL WINAPI CRYPT32$CryptHashCertificate(HCRYPTPROV_LEGACY, ALG_ID, DWORD, const BYTE *, DWORD, BYTE *, DWORD *);
BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *, LPSYSTEMTIME);

static void bofbench_certificate_text(const WCHAR *source, char *target, DWORD capacity) {
    DWORD index = 0;
    if (capacity == 0) return;
    while (source != NULL && source[index] != L'\0' && index + 1 < capacity) {
        target[index] = source[index] < 128 ? (char)source[index] : '?';
        index++;
    }
    target[index] = '\0';
}

static BOOL bofbench_certificate_match(const WCHAR *value, const WCHAR *filter, int bytes) {
    int length = bytes > 1 ? (bytes / (int)sizeof(WCHAR)) - 1 : 0;
    int start = 0;
    if (filter == NULL || length <= 0) return TRUE;
    while (value[start] != L'\0') {
        int index = 0;
        while (index < length && value[start + index] != L'\0') {
            WCHAR left = value[start + index], right = filter[index];
            if (left >= L'A' && left <= L'Z') left = (WCHAR)(left + 32);
            if (right >= L'A' && right <= L'Z') right = (WCHAR)(right + 32);
            if (left != right) break;
            index++;
        }
        if (index == length) return TRUE;
        start++;
    }
    return FALSE;
}

static void bofbench_feature_certificate_store_inventory(datap *parser) {
    int scope_length = 0, store_length = 0, filter_length = 0;
    char *scope = BeaconDataExtract(parser, &scope_length);
    WCHAR *store_name = (WCHAR *)BeaconDataExtract(parser, &store_length);
    WCHAR *filter = (WCHAR *)BeaconDataExtract(parser, &filter_length);
    int requested = BeaconDataInt(parser);
    DWORD limit = requested > 0 ? (DWORD)requested : 25;
    DWORD flags = CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG;
    HCERTSTORE store;
    PCCERT_CONTEXT certificate = NULL;
    DWORD shown = 0;
    WCHAR default_store[] = L"MY";
    if (limit > 256) limit = 256;
    if (scope_length > 1 && (scope[0] == 'l' || scope[0] == 'L')) flags = CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG;
    if (store_length <= (int)sizeof(WCHAR)) store_name = default_store;
    store = CRYPT32$CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, store_name);
    if (store == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[certificate-store-inventory] status=error api=CertOpenStore");
        return;
    }
    while (shown < limit && (certificate = CRYPT32$CertEnumCertificatesInStore(store, certificate)) != NULL) {
        WCHAR subject_wide[256], issuer_wide[256];
        char subject[256], issuer[256], thumbprint[65];
        BYTE hash[32];
        DWORD hash_size = sizeof(hash), property_size = 0, index;
        SYSTEMTIME before, after;
        BOOL has_private_key;
        CRYPT32$CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject_wide, 256);
        if (!bofbench_certificate_match(subject_wide, filter, filter_length)) continue;
        CRYPT32$CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuer_wide, 256);
        bofbench_certificate_text(subject_wide, subject, sizeof(subject));
        bofbench_certificate_text(issuer_wide, issuer, sizeof(issuer));
        if (!CRYPT32$CryptHashCertificate(0, CALG_SHA1, 0, certificate->pbCertEncoded, certificate->cbCertEncoded, hash, &hash_size)) hash_size = 0;
        for (index = 0; index < hash_size && index < 32; index++) {
            const char digits[] = "0123456789ABCDEF";
            thumbprint[index * 2] = digits[(hash[index] >> 4) & 0x0f];
            thumbprint[index * 2 + 1] = digits[hash[index] & 0x0f];
        }
        thumbprint[hash_size * 2] = '\0';
        has_private_key = CRYPT32$CertGetCertificateContextProperty(certificate, CERT_KEY_PROV_INFO_PROP_ID, NULL, &property_size);
        KERNEL32$FileTimeToSystemTime(&certificate->pCertInfo->NotBefore, &before);
        KERNEL32$FileTimeToSystemTime(&certificate->pCertInfo->NotAfter, &after);
        BeaconPrintf(CALLBACK_OUTPUT, "[certificate-store-inventory] thumbprint=%s subject=%s issuer=%s not_before=%04u-%02u-%02u not_after=%04u-%02u-%02u has_private_key=%lu",
            thumbprint, subject, issuer, before.wYear, before.wMonth, before.wDay, after.wYear, after.wMonth, after.wDay, has_private_key ? 1 : 0);
        shown++;
    }
    CRYPT32$CertCloseStore(store, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "[certificate-store-inventory] status=complete shown=%lu limit=%lu scope=%s", shown, limit, (flags & CERT_SYSTEM_STORE_LOCAL_MACHINE) ? "local_machine" : "current_user");
}`,
		Call: "bofbench_feature_certificate_store_inventory($PARSER);",
	},
	{
		Name:        "remote-host-info",
		Description: "report bounded workstation and server identity for one explicitly supplied Windows host",
		Declaration: `#include <lm.h>
NET_API_STATUS NET_API_FUNCTION NETAPI32$NetWkstaGetInfo(LMSTR, DWORD, LPBYTE *);
NET_API_STATUS NET_API_FUNCTION NETAPI32$NetServerGetInfo(LMSTR, DWORD, LPBYTE *);
NET_API_STATUS NET_API_FUNCTION NETAPI32$NetApiBufferFree(LPVOID);

static void bofbench_remote_host_text(const WCHAR *source, char *target, DWORD capacity) {
    DWORD index = 0;
    if (capacity == 0) return;
    while (source != NULL && source[index] != L'\0' && index + 1 < capacity) {
        target[index] = source[index] < 128 ? (char)source[index] : '?';
        index++;
    }
    target[index] = '\0';
}

static void bofbench_feature_remote_host_info(datap *parser) {
    int host_bytes = 0;
    WCHAR *host = (WCHAR *)BeaconDataExtract(parser, &host_bytes);
    LPBYTE workstation_buffer = NULL, server_buffer = NULL;
    WKSTA_INFO_100 *workstation;
    SERVER_INFO_101 *server;
    NET_API_STATUS workstation_status, server_status;
    char host_text[256], computer[256], workgroup[256], comment[256];
    if (host == NULL || host_bytes < 2) {
        BeaconPrintf(CALLBACK_ERROR, "[remote-host-info] status=bad-arguments");
        return;
    }
    bofbench_remote_host_text(host, host_text, sizeof(host_text));
    workstation_status = NETAPI32$NetWkstaGetInfo(host, 100, &workstation_buffer);
    server_status = NETAPI32$NetServerGetInfo(host, 101, &server_buffer);
    if (workstation_status != NERR_Success || workstation_buffer == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[remote-host-info] status=failed target=%s api=NetWkstaGetInfo error=%lu", host_text, workstation_status);
        if (server_buffer != NULL) NETAPI32$NetApiBufferFree(server_buffer);
        return;
    }
    workstation = (WKSTA_INFO_100 *)workstation_buffer;
    bofbench_remote_host_text(workstation->wki100_computername, computer, sizeof(computer));
    bofbench_remote_host_text(workstation->wki100_langroup, workgroup, sizeof(workgroup));
    if (server_status == NERR_Success && server_buffer != NULL) {
        server = (SERVER_INFO_101 *)server_buffer;
        bofbench_remote_host_text(server->sv101_comment, comment, sizeof(comment));
        BeaconPrintf(CALLBACK_OUTPUT, "[remote-host-info] target=%s computer=%s workgroup=%s platform=%lu major=%lu minor=%lu server_type=0x%08lx comment=%s",
            host_text, computer, workgroup, workstation->wki100_platform_id, workstation->wki100_ver_major, workstation->wki100_ver_minor, server->sv101_type, comment);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[remote-host-info] target=%s computer=%s workgroup=%s platform=%lu major=%lu minor=%lu server_type=unavailable server_error=%lu",
            host_text, computer, workgroup, workstation->wki100_platform_id, workstation->wki100_ver_major, workstation->wki100_ver_minor, server_status);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[remote-host-info] status=complete target=%s", host_text);
    if (server_buffer != NULL) NETAPI32$NetApiBufferFree(server_buffer);
    NETAPI32$NetApiBufferFree(workstation_buffer);
}`,
		Call: "bofbench_feature_remote_host_info($PARSER);",
	},
	{
		Name:        "remote-service-inventory",
		Description: "enumerate a bounded filtered service inventory from one explicitly supplied Windows host",
		Declaration: `SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
BOOL WINAPI ADVAPI32$EnumServicesStatusExW(SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD, LPDWORD, LPCWSTR);
BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DWORD WINAPI KERNEL32$GetLastError(void);

static BYTE bofbench_remote_service_buffer[65536];

static void bofbench_remote_service_text(const WCHAR *source, char *target, DWORD capacity) {
    DWORD index = 0;
    if (capacity == 0) return;
    while (source != NULL && source[index] != L'\0' && index + 1 < capacity) {
        target[index] = source[index] < 128 ? (char)source[index] : '?';
        index++;
    }
    target[index] = '\0';
}

static BOOL bofbench_remote_service_match(const WCHAR *value, const WCHAR *filter, int filter_bytes) {
    int length = filter_bytes > 1 ? (filter_bytes / (int)sizeof(WCHAR)) - 1 : 0;
    int start = 0;
    if (filter == NULL || length <= 0) return TRUE;
    while (value != NULL && value[start] != L'\0') {
        int index = 0;
        while (index < length && value[start + index] != L'\0') {
            WCHAR left = value[start + index], right = filter[index];
            if (left >= L'A' && left <= L'Z') left = (WCHAR)(left + 32);
            if (right >= L'A' && right <= L'Z') right = (WCHAR)(right + 32);
            if (left != right) break;
            index++;
        }
        if (index == length) return TRUE;
        start++;
    }
    return FALSE;
}

static void bofbench_feature_remote_service_inventory(datap *parser) {
    int host_bytes = 0, filter_bytes = 0, state_bytes = 0;
    WCHAR *host = (WCHAR *)BeaconDataExtract(parser, &host_bytes);
    WCHAR *filter = (WCHAR *)BeaconDataExtract(parser, &filter_bytes);
    char *state_filter = BeaconDataExtract(parser, &state_bytes);
    int requested = BeaconDataInt(parser);
    DWORD limit = requested > 0 ? (DWORD)requested : 32;
    DWORD resume = 0, needed = 0, returned = 0, shown = 0, examined = 0, pages = 0, error = ERROR_SUCCESS;
    SC_HANDLE manager;
    char host_text[256], name[256], display[256];
    BOOL more = TRUE;
    if (host == NULL || host_bytes < 2) { BeaconPrintf(CALLBACK_ERROR, "[remote-service-inventory] status=bad-arguments"); return; }
    if (limit > 256) limit = 256;
    bofbench_remote_service_text(host, host_text, sizeof(host_text));
    manager = ADVAPI32$OpenSCManagerW(host, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (manager == NULL) { BeaconPrintf(CALLBACK_ERROR, "[remote-service-inventory] status=failed target=%s api=OpenSCManagerW error=%lu", host_text, KERNEL32$GetLastError()); return; }
    while (more && shown < limit) {
        DWORD index;
        ENUM_SERVICE_STATUS_PROCESSW *entries;
        returned = 0; needed = 0;
        more = ADVAPI32$EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            bofbench_remote_service_buffer, sizeof(bofbench_remote_service_buffer), &needed, &returned, &resume, NULL);
        error = more ? ERROR_SUCCESS : KERNEL32$GetLastError();
        if (!more && error != ERROR_MORE_DATA) break;
        pages++;
        entries = (ENUM_SERVICE_STATUS_PROCESSW *)bofbench_remote_service_buffer;
        for (index = 0; index < returned && shown < limit; index++) {
            DWORD current_state = entries[index].ServiceStatusProcess.dwCurrentState;
            BOOL state_match = TRUE;
            examined++;
            if (state_filter != NULL && state_bytes > 1) {
                if ((state_filter[0] == 'r' || state_filter[0] == 'R') && current_state != SERVICE_RUNNING) state_match = FALSE;
                if ((state_filter[0] == 's' || state_filter[0] == 'S') && current_state != SERVICE_STOPPED) state_match = FALSE;
            }
            if (!state_match || (!bofbench_remote_service_match(entries[index].lpServiceName, filter, filter_bytes) && !bofbench_remote_service_match(entries[index].lpDisplayName, filter, filter_bytes))) continue;
            bofbench_remote_service_text(entries[index].lpServiceName, name, sizeof(name));
            bofbench_remote_service_text(entries[index].lpDisplayName, display, sizeof(display));
            BeaconPrintf(CALLBACK_OUTPUT, "[remote-service-inventory] target=%s name=%s display=%s state=%lu type=0x%08lx pid=%lu",
                host_text, name, display, current_state, entries[index].ServiceStatusProcess.dwServiceType, entries[index].ServiceStatusProcess.dwProcessId);
            shown++;
        }
        if (more || error != ERROR_MORE_DATA || resume == 0) break;
    }
    ADVAPI32$CloseServiceHandle(manager);
    if (error != ERROR_SUCCESS && error != ERROR_MORE_DATA) {
        BeaconPrintf(CALLBACK_ERROR, "[remote-service-inventory] status=failed target=%s api=EnumServicesStatusExW error=%lu", host_text, error);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[remote-service-inventory] status=complete target=%s shown=%lu examined=%lu pages=%lu limit=%lu filter=%s state=%s",
        host_text, shown, examined, pages, limit, filter_bytes > 2 ? "set" : "*", state_bytes > 1 ? state_filter : "all");
}`,
		Call: "bofbench_feature_remote_service_inventory($PARSER);",
	},
	{
		Name:        "remote-task-inventory",
		Description: "enumerate bounded Task Scheduler metadata from one explicitly supplied Windows host",
		Declaration: `#ifndef COBJMACROS
#define COBJMACROS
#endif
#include <taskschd.h>
#include <oleauto.h>
HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE *, LPVOID, DWORD, DWORD, LPVOID, DWORD, LPVOID);
HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID *);
VOID WINAPI OLE32$CoUninitialize(void);
BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR *);
VOID WINAPI OLEAUT32$SysFreeString(BSTR);
HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG *);

static const CLSID BOFBENCH_CLSID_TaskSchedulerInventory = {0x0f87369f,0xa4e5,0x4cfc,{0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
static const IID BOFBENCH_IID_ITaskServiceInventory = {0x2faba4c7,0x4da9,0x4013,{0x96,0x97,0x20,0xcc,0x3f,0xd4,0x0f,0x85}};

static void bofbench_remote_task_text(const WCHAR *source, char *target, DWORD capacity) {
    DWORD index = 0;
    if (capacity == 0) return;
    while (source != NULL && source[index] != L'\0' && index + 1 < capacity) { target[index] = source[index] < 128 ? (char)source[index] : '?'; index++; }
    target[index] = '\0';
}

static BOOL bofbench_remote_task_match(const WCHAR *value, const WCHAR *filter, int filter_bytes) {
    int length = filter_bytes > 1 ? (filter_bytes / (int)sizeof(WCHAR)) - 1 : 0, start = 0;
    if (filter == NULL || length <= 0) return TRUE;
    while (value != NULL && value[start] != L'\0') {
        int index = 0;
        while (index < length && value[start + index] != L'\0') {
            WCHAR left = value[start + index], right = filter[index];
            if (left >= L'A' && left <= L'Z') left = (WCHAR)(left + 32);
            if (right >= L'A' && right <= L'Z') right = (WCHAR)(right + 32);
            if (left != right) break;
            index++;
        }
        if (index == length) return TRUE;
        start++;
    }
    return FALSE;
}

static void bofbench_feature_remote_task_inventory(datap *parser) {
    int host_bytes = 0, filter_bytes = 0;
    WCHAR *host = (WCHAR *)BeaconDataExtract(parser, &host_bytes);
    WCHAR *filter = (WCHAR *)BeaconDataExtract(parser, &filter_bytes);
    int requested = BeaconDataInt(parser);
    LONG limit = requested > 0 ? requested : 32, count = 0, index, shown = 0;
    HRESULT hr, security;
    ITaskService *service = NULL;
    ITaskFolder *folder = NULL;
    IRegisteredTaskCollection *tasks = NULL;
    BSTR server_name = NULL, root_name = NULL;
    VARIANT server, empty;
    char host_text[256];
    if (host == NULL || host_bytes < 2) { BeaconPrintf(CALLBACK_ERROR, "[remote-task-inventory] status=bad-arguments"); return; }
    if (limit > 256) limit = 256;
    bofbench_remote_task_text(host, host_text, sizeof(host_text));
    server.vt = VT_EMPTY; server.ullVal = 0; empty.vt = VT_EMPTY; empty.ullVal = 0;
    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) goto cleanup;
    security = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(security) && security != RPC_E_TOO_LATE) { hr = security; goto cleanup; }
    hr = OLE32$CoCreateInstance(&BOFBENCH_CLSID_TaskSchedulerInventory, NULL, CLSCTX_INPROC_SERVER, &BOFBENCH_IID_ITaskServiceInventory, (LPVOID *)&service); if (FAILED(hr)) goto cleanup;
    server_name = OLEAUT32$SysAllocString(host); server.vt = VT_BSTR; server.bstrVal = server_name;
    hr = ITaskService_Connect(service, server, empty, empty, empty); if (FAILED(hr)) goto cleanup;
    root_name = OLEAUT32$SysAllocString(L"\\");
    hr = ITaskService_GetFolder(service, root_name, &folder); if (FAILED(hr)) goto cleanup;
    hr = ITaskFolder_GetTasks(folder, TASK_ENUM_HIDDEN, &tasks); if (FAILED(hr)) goto cleanup;
    hr = IRegisteredTaskCollection_get_Count(tasks, &count); if (FAILED(hr)) goto cleanup;
    for (index = 1; index <= count && shown < limit; index++) {
        VARIANT item_index; IRegisteredTask *task = NULL; BSTR name = NULL; TASK_STATE state = TASK_STATE_UNKNOWN; LONG last_result = 0; char task_name[512];
        item_index.vt = VT_I4; item_index.lVal = index;
        if (FAILED(IRegisteredTaskCollection_get_Item(tasks, item_index, &task)) || task == NULL) continue;
        if (SUCCEEDED(IRegisteredTask_get_Name(task, &name)) && bofbench_remote_task_match(name, filter, filter_bytes)) {
            IRegisteredTask_get_State(task, &state); IRegisteredTask_get_LastTaskResult(task, &last_result);
            bofbench_remote_task_text(name, task_name, sizeof(task_name));
            BeaconPrintf(CALLBACK_OUTPUT, "[remote-task-inventory] target=%s name=%s state=%lu last_result=%ld", host_text, task_name, (DWORD)state, last_result);
            shown++;
        }
        if (name != NULL) OLEAUT32$SysFreeString(name);
        IRegisteredTask_Release(task);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[remote-task-inventory] status=complete target=%s shown=%ld total=%ld limit=%ld filter=%s", host_text, shown, count, limit, filter_bytes > 2 ? "set" : "*");
cleanup:
    if (FAILED(hr)) BeaconPrintf(CALLBACK_ERROR, "[remote-task-inventory] status=failed target=%s hresult=0x%08lx", host_text, hr);
    if (tasks) IRegisteredTaskCollection_Release(tasks); if (folder) ITaskFolder_Release(folder); if (service) ITaskService_Release(service);
    if (root_name) OLEAUT32$SysFreeString(root_name); if (server_name) OLEAUT32$SysFreeString(server_name);
    OLEAUT32$VariantClear(&server); OLEAUT32$VariantClear(&empty); OLE32$CoUninitialize();
}`,
		Call: "bofbench_feature_remote_task_inventory($PARSER);",
	},
	{
		Name:        "lab-file-write",
		Description: "create a known BOFBench marker file in the Windows temporary directory",
		Declaration: `DWORD WINAPI KERNEL32$GetTempPathA(DWORD, LPSTR);
HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static BOOL bofbench_lab_file_path(char *path, DWORD capacity) {
    const char leaf[] = "bofbench-active-marker.txt";
    DWORD used = KERNEL32$GetTempPathA(capacity, path);
    DWORD index = 0;
    if (used == 0 || used >= capacity) return FALSE;
    while (leaf[index] != '\0' && used + index + 1 < capacity) {
        path[used + index] = leaf[index];
        index++;
    }
    if (leaf[index] != '\0') return FALSE;
    path[used + index] = '\0';
    return TRUE;
}

static void bofbench_feature_lab_file_write(void) {
    const char message[] = "BOFBench active lab marker\r\n";
    char path[MAX_PATH + 1];
    DWORD written = 0;
    HANDLE file = INVALID_HANDLE_VALUE;
    if (!bofbench_lab_file_path(path, sizeof(path))) {
        BeaconPrintf(CALLBACK_ERROR, "[lab-file-write] temporary path construction failed");
        return;
    }
    file = KERNEL32$CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[lab-file-write] CreateFileA failed path=%s", path);
        return;
    }
    if (!KERNEL32$WriteFile(file, message, sizeof(message) - 1, &written, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[lab-file-write] WriteFile failed path=%s", path);
        KERNEL32$CloseHandle(file);
        return;
    }
    KERNEL32$CloseHandle(file);
    BeaconPrintf(CALLBACK_OUTPUT, "[lab-file-write] created=%s bytes=%lu", path, written);
}`,
		Call: "bofbench_feature_lab_file_write();",
	},
	{
		Name:        "lab-registry-write",
		Description: "write a known BOFBench marker under the current user's registry hive",
		Declaration: `LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);

static void bofbench_feature_lab_registry_write(void) {
    const char value[] = "authorized-lab";
    HKEY key = NULL;
    DWORD disposition = 0;
    LSTATUS status = ADVAPI32$RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\BOFBench", 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, &disposition);
    if (status == ERROR_SUCCESS) {
        status = ADVAPI32$RegSetValueExA(key, "LabMarker", 0, REG_SZ,
            (const BYTE *)value, sizeof(value));
        ADVAPI32$RegCloseKey(key);
    }
    if (status == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[lab-registry-write] set=HKCU\\Software\\BOFBench\\LabMarker disposition=%lu", disposition);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[lab-registry-write] registry update failed status=%ld", status);
    }
}`,
		Call: "bofbench_feature_lab_registry_write();",
	},
	{
		Name:        "lab-run-key",
		Description: "install an inert current-user Run-key persistence proof for the authorized lab",
		Declaration: `LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD);
LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);

static void bofbench_feature_lab_run_key(void) {
    const char command[] = "C:\\Windows\\System32\\cmd.exe /d /c exit 0";
    HKEY key = NULL;
    DWORD disposition = 0;
    LSTATUS status = ADVAPI32$RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, &disposition);
    if (status == ERROR_SUCCESS) {
        status = ADVAPI32$RegSetValueExA(key, "BOFBenchLab", 0, REG_SZ,
            (const BYTE *)command, sizeof(command));
        ADVAPI32$RegCloseKey(key);
    }
    if (status == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[lab-run-key] set=HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BOFBenchLab command=%s",
            command);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[lab-run-key] persistence proof failed status=%ld", status);
    }
}`,
		Call: "bofbench_feature_lab_run_key();",
	},
	{
		Name:        "lab-process-launch",
		Description: "launch a bounded child process that creates a second BOFBench lab marker",
		Declaration: `BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static void bofbench_lab_zero(void *value, DWORD size) {
    BYTE *cursor = (BYTE *)value;
    while (size > 0) {
        *cursor = 0;
        cursor++;
        size--;
    }
}

static void bofbench_feature_lab_process_launch(void) {
    char command[] = "cmd.exe /d /c echo BOFBench active child process>\"%TEMP%\\bofbench-process-marker.txt\"";
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    bofbench_lab_zero(&startup, sizeof(startup));
    bofbench_lab_zero(&process, sizeof(process));
    startup.cb = sizeof(startup);
    if (!KERNEL32$CreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        BeaconPrintf(CALLBACK_ERROR, "[lab-process-launch] CreateProcessA failed");
        return;
    }
    KERNEL32$WaitForSingleObject(process.hProcess, 5000);
    BeaconPrintf(CALLBACK_OUTPUT, "[lab-process-launch] child_pid=%lu marker=%%TEMP%%\\bofbench-process-marker.txt", process.dwProcessId);
    KERNEL32$CloseHandle(process.hThread);
    KERNEL32$CloseHandle(process.hProcess);
}`,
		Call: "bofbench_feature_lab_process_launch();",
	},
	{
		Name:        "lab-cleanup",
		Description: "remove only the known BOFBench temporary-file and registry lab markers",
		Declaration: `DWORD WINAPI KERNEL32$GetTempPathA(DWORD, LPSTR);
BOOL WINAPI KERNEL32$DeleteFileA(LPCSTR);
LSTATUS WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
LSTATUS WINAPI ADVAPI32$RegDeleteValueA(HKEY, LPCSTR);
LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
LSTATUS WINAPI ADVAPI32$RegDeleteTreeA(HKEY, LPCSTR);

static BOOL bofbench_cleanup_path(char *path, DWORD capacity, const char *leaf) {
    DWORD used = KERNEL32$GetTempPathA(capacity, path);
    DWORD index = 0;
    if (used == 0 || used >= capacity) return FALSE;
    while (leaf[index] != '\0' && used + index + 1 < capacity) {
        path[used + index] = leaf[index];
        index++;
    }
    if (leaf[index] != '\0') return FALSE;
    path[used + index] = '\0';
    return TRUE;
}

static void bofbench_feature_lab_cleanup(void) {
    char file_marker[MAX_PATH + 1];
    char process_marker[MAX_PATH + 1];
    BOOL file_path = bofbench_cleanup_path(file_marker, sizeof(file_marker), "bofbench-active-marker.txt");
    BOOL process_path = bofbench_cleanup_path(process_marker, sizeof(process_marker), "bofbench-process-marker.txt");
    BOOL file_removed = file_path ? KERNEL32$DeleteFileA(file_marker) : FALSE;
    BOOL process_removed = process_path ? KERNEL32$DeleteFileA(process_marker) : FALSE;
    HKEY run_key = NULL;
    LSTATUS runkey_status = ADVAPI32$RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &run_key);
    if (runkey_status == ERROR_SUCCESS) {
        runkey_status = ADVAPI32$RegDeleteValueA(run_key, "BOFBenchLab");
        ADVAPI32$RegCloseKey(run_key);
    }
    LSTATUS registry_status = ADVAPI32$RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\BOFBench");
    BeaconPrintf(CALLBACK_OUTPUT, "[lab-cleanup] file=%lu process_marker=%lu registry_status=%ld runkey_status=%ld",
        file_removed, process_removed, registry_status, runkey_status);
}`,
		Call: "bofbench_feature_lab_cleanup();",
	},
}

var featurePacks = []FeaturePack{
	{Name: "host-discovery", Description: "core process, host, identity, and filesystem context", Impact: "read_only", Features: []string{"process", "host", "identity", "filesystem"}},
	{Name: "network-discovery", Description: "host, Winsock, TCP endpoint, and domain context", Impact: "read_only", Features: []string{"host", "network", "tcp-connections", "domain-context"}},
	{Name: "system-discovery", Description: "process, token, and service enumeration", Impact: "read_only", Features: []string{"process-list", "token-context", "service-list"}},
	{Name: "deep-discovery", Description: "all built-in read-only discovery techniques", Impact: "read_only", Features: []string{"process", "host", "identity", "filesystem", "network", "registry", "process-list", "token-context", "service-list", "tcp-connections", "domain-context"}},
	{Name: "active-lab", Description: "observable file, registry, inert Run-key persistence, and child-process state changes", Impact: "modifies_state", Features: []string{"lab-file-write", "lab-registry-write", "lab-run-key", "lab-process-launch"}},
	{Name: "offensive-lab", Description: "deep discovery plus observable reversible action primitives", Impact: "modifies_state", Features: []string{"process", "host", "identity", "filesystem", "network", "registry", "process-list", "token-context", "service-list", "tcp-connections", "domain-context", "lab-file-write", "lab-registry-write", "lab-run-key", "lab-process-launch"}},
	{Name: "active-cleanup", Description: "remove BOFBench-owned lab files and registry markers", Impact: "modifies_state", Features: []string{"lab-cleanup"}},
}

func Features() []Feature {
	out := append([]Feature(nil), features...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func FeaturePacks() []FeaturePack {
	out := make([]FeaturePack, len(featurePacks))
	for i, pack := range featurePacks {
		out[i] = pack
		out[i].Features = append([]string(nil), pack.Features...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func FeaturePackByName(name string) (FeaturePack, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, pack := range featurePacks {
		if pack.Name == name {
			pack.Features = append([]string(nil), pack.Features...)
			return pack, true
		}
	}
	return FeaturePack{}, false
}

func AddFeaturePack(project, name string) (AddResult, error) {
	pack, ok := FeaturePackByName(name)
	if !ok {
		names := make([]string, 0, len(featurePacks))
		for _, item := range FeaturePacks() {
			names = append(names, item.Name)
		}
		return AddResult{}, fmt.Errorf("unknown feature pack %q; choose %s", name, strings.Join(names, ", "))
	}
	return AddFeatures(project, pack.Features)
}

// AddPackFragments injects source supplied by an external capability pack. The
// fragment is wrapped in a stable marker so applying the same pack twice is
// idempotent. Calls are inserted into the generated entrypoint in declaration
// order. Pack validation owns identifier/path checks; this function still
// rejects marker-breaking identifiers because it is also a public package API.
func AddPackFragments(project, id, declaration string, calls []string) (AddResult, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" || strings.ContainsAny(id, "\r\n*/") {
		return AddResult{}, fmt.Errorf("invalid pack identifier %q", id)
	}
	sourcePath, err := projectSource(project)
	if err != nil {
		return AddResult{}, err
	}
	sourceBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		return AddResult{}, err
	}
	source, err := ensureMarkers(string(sourceBytes))
	if err != nil {
		return AddResult{}, fmt.Errorf("prepare %s: %w", sourcePath, err)
	}
	headerPath := filepath.Join(filepath.Dir(sourcePath), "bofbench_features.h")
	header := featureHeaderPreamble()
	if body, readErr := os.ReadFile(headerPath); readErr == nil {
		header = string(body)
	} else if !os.IsNotExist(readErr) {
		return AddResult{}, readErr
	}

	result := AddResult{Project: project, Source: sourcePath, Header: headerPath}
	begin := fmt.Sprintf("/* bofbench:pack %s begin */", id)
	if strings.Contains(header, begin) {
		result.Existing = []string{id}
		return result, nil
	}
	declaration = strings.TrimSpace(declaration)
	if declaration == "" {
		return AddResult{}, fmt.Errorf("pack %s has no source declarations", id)
	}
	body := strings.ReplaceAll(importDeclarations(declaration), "BeaconPrintf(", "BOFBENCH_PRINTF(")
	header += fmt.Sprintf("\n%s\n%s\n/* bofbench:pack %s end */\n", begin, body, id)
	for _, raw := range calls {
		call := strings.TrimSpace(raw)
		if call == "" {
			continue
		}
		if !strings.HasSuffix(call, ";") {
			call += ";"
		}
		if strings.Contains(call, "$PARSER") {
			const parserMarker = "/* bofbench:pack-argument-parser */"
			if !strings.Contains(source, parserMarker) {
				initialization := "    datap bofbench_pack_parser;\n    BeaconDataParse(&bofbench_pack_parser, args, len);\n    " + parserMarker + "\n"
				source = strings.Replace(source, callMarker, initialization+callMarker, 1)
			}
			call = strings.ReplaceAll(call, "$PARSER", "&bofbench_pack_parser")
		}
		source = strings.Replace(source, callMarker, "    "+call+"\n"+callMarker, 1)
	}
	if !strings.Contains(source, `#include "bofbench_features.h"`) {
		source = strings.Replace(source, includeMarker, `#include "bofbench_features.h"`+"\n"+includeMarker, 1)
	}
	if err := os.WriteFile(headerPath, []byte(header), 0o644); err != nil {
		return AddResult{}, err
	}
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return AddResult{}, err
	}
	result.Added = []string{id}
	return result, nil
}

func SourceMarkers() (string, string) {
	return includeMarker, callMarker
}

func AddFeatures(project string, names []string) (AddResult, error) {
	if len(names) == 0 {
		return AddResult{}, fmt.Errorf("provide at least one feature; use 'bofbench feature list'")
	}
	sourcePath, err := projectSource(project)
	if err != nil {
		return AddResult{}, err
	}
	sourceBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		return AddResult{}, err
	}
	source, err := ensureMarkers(string(sourceBytes))
	if err != nil {
		return AddResult{}, fmt.Errorf("prepare %s: %w", sourcePath, err)
	}
	headerPath := filepath.Join(filepath.Dir(sourcePath), "bofbench_features.h")
	header := featureHeaderPreamble()
	if body, readErr := os.ReadFile(headerPath); readErr == nil {
		header = string(body)
	} else if !os.IsNotExist(readErr) {
		return AddResult{}, readErr
	}

	result := AddResult{Project: project, Source: sourcePath, Header: headerPath}
	seen := map[string]bool{}
	for _, rawName := range names {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		feature, ok := featureByName(name)
		if !ok {
			return AddResult{}, fmt.Errorf("unknown feature %q; choose %s", rawName, featureNames())
		}
		begin := fmt.Sprintf("/* bofbench:feature %s begin */", feature.Name)
		if strings.Contains(header, begin) {
			result.Existing = append(result.Existing, feature.Name)
			continue
		}
		body := strings.ReplaceAll(importDeclarations(feature.Declaration), "BeaconPrintf(", "BOFBENCH_PRINTF(")
		header += fmt.Sprintf("\n%s\n%s\n/* bofbench:feature %s end */\n", begin, body, feature.Name)
		callText := feature.Call
		if strings.Contains(callText, "$PARSER") {
			const parserMarker = "/* bofbench:pack-argument-parser */"
			if !strings.Contains(source, parserMarker) {
				initialization := "    datap bofbench_pack_parser;\n    BeaconDataParse(&bofbench_pack_parser, args, len);\n    " + parserMarker + "\n"
				source = strings.Replace(source, callMarker, initialization+callMarker, 1)
			}
			callText = strings.ReplaceAll(callText, "$PARSER", "&bofbench_pack_parser")
		}
		call := "    " + callText
		source = strings.Replace(source, callMarker, call+"\n"+callMarker, 1)
		result.Added = append(result.Added, feature.Name)
	}

	if len(result.Added) == 0 {
		return result, nil
	}
	if !strings.Contains(source, `#include "bofbench_features.h"`) {
		source = strings.Replace(source, includeMarker, `#include "bofbench_features.h"`+"\n"+includeMarker, 1)
	}
	if err := os.WriteFile(headerPath, []byte(header), 0o644); err != nil {
		return AddResult{}, err
	}
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		return AddResult{}, err
	}
	return result, nil
}

// importDeclarations emits the standard BOF import-pointer symbols expected by
// Cobalt-compatible COFF loaders (for example __imp_KERNEL32$CreateFileA).
// MinGW otherwise emits bare external symbols, which some loaders intentionally
// reject even though the dynamic function resolution convention is identical.
func importDeclarations(declaration string) string {
	lines := strings.Split(declaration, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "static ") {
			break
		}
		if strings.Contains(trimmed, "$") && strings.Contains(trimmed, "(") && strings.HasSuffix(trimmed, ";") && !strings.Contains(trimmed, "DECLSPEC_IMPORT") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = indent + "DECLSPEC_IMPORT " + strings.TrimLeft(line, " \t")
		}
	}
	return strings.Join(lines, "\n")
}

func featureByName(name string) (Feature, bool) {
	for _, feature := range features {
		if feature.Name == name {
			return feature, true
		}
	}
	return Feature{}, false
}

func featureNames() string {
	names := make([]string, 0, len(features))
	for _, feature := range Features() {
		names = append(names, feature.Name)
	}
	return strings.Join(names, ", ")
}

func projectSource(project string) (string, error) {
	info, err := os.Stat(project)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		if strings.EqualFold(filepath.Ext(project), ".c") {
			return project, nil
		}
		return "", fmt.Errorf("%s is not a C source or BOF project directory", project)
	}
	entries, err := os.ReadDir(project)
	if err != nil {
		return "", err
	}
	var sources []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".c") {
			sources = append(sources, filepath.Join(project, entry.Name()))
		}
	}
	sort.Strings(sources)
	if len(sources) == 0 {
		return "", fmt.Errorf("no C source found directly under %s", project)
	}
	if len(sources) > 1 {
		return "", fmt.Errorf("multiple C sources found under %s; pass the intended source file", project)
	}
	return sources[0], nil
}

func ensureMarkers(source string) (string, error) {
	if !strings.Contains(source, includeMarker) {
		needle := `#include "beacon.h"`
		if !strings.Contains(source, needle) {
			return "", fmt.Errorf("missing %s and %q include", includeMarker, needle)
		}
		source = strings.Replace(source, needle, needle+"\n"+includeMarker, 1)
	}
	if !strings.Contains(source, callMarker) {
		entry := strings.Index(source, "void go(")
		lastBrace := strings.LastIndex(source, "}")
		if entry < 0 || lastBrace < entry {
			return "", fmt.Errorf("could not locate void go(...) body for %s", callMarker)
		}
		source = source[:lastBrace] + callMarker + "\n" + source[lastBrace:]
	}
	return source, nil
}

func featureHeaderPreamble() string {
	return `#pragma once
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <iphlpapi.h>
#include <lm.h>
#include <lmcons.h>

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

#ifndef CALLBACK_ERROR
#define CALLBACK_ERROR 0x0d
#endif

#ifndef BOFBENCH_PRINTF
#define BOFBENCH_PRINTF(type, ...) do { \
    BeaconPrintf((type), __VA_ARGS__); \
    BeaconPrintf((type), "\n"); \
} while (0)
#endif
`
}
