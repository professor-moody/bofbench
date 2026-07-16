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
		Name:        "process-image-inventory",
		Description: "enumerate bounded loaded images for one explicitly selected process",
		Declaration: `HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Module32FirstW(HANDLE, LPMODULEENTRY32W);
BOOL WINAPI KERNEL32$Module32NextW(HANDLE, LPMODULEENTRY32W);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static void bofbench_process_image_text(const WCHAR *source, char *target, DWORD capacity) {
    DWORD index = 0;
    while (source && source[index] && index + 1 < capacity) { target[index] = source[index] < 128 ? (char)source[index] : '?'; index++; }
    target[index] = 0;
}

static BOOL bofbench_process_image_match(const char *value, const char *filter, int length) {
    int start = 0;
    if (!filter || length <= 0) return TRUE;
    while (value[start]) {
        int index = 0;
        while (index < length && value[start + index]) { char a = value[start + index], b = filter[index]; if (a >= 'A' && a <= 'Z') a += 32; if (b >= 'A' && b <= 'Z') b += 32; if (a != b) break; index++; }
        if (index == length) return TRUE;
        start++;
    }
    return FALSE;
}

static void bofbench_feature_process_image_inventory(datap *parser) {
    DWORD target_pid = (DWORD)BeaconDataInt(parser); int filter_bytes = 0; char *filter = BeaconDataExtract(parser, &filter_bytes); int requested = BeaconDataInt(parser);
    DWORD limit = requested > 0 ? (DWORD)requested : 64, shown = 0; HANDLE snapshot; MODULEENTRY32W entry; char module[260], path[520];
    if (!target_pid) { BeaconPrintf(CALLBACK_ERROR, "[process-image-inventory] status=bad-arguments"); return; }
    if (limit > 512) limit = 512;
    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target_pid);
    if (snapshot == INVALID_HANDLE_VALUE) { BeaconPrintf(CALLBACK_ERROR, "[process-image-inventory] status=failed target_pid=%lu error=%lu", target_pid, KERNEL32$GetLastError()); return; }
    entry.dwSize = sizeof(entry);
    if (KERNEL32$Module32FirstW(snapshot, &entry)) do {
        bofbench_process_image_text(entry.szModule, module, sizeof(module)); bofbench_process_image_text(entry.szExePath, path, sizeof(path));
        if (!bofbench_process_image_match(module, filter, filter_bytes > 0 ? filter_bytes - 1 : 0)) continue;
        BeaconPrintf(CALLBACK_OUTPUT, "[process-image-inventory] target_pid=%lu base=0x%llx size=%lu module=%s path=%s", target_pid, (unsigned long long)(ULONG_PTR)entry.modBaseAddr, entry.modBaseSize, module, path);
        shown++;
    } while (shown < limit && KERNEL32$Module32NextW(snapshot, &entry));
    KERNEL32$CloseHandle(snapshot);
    BeaconPrintf(CALLBACK_OUTPUT, "[process-image-inventory] status=complete target_pid=%lu shown=%lu limit=%lu filter=%s", target_pid, shown, limit, filter_bytes > 1 ? filter : "*");
}`,
		Call: "bofbench_feature_process_image_inventory($PARSER);",
	},
	{
		Name:        "thread-state-inventory",
		Description: "enumerate bounded thread scheduling and execution-time state for one selected process",
		Declaration: `HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Thread32First(HANDLE, LPTHREADENTRY32);
BOOL WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);
HANDLE WINAPI KERNEL32$OpenThread(DWORD, BOOL, DWORD);
int WINAPI KERNEL32$GetThreadPriority(HANDLE);
BOOL WINAPI KERNEL32$GetThreadTimes(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static unsigned long long bofbench_thread_state_time(FILETIME value) { return ((unsigned long long)value.dwHighDateTime << 32) | value.dwLowDateTime; }

static void bofbench_feature_thread_state_inventory(datap *parser) {
    DWORD target_pid = (DWORD)BeaconDataInt(parser); int requested = BeaconDataInt(parser); DWORD limit = requested > 0 ? (DWORD)requested : 64, shown = 0;
    HANDLE snapshot; THREADENTRY32 entry;
    if (!target_pid) { BeaconPrintf(CALLBACK_ERROR, "[thread-state-inventory] status=bad-arguments"); return; }
    if (limit > 512) limit = 512;
    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { BeaconPrintf(CALLBACK_ERROR, "[thread-state-inventory] status=failed target_pid=%lu error=%lu", target_pid, KERNEL32$GetLastError()); return; }
    entry.dwSize = sizeof(entry);
    if (KERNEL32$Thread32First(snapshot, &entry)) do {
        HANDLE thread; FILETIME created, exited, kernel, user; int priority;
        if (entry.th32OwnerProcessID != target_pid) continue;
        thread = KERNEL32$OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
        if (!thread) { BeaconPrintf(CALLBACK_OUTPUT, "[thread-state-inventory] target_pid=%lu tid=%lu state=unavailable base_priority=%ld", target_pid, entry.th32ThreadID, entry.tpBasePri); shown++; continue; }
        priority = KERNEL32$GetThreadPriority(thread);
        if (KERNEL32$GetThreadTimes(thread, &created, &exited, &kernel, &user)) BeaconPrintf(CALLBACK_OUTPUT, "[thread-state-inventory] target_pid=%lu tid=%lu state=queryable priority=%d base_priority=%ld created=%llu kernel=%llu user=%llu", target_pid, entry.th32ThreadID, priority, entry.tpBasePri, bofbench_thread_state_time(created), bofbench_thread_state_time(kernel), bofbench_thread_state_time(user));
        else BeaconPrintf(CALLBACK_OUTPUT, "[thread-state-inventory] target_pid=%lu tid=%lu state=unavailable priority=%d base_priority=%ld", target_pid, entry.th32ThreadID, priority, entry.tpBasePri);
        KERNEL32$CloseHandle(thread); shown++;
    } while (shown < limit && KERNEL32$Thread32Next(snapshot, &entry));
    KERNEL32$CloseHandle(snapshot); BeaconPrintf(CALLBACK_OUTPUT, "[thread-state-inventory] status=complete target_pid=%lu shown=%lu limit=%lu", target_pid, shown, limit);
}`,
		Call: "bofbench_feature_thread_state_inventory($PARSER);",
	},
	{
		Name:        "process-job-inventory",
		Description: "report job-object membership for one explicitly selected process",
		Declaration: `HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
BOOL WINAPI KERNEL32$IsProcessInJob(HANDLE, HANDLE, PBOOL);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

static void bofbench_feature_process_job_inventory(datap *parser) {
    DWORD target_pid = (DWORD)BeaconDataInt(parser); HANDLE process; BOOL in_job = FALSE;
    if (!target_pid) { BeaconPrintf(CALLBACK_ERROR, "[process-job-inventory] status=bad-arguments"); return; }
    process = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
    if (!process || !KERNEL32$IsProcessInJob(process, NULL, &in_job)) { if (process) KERNEL32$CloseHandle(process); BeaconPrintf(CALLBACK_ERROR, "[process-job-inventory] status=failed target_pid=%lu error=%lu", target_pid, KERNEL32$GetLastError()); return; }
    BeaconPrintf(CALLBACK_OUTPUT, "[process-job-inventory] status=complete target_pid=%lu in_job=%d", target_pid, in_job ? 1 : 0); KERNEL32$CloseHandle(process);
}`,
		Call: "bofbench_feature_process_job_inventory($PARSER);",
	},
	{
		Name:        "object-namespace-inventory",
		Description: "enumerate bounded entries from one Windows object-manager directory",
		Declaration: `#include <winternl.h>
NTSTATUS NTAPI NTDLL$NtOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NTDLL$NtQueryDirectoryObject(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
VOID NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

typedef struct _BOFBENCH_OBJECT_DIRECTORY_INFORMATION { UNICODE_STRING Name; UNICODE_STRING TypeName; } BOFBENCH_OBJECT_DIRECTORY_INFORMATION;
static BYTE bofbench_object_buffer[4096];
static char bofbench_object_entry_name[512];
static char bofbench_object_entry_type[128];
static void bofbench_object_text(PUNICODE_STRING source, char *target, DWORD capacity) { DWORD index = 0, count = source ? source->Length / 2 : 0; while (index < count && index + 1 < capacity) { target[index] = source->Buffer[index] < 128 ? (char)source->Buffer[index] : '?'; index++; } target[index] = 0; }
static BOOL bofbench_object_prefix(const char *value, const char *prefix, int length) { int index = 0; if (!prefix || length <= 0) return TRUE; while (index < length && value[index]) { char a=value[index],b=prefix[index];if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=b)return FALSE;index++;}return index==length; }

static void bofbench_feature_object_namespace_inventory(datap *parser) {
    int directory_bytes=0,prefix_bytes=0; WCHAR *directory=(WCHAR *)BeaconDataExtract(parser,&directory_bytes); char *prefix=BeaconDataExtract(parser,&prefix_bytes); int requested=BeaconDataInt(parser);
    DWORD limit=requested>0?(DWORD)requested:64,shown=0,context=0,returned=0; HANDLE handle=NULL; UNICODE_STRING name; OBJECT_ATTRIBUTES attributes; NTSTATUS status; BOFBENCH_OBJECT_DIRECTORY_INFORMATION *entry;
    if(!directory||directory_bytes<2){BeaconPrintf(CALLBACK_ERROR,"[object-namespace-inventory] status=bad-arguments");return;}if(limit>512)limit=512;
    NTDLL$RtlInitUnicodeString(&name,directory);InitializeObjectAttributes(&attributes,&name,OBJ_CASE_INSENSITIVE,NULL,NULL);
    status=NTDLL$NtOpenDirectoryObject(&handle,0x0001,&attributes);if(status<0){BeaconPrintf(CALLBACK_ERROR,"[object-namespace-inventory] status=failed api=NtOpenDirectoryObject ntstatus=0x%08lx",status);return;}
    while(shown<limit){status=NTDLL$NtQueryDirectoryObject(handle,bofbench_object_buffer,sizeof(bofbench_object_buffer),TRUE,FALSE,&context,&returned);if(status<0)break;entry=(BOFBENCH_OBJECT_DIRECTORY_INFORMATION *)bofbench_object_buffer;bofbench_object_text(&entry->Name,bofbench_object_entry_name,sizeof(bofbench_object_entry_name));bofbench_object_text(&entry->TypeName,bofbench_object_entry_type,sizeof(bofbench_object_entry_type));if(!bofbench_object_prefix(bofbench_object_entry_name,prefix,prefix_bytes>0?prefix_bytes-1:0))continue;BeaconPrintf(CALLBACK_OUTPUT,"[object-namespace-inventory] name=%s type=%s",bofbench_object_entry_name,bofbench_object_entry_type);shown++;}
    KERNEL32$CloseHandle(handle);BeaconPrintf(CALLBACK_OUTPUT,"[object-namespace-inventory] status=complete shown=%lu limit=%lu",shown,limit);
}`,
		Call: "bofbench_feature_object_namespace_inventory($PARSER);",
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
        BeaconPrintf(CALLBACK_OUTPUT, "[named-pipe-inventory] name=%s path=\\\\.\\pipe\\%s", entry.cFileName, entry.cFileName);
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
		Name:        "module-section-inventory",
		Description: "enumerate bounded PE sections from one selected process module",
		Declaration: `HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Module32FirstW(HANDLE, LPMODULEENTRY32W);
BOOL WINAPI KERNEL32$Module32NextW(HANDLE, LPMODULEENTRY32W);
HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DWORD WINAPI KERNEL32$GetLastError(void);

static ULONG_PTR bofbench_section_address(const char *value, int bytes) { ULONG_PTR result=0; int i=0,d; if(!value||bytes<=0)return 0; if(bytes>2&&value[0]=='0'&&(value[1]=='x'||value[1]=='X'))i=2; for(;i<bytes&&value[i];i++){char c=value[i];if(c>='0'&&c<='9')d=c-'0';else if(c>='a'&&c<='f')d=c-'a'+10;else if(c>='A'&&c<='F')d=c-'A'+10;else break;result=(result<<4)|(ULONG_PTR)d;}return result; }
static int bofbench_section_lower(int value){return value>='A'&&value<='Z'?value+('a'-'A'):value;}
static BOOL bofbench_section_contains(const char *value,const char *filter,int bytes){int i,j,limit=bytes>0?bytes-1:0;if(!filter||limit==0)return TRUE;for(i=0;value[i];i++){for(j=0;j<limit&&value[i+j]&&bofbench_section_lower(value[i+j])==bofbench_section_lower(filter[j]);j++){}if(j==limit)return TRUE;}return FALSE;}
static void bofbench_section_text(const WCHAR *source,char *target,DWORD capacity){DWORD i=0;while(source&&source[i]&&i+1<capacity){target[i]=source[i]<128?(char)source[i]:'?';i++;}target[i]=0;}
static BOOL bofbench_section_read(HANDLE process,ULONG_PTR address,void *buffer,SIZE_T size){SIZE_T read=0;return KERNEL32$ReadProcessMemory(process,(LPCVOID)address,buffer,size,&read)&&read==size;}
static void bofbench_feature_module_section_inventory(datap *parser){
 DWORD pid=(DWORD)BeaconDataInt(parser);int filter_bytes=0,base_bytes=0;char *filter=BeaconDataExtract(parser,&filter_bytes),*base_text=BeaconDataExtract(parser,&base_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:32,shown=0,index;ULONG_PTR selected=bofbench_section_address(base_text,base_bytes);HANDLE snapshot=INVALID_HANDLE_VALUE,process=NULL;MODULEENTRY32W module;BOOL found=FALSE;char module_name[260];IMAGE_DOS_HEADER dos;DWORD signature=0;IMAGE_FILE_HEADER file_header;ULONG_PTR section_table=0;
 if(!pid){BeaconPrintf(CALLBACK_ERROR,"[module-section-inventory] status=bad-arguments");return;}if(limit>128)limit=128;
 snapshot=KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);if(snapshot==INVALID_HANDLE_VALUE)goto failed;module.dwSize=sizeof(module);
 if(KERNEL32$Module32FirstW(snapshot,&module))do{bofbench_section_text(module.szModule,module_name,sizeof(module_name));if((selected==0||selected==(ULONG_PTR)module.modBaseAddr)&&bofbench_section_contains(module_name,filter,filter_bytes)){found=TRUE;break;}}while(KERNEL32$Module32NextW(snapshot,&module));
 if(!found){BeaconPrintf(CALLBACK_ERROR,"[module-section-inventory] status=not-found target_pid=%lu",pid);goto cleanup;}process=KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,pid);if(!process)goto failed;
 if(!bofbench_section_read(process,(ULONG_PTR)module.modBaseAddr,&dos,sizeof(dos))||dos.e_magic!=IMAGE_DOS_SIGNATURE)goto failed;if(!bofbench_section_read(process,(ULONG_PTR)module.modBaseAddr+dos.e_lfanew,&signature,sizeof(signature))||signature!=IMAGE_NT_SIGNATURE)goto failed;if(!bofbench_section_read(process,(ULONG_PTR)module.modBaseAddr+dos.e_lfanew+sizeof(DWORD),&file_header,sizeof(file_header)))goto failed;
 section_table=(ULONG_PTR)module.modBaseAddr+dos.e_lfanew+sizeof(DWORD)+sizeof(file_header)+file_header.SizeOfOptionalHeader;
 for(index=0;index<file_header.NumberOfSections&&shown<limit;index++){IMAGE_SECTION_HEADER section;char name[9];DWORD j;if(!bofbench_section_read(process,section_table+index*sizeof(section),&section,sizeof(section)))break;for(j=0;j<8;j++)name[j]=(char)section.Name[j];name[8]=0;BeaconPrintf(CALLBACK_OUTPUT,"[module-section-inventory] target_pid=%lu module=%s base=0x%llx section=%s rva=0x%08lx virtual_size=%lu raw_size=%lu characteristics=0x%08lx",pid,module_name,(unsigned long long)(ULONG_PTR)module.modBaseAddr,name,section.VirtualAddress,section.Misc.VirtualSize,section.SizeOfRawData,section.Characteristics);shown++;}
 BeaconPrintf(CALLBACK_OUTPUT,"[module-section-inventory] status=complete target_pid=%lu module=%s base=0x%llx shown=%lu limit=%lu",pid,module_name,(unsigned long long)(ULONG_PTR)module.modBaseAddr,shown,limit);goto cleanup;
failed:BeaconPrintf(CALLBACK_ERROR,"[module-section-inventory] status=failed target_pid=%lu error=%lu",pid,KERNEL32$GetLastError());
cleanup:if(process)KERNEL32$CloseHandle(process);if(snapshot!=INVALID_HANDLE_VALUE)KERNEL32$CloseHandle(snapshot);
}`,
		Call: "bofbench_feature_module_section_inventory($PARSER);",
	},
	{
		Name:        "process-heap-inventory",
		Description: "enumerate bounded heaps and entries for one selected process",
		Declaration: `HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Heap32ListFirst(HANDLE, LPHEAPLIST32);
BOOL WINAPI KERNEL32$Heap32ListNext(HANDLE, LPHEAPLIST32);
BOOL WINAPI KERNEL32$Heap32First(LPHEAPENTRY32, DWORD, ULONG_PTR);
BOOL WINAPI KERNEL32$Heap32Next(LPHEAPENTRY32);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DWORD WINAPI KERNEL32$GetLastError(void);
static void bofbench_feature_process_heap_inventory(datap *parser){DWORD pid=(DWORD)BeaconDataInt(parser),requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0,heaps=0;HANDLE snapshot;HEAPLIST32 list;if(!pid){BeaconPrintf(CALLBACK_ERROR,"[process-heap-inventory] status=bad-arguments");return;}if(limit>512)limit=512;snapshot=KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST,pid);if(snapshot==INVALID_HANDLE_VALUE){BeaconPrintf(CALLBACK_ERROR,"[process-heap-inventory] status=failed target_pid=%lu error=%lu",pid,KERNEL32$GetLastError());return;}list.dwSize=sizeof(list);if(KERNEL32$Heap32ListFirst(snapshot,&list))do{HEAPENTRY32 entry;DWORD entries=0;heaps++;entry.dwSize=sizeof(entry);if(KERNEL32$Heap32First(&entry,pid,list.th32HeapID))do{BeaconPrintf(CALLBACK_OUTPUT,"[process-heap-inventory] target_pid=%lu heap=0x%llx flags=0x%08lx address=0x%llx size=%llu entry_flags=0x%08lx",pid,(unsigned long long)list.th32HeapID,list.dwFlags,(unsigned long long)entry.dwAddress,(unsigned long long)entry.dwBlockSize,entry.dwFlags);entries++;shown++;entry.dwSize=sizeof(entry);}while(shown<limit&&KERNEL32$Heap32Next(&entry));if(shown>=limit)break;}while(KERNEL32$Heap32ListNext(snapshot,&list));KERNEL32$CloseHandle(snapshot);BeaconPrintf(CALLBACK_OUTPUT,"[process-heap-inventory] status=complete target_pid=%lu heaps=%lu shown=%lu limit=%lu",pid,heaps,shown,limit);}`,
		Call: "bofbench_feature_process_heap_inventory($PARSER);",
	},
	{
		Name:        "process-security-inventory",
		Description: "report owner, group, DACL, inheritance, and security-control metadata for one process",
		Declaration: `#include <aclapi.h>
HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DWORD WINAPI KERNEL32$GetLastError(void);
DWORD WINAPI ADVAPI32$GetSecurityInfo(HANDLE, SE_OBJECT_TYPE, SECURITY_INFORMATION, PSID *, PSID *, PACL *, PACL *, PSECURITY_DESCRIPTOR *);
BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR *);
BOOL WINAPI ADVAPI32$GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR_CONTROL, LPDWORD);
static void bofbench_feature_process_security_inventory(datap *parser){DWORD pid=(DWORD)BeaconDataInt(parser),status;HANDLE process;PSID owner=NULL,group=NULL;PACL dacl=NULL;PSECURITY_DESCRIPTOR descriptor=NULL;LPSTR owner_text=NULL,group_text=NULL;SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0,aces=0;process=KERNEL32$OpenProcess(READ_CONTROL|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(!process){BeaconPrintf(CALLBACK_ERROR,"[process-security-inventory] status=failed target_pid=%lu error=%lu",pid,KERNEL32$GetLastError());return;}status=ADVAPI32$GetSecurityInfo(process,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,&group,&dacl,NULL,&descriptor);if(status!=ERROR_SUCCESS){BeaconPrintf(CALLBACK_ERROR,"[process-security-inventory] status=failed target_pid=%lu error=%lu",pid,status);KERNEL32$CloseHandle(process);return;}ADVAPI32$ConvertSidToStringSidA(owner,&owner_text);ADVAPI32$ConvertSidToStringSidA(group,&group_text);ADVAPI32$GetSecurityDescriptorControl(descriptor,&control,&revision);if(dacl)aces=dacl->AceCount;BeaconPrintf(CALLBACK_OUTPUT,"[process-security-inventory] target_pid=%lu owner=%s group=%s dacl_present=%lu ace_count=%lu protected=%lu auto_inherited=%lu control=0x%04x revision=%lu",pid,owner_text?owner_text:"-",group_text?group_text:"-",dacl?1UL:0UL,aces,(control&SE_DACL_PROTECTED)?1UL:0UL,(control&SE_DACL_AUTO_INHERITED)?1UL:0UL,control,revision);BeaconPrintf(CALLBACK_OUTPUT,"[process-security-inventory] status=complete target_pid=%lu",pid);if(owner_text)KERNEL32$LocalFree(owner_text);if(group_text)KERNEL32$LocalFree(group_text);if(descriptor)KERNEL32$LocalFree(descriptor);KERNEL32$CloseHandle(process);}`,
		Call: "bofbench_feature_process_security_inventory($PARSER);",
	},
	{
		Name:        "process-access-check",
		Description: "test requested process access rights against one selected PID",
		Declaration: `HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DWORD WINAPI KERNEL32$GetLastError(void);

typedef struct _BOFBENCH_PROCESS_ACCESS_ITEM { DWORD mask; const char *name; } BOFBENCH_PROCESS_ACCESS_ITEM;
static BOFBENCH_PROCESS_ACCESS_ITEM bofbench_process_access_items[] = {
    { PROCESS_QUERY_LIMITED_INFORMATION, "query" }, { PROCESS_VM_READ, "read" },
    { PROCESS_VM_WRITE, "write" }, { PROCESS_VM_OPERATION, "operation" },
    { PROCESS_CREATE_THREAD, "create_thread" }, { PROCESS_DUP_HANDLE, "duplicate_handle" },
    { PROCESS_SUSPEND_RESUME, "suspend_resume" }, { PROCESS_TERMINATE, "terminate" }
};

static void bofbench_feature_process_access_check(datap *parser) {
    DWORD pid = (DWORD)BeaconDataInt(parser), requested = (DWORD)BeaconDataInt(parser);
    DWORD shown = 0, granted = 0, index, count = sizeof(bofbench_process_access_items) / sizeof(bofbench_process_access_items[0]);
    if (!pid) { BeaconPrintf(CALLBACK_ERROR, "[process-access-check] status=bad-arguments"); return; }
    if (requested) {
        HANDLE process = KERNEL32$OpenProcess(requested, FALSE, pid); DWORD error = process ? 0 : KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_OUTPUT, "[process-access-check] target_pid=%lu right=custom mask=0x%08lx granted=%lu error=%lu", pid, requested, process != NULL, error);
        if (process) { granted = 1; KERNEL32$CloseHandle(process); }
        shown = 1;
    } else {
        for (index = 0; index < count; index++) {
            HANDLE process = KERNEL32$OpenProcess(bofbench_process_access_items[index].mask, FALSE, pid); DWORD error = process ? 0 : KERNEL32$GetLastError();
            BeaconPrintf(CALLBACK_OUTPUT, "[process-access-check] target_pid=%lu right=%s mask=0x%08lx granted=%lu error=%lu", pid, bofbench_process_access_items[index].name, bofbench_process_access_items[index].mask, process != NULL, error);
            shown++; if (process) { granted++; KERNEL32$CloseHandle(process); }
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[process-access-check] status=complete target_pid=%lu requested=0x%08lx shown=%lu granted=%lu", pid, requested, shown, granted);
}`,
		Call: "bofbench_feature_process_access_check($PARSER);",
	},
	{
		Name:        "module-export-inventory",
		Description: "enumerate bounded exports from one selected process module",
		Declaration: `HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
BOOL WINAPI KERNEL32$Module32FirstW(HANDLE, LPMODULEENTRY32W);
BOOL WINAPI KERNEL32$Module32NextW(HANDLE, LPMODULEENTRY32W);
HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DWORD WINAPI KERNEL32$GetLastError(void);

static int bofbench_export_lower(int value) { return value >= 'A' && value <= 'Z' ? value + ('a' - 'A') : value; }
static BOOL bofbench_export_contains(const char *value, const char *filter, int filter_bytes) {
    int i, j, limit = filter_bytes > 0 ? filter_bytes - 1 : 0; if (!filter || limit == 0) return TRUE;
    for (i = 0; value[i]; i++) { for (j = 0; j < limit && value[i+j] && bofbench_export_lower(value[i+j]) == bofbench_export_lower(filter[j]); j++) {} if (j == limit) return TRUE; }
    return FALSE;
}
static void bofbench_export_text(const WCHAR *source, char *target, DWORD capacity) { DWORD index = 0; while (source && source[index] && index + 1 < capacity) { target[index] = source[index] < 128 ? (char)source[index] : '?'; index++; } target[index] = 0; }
static ULONG_PTR bofbench_export_address(const char *value, int bytes) {
    ULONG_PTR result = 0; int index = 0, digit; if (!value || bytes <= 0) return 0;
    if (bytes > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) index = 2;
    for (; index < bytes && value[index]; index++) { char c = value[index]; if (c >= '0' && c <= '9') digit = c - '0'; else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10; else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10; else break; result = (result << 4) | (ULONG_PTR)digit; }
    return result;
}
static BOOL bofbench_export_read(HANDLE process, ULONG_PTR address, void *buffer, SIZE_T size) { SIZE_T read = 0; return KERNEL32$ReadProcessMemory(process, (LPCVOID)address, buffer, size, &read) && read == size; }

static void bofbench_feature_module_export_inventory(datap *parser) {
    DWORD pid = (DWORD)BeaconDataInt(parser); int filter_bytes = 0, base_bytes = 0;
    char *filter = BeaconDataExtract(parser, &filter_bytes), *base_text = BeaconDataExtract(parser, &base_bytes);
    DWORD requested = (DWORD)BeaconDataInt(parser), limit = requested ? requested : 64, shown = 0, index;
    ULONG_PTR selected_base = bofbench_export_address(base_text, base_bytes); HANDLE snapshot = INVALID_HANDLE_VALUE, process = NULL; MODULEENTRY32W module; BOOL found = FALSE; char module_name[260];
    IMAGE_DOS_HEADER dos; DWORD signature = 0; IMAGE_FILE_HEADER file_header; WORD magic = 0; IMAGE_DATA_DIRECTORY exports; IMAGE_EXPORT_DIRECTORY directory;
    if (!pid) { BeaconPrintf(CALLBACK_ERROR, "[module-export-inventory] status=bad-arguments"); return; } if (limit > 512) limit = 512;
    snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid); if (snapshot == INVALID_HANDLE_VALUE) goto failed;
    module.dwSize = sizeof(module);
    if (KERNEL32$Module32FirstW(snapshot, &module)) do { bofbench_export_text(module.szModule, module_name, sizeof(module_name)); if ((selected_base == 0 || selected_base == (ULONG_PTR)module.modBaseAddr) && bofbench_export_contains(module_name, filter, filter_bytes)) { found = TRUE; break; } } while (KERNEL32$Module32NextW(snapshot, &module));
    if (!found) { BeaconPrintf(CALLBACK_ERROR, "[module-export-inventory] status=not-found target_pid=%lu", pid); goto cleanup; }
    process = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid); if (!process) goto failed;
    if (!bofbench_export_read(process, (ULONG_PTR)module.modBaseAddr, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) goto failed;
    if (!bofbench_export_read(process, (ULONG_PTR)module.modBaseAddr + dos.e_lfanew, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE) goto failed;
    if (!bofbench_export_read(process, (ULONG_PTR)module.modBaseAddr + dos.e_lfanew + sizeof(DWORD), &file_header, sizeof(file_header))) goto failed;
    if (!bofbench_export_read(process, (ULONG_PTR)module.modBaseAddr + dos.e_lfanew + sizeof(DWORD) + sizeof(file_header), &magic, sizeof(magic))) goto failed;
    { ULONG_PTR optional = (ULONG_PTR)module.modBaseAddr + dos.e_lfanew + sizeof(DWORD) + sizeof(file_header); ULONG_PTR offset = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? 112 : 96;
      if (!bofbench_export_read(process, optional + offset, &exports, sizeof(exports)) || !exports.VirtualAddress) goto complete; }
    if (!bofbench_export_read(process, (ULONG_PTR)module.modBaseAddr + exports.VirtualAddress, &directory, sizeof(directory))) goto failed;
    for (index = 0; index < directory.NumberOfNames && shown < limit; index++) {
        DWORD name_rva = 0, function_rva = 0; WORD ordinal_index = 0; char name[256]; SIZE_T read = 0;
        if (!bofbench_export_read(process, (ULONG_PTR)module.modBaseAddr + directory.AddressOfNames + index * sizeof(DWORD), &name_rva, sizeof(name_rva))) break;
        if (!KERNEL32$ReadProcessMemory(process, (LPCVOID)((ULONG_PTR)module.modBaseAddr + name_rva), name, sizeof(name)-1, &read) || read == 0) continue; name[sizeof(name)-1] = 0;
        if (!bofbench_export_contains(name, filter, filter_bytes)) continue;
        if (!bofbench_export_read(process, (ULONG_PTR)module.modBaseAddr + directory.AddressOfNameOrdinals + index * sizeof(WORD), &ordinal_index, sizeof(ordinal_index))) continue;
        if (!bofbench_export_read(process, (ULONG_PTR)module.modBaseAddr + directory.AddressOfFunctions + ordinal_index * sizeof(DWORD), &function_rva, sizeof(function_rva))) continue;
        BeaconPrintf(CALLBACK_OUTPUT, "[module-export-inventory] target_pid=%lu module=%s base=0x%llx name=%s ordinal=%lu address=0x%llx", pid, module_name, (unsigned long long)(ULONG_PTR)module.modBaseAddr, name, directory.Base + ordinal_index, (unsigned long long)((ULONG_PTR)module.modBaseAddr + function_rva)); shown++;
    }
complete:
    BeaconPrintf(CALLBACK_OUTPUT, "[module-export-inventory] status=complete target_pid=%lu module=%s base=0x%llx shown=%lu limit=%lu", pid, module_name, (unsigned long long)(ULONG_PTR)module.modBaseAddr, shown, limit); goto cleanup;
failed:
    BeaconPrintf(CALLBACK_ERROR, "[module-export-inventory] status=failed target_pid=%lu error=%lu", pid, KERNEL32$GetLastError());
cleanup:
    if (process) KERNEL32$CloseHandle(process); if (snapshot != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(snapshot);
}`,
		Call: "bofbench_feature_module_export_inventory($PARSER);",
	},
	{
		Name:        "local-account-policy-inventory",
		Description: "report local password, lockout, and authentication policy metadata",
		Declaration: `#include <lm.h>
NET_API_STATUS WINAPI NETAPI32$NetUserModalsGet(LPCWSTR, DWORD, LPBYTE *);
NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID);

static void bofbench_feature_local_account_policy_inventory(void) {
    LPBYTE buffer = NULL; NET_API_STATUS status; USER_MODALS_INFO_0 *password = NULL; USER_MODALS_INFO_1 *role = NULL; USER_MODALS_INFO_3 *lockout = NULL;
    status = NETAPI32$NetUserModalsGet(NULL, 0, &buffer); if (status != NERR_Success) goto failed; password = (USER_MODALS_INFO_0 *)buffer;
    BeaconPrintf(CALLBACK_OUTPUT, "[local-account-policy-inventory] min_length=%lu min_age=%lu max_age=%lu force_logoff=%lu history=%lu", password->usrmod0_min_passwd_len, password->usrmod0_min_passwd_age, password->usrmod0_max_passwd_age, password->usrmod0_force_logoff, password->usrmod0_password_hist_len); NETAPI32$NetApiBufferFree(buffer); buffer = NULL;
    status = NETAPI32$NetUserModalsGet(NULL, 1, &buffer); if (status != NERR_Success) goto failed; role = (USER_MODALS_INFO_1 *)buffer;
    BeaconPrintf(CALLBACK_OUTPUT, "[local-account-policy-inventory] role=%lu", role->usrmod1_role); NETAPI32$NetApiBufferFree(buffer); buffer = NULL;
    status = NETAPI32$NetUserModalsGet(NULL, 3, &buffer); if (status != NERR_Success) goto failed; lockout = (USER_MODALS_INFO_3 *)buffer;
    BeaconPrintf(CALLBACK_OUTPUT, "[local-account-policy-inventory] lockout_duration=%lu lockout_window=%lu lockout_threshold=%lu", lockout->usrmod3_lockout_duration, lockout->usrmod3_lockout_observation_window, lockout->usrmod3_lockout_threshold);
    NETAPI32$NetApiBufferFree(buffer); BeaconPrintf(CALLBACK_OUTPUT, "[local-account-policy-inventory] status=complete"); return;
failed:
    if (buffer) NETAPI32$NetApiBufferFree(buffer); BeaconPrintf(CALLBACK_ERROR, "[local-account-policy-inventory] status=failed error=%lu", status);
}`,
		Call: "bofbench_feature_local_account_policy_inventory();",
	},
	{
		Name:        "network-neighbor-inventory",
		Description: "enumerate bounded IPv4 and IPv6 neighbor-cache metadata",
		Declaration: `#include <ws2tcpip.h>
typedef union _BOFBENCH_SOCKADDR_INET { SOCKADDR_IN Ipv4; SOCKADDR_IN6 Ipv6; USHORT si_family; } BOFBENCH_SOCKADDR_INET;
typedef struct _BOFBENCH_MIB_IPNET_ROW2 { BOFBENCH_SOCKADDR_INET Address; ULONGLONG InterfaceLuid; DWORD InterfaceIndex; UCHAR PhysicalAddress[32]; DWORD PhysicalAddressLength; DWORD State; UCHAR Flags; UCHAR Reserved[3]; DWORD LastReachable; } BOFBENCH_MIB_IPNET_ROW2, *PBOFBENCH_MIB_IPNET_ROW2;
typedef struct _BOFBENCH_MIB_IPNET_TABLE2 { DWORD NumEntries; DWORD Reserved; BOFBENCH_MIB_IPNET_ROW2 Table[1]; } BOFBENCH_MIB_IPNET_TABLE2, *PBOFBENCH_MIB_IPNET_TABLE2;
DWORD WINAPI IPHLPAPI$GetIpNetTable2(USHORT, PBOFBENCH_MIB_IPNET_TABLE2 *);
VOID WINAPI IPHLPAPI$FreeMibTable(PVOID);
int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
int WSAAPI WS2_32$WSACleanup(void);
PCSTR WSAAPI WS2_32$inet_ntop(INT, const VOID *, PSTR, size_t);

static BOOL bofbench_neighbor_family(const char *family, int bytes, ADDRESS_FAMILY candidate) {
    if (!family || bytes <= 1 || family[0] == 'a' || family[0] == 'A') return TRUE;
    if ((family[0] == '4' || family[0] == 'i' || family[0] == 'I') && candidate == AF_INET) return TRUE;
    if ((family[0] == '6' || family[0] == 'v' || family[0] == 'V') && candidate == AF_INET6) return TRUE;
    return FALSE;
}
static void bofbench_feature_network_neighbor_inventory(datap *parser) {
    int family_bytes = 0; char *family = BeaconDataExtract(parser, &family_bytes); DWORD interface_index = (DWORD)BeaconDataInt(parser), requested = (DWORD)BeaconDataInt(parser), limit = requested ? requested : 64, shown = 0, index; WSADATA winsock; PBOFBENCH_MIB_IPNET_TABLE2 table = NULL; DWORD status;
    if (limit > 512) limit = 512; if (WS2_32$WSAStartup(MAKEWORD(2,2), &winsock) != 0) { BeaconPrintf(CALLBACK_ERROR, "[network-neighbor-inventory] status=failed api=WSAStartup"); return; }
    status = IPHLPAPI$GetIpNetTable2(AF_UNSPEC, &table); if (status != NO_ERROR || !table) { BeaconPrintf(CALLBACK_ERROR, "[network-neighbor-inventory] status=failed error=%lu", status); WS2_32$WSACleanup(); return; }
    for (index = 0; index < table->NumEntries && shown < limit; index++) { PBOFBENCH_MIB_IPNET_ROW2 row = &table->Table[index]; char address[INET6_ADDRSTRLEN]; const void *source = NULL;
        if (interface_index && row->InterfaceIndex != interface_index) continue; if (!bofbench_neighbor_family(family, family_bytes, row->Address.si_family)) continue;
        source = row->Address.si_family == AF_INET ? (const void *)&row->Address.Ipv4.sin_addr : (const void *)&row->Address.Ipv6.sin6_addr;
        if (!WS2_32$inet_ntop(row->Address.si_family, source, address, sizeof(address))) continue;
        BeaconPrintf(CALLBACK_OUTPUT, "[network-neighbor-inventory] address=%s family=%s interface=%lu state=%lu router=%lu reachable=%lu", address, row->Address.si_family == AF_INET ? "ipv4" : "ipv6", row->InterfaceIndex, row->State, row->Flags & 1, row->LastReachable);
        shown++;
    }
    IPHLPAPI$FreeMibTable(table); WS2_32$WSACleanup(); BeaconPrintf(CALLBACK_OUTPUT, "[network-neighbor-inventory] status=complete shown=%lu limit=%lu interface=%lu", shown, limit, interface_index);
}`,
		Call: "bofbench_feature_network_neighbor_inventory($PARSER);",
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
	{
		Name:        "network-adapter-inventory",
		Description: "enumerate bounded network adapters, addresses, gateways, and DNS servers",
		Declaration: `#include <iphlpapi.h>
#include <ws2tcpip.h>
ULONG WINAPI IPHLPAPI$GetAdaptersAddresses(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
int WSAAPI WS2_32$WSACleanup(void);
int WSAAPI WS2_32$getnameinfo(const SOCKADDR *, socklen_t, PCHAR, DWORD, PCHAR, DWORD, INT);
static BYTE bofbench_adapter_buffer[65536];
static void bofbench_adapter_wide(const WCHAR *source,char *target,DWORD size){DWORD i=0;while(source&&source[i]&&i+1<size){target[i]=source[i]<128?(char)source[i]:'?';i++;}target[i]=0;}
static BOOL bofbench_adapter_contains(const char *value,const char *filter,int bytes){int i,j,n=bytes>0?bytes-1:0;if(!n)return TRUE;for(i=0;value&&value[i];i++){for(j=0;j<n&&value[i+j];j++){char a=value[i+j],b=filter[j];if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=b)break;}if(j==n)return TRUE;}return FALSE;}
static void bofbench_adapter_address(const char *kind,ULONG index,PSOCKET_ADDRESS address){char text[96];DWORD size=sizeof(text);if(address&&address->lpSockaddr&&WS2_32$getnameinfo(address->lpSockaddr,(socklen_t)address->iSockaddrLength,text,size,NULL,0,NI_NUMERICHOST)==0)BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[network-adapter-inventory] interface=%lu kind=%s address=%s",index,kind,text);}
static void bofbench_feature_network_adapter_inventory(datap *parser){int family_bytes=0,filter_bytes=0;char *family=BeaconDataExtract(parser,&family_bytes),*filter=BeaconDataExtract(parser,&filter_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:32,shown=0;ULONG af=AF_UNSPEC,size=sizeof(bofbench_adapter_buffer),status;PIP_ADAPTER_ADDRESSES row;WSADATA winsock;if(family&&family_bytes>1){if((family[0]=='4')||(family[0]=='i'&&family[3]=='4'))af=AF_INET;else if((family[0]=='6')||(family[0]=='i'&&family[3]=='6'))af=AF_INET6;}if(limit>256)limit=256;if(WS2_32$WSAStartup(MAKEWORD(2,2),&winsock)!=0){BOFBENCH_PRINTF(CALLBACK_ERROR,"[network-adapter-inventory] status=failed api=WSAStartup");return;}status=IPHLPAPI$GetAdaptersAddresses(af,GAA_FLAG_INCLUDE_PREFIX|GAA_FLAG_INCLUDE_GATEWAYS,NULL,(PIP_ADAPTER_ADDRESSES)bofbench_adapter_buffer,&size);if(status!=NO_ERROR){BOFBENCH_PRINTF(CALLBACK_ERROR,"[network-adapter-inventory] status=failed error=%lu required=%lu",status,size);WS2_32$WSACleanup();return;}for(row=(PIP_ADAPTER_ADDRESSES)bofbench_adapter_buffer;row&&shown<limit;row=row->Next){char friendly[260];PIP_ADAPTER_UNICAST_ADDRESS u;PIP_ADAPTER_GATEWAY_ADDRESS_LH g;PIP_ADAPTER_DNS_SERVER_ADDRESS d;bofbench_adapter_wide(row->FriendlyName,friendly,sizeof(friendly));if(!bofbench_adapter_contains(friendly,filter,filter_bytes)&&!bofbench_adapter_contains(row->AdapterName,filter,filter_bytes))continue;BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[network-adapter-inventory] interface=%lu name=%s adapter=%s status=%lu mtu=%lu type=%lu",row->IfIndex,friendly,row->AdapterName?row->AdapterName:"-",row->OperStatus,row->Mtu,row->IfType);for(u=row->FirstUnicastAddress;u;u=u->Next)bofbench_adapter_address("unicast",row->IfIndex,&u->Address);for(g=row->FirstGatewayAddress;g;g=g->Next)bofbench_adapter_address("gateway",row->IfIndex,&g->Address);for(d=row->FirstDnsServerAddress;d;d=d->Next)bofbench_adapter_address("dns",row->IfIndex,&d->Address);shown++;}WS2_32$WSACleanup();BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[network-adapter-inventory] status=complete shown=%lu limit=%lu family=%lu",shown,limit,af);}`,
		Call: "bofbench_feature_network_adapter_inventory($PARSER);",
	},
	{
		Name:        "network-route-inventory",
		Description: "enumerate bounded IPv4 and IPv6 forwarding routes",
		Declaration: `#include <ws2tcpip.h>
typedef union _BOFBENCH_ROUTE_SOCKADDR_INET { SOCKADDR_IN Ipv4; SOCKADDR_IN6 Ipv6; USHORT si_family; } BOFBENCH_ROUTE_SOCKADDR_INET;
typedef union _BOFBENCH_NET_LUID { ULONGLONG Value; struct { ULONGLONG Reserved:24; ULONGLONG NetLuidIndex:24; ULONGLONG IfType:16; } Info; } BOFBENCH_NET_LUID;
typedef struct _BOFBENCH_IP_ADDRESS_PREFIX { BOFBENCH_ROUTE_SOCKADDR_INET Prefix; UINT8 PrefixLength; } BOFBENCH_IP_ADDRESS_PREFIX;
typedef struct _BOFBENCH_MIB_IPFORWARD_ROW2 { BOFBENCH_NET_LUID InterfaceLuid; ULONG InterfaceIndex; BOFBENCH_IP_ADDRESS_PREFIX DestinationPrefix; BOFBENCH_ROUTE_SOCKADDR_INET NextHop; UCHAR SitePrefixLength; ULONG ValidLifetime; ULONG PreferredLifetime; ULONG Metric; ULONG Protocol; BOOLEAN Loopback; BOOLEAN AutoconfigureAddress; BOOLEAN Publish; BOOLEAN Immortal; ULONG Age; ULONG Origin; } BOFBENCH_MIB_IPFORWARD_ROW2;
typedef struct _BOFBENCH_MIB_IPFORWARD_TABLE2 { ULONG NumEntries; BOFBENCH_MIB_IPFORWARD_ROW2 Table[1]; } BOFBENCH_MIB_IPFORWARD_TABLE2;
ULONG WINAPI IPHLPAPI$GetIpForwardTable2(USHORT, BOFBENCH_MIB_IPFORWARD_TABLE2 **);
VOID WINAPI IPHLPAPI$FreeMibTable(PVOID);
int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
int WSAAPI WS2_32$WSACleanup(void);
int WSAAPI WS2_32$getnameinfo(const SOCKADDR *, socklen_t, PCHAR, DWORD, PCHAR, DWORD, INT);
static void bofbench_route_text(const BOFBENCH_ROUTE_SOCKADDR_INET *address,char *text,DWORD size){DWORD length=address->si_family==AF_INET?sizeof(SOCKADDR_IN):sizeof(SOCKADDR_IN6);if(WS2_32$getnameinfo((const SOCKADDR*)address,(socklen_t)length,text,size,NULL,0,NI_NUMERICHOST)!=0){text[0]='-';text[1]=0;}}
static void bofbench_feature_network_route_inventory(datap *parser){int family_bytes=0;char *family=BeaconDataExtract(parser,&family_bytes);DWORD interface_index=(DWORD)BeaconDataInt(parser),requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0,index;USHORT af=AF_UNSPEC;BOFBENCH_MIB_IPFORWARD_TABLE2 *table=NULL;ULONG status;WSADATA winsock;if(family&&family_bytes>1){if(family[0]=='4'||(family[0]=='i'&&family[3]=='4'))af=AF_INET;else if(family[0]=='6'||(family[0]=='i'&&family[3]=='6'))af=AF_INET6;}if(limit>512)limit=512;if(WS2_32$WSAStartup(MAKEWORD(2,2),&winsock)!=0){BOFBENCH_PRINTF(CALLBACK_ERROR,"[network-route-inventory] status=failed api=WSAStartup");return;}status=IPHLPAPI$GetIpForwardTable2(af,&table);if(status!=NO_ERROR||!table){BOFBENCH_PRINTF(CALLBACK_ERROR,"[network-route-inventory] status=failed error=%lu",status);WS2_32$WSACleanup();return;}for(index=0;index<table->NumEntries&&shown<limit;index++){BOFBENCH_MIB_IPFORWARD_ROW2 *row=&table->Table[index];char destination[96],next_hop[96];if(interface_index&&row->InterfaceIndex!=interface_index)continue;bofbench_route_text(&row->DestinationPrefix.Prefix,destination,sizeof(destination));bofbench_route_text(&row->NextHop,next_hop,sizeof(next_hop));BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[network-route-inventory] destination=%s prefix=%u next_hop=%s interface=%lu metric=%lu protocol=%lu origin=%lu",destination,row->DestinationPrefix.PrefixLength,next_hop,row->InterfaceIndex,row->Metric,row->Protocol,row->Origin);shown++;}IPHLPAPI$FreeMibTable(table);WS2_32$WSACleanup();BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[network-route-inventory] status=complete shown=%lu limit=%lu family=%u interface=%lu",shown,limit,af,interface_index);}`,
		Call: "bofbench_feature_network_route_inventory($PARSER);",
	},
	{
		Name:        "proxy-configuration-inventory",
		Description: "report current-user WinHTTP proxy, PAC, bypass, and auto-detection configuration",
		Declaration: `#include <winhttp.h>
BOOL WINAPI WINHTTP$WinHttpGetIEProxyConfigForCurrentUser(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG *);
HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);
DWORD WINAPI KERNEL32$GetLastError(void);
static void bofbench_proxy_text(const WCHAR *source,char *target,DWORD size){DWORD i=0;while(source&&source[i]&&i+1<size){target[i]=source[i]<128?(char)source[i]:'?';i++;}target[i]=0;}
static void bofbench_feature_proxy_configuration_inventory(void){WINHTTP_CURRENT_USER_IE_PROXY_CONFIG config;char proxy[1024],bypass[1024],pac[1024];config.fAutoDetect=FALSE;config.lpszAutoConfigUrl=NULL;config.lpszProxy=NULL;config.lpszProxyBypass=NULL;if(!WINHTTP$WinHttpGetIEProxyConfigForCurrentUser(&config)){BOFBENCH_PRINTF(CALLBACK_ERROR,"[proxy-configuration-inventory] status=failed error=%lu",KERNEL32$GetLastError());return;}bofbench_proxy_text(config.lpszProxy,proxy,sizeof(proxy));bofbench_proxy_text(config.lpszProxyBypass,bypass,sizeof(bypass));bofbench_proxy_text(config.lpszAutoConfigUrl,pac,sizeof(pac));BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[proxy-configuration-inventory] status=complete auto_detect=%lu proxy=%s bypass=%s auto_config_url=%s",config.fAutoDetect?1UL:0UL,proxy[0]?proxy:"-",bypass[0]?bypass:"-",pac[0]?pac:"-");if(config.lpszAutoConfigUrl)KERNEL32$GlobalFree(config.lpszAutoConfigUrl);if(config.lpszProxy)KERNEL32$GlobalFree(config.lpszProxy);if(config.lpszProxyBypass)KERNEL32$GlobalFree(config.lpszProxyBypass);}`,
		Call: "bofbench_feature_proxy_configuration_inventory();",
	},
	{
		Name:        "thread-wait-chain-inventory",
		Description: "inspect bounded Windows wait chains for an exact process or thread",
		Declaration: `#include <wct.h>
#include <tlhelp32.h>
#ifndef WCT_MAX_NODE_COUNT
#define WCT_MAX_NODE_COUNT 16
#endif
#ifndef WCTP_GETINFO_ALL_FLAGS
#define WCTP_GETINFO_ALL_FLAGS 1
#endif
HWCT WINAPI ADVAPI32$OpenThreadWaitChainSession(DWORD, PWAITCHAINCALLBACK);
BOOL WINAPI ADVAPI32$GetThreadWaitChain(HWCT, DWORD_PTR, DWORD, DWORD, LPDWORD, PWAITCHAIN_NODE_INFO, LPBOOL);
VOID WINAPI ADVAPI32$CloseThreadWaitChainSession(HWCT);
HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD,DWORD);
BOOL WINAPI KERNEL32$Thread32First(HANDLE,LPTHREADENTRY32);
BOOL WINAPI KERNEL32$Thread32Next(HANDLE,LPTHREADENTRY32);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DWORD WINAPI KERNEL32$GetLastError(void);
static WAITCHAIN_NODE_INFO bofbench_wait_chain_nodes[WCT_MAX_NODE_COUNT];
static void bofbench_wait_chain_one(HWCT session,DWORD pid,DWORD tid,DWORD *shown,DWORD limit){DWORD count=WCT_MAX_NODE_COUNT,index;BOOL cycle=FALSE;if(*shown>=limit)return;if(!ADVAPI32$GetThreadWaitChain(session,0,WCTP_GETINFO_ALL_FLAGS,tid,&count,bofbench_wait_chain_nodes,&cycle)){BOFBENCH_PRINTF(CALLBACK_ERROR,"[thread-wait-chain-inventory] status=thread-failed target_pid=%lu target_tid=%lu error=%lu",pid,tid,KERNEL32$GetLastError());return;}for(index=0;index<count&&*shown<limit;index++){if(bofbench_wait_chain_nodes[index].ObjectType==WctThreadType)BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[thread-wait-chain-inventory] target_pid=%lu target_tid=%lu node=%lu kind=thread pid=%lu tid=%lu status=%lu cycle=%lu",pid,tid,index,bofbench_wait_chain_nodes[index].ThreadObject.ProcessId,bofbench_wait_chain_nodes[index].ThreadObject.ThreadId,bofbench_wait_chain_nodes[index].ObjectStatus,cycle?1UL:0UL);else BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[thread-wait-chain-inventory] target_pid=%lu target_tid=%lu node=%lu kind=object type=%lu status=%lu cycle=%lu",pid,tid,index,bofbench_wait_chain_nodes[index].ObjectType,bofbench_wait_chain_nodes[index].ObjectStatus,cycle?1UL:0UL);(*shown)++;}}
static void bofbench_feature_thread_wait_chain_inventory(datap *parser){DWORD pid=(DWORD)BeaconDataInt(parser),tid=(DWORD)BeaconDataInt(parser),requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0;HWCT session;if(!pid&&!tid){BOFBENCH_PRINTF(CALLBACK_ERROR,"[thread-wait-chain-inventory] status=bad-arguments");return;}if(limit>512)limit=512;session=ADVAPI32$OpenThreadWaitChainSession(0,NULL);if(!session){BOFBENCH_PRINTF(CALLBACK_ERROR,"[thread-wait-chain-inventory] status=failed api=OpenThreadWaitChainSession error=%lu",KERNEL32$GetLastError());return;}if(tid)bofbench_wait_chain_one(session,pid,tid,&shown,limit);else{HANDLE snapshot=KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);THREADENTRY32 row;if(snapshot==INVALID_HANDLE_VALUE){ADVAPI32$CloseThreadWaitChainSession(session);BOFBENCH_PRINTF(CALLBACK_ERROR,"[thread-wait-chain-inventory] status=failed api=CreateToolhelp32Snapshot error=%lu",KERNEL32$GetLastError());return;}row.dwSize=sizeof(row);if(KERNEL32$Thread32First(snapshot,&row)){do{if(row.th32OwnerProcessID==pid)bofbench_wait_chain_one(session,pid,row.th32ThreadID,&shown,limit);}while(shown<limit&&KERNEL32$Thread32Next(snapshot,&row));}KERNEL32$CloseHandle(snapshot);}ADVAPI32$CloseThreadWaitChainSession(session);BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[thread-wait-chain-inventory] status=complete target_pid=%lu target_tid=%lu shown=%lu limit=%lu",pid,tid,shown,limit);}`,
		Call: "bofbench_feature_thread_wait_chain_inventory($PARSER);",
	},
	{
		Name:        "process-handle-type-summary",
		Description: "summarize bounded process handles by Windows object type",
		Declaration: `typedef LONG NTSTATUS;
typedef struct _BOFBENCH_HANDLE_ENTRY_EX {PVOID Object;ULONG_PTR UniqueProcessId;ULONG_PTR HandleValue;ULONG GrantedAccess;USHORT CreatorBackTraceIndex;USHORT ObjectTypeIndex;ULONG HandleAttributes;ULONG Reserved;} BOFBENCH_HANDLE_ENTRY_EX;
typedef struct _BOFBENCH_HANDLE_INFO_EX {ULONG_PTR NumberOfHandles;ULONG_PTR Reserved;BOFBENCH_HANDLE_ENTRY_EX Handles[1];} BOFBENCH_HANDLE_INFO_EX;
typedef struct _BOFBENCH_UNICODE_STRING {USHORT Length;USHORT MaximumLength;PWSTR Buffer;} BOFBENCH_UNICODE_STRING;
typedef struct _BOFBENCH_OBJECT_TYPE_INFORMATION {BOFBENCH_UNICODE_STRING TypeName;} BOFBENCH_OBJECT_TYPE_INFORMATION;
NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(ULONG,PVOID,ULONG,PULONG);
NTSTATUS NTAPI NTDLL$NtQueryObject(HANDLE,ULONG,PVOID,ULONG,PULONG);
HANDLE WINAPI KERNEL32$OpenProcess(DWORD,BOOL,DWORD);
HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
BOOL WINAPI KERNEL32$DuplicateHandle(HANDLE,HANDLE,HANDLE,LPHANDLE,DWORD,BOOL,DWORD);
BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
HANDLE WINAPI KERNEL32$GetProcessHeap(void);
LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);
BOOL WINAPI KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);
static ULONG bofbench_handle_summary_counts[256];static char bofbench_handle_summary_names[256][48];
static void bofbench_handle_type_name(HANDLE process,ULONG_PTR value,USHORT type){HANDLE copy=NULL;BYTE info[1024];ULONG needed=0,index=0;BOFBENCH_OBJECT_TYPE_INFORMATION *object;if(type>=256||bofbench_handle_summary_names[type][0])return;if(!KERNEL32$DuplicateHandle(process,(HANDLE)value,KERNEL32$GetCurrentProcess(),&copy,0,FALSE,DUPLICATE_SAME_ACCESS))return;if(NTDLL$NtQueryObject(copy,2,info,sizeof(info),&needed)>=0){object=(BOFBENCH_OBJECT_TYPE_INFORMATION*)info;while(object->TypeName.Buffer&&index+1<sizeof(bofbench_handle_summary_names[type])&&index<object->TypeName.Length/2){WCHAR c=object->TypeName.Buffer[index];bofbench_handle_summary_names[type][index]=c<128?(char)c:'?';index++;}bofbench_handle_summary_names[type][index]=0;}KERNEL32$CloseHandle(copy);}
static void bofbench_feature_process_handle_type_summary(datap *parser){DWORD pid=(DWORD)BeaconDataInt(parser),requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0,index;ULONG needed=0,capacity=16777216UL;NTSTATUS status;HANDLE process=NULL,heap=KERNEL32$GetProcessHeap();BYTE *buffer=NULL;BOFBENCH_HANDLE_INFO_EX *info;if(!pid){BOFBENCH_PRINTF(CALLBACK_ERROR,"[process-handle-type-summary] status=bad-arguments");return;}if(limit>256)limit=256;for(index=0;index<256;index++){bofbench_handle_summary_counts[index]=0;bofbench_handle_summary_names[index][0]=0;}buffer=(BYTE*)KERNEL32$HeapAlloc(heap,0,capacity);if(!buffer){BOFBENCH_PRINTF(CALLBACK_ERROR,"[process-handle-type-summary] status=failed api=HeapAlloc required=%lu",capacity);return;}status=NTDLL$NtQuerySystemInformation(64,buffer,capacity,&needed);if(status<0){BOFBENCH_PRINTF(CALLBACK_ERROR,"[process-handle-type-summary] status=failed api=NtQuerySystemInformation ntstatus=0x%08lx required=%lu",status,needed);goto cleanup;}process=KERNEL32$OpenProcess(PROCESS_DUP_HANDLE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(!process){BOFBENCH_PRINTF(CALLBACK_ERROR,"[process-handle-type-summary] status=failed api=OpenProcess target_pid=%lu",pid);goto cleanup;}info=(BOFBENCH_HANDLE_INFO_EX*)buffer;for(index=0;index<info->NumberOfHandles;index++){BOFBENCH_HANDLE_ENTRY_EX *row=&info->Handles[index];if((DWORD)row->UniqueProcessId!=pid||row->ObjectTypeIndex>=256)continue;bofbench_handle_summary_counts[row->ObjectTypeIndex]++;bofbench_handle_type_name(process,row->HandleValue,row->ObjectTypeIndex);}for(index=0;index<256&&shown<limit;index++){if(!bofbench_handle_summary_counts[index])continue;BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[process-handle-type-summary] target_pid=%lu type_index=%lu type=%s count=%lu",pid,index,bofbench_handle_summary_names[index][0]?bofbench_handle_summary_names[index]:"unknown",bofbench_handle_summary_counts[index]);shown++;}BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[process-handle-type-summary] status=complete target_pid=%lu shown=%lu limit=%lu",pid,shown,limit);cleanup:if(process)KERNEL32$CloseHandle(process);if(buffer)KERNEL32$HeapFree(heap,0,buffer);}`,
		Call: "bofbench_feature_process_handle_type_summary($PARSER);",
	},
	{
		Name:        "named-object-security-inventory",
		Description: "read owner and DACL metadata for one exact named kernel object",
		Declaration: `#include <aclapi.h>
#include <sddl.h>
HANDLE WINAPI KERNEL32$OpenEventW(DWORD,BOOL,LPCWSTR);HANDLE WINAPI KERNEL32$OpenMutexW(DWORD,BOOL,LPCWSTR);HANDLE WINAPI KERNEL32$OpenSemaphoreW(DWORD,BOOL,LPCWSTR);HANDLE WINAPI KERNEL32$OpenFileMappingW(DWORD,BOOL,LPCWSTR);HANDLE WINAPI KERNEL32$OpenJobObjectW(DWORD,BOOL,LPCWSTR);BOOL WINAPI KERNEL32$CloseHandle(HANDLE);HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);DWORD WINAPI KERNEL32$GetLastError(void);
DWORD WINAPI ADVAPI32$GetSecurityInfo(HANDLE,SE_OBJECT_TYPE,SECURITY_INFORMATION,PSID*,PSID*,PACL*,PACL*,PSECURITY_DESCRIPTOR*);BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID,LPSTR*);BOOL WINAPI ADVAPI32$GetSecurityDescriptorControl(PSECURITY_DESCRIPTOR,PSECURITY_DESCRIPTOR_CONTROL,LPDWORD);BOOL WINAPI ADVAPI32$GetAce(PACL,DWORD,LPVOID*);
static BOOL bofbench_object_kind(const char *value,int bytes,const char *want){int i=0;if(!value)return FALSE;while(i<bytes-1&&value[i]&&want[i]){char a=value[i],b=want[i];if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=b)return FALSE;i++;}return want[i]==0&&(i==bytes-1||value[i]==0);}
static void bofbench_feature_named_object_security_inventory(datap *parser){int kind_bytes=0,name_bytes=0;char *kind=BeaconDataExtract(parser,&kind_bytes);WCHAR *name=(WCHAR*)BeaconDataExtract(parser,&name_bytes);HANDLE object=NULL;DWORD status,revision=0,index,ace_limit=32;PSID owner=NULL,group=NULL;PACL dacl=NULL;PSECURITY_DESCRIPTOR descriptor=NULL;SECURITY_DESCRIPTOR_CONTROL control=0;LPSTR owner_text=NULL;if(!kind||kind_bytes<=1||!name||name_bytes<2){BOFBENCH_PRINTF(CALLBACK_ERROR,"[named-object-security-inventory] status=bad-arguments");return;}if(bofbench_object_kind(kind,kind_bytes,"event"))object=KERNEL32$OpenEventW(READ_CONTROL,FALSE,name);else if(bofbench_object_kind(kind,kind_bytes,"mutex"))object=KERNEL32$OpenMutexW(READ_CONTROL,FALSE,name);else if(bofbench_object_kind(kind,kind_bytes,"semaphore"))object=KERNEL32$OpenSemaphoreW(READ_CONTROL,FALSE,name);else if(bofbench_object_kind(kind,kind_bytes,"section"))object=KERNEL32$OpenFileMappingW(READ_CONTROL,FALSE,name);else if(bofbench_object_kind(kind,kind_bytes,"job"))object=KERNEL32$OpenJobObjectW(READ_CONTROL,FALSE,name);else{BOFBENCH_PRINTF(CALLBACK_ERROR,"[named-object-security-inventory] status=bad-object-type");return;}if(!object){BOFBENCH_PRINTF(CALLBACK_ERROR,"[named-object-security-inventory] status=failed api=open-object error=%lu",KERNEL32$GetLastError());return;}status=ADVAPI32$GetSecurityInfo(object,SE_KERNEL_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,&group,&dacl,NULL,&descriptor);if(status!=ERROR_SUCCESS){BOFBENCH_PRINTF(CALLBACK_ERROR,"[named-object-security-inventory] status=failed api=GetSecurityInfo error=%lu",status);KERNEL32$CloseHandle(object);return;}ADVAPI32$ConvertSidToStringSidA(owner,&owner_text);ADVAPI32$GetSecurityDescriptorControl(descriptor,&control,&revision);if(dacl){for(index=0;index<dacl->AceCount&&index<ace_limit;index++){LPVOID ace=NULL;PACE_HEADER header;DWORD mask=0;PSID ace_sid=NULL;LPSTR sid_text=NULL;if(!ADVAPI32$GetAce(dacl,index,&ace)||!ace)continue;header=(PACE_HEADER)ace;if(header->AceSize>=sizeof(ACE_HEADER)+sizeof(DWORD))mask=*(DWORD*)((BYTE*)ace+sizeof(ACE_HEADER));if(header->AceType==ACCESS_ALLOWED_ACE_TYPE||header->AceType==ACCESS_DENIED_ACE_TYPE||header->AceType==SYSTEM_AUDIT_ACE_TYPE||header->AceType==SYSTEM_ALARM_ACE_TYPE)ace_sid=(PSID)&((PACCESS_ALLOWED_ACE)ace)->SidStart;if(ace_sid)ADVAPI32$ConvertSidToStringSidA(ace_sid,&sid_text);BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[named-object-security-inventory] object_type=%s ace_index=%lu ace_type=%lu rights=0x%08lx sid=%s inherited=%lu",kind,index,(DWORD)header->AceType,mask,sid_text?sid_text:"-",(header->AceFlags&INHERITED_ACE)?1UL:0UL);if(sid_text)KERNEL32$LocalFree(sid_text);}}BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[named-object-security-inventory] status=complete object_type=%s owner=%s dacl_present=%lu ace_count=%lu shown=%lu protected=%lu inherited=%lu control=0x%04x",kind,owner_text?owner_text:"-",dacl?1UL:0UL,dacl?(DWORD)dacl->AceCount:0UL,dacl?((DWORD)dacl->AceCount<ace_limit?(DWORD)dacl->AceCount:ace_limit):0UL,(control&SE_DACL_PROTECTED)?1UL:0UL,(control&SE_DACL_AUTO_INHERITED)?1UL:0UL,control);if(owner_text)KERNEL32$LocalFree(owner_text);if(descriptor)KERNEL32$LocalFree(descriptor);KERNEL32$CloseHandle(object);}`,
		Call: "bofbench_feature_named_object_security_inventory($PARSER);",
	},
	{
		Name:        "process-handle-detail-inventory",
		Description: "enumerate bounded handle values, types, names, access, and attributes for one exact process",
		Declaration: `typedef LONG NTSTATUS;
typedef struct _BOFBENCH_DETAIL_HANDLE_ENTRY {PVOID Object;ULONG_PTR UniqueProcessId;ULONG_PTR HandleValue;ULONG GrantedAccess;USHORT CreatorBackTraceIndex;USHORT ObjectTypeIndex;ULONG HandleAttributes;ULONG Reserved;} BOFBENCH_DETAIL_HANDLE_ENTRY;
typedef struct _BOFBENCH_DETAIL_HANDLE_INFO {ULONG_PTR NumberOfHandles;ULONG_PTR Reserved;BOFBENCH_DETAIL_HANDLE_ENTRY Handles[1];} BOFBENCH_DETAIL_HANDLE_INFO;
typedef struct _BOFBENCH_DETAIL_UNICODE {USHORT Length;USHORT MaximumLength;PWSTR Buffer;} BOFBENCH_DETAIL_UNICODE;
typedef struct _BOFBENCH_DETAIL_TYPE {BOFBENCH_DETAIL_UNICODE TypeName;} BOFBENCH_DETAIL_TYPE;
typedef struct _BOFBENCH_DETAIL_NAME {BOFBENCH_DETAIL_UNICODE Name;} BOFBENCH_DETAIL_NAME;
NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(ULONG,PVOID,ULONG,PULONG);NTSTATUS NTAPI NTDLL$NtQueryObject(HANDLE,ULONG,PVOID,ULONG,PULONG);
HANDLE WINAPI KERNEL32$OpenProcess(DWORD,BOOL,DWORD);HANDLE WINAPI KERNEL32$GetCurrentProcess(void);BOOL WINAPI KERNEL32$DuplicateHandle(HANDLE,HANDLE,HANDLE,LPHANDLE,DWORD,BOOL,DWORD);BOOL WINAPI KERNEL32$CloseHandle(HANDLE);HANDLE WINAPI KERNEL32$GetProcessHeap(void);LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);BOOL WINAPI KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);
static void bofbench_detail_text(BOFBENCH_DETAIL_UNICODE *value,char *target,DWORD capacity){DWORD i=0,n=value&&value->Buffer?value->Length/2:0;while(i<n&&i+1<capacity){WCHAR c=value->Buffer[i];target[i]=c<128?(char)c:'?';i++;}target[i]=0;}
static BOOL bofbench_detail_match(const char *value,const char *filter,int bytes){int i,j,n=bytes>0?bytes-1:0;if(!n)return TRUE;for(i=0;value&&value[i];i++){for(j=0;j<n&&value[i+j];j++){char a=value[i+j],b=filter[j];if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=b)break;}if(j==n)return TRUE;}return FALSE;}
static void bofbench_feature_process_handle_detail_inventory(datap *parser){DWORD pid=(DWORD)BeaconDataInt(parser);int type_bytes=0,name_bytes=0;char *type_filter=BeaconDataExtract(parser,&type_bytes),*name_filter=BeaconDataExtract(parser,&name_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0,index;ULONG capacity=16777216UL,needed=0;ULONG_PTR maximum=0;BYTE *buffer=NULL,*scratch=NULL,*type_buffer,*name_buffer;char *type,*name;HANDLE heap=KERNEL32$GetProcessHeap(),process=NULL;BOFBENCH_DETAIL_HANDLE_INFO *info;NTSTATUS status;if(!pid){BOFBENCH_PRINTF(CALLBACK_ERROR,"[process-handle-detail-inventory] status=bad-arguments");return;}if(limit>512)limit=512;buffer=(BYTE*)KERNEL32$HeapAlloc(heap,0,capacity);scratch=(BYTE*)KERNEL32$HeapAlloc(heap,0,6240);if(!buffer||!scratch){BOFBENCH_PRINTF(CALLBACK_ERROR,"[process-handle-detail-inventory] status=failed api=HeapAlloc");goto cleanup;}type_buffer=scratch;name_buffer=scratch+1024;type=(char*)(scratch+5120);name=(char*)(scratch+5216);status=NTDLL$NtQuerySystemInformation(64,buffer,capacity,&needed);if(status<0){BOFBENCH_PRINTF(CALLBACK_ERROR,"[process-handle-detail-inventory] status=failed api=NtQuerySystemInformation ntstatus=0x%08lx required=%lu",status,needed);goto cleanup;}process=KERNEL32$OpenProcess(PROCESS_DUP_HANDLE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(!process){BOFBENCH_PRINTF(CALLBACK_ERROR,"[process-handle-detail-inventory] status=failed api=OpenProcess target_pid=%lu",pid);goto cleanup;}info=(BOFBENCH_DETAIL_HANDLE_INFO*)buffer;maximum=((needed?needed:capacity)-sizeof(ULONG_PTR)*2)/sizeof(BOFBENCH_DETAIL_HANDLE_ENTRY);for(index=0;index<info->NumberOfHandles&&index<maximum&&shown<limit;index++){BOFBENCH_DETAIL_HANDLE_ENTRY *row=&info->Handles[index];HANDLE copy=NULL;if((DWORD)row->UniqueProcessId!=pid)continue;if(!KERNEL32$DuplicateHandle(process,(HANDLE)row->HandleValue,KERNEL32$GetCurrentProcess(),&copy,0,FALSE,DUPLICATE_SAME_ACCESS))continue;type[0]=0;name[0]=0;if(NTDLL$NtQueryObject(copy,2,type_buffer,1024,&needed)>=0)bofbench_detail_text(&((BOFBENCH_DETAIL_TYPE*)type_buffer)->TypeName,type,96);if(!bofbench_detail_match(type,type_filter,type_bytes)){KERNEL32$CloseHandle(copy);continue;}if(NTDLL$NtQueryObject(copy,1,name_buffer,4096,&needed)>=0)bofbench_detail_text(&((BOFBENCH_DETAIL_NAME*)name_buffer)->Name,name,1024);if(!bofbench_detail_match(name,name_filter,name_bytes)){KERNEL32$CloseHandle(copy);continue;}BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[process-handle-detail-inventory] target_pid=%lu handle=0x%llx type=%s name=%s access=0x%08lx attributes=0x%08lx inheritable=%lu protected=%lu",pid,(unsigned long long)row->HandleValue,type[0]?type:"unknown",name[0]?name:"-",row->GrantedAccess,row->HandleAttributes,(row->HandleAttributes&2)?1UL:0UL,(row->HandleAttributes&1)?1UL:0UL);shown++;KERNEL32$CloseHandle(copy);}BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[process-handle-detail-inventory] status=complete target_pid=%lu shown=%lu limit=%lu",pid,shown,limit);cleanup:if(process)KERNEL32$CloseHandle(process);if(scratch)KERNEL32$HeapFree(heap,0,scratch);if(buffer)KERNEL32$HeapFree(heap,0,buffer);}`,
		Call: "bofbench_feature_process_handle_detail_inventory($PARSER);",
	},
	{
		Name:        "synchronization-object-state",
		Description: "query exact named event, mutex, semaphore, or waitable-timer state without changing it",
		Declaration: `typedef LONG NTSTATUS;
typedef struct _BOFBENCH_EVENT_STATE {LONG Type;LONG State;} BOFBENCH_EVENT_STATE;typedef struct _BOFBENCH_MUTANT_STATE {LONG CurrentCount;BOOLEAN OwnedByCaller;BOOLEAN AbandonedState;} BOFBENCH_MUTANT_STATE;typedef struct _BOFBENCH_SEMAPHORE_STATE {LONG CurrentCount;LONG MaximumCount;} BOFBENCH_SEMAPHORE_STATE;typedef struct _BOFBENCH_TIMER_STATE {LARGE_INTEGER RemainingTime;BOOLEAN TimerState;} BOFBENCH_TIMER_STATE;
HANDLE WINAPI KERNEL32$OpenEventW(DWORD,BOOL,LPCWSTR);HANDLE WINAPI KERNEL32$OpenMutexW(DWORD,BOOL,LPCWSTR);HANDLE WINAPI KERNEL32$OpenSemaphoreW(DWORD,BOOL,LPCWSTR);HANDLE WINAPI KERNEL32$OpenWaitableTimerW(DWORD,BOOL,LPCWSTR);BOOL WINAPI KERNEL32$CloseHandle(HANDLE);DWORD WINAPI KERNEL32$GetLastError(void);
NTSTATUS NTAPI NTDLL$NtQueryEvent(HANDLE,ULONG,PVOID,ULONG,PULONG);NTSTATUS NTAPI NTDLL$NtQueryMutant(HANDLE,ULONG,PVOID,ULONG,PULONG);NTSTATUS NTAPI NTDLL$NtQuerySemaphore(HANDLE,ULONG,PVOID,ULONG,PULONG);NTSTATUS NTAPI NTDLL$NtQueryTimer(HANDLE,ULONG,PVOID,ULONG,PULONG);
static BOOL bofbench_sync_kind(const char *value,int bytes,const char *expected){int i=0;while(expected[i]&&i+1<bytes){char a=value[i],b=expected[i];if(a>='A'&&a<='Z')a+=32;if(a!=b)return FALSE;i++;}return expected[i]==0&&(i+1==bytes||value[i]==0);}
static void bofbench_feature_synchronization_object_state(datap *parser){int kind_bytes=0,name_bytes=0;char *kind=BeaconDataExtract(parser,&kind_bytes);WCHAR *name=(WCHAR*)BeaconDataExtract(parser,&name_bytes);HANDLE object=NULL;ULONG returned=0;NTSTATUS status=-1;if(!kind||kind_bytes<=1||!name||name_bytes<2){BOFBENCH_PRINTF(CALLBACK_ERROR,"[synchronization-object-state] status=bad-arguments");return;}if(bofbench_sync_kind(kind,kind_bytes,"event")){BOFBENCH_EVENT_STATE state;object=KERNEL32$OpenEventW(1|SYNCHRONIZE,FALSE,name);if(object)status=NTDLL$NtQueryEvent(object,0,&state,sizeof(state),&returned);if(status>=0)BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[synchronization-object-state] status=complete object_type=event state=%ld manual_reset=%lu",state.State,state.Type?0UL:1UL);}else if(bofbench_sync_kind(kind,kind_bytes,"mutex")){BOFBENCH_MUTANT_STATE state;object=KERNEL32$OpenMutexW(1|SYNCHRONIZE,FALSE,name);if(object)status=NTDLL$NtQueryMutant(object,0,&state,sizeof(state),&returned);if(status>=0)BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[synchronization-object-state] status=complete object_type=mutex count=%ld owned=%lu abandoned=%lu",state.CurrentCount,state.OwnedByCaller?1UL:0UL,state.AbandonedState?1UL:0UL);}else if(bofbench_sync_kind(kind,kind_bytes,"semaphore")){BOFBENCH_SEMAPHORE_STATE state;object=KERNEL32$OpenSemaphoreW(1|SYNCHRONIZE,FALSE,name);if(object)status=NTDLL$NtQuerySemaphore(object,0,&state,sizeof(state),&returned);if(status>=0)BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[synchronization-object-state] status=complete object_type=semaphore count=%ld maximum=%ld",state.CurrentCount,state.MaximumCount);}else if(bofbench_sync_kind(kind,kind_bytes,"timer")){BOFBENCH_TIMER_STATE state;object=KERNEL32$OpenWaitableTimerW(1|SYNCHRONIZE,FALSE,name);if(object)status=NTDLL$NtQueryTimer(object,0,&state,sizeof(state),&returned);if(status>=0)BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[synchronization-object-state] status=complete object_type=timer state=%lu remaining_100ns=%lld",state.TimerState?1UL:0UL,(long long)state.RemainingTime.QuadPart);}else{BOFBENCH_PRINTF(CALLBACK_ERROR,"[synchronization-object-state] status=bad-object-type");return;}if(!object){BOFBENCH_PRINTF(CALLBACK_ERROR,"[synchronization-object-state] status=failed api=open-object error=%lu",KERNEL32$GetLastError());return;}if(status<0)BOFBENCH_PRINTF(CALLBACK_ERROR,"[synchronization-object-state] status=failed api=NtQueryObjectState ntstatus=0x%08lx",status);KERNEL32$CloseHandle(object);}`,
		Call: "bofbench_feature_synchronization_object_state($PARSER);",
	},
	{
		Name:        "mailslot-inventory",
		Description: "enumerate bounded local mailslot names with an exact prefix filter",
		Declaration: `typedef LONG NTSTATUS;
typedef struct _BOFBENCH_MAILSLOT_HANDLE_ENTRY {PVOID Object;ULONG_PTR UniqueProcessId;ULONG_PTR HandleValue;ULONG GrantedAccess;USHORT CreatorBackTraceIndex;USHORT ObjectTypeIndex;ULONG HandleAttributes;ULONG Reserved;} BOFBENCH_MAILSLOT_HANDLE_ENTRY;
typedef struct _BOFBENCH_MAILSLOT_HANDLE_INFO {ULONG_PTR NumberOfHandles;ULONG_PTR Reserved;BOFBENCH_MAILSLOT_HANDLE_ENTRY Handles[1];} BOFBENCH_MAILSLOT_HANDLE_INFO;
typedef struct _BOFBENCH_MAILSLOT_UNICODE {USHORT Length;USHORT MaximumLength;PWSTR Buffer;} BOFBENCH_MAILSLOT_UNICODE;
typedef struct _BOFBENCH_MAILSLOT_NAME {BOFBENCH_MAILSLOT_UNICODE Name;} BOFBENCH_MAILSLOT_NAME;
NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(ULONG,PVOID,ULONG,PULONG);NTSTATUS NTAPI NTDLL$NtQueryObject(HANDLE,ULONG,PVOID,ULONG,PULONG);HANDLE WINAPI KERNEL32$OpenProcess(DWORD,BOOL,DWORD);HANDLE WINAPI KERNEL32$GetCurrentProcess(void);BOOL WINAPI KERNEL32$DuplicateHandle(HANDLE,HANDLE,HANDLE,LPHANDLE,DWORD,BOOL,DWORD);BOOL WINAPI KERNEL32$GetMailslotInfo(HANDLE,LPDWORD,LPDWORD,LPDWORD,LPDWORD);BOOL WINAPI KERNEL32$CloseHandle(HANDLE);HANDLE WINAPI KERNEL32$GetProcessHeap(void);LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE,DWORD,SIZE_T);BOOL WINAPI KERNEL32$HeapFree(HANDLE,DWORD,LPVOID);
static BOOL bofbench_mailslot_wide_equal(const WCHAR *value,USHORT chars,const char *expected){USHORT i=0;while(i<chars&&expected[i]){WCHAR a=value[i];char b=expected[i];if(a>=L'A'&&a<=L'Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=(WCHAR)b)return FALSE;i++;}return i==chars&&expected[i]==0;}
static BOOL bofbench_mailslot_leaf(BOFBENCH_MAILSLOT_UNICODE *value,WCHAR *prefix,int prefix_bytes,char *leaf,DWORD capacity){static const char marker[]="\\Device\\Mailslot\\";USHORT i,marker_chars=17,start,prefix_chars=prefix_bytes>1?(USHORT)(prefix_bytes/2-1):0;if(!value||!value->Buffer||value->Length/2<=marker_chars||!bofbench_mailslot_wide_equal(value->Buffer,marker_chars,marker))return FALSE;start=marker_chars;if(prefix_chars){for(i=0;i<prefix_chars;i++){WCHAR a=value->Buffer[start+i],b=prefix[i];if(a>=L'A'&&a<=L'Z')a+=32;if(b>=L'A'&&b<=L'Z')b+=32;if(a!=b)return FALSE;}}for(i=0;start+i<value->Length/2&&i+1<capacity;i++)leaf[i]=value->Buffer[start+i]<128?(char)value->Buffer[start+i]:'?';leaf[i]=0;return TRUE;}
static void bofbench_feature_mailslot_inventory(datap *parser){int prefix_bytes=0;WCHAR *prefix=(WCHAR*)BeaconDataExtract(parser,&prefix_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0,index,current_pid=0;ULONG capacity=16777216UL,needed=0;ULONG_PTR maximum=0;BYTE *buffer=NULL,*scratch=NULL,*name_buffer;char *leaf;HANDLE heap=KERNEL32$GetProcessHeap(),process=NULL,current=KERNEL32$GetCurrentProcess();BOFBENCH_MAILSLOT_HANDLE_INFO *info;NTSTATUS status;if(limit>512)limit=512;buffer=(BYTE*)KERNEL32$HeapAlloc(heap,0,capacity);scratch=(BYTE*)KERNEL32$HeapAlloc(heap,0,5120);if(!buffer||!scratch){BOFBENCH_PRINTF(CALLBACK_ERROR,"[mailslot-inventory] status=failed api=HeapAlloc");goto cleanup;}name_buffer=scratch;leaf=(char*)(scratch+4096);status=NTDLL$NtQuerySystemInformation(64,buffer,capacity,&needed);if(status<0){BOFBENCH_PRINTF(CALLBACK_ERROR,"[mailslot-inventory] status=failed api=NtQuerySystemInformation ntstatus=0x%08lx",status);goto cleanup;}info=(BOFBENCH_MAILSLOT_HANDLE_INFO*)buffer;maximum=((needed?needed:capacity)-sizeof(ULONG_PTR)*2)/sizeof(BOFBENCH_MAILSLOT_HANDLE_ENTRY);for(index=0;index<info->NumberOfHandles&&index<maximum&&shown<limit;index++){BOFBENCH_MAILSLOT_HANDLE_ENTRY *row=&info->Handles[index];HANDLE copy=NULL;DWORD pid=(DWORD)row->UniqueProcessId,maximum_message=0,next_size=0,message_count=0,timeout=0;if(!pid||row->GrantedAccess!=0x00160089UL)continue;if(pid!=current_pid){if(process)KERNEL32$CloseHandle(process);process=KERNEL32$OpenProcess(PROCESS_DUP_HANDLE,FALSE,pid);current_pid=pid;}if(!process||!KERNEL32$DuplicateHandle(process,(HANDLE)row->HandleValue,current,&copy,0,FALSE,DUPLICATE_SAME_ACCESS))continue;if(!KERNEL32$GetMailslotInfo(copy,&maximum_message,&next_size,&message_count,&timeout)){KERNEL32$CloseHandle(copy);continue;}if(NTDLL$NtQueryObject(copy,1,name_buffer,4096,&needed)>=0&&bofbench_mailslot_leaf(&((BOFBENCH_MAILSLOT_NAME*)name_buffer)->Name,prefix,prefix_bytes,leaf,1024)){BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[mailslot-inventory] name=%s path=\\\\.\\mailslot\\%s owner_pid=%lu handle=0x%llx messages=%lu next_bytes=%lu",leaf,leaf,pid,(unsigned long long)row->HandleValue,message_count,next_size);shown++;}KERNEL32$CloseHandle(copy);}BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[mailslot-inventory] status=complete shown=%lu limit=%lu",shown,limit);cleanup:if(process)KERNEL32$CloseHandle(process);if(scratch)KERNEL32$HeapFree(heap,0,scratch);if(buffer)KERNEL32$HeapFree(heap,0,buffer);}`,
		Call: "bofbench_feature_mailslot_inventory($PARSER);",
	},
	{
		Name:        "rpc-endpoint-inventory",
		Description: "enumerate bounded local RPC endpoint-mapper registrations",
		Declaration: `#include <rpc.h>
RPC_STATUS RPC_ENTRY RPCRT4$RpcMgmtEpEltInqBegin(RPC_BINDING_HANDLE,ULONG,RPC_IF_ID*,ULONG,UUID*,RPC_EP_INQ_HANDLE*);
RPC_STATUS RPC_ENTRY RPCRT4$RpcMgmtEpEltInqNextA(RPC_EP_INQ_HANDLE,RPC_IF_ID*,RPC_BINDING_HANDLE*,UUID*,RPC_CSTR*);
RPC_STATUS RPC_ENTRY RPCRT4$RpcMgmtEpEltInqDone(RPC_EP_INQ_HANDLE*);
RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingToStringBindingA(RPC_BINDING_HANDLE,RPC_CSTR*);
RPC_STATUS RPC_ENTRY RPCRT4$RpcBindingFree(RPC_BINDING_HANDLE*);
RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeA(RPC_CSTR*);
static void bofbench_rpc_text(const unsigned char *source,char *target,DWORD capacity){DWORD i=0;while(source&&source[i]&&i+1<capacity){unsigned char c=source[i];target[i]=(c>=32&&c<127)?(char)c:'_';i++;}target[i]=0;}
static void bofbench_rpc_hex(char *target,DWORD *offset,ULONGLONG value,DWORD digits){static const char alphabet[]="0123456789abcdef";DWORD i;for(i=0;i<digits;i++)target[(*offset)++]=alphabet[(value>>((digits-i-1)*4))&15];}
static void bofbench_rpc_uuid(UUID *uuid,char *target,DWORD capacity){DWORD offset=0,index;if(capacity<37){if(capacity)target[0]=0;return;}bofbench_rpc_hex(target,&offset,uuid->Data1,8);target[offset++]='-';bofbench_rpc_hex(target,&offset,uuid->Data2,4);target[offset++]='-';bofbench_rpc_hex(target,&offset,uuid->Data3,4);target[offset++]='-';for(index=0;index<2;index++)bofbench_rpc_hex(target,&offset,uuid->Data4[index],2);target[offset++]='-';for(index=2;index<8;index++)bofbench_rpc_hex(target,&offset,uuid->Data4[index],2);target[offset]=0;}
static BOOL bofbench_rpc_contains(const char *value,const char *filter,int bytes){int i,j,n=bytes>0?bytes-1:0;if(!n)return TRUE;for(i=0;value&&value[i];i++){for(j=0;j<n&&value[i+j];j++){char a=value[i+j],b=filter[j];if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=b)break;}if(j==n)return TRUE;}return FALSE;}
static void bofbench_feature_rpc_endpoint_inventory(datap *parser){int interface_bytes=0,protocol_bytes=0,annotation_bytes=0;char *interface_filter=BeaconDataExtract(parser,&interface_bytes),*protocol_filter=BeaconDataExtract(parser,&protocol_bytes),*annotation_filter=BeaconDataExtract(parser,&annotation_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0;RPC_EP_INQ_HANDLE inquiry=NULL;RPC_STATUS status;status=RPCRT4$RpcMgmtEpEltInqBegin(NULL,RPC_C_EP_ALL_ELTS,NULL,RPC_C_VERS_ALL,NULL,&inquiry);if(status!=RPC_S_OK){BOFBENCH_PRINTF(CALLBACK_ERROR,"[rpc-endpoint-inventory] status=failed api=RpcMgmtEpEltInqBegin error=%lu",status);return;}if(limit>512)limit=512;while(shown<limit){RPC_IF_ID interface_id;RPC_BINDING_HANDLE binding=NULL;RPC_CSTR annotation=NULL,binding_text=NULL;UUID object_uuid;char uuid[48],binding_ascii[1024],annotation_ascii[256];status=RPCRT4$RpcMgmtEpEltInqNextA(inquiry,&interface_id,&binding,&object_uuid,&annotation);if(status==RPC_X_NO_MORE_ENTRIES)break;if(status!=RPC_S_OK){BOFBENCH_PRINTF(CALLBACK_ERROR,"[rpc-endpoint-inventory] status=row-failed error=%lu",status);break;}binding_ascii[0]=annotation_ascii[0]=0;bofbench_rpc_uuid(&interface_id.Uuid,uuid,sizeof(uuid));if(binding&&RPCRT4$RpcBindingToStringBindingA(binding,&binding_text)==RPC_S_OK)bofbench_rpc_text(binding_text,binding_ascii,sizeof(binding_ascii));bofbench_rpc_text(annotation,annotation_ascii,sizeof(annotation_ascii));if(bofbench_rpc_contains(uuid,interface_filter,interface_bytes)&&bofbench_rpc_contains(binding_ascii,protocol_filter,protocol_bytes)&&bofbench_rpc_contains(annotation_ascii,annotation_filter,annotation_bytes)){BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[rpc-endpoint-inventory] interface=%s version=%u.%u binding=%s annotation=%s",uuid,interface_id.VersMajor,interface_id.VersMinor,binding_ascii[0]?binding_ascii:"-",annotation_ascii[0]?annotation_ascii:"-");shown++;}if(binding_text)RPCRT4$RpcStringFreeA(&binding_text);if(annotation)RPCRT4$RpcStringFreeA(&annotation);if(binding)RPCRT4$RpcBindingFree(&binding);}RPCRT4$RpcMgmtEpEltInqDone(&inquiry);BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[rpc-endpoint-inventory] status=complete shown=%lu limit=%lu",shown,limit);}`,
		Call: "bofbench_feature_rpc_endpoint_inventory($PARSER);",
	},
	{
		Name:        "com-registration-inventory",
		Description: "enumerate bounded COM CLSID registration metadata",
		Declaration: `LSTATUS WINAPI ADVAPI32$RegOpenKeyExW(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);
LSTATUS WINAPI ADVAPI32$RegEnumKeyExW(HKEY,DWORD,LPWSTR,LPDWORD,LPDWORD,LPWSTR,LPDWORD,PFILETIME);
LSTATUS WINAPI ADVAPI32$RegQueryValueExW(HKEY,LPCWSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);
LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
static WCHAR bofbench_com_clsid[96],bofbench_com_path[1024],bofbench_com_progid[256],bofbench_com_server[1024],bofbench_com_threading[128];
static BOOL bofbench_com_contains(const WCHAR *value,const WCHAR *filter,DWORD filter_chars){DWORD i,j;if(!filter_chars)return TRUE;for(i=0;value&&value[i];i++){for(j=0;j<filter_chars&&value[i+j];j++){WCHAR a=value[i+j],b=filter[j];if(a>=L'A'&&a<=L'Z')a+=32;if(b>=L'A'&&b<=L'Z')b+=32;if(a!=b)break;}if(j==filter_chars)return TRUE;}return FALSE;}
static void bofbench_com_ascii(const WCHAR *source,char *target,DWORD capacity){DWORD i=0;while(source&&source[i]&&i+1<capacity){WCHAR c=source[i];target[i]=(c<128&&c!=' ')?(char)c:'_';i++;}target[i]=0;}
static BOOL bofbench_com_value(HKEY root,const WCHAR *subkey,const WCHAR *name,WCHAR *value,DWORD capacity,REGSAM view){HKEY key=NULL;DWORD bytes=capacity*sizeof(WCHAR),type=0;value[0]=0;if(ADVAPI32$RegOpenKeyExW(root,subkey,0,KEY_QUERY_VALUE|view,&key)!=ERROR_SUCCESS)return FALSE;if(ADVAPI32$RegQueryValueExW(key,name,NULL,&type,(LPBYTE)value,&bytes)!=ERROR_SUCCESS||(type!=REG_SZ&&type!=REG_EXPAND_SZ)){ADVAPI32$RegCloseKey(key);value[0]=0;return FALSE;}value[capacity-1]=0;ADVAPI32$RegCloseKey(key);return TRUE;}
static void bofbench_com_path_join(const WCHAR *clsid,const WCHAR *suffix){static const WCHAR prefix[]=L"Software\\Classes\\CLSID\\";DWORD offset=0,index=0;while(prefix[index]&&offset+1<1024)bofbench_com_path[offset++]=prefix[index++];index=0;while(clsid[index]&&offset+1<1024)bofbench_com_path[offset++]=clsid[index++];index=0;while(suffix[index]&&offset+1<1024)bofbench_com_path[offset++]=suffix[index++];bofbench_com_path[offset]=0;}
static void bofbench_com_enumerate(HKEY hive,const char *scope,REGSAM view,WCHAR *filter,DWORD filter_chars,DWORD limit,DWORD *shown){HKEY root=NULL;DWORD index=0;if(ADVAPI32$RegOpenKeyExW(hive,L"Software\\Classes\\CLSID",0,KEY_ENUMERATE_SUB_KEYS|view,&root)!=ERROR_SUCCESS)return;while(*shown<limit){DWORD chars=sizeof(bofbench_com_clsid)/sizeof(WCHAR);char clsid[128],progid[256],server[1024],threading[128],kind[24]="none";if(ADVAPI32$RegEnumKeyExW(root,index++,bofbench_com_clsid,&chars,NULL,NULL,NULL,NULL)!=ERROR_SUCCESS)break;bofbench_com_clsid[chars]=0;if(!bofbench_com_contains(bofbench_com_clsid,filter,filter_chars))continue;bofbench_com_path_join(bofbench_com_clsid,L"\\ProgID");bofbench_com_value(hive,bofbench_com_path,NULL,bofbench_com_progid,sizeof(bofbench_com_progid)/sizeof(WCHAR),view);bofbench_com_path_join(bofbench_com_clsid,L"\\InprocServer32");if(bofbench_com_value(hive,bofbench_com_path,NULL,bofbench_com_server,sizeof(bofbench_com_server)/sizeof(WCHAR),view)){kind[0]='i';kind[1]='n';kind[2]='p';kind[3]='r';kind[4]='o';kind[5]='c';kind[6]=0;bofbench_com_value(hive,bofbench_com_path,L"ThreadingModel",bofbench_com_threading,sizeof(bofbench_com_threading)/sizeof(WCHAR),view);}else{bofbench_com_path_join(bofbench_com_clsid,L"\\LocalServer32");if(bofbench_com_value(hive,bofbench_com_path,NULL,bofbench_com_server,sizeof(bofbench_com_server)/sizeof(WCHAR),view)){kind[0]='l';kind[1]='o';kind[2]='c';kind[3]='a';kind[4]='l';kind[5]=0;}else bofbench_com_threading[0]=0;}bofbench_com_ascii(bofbench_com_clsid,clsid,sizeof(clsid));bofbench_com_ascii(bofbench_com_progid,progid,sizeof(progid));bofbench_com_ascii(bofbench_com_server,server,sizeof(server));bofbench_com_ascii(bofbench_com_threading,threading,sizeof(threading));BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[com-registration-inventory] scope=%s clsid=%s progid=%s server_kind=%s server=%s threading=%s",scope,clsid,progid[0]?progid:"-",kind,server[0]?server:"-",threading[0]?threading:"-");(*shown)++;}ADVAPI32$RegCloseKey(root);}
static void bofbench_feature_com_registration_inventory(datap *parser){int scope_bytes=0,view_bytes=0,filter_bytes=0;char *scope=BeaconDataExtract(parser,&scope_bytes),*view_text=BeaconDataExtract(parser,&view_bytes);WCHAR *filter=(WCHAR*)BeaconDataExtract(parser,&filter_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0;REGSAM view=0;BOOL user=TRUE,machine=TRUE;if(limit>512)limit=512;if(view_text&&view_bytes>1&&view_text[0]=='3'&&view_text[1]=='2')view=KEY_WOW64_32KEY;else if(view_text&&view_bytes>1&&view_text[0]=='6'&&view_text[1]=='4')view=KEY_WOW64_64KEY;if(scope&&scope_bytes>1){if(scope[0]=='u'){machine=FALSE;}else if(scope[0]=='m'){user=FALSE;}}if(user)bofbench_com_enumerate(HKEY_CURRENT_USER,"user",view,filter,filter_bytes>1?(DWORD)(filter_bytes/2-1):0,limit,&shown);if(machine&&shown<limit)bofbench_com_enumerate(HKEY_LOCAL_MACHINE,"machine",view,filter,filter_bytes>1?(DWORD)(filter_bytes/2-1):0,limit,&shown);BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[com-registration-inventory] status=complete shown=%lu limit=%lu",shown,limit);}`,
		Call: "bofbench_feature_com_registration_inventory($PARSER);",
	},
	{
		Name:        "alpc-port-inventory",
		Description: "enumerate bounded ALPC and LPC port names from an Object Manager directory",
		Declaration: `#include <winternl.h>
typedef struct _BOFBENCH_DIRECTORY_INFORMATION {UNICODE_STRING Name;UNICODE_STRING TypeName;} BOFBENCH_DIRECTORY_INFORMATION;
NTSTATUS NTAPI NTDLL$RtlInitUnicodeString(PUNICODE_STRING,PCWSTR);
NTSTATUS NTAPI NTDLL$NtOpenDirectoryObject(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NTDLL$NtQueryDirectoryObject(HANDLE,PVOID,ULONG,BOOLEAN,BOOLEAN,PULONG,PULONG);
NTSTATUS NTAPI NTDLL$NtClose(HANDLE);
static WCHAR bofbench_alpc_directory[512],bofbench_alpc_prefix[256];static BYTE bofbench_alpc_buffer[4096];
static void bofbench_alpc_copy(WCHAR *target,DWORD capacity,const WCHAR *source,DWORD bytes){DWORD i,chars=bytes>1?(DWORD)(bytes/2-1):0;if(chars>=capacity)chars=capacity-1;for(i=0;i<chars;i++)target[i]=source[i];target[chars]=0;}
static BOOL bofbench_alpc_prefix_match(UNICODE_STRING *name,WCHAR *prefix){DWORD i;if(!prefix[0])return TRUE;for(i=0;prefix[i];i++){WCHAR a=i<name->Length/2?name->Buffer[i]:0,b=prefix[i];if(a>=L'A'&&a<=L'Z')a+=32;if(b>=L'A'&&b<=L'Z')b+=32;if(!a||a!=b)return FALSE;}return TRUE;}
static void bofbench_alpc_ascii(UNICODE_STRING *source,char *target,DWORD capacity){DWORD i=0,chars=source&&source->Buffer?source->Length/2:0;while(i<chars&&i+1<capacity){WCHAR c=source->Buffer[i];target[i]=(c<128&&c!=' ')?(char)c:'_';i++;}target[i]=0;}
static void bofbench_feature_alpc_port_inventory(datap *parser){int directory_bytes=0,prefix_bytes=0;WCHAR *directory=(WCHAR*)BeaconDataExtract(parser,&directory_bytes),*prefix=(WCHAR*)BeaconDataExtract(parser,&prefix_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0,context=0,returned=0;UNICODE_STRING name;OBJECT_ATTRIBUTES attributes;HANDLE handle=NULL;NTSTATUS status;char object_name[512],type_name[96];if(limit>512)limit=512;bofbench_alpc_copy(bofbench_alpc_directory,512,directory,directory_bytes);bofbench_alpc_copy(bofbench_alpc_prefix,256,prefix,prefix_bytes);if(!bofbench_alpc_directory[0]){bofbench_alpc_directory[0]=L'\\';bofbench_alpc_directory[1]=L'R';bofbench_alpc_directory[2]=L'P';bofbench_alpc_directory[3]=L'C';bofbench_alpc_directory[4]=L' ';bofbench_alpc_directory[5]=L'C';bofbench_alpc_directory[6]=L'o';bofbench_alpc_directory[7]=L'n';bofbench_alpc_directory[8]=L't';bofbench_alpc_directory[9]=L'r';bofbench_alpc_directory[10]=L'o';bofbench_alpc_directory[11]=L'l';bofbench_alpc_directory[12]=0;}NTDLL$RtlInitUnicodeString(&name,bofbench_alpc_directory);attributes.Length=sizeof(attributes);attributes.RootDirectory=NULL;attributes.Attributes=OBJ_CASE_INSENSITIVE;attributes.ObjectName=&name;attributes.SecurityDescriptor=NULL;attributes.SecurityQualityOfService=NULL;status=NTDLL$NtOpenDirectoryObject(&handle,1,&attributes);if(status<0){BOFBENCH_PRINTF(CALLBACK_ERROR,"[alpc-port-inventory] status=failed api=NtOpenDirectoryObject ntstatus=0x%08lx",status);return;}while(shown<limit){BOFBENCH_DIRECTORY_INFORMATION *row=(BOFBENCH_DIRECTORY_INFORMATION*)bofbench_alpc_buffer;status=NTDLL$NtQueryDirectoryObject(handle,bofbench_alpc_buffer,sizeof(bofbench_alpc_buffer),TRUE,FALSE,&context,&returned);if(status<0)break;bofbench_alpc_ascii(&row->TypeName,type_name,sizeof(type_name));if((type_name[0]=='A'&&type_name[1]=='L'&&type_name[2]=='P'&&type_name[3]=='C')||(type_name[0]=='P'&&type_name[1]=='o'&&type_name[2]=='r'&&type_name[3]=='t')){if(!bofbench_alpc_prefix_match(&row->Name,bofbench_alpc_prefix))continue;bofbench_alpc_ascii(&row->Name,object_name,sizeof(object_name));BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[alpc-port-inventory] directory=%ls name=%s type=%s",bofbench_alpc_directory,object_name,type_name);shown++;}}NTDLL$NtClose(handle);BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[alpc-port-inventory] status=complete shown=%lu limit=%lu",shown,limit);}`,
		Call: "bofbench_feature_alpc_port_inventory($PARSER);",
	},
	{
		Name:        "com-running-object-inventory",
		Description: "enumerate bounded COM Running Object Table display names",
		Declaration: `#ifndef COBJMACROS
#define COBJMACROS
#endif
#include <objbase.h>
HRESULT WINAPI OLE32$CoInitializeEx(LPVOID,DWORD);HRESULT WINAPI OLE32$GetRunningObjectTable(DWORD,IRunningObjectTable**);HRESULT WINAPI OLE32$CreateBindCtx(DWORD,IBindCtx**);VOID WINAPI OLE32$CoTaskMemFree(LPVOID);VOID WINAPI OLE32$CoUninitialize(void);
static void bofbench_rot_ascii(const WCHAR *value,char *target,DWORD capacity){DWORD i=0;while(value&&value[i]&&i+1<capacity){WCHAR c=value[i];target[i]=(c>=32&&c<127&&c!=' ')?(char)c:'_';i++;}target[i]=0;}
static BOOL bofbench_rot_contains(const char *value,const char *filter,int bytes){int i,j,n=bytes>0?bytes-1:0;if(!n)return TRUE;for(i=0;value&&value[i];i++){for(j=0;j<n&&value[i+j];j++){char a=value[i+j],b=filter[j];if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=b)break;}if(j==n)return TRUE;}return FALSE;}
static void bofbench_feature_com_running_object_inventory(datap *parser){int filter_bytes=0;char *filter=BeaconDataExtract(parser,&filter_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0;IRunningObjectTable *rot=NULL;IEnumMoniker *enumerator=NULL;IBindCtx *context=NULL;IMoniker *moniker=NULL;ULONG fetched=0;HRESULT hr;BOOL initialized=FALSE;char display[1024];if(limit>512)limit=512;hr=OLE32$CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);if(SUCCEEDED(hr))initialized=TRUE;else if(hr!=RPC_E_CHANGED_MODE)goto failed;hr=OLE32$GetRunningObjectTable(0,&rot);if(FAILED(hr))goto failed;hr=rot->lpVtbl->EnumRunning(rot,&enumerator);if(FAILED(hr))goto failed;hr=OLE32$CreateBindCtx(0,&context);if(FAILED(hr))goto failed;while(shown<limit&&enumerator->lpVtbl->Next(enumerator,1,&moniker,&fetched)==S_OK){LPOLESTR name=NULL;display[0]=0;if(SUCCEEDED(moniker->lpVtbl->GetDisplayName(moniker,context,NULL,&name))&&name){bofbench_rot_ascii(name,display,sizeof(display));OLE32$CoTaskMemFree(name);}if(display[0]&&bofbench_rot_contains(display,filter,filter_bytes)){BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[com-running-object-inventory] index=%lu display_name=%s",shown,display);shown++;}moniker->lpVtbl->Release(moniker);moniker=NULL;}BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[com-running-object-inventory] status=complete shown=%lu limit=%lu",shown,limit);goto cleanup;failed:BOFBENCH_PRINTF(CALLBACK_ERROR,"[com-running-object-inventory] status=failed hresult=0x%08lx",hr);cleanup:if(moniker)moniker->lpVtbl->Release(moniker);if(context)context->lpVtbl->Release(context);if(enumerator)enumerator->lpVtbl->Release(enumerator);if(rot)rot->lpVtbl->Release(rot);if(initialized)OLE32$CoUninitialize();}`,
		Call: "bofbench_feature_com_running_object_inventory($PARSER);",
	},
	{
		Name:        "com-class-detail-inventory",
		Description: "read exact COM class registration, server, AppID, TreatAs, and elevation metadata",
		Declaration: `#include <objbase.h>
HRESULT WINAPI OLE32$CLSIDFromProgID(LPCOLESTR,LPCLSID);HRESULT WINAPI OLE32$CLSIDFromString(LPCOLESTR,LPCLSID);INT WINAPI OLE32$StringFromGUID2(REFGUID,LPOLESTR,INT);
LSTATUS WINAPI ADVAPI32$RegOpenKeyExW(HKEY,LPCWSTR,DWORD,REGSAM,PHKEY);LSTATUS WINAPI ADVAPI32$RegQueryValueExW(HKEY,LPCWSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
static WCHAR bofbench_com_detail_clsid[96],bofbench_com_detail_keypath[1024],bofbench_com_detail_value[2048];
static BOOL bofbench_com_detail_equal(const char *value,int bytes,const char *want){int i=0;while(value&&i<bytes-1&&value[i]&&want[i]){char a=value[i],b=want[i];if(a>='A'&&a<='Z')a+=32;if(b>='A'&&b<='Z')b+=32;if(a!=b)return FALSE;i++;}return want[i]==0&&(i==bytes-1||value[i]==0);}
static void bofbench_com_detail_path(const WCHAR *suffix){static const WCHAR prefix[]=L"CLSID\\";DWORD i=0,j=0;while(prefix[i]&&j+1<1024)bofbench_com_detail_keypath[j++]=prefix[i++];i=0;while(bofbench_com_detail_clsid[i]&&j+1<1024)bofbench_com_detail_keypath[j++]=bofbench_com_detail_clsid[i++];i=0;while(suffix&&suffix[i]&&j+1<1024)bofbench_com_detail_keypath[j++]=suffix[i++];bofbench_com_detail_keypath[j]=0;}
static BOOL bofbench_com_detail_read(const WCHAR *suffix,const WCHAR *name,char *rendered,DWORD capacity){HKEY key=NULL;DWORD type=0,bytes=sizeof(bofbench_com_detail_value),i=0;bofbench_com_detail_path(suffix);rendered[0]=0;if(ADVAPI32$RegOpenKeyExW(HKEY_CLASSES_ROOT,bofbench_com_detail_keypath,0,KEY_QUERY_VALUE,&key)!=ERROR_SUCCESS)return FALSE;if(ADVAPI32$RegQueryValueExW(key,name,NULL,&type,(LPBYTE)bofbench_com_detail_value,&bytes)==ERROR_SUCCESS&&(type==REG_SZ||type==REG_EXPAND_SZ||type==REG_DWORD)){if(type==REG_DWORD){DWORD value=*(DWORD*)bofbench_com_detail_value;rendered[0]=value?'1':'0';rendered[1]=0;}else{bofbench_com_detail_value[(sizeof(bofbench_com_detail_value)/sizeof(WCHAR))-1]=0;while(bofbench_com_detail_value[i]&&i+1<capacity){WCHAR c=bofbench_com_detail_value[i];rendered[i]=(c>=32&&c<127&&c!=' ')?(char)c:'_';i++;}rendered[i]=0;}}ADVAPI32$RegCloseKey(key);return rendered[0]!=0;}
static void bofbench_feature_com_class_detail_inventory(datap *parser){int kind_bytes=0,id_bytes=0;char *kind=BeaconDataExtract(parser,&kind_bytes);WCHAR *identifier=(WCHAR*)BeaconDataExtract(parser,&id_bytes);CLSID clsid;HRESULT hr;char server[2048],threading[128],appid[256],treatas[256],elevation[16],progid[512];if(!identifier||id_bytes<2){BOFBENCH_PRINTF(CALLBACK_ERROR,"[com-class-detail-inventory] status=bad-arguments");return;}if(bofbench_com_detail_equal(kind,kind_bytes,"clsid"))hr=OLE32$CLSIDFromString(identifier,&clsid);else hr=OLE32$CLSIDFromProgID(identifier,&clsid);if(FAILED(hr)){BOFBENCH_PRINTF(CALLBACK_ERROR,"[com-class-detail-inventory] status=failed hresult=0x%08lx",hr);return;}OLE32$StringFromGUID2(&clsid,bofbench_com_detail_clsid,sizeof(bofbench_com_detail_clsid)/sizeof(WCHAR));server[0]=threading[0]=appid[0]=treatas[0]=elevation[0]=progid[0]=0;if(bofbench_com_detail_read(L"\\InprocServer32",NULL,server,sizeof(server)))bofbench_com_detail_read(L"\\InprocServer32",L"ThreadingModel",threading,sizeof(threading));else bofbench_com_detail_read(L"\\LocalServer32",NULL,server,sizeof(server));bofbench_com_detail_read(L"",L"AppID",appid,sizeof(appid));bofbench_com_detail_read(L"\\TreatAs",NULL,treatas,sizeof(treatas));bofbench_com_detail_read(L"\\Elevation",L"Enabled",elevation,sizeof(elevation));bofbench_com_detail_read(L"\\ProgID",NULL,progid,sizeof(progid));BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[com-class-detail-inventory] status=complete clsid=%ls progid=%s server=%s threading=%s appid=%s treat_as=%s elevation=%s",bofbench_com_detail_clsid,progid[0]?progid:"-",server[0]?server:"-",threading[0]?threading:"-",appid[0]?appid:"-",treatas[0]?treatas:"-",elevation[0]?elevation:"0");}`,
		Call: "bofbench_feature_com_class_detail_inventory($PARSER);",
	},
	{
		Name:        "window-inventory",
		Description: "enumerate bounded top-level or message-only windows with owning process and thread metadata",
		Declaration: `BOOL WINAPI USER32$EnumWindows(WNDENUMPROC,LPARAM);HWND WINAPI USER32$FindWindowExW(HWND,HWND,LPCWSTR,LPCWSTR);INT WINAPI USER32$GetWindowTextW(HWND,LPWSTR,INT);INT WINAPI USER32$GetClassNameW(HWND,LPWSTR,INT);DWORD WINAPI USER32$GetWindowThreadProcessId(HWND,LPDWORD);BOOL WINAPI USER32$IsWindowVisible(HWND);BOOL WINAPI USER32$IsWindowEnabled(HWND);HWINSTA WINAPI USER32$OpenWindowStationW(LPCWSTR,BOOL,ACCESS_MASK);BOOL WINAPI USER32$SetProcessWindowStation(HWINSTA);HDESK WINAPI USER32$OpenDesktopW(LPCWSTR,DWORD,BOOL,ACCESS_MASK);BOOL WINAPI USER32$SetThreadDesktop(HDESK);
static DWORD bofbench_window_limit,bofbench_window_shown;static int bofbench_window_class_bytes,bofbench_window_title_bytes;static WCHAR *bofbench_window_class_filter,*bofbench_window_title_filter;static WCHAR bofbench_window_class[256],bofbench_window_title[512];
static void bofbench_window_select_desktop(void){HWINSTA station=USER32$OpenWindowStationW(L"BOFBenchTargetStation",FALSE,0x00000103);HDESK desktop;const WCHAR *desktop_name=L"BOFBenchTargetDesktop";if(!station){station=USER32$OpenWindowStationW(L"WinSta0",FALSE,0x00000103);desktop_name=L"Default";}if(!station||!USER32$SetProcessWindowStation(station))return;desktop=USER32$OpenDesktopW(desktop_name,0,FALSE,0x00000083);if(desktop)USER32$SetThreadDesktop(desktop);}
static BOOL bofbench_window_contains(const WCHAR *value,const WCHAR *filter,int bytes){DWORD i,j,n=bytes>1?(DWORD)(bytes/2-1):0;if(!n)return TRUE;for(i=0;value&&value[i];i++){for(j=0;j<n&&value[i+j];j++){WCHAR a=value[i+j],b=filter[j];if(a>=L'A'&&a<=L'Z')a+=32;if(b>=L'A'&&b<=L'Z')b+=32;if(a!=b)break;}if(j==n)return TRUE;}return FALSE;}
static BOOL CALLBACK bofbench_window_row(HWND window,LPARAM message_only){DWORD pid=0,tid;UINT_PTR value=(UINT_PTR)window;if(bofbench_window_shown>=bofbench_window_limit)return FALSE;bofbench_window_class[0]=bofbench_window_title[0]=0;USER32$GetClassNameW(window,bofbench_window_class,256);USER32$GetWindowTextW(window,bofbench_window_title,512);if(!bofbench_window_contains(bofbench_window_class,bofbench_window_class_filter,bofbench_window_class_bytes)||!bofbench_window_contains(bofbench_window_title,bofbench_window_title_filter,bofbench_window_title_bytes))return TRUE;tid=USER32$GetWindowThreadProcessId(window,&pid);BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[window-inventory] hwnd=0x%llX pid=%lu tid=%lu class=%ls title=%ls visible=%lu enabled=%lu message_only=%lu",(unsigned long long)value,pid,tid,bofbench_window_class,bofbench_window_title,USER32$IsWindowVisible(window)?1UL:0UL,USER32$IsWindowEnabled(window)?1UL:0UL,(DWORD)message_only);bofbench_window_shown++;return bofbench_window_shown<bofbench_window_limit;}
static void bofbench_feature_window_inventory(datap *parser){int scope_bytes=0;char *scope=BeaconDataExtract(parser,&scope_bytes);bofbench_window_class_filter=(WCHAR*)BeaconDataExtract(parser,&bofbench_window_class_bytes);bofbench_window_title_filter=(WCHAR*)BeaconDataExtract(parser,&bofbench_window_title_bytes);bofbench_window_limit=(DWORD)BeaconDataInt(parser);if(!bofbench_window_limit)bofbench_window_limit=64;if(bofbench_window_limit>512)bofbench_window_limit=512;bofbench_window_shown=0;bofbench_window_select_desktop();if(!scope||scope_bytes<=1||scope[0]=='a'||scope[0]=='t')USER32$EnumWindows(bofbench_window_row,0);if(bofbench_window_shown<bofbench_window_limit&&scope&&scope_bytes>1&&(scope[0]=='a'||scope[0]=='m')){HWND previous=NULL,current;while(bofbench_window_shown<bofbench_window_limit&&(current=USER32$FindWindowExW(HWND_MESSAGE,previous,NULL,NULL))!=NULL){previous=current;if(!bofbench_window_row(current,1))break;}}BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[window-inventory] status=complete shown=%lu limit=%lu",bofbench_window_shown,bofbench_window_limit);}`,
		Call: "bofbench_feature_window_inventory($PARSER);",
	},
	{
		Name:        "event-log-channel-inventory",
		Description: "enumerate bounded Windows Event Log channel configuration and record metadata",
		Declaration: `#include <winevt.h>
EVT_HANDLE WINAPI WEVTAPI$EvtOpenChannelEnum(EVT_HANDLE,DWORD);BOOL WINAPI WEVTAPI$EvtNextChannelPath(EVT_HANDLE,DWORD,LPWSTR,PDWORD);EVT_HANDLE WINAPI WEVTAPI$EvtOpenChannelConfig(EVT_HANDLE,LPCWSTR,DWORD);BOOL WINAPI WEVTAPI$EvtGetChannelConfigProperty(EVT_HANDLE,EVT_CHANNEL_CONFIG_PROPERTY_ID,DWORD,DWORD,PEVT_VARIANT,PDWORD);EVT_HANDLE WINAPI WEVTAPI$EvtOpenLog(EVT_HANDLE,LPCWSTR,DWORD);BOOL WINAPI WEVTAPI$EvtGetLogInfo(EVT_HANDLE,EVT_LOG_PROPERTY_ID,DWORD,PEVT_VARIANT,PDWORD);BOOL WINAPI WEVTAPI$EvtClose(EVT_HANDLE);
static BYTE bofbench_event_channel_buffer[16384];static WCHAR bofbench_event_channel_path[1024];
static BOOL bofbench_event_channel_contains(const WCHAR *value,const WCHAR *filter,int bytes){DWORD i,j,n=bytes>1?(DWORD)(bytes/2-1):0;if(!n)return TRUE;for(i=0;value&&value[i];i++){for(j=0;j<n&&value[i+j];j++){WCHAR a=value[i+j],b=filter[j];if(a>=L'A'&&a<=L'Z')a+=32;if(b>=L'A'&&b<=L'Z')b+=32;if(a!=b)break;}if(j==n)return TRUE;}return FALSE;}
static ULONGLONG bofbench_event_log_value(EVT_HANDLE log,EVT_LOG_PROPERTY_ID id){DWORD used=0;PEVT_VARIANT value=(PEVT_VARIANT)bofbench_event_channel_buffer;if(!WEVTAPI$EvtGetLogInfo(log,id,sizeof(bofbench_event_channel_buffer),value,&used))return 0;return value->UInt64Val;}
static void bofbench_feature_event_log_channel_inventory(datap *parser){int filter_bytes=0;WCHAR *filter=(WCHAR*)BeaconDataExtract(parser,&filter_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0,used=0;EVT_HANDLE enumeration;if(limit>512)limit=512;enumeration=WEVTAPI$EvtOpenChannelEnum(NULL,0);if(!enumeration){BOFBENCH_PRINTF(CALLBACK_ERROR,"[event-log-channel-inventory] status=failed error=%lu",KERNEL32$GetLastError());return;}while(shown<limit){EVT_HANDLE config=NULL,log=NULL;PEVT_VARIANT enabled=(PEVT_VARIANT)bofbench_event_channel_buffer;DWORD enabled_value=0,type=0,isolation=0;used=0;if(!WEVTAPI$EvtNextChannelPath(enumeration,sizeof(bofbench_event_channel_path)/sizeof(WCHAR),bofbench_event_channel_path,&used)){DWORD error=KERNEL32$GetLastError();if(error==ERROR_NO_MORE_ITEMS)break;if(error==ERROR_INSUFFICIENT_BUFFER){BOFBENCH_PRINTF(CALLBACK_ERROR,"[event-log-channel-inventory] status=failed error=%lu required=%lu",error,used);break;}continue;}if(!bofbench_event_channel_contains(bofbench_event_channel_path,filter,filter_bytes))continue;config=WEVTAPI$EvtOpenChannelConfig(NULL,bofbench_event_channel_path,0);if(config){used=0;if(WEVTAPI$EvtGetChannelConfigProperty(config,EvtChannelConfigEnabled,0,sizeof(bofbench_event_channel_buffer),enabled,&used))enabled_value=enabled->BooleanVal?1:0;used=0;if(WEVTAPI$EvtGetChannelConfigProperty(config,EvtChannelConfigType,0,sizeof(bofbench_event_channel_buffer),enabled,&used))type=enabled->UInt32Val;used=0;if(WEVTAPI$EvtGetChannelConfigProperty(config,EvtChannelConfigIsolation,0,sizeof(bofbench_event_channel_buffer),enabled,&used))isolation=enabled->UInt32Val;}log=WEVTAPI$EvtOpenLog(NULL,bofbench_event_channel_path,EvtOpenChannelPath);BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[event-log-channel-inventory] channel=%ls enabled=%lu type=%lu isolation=%lu records=%llu oldest=%llu",bofbench_event_channel_path,enabled_value,type,isolation,(unsigned long long)(log?bofbench_event_log_value(log,EvtLogNumberOfLogRecords):0),(unsigned long long)(log?bofbench_event_log_value(log,EvtLogOldestRecordNumber):0));shown++;if(log)WEVTAPI$EvtClose(log);if(config)WEVTAPI$EvtClose(config);}WEVTAPI$EvtClose(enumeration);BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[event-log-channel-inventory] status=complete shown=%lu limit=%lu",shown,limit);}`,
		Call: "bofbench_feature_event_log_channel_inventory($PARSER);",
	},
	{
		Name:        "event-log-query",
		Description: "query bounded structured event metadata from one exact channel or exported log",
		Declaration: `#include <winevt.h>
EVT_HANDLE WINAPI WEVTAPI$EvtQuery(EVT_HANDLE,LPCWSTR,LPCWSTR,DWORD);BOOL WINAPI WEVTAPI$EvtNext(EVT_HANDLE,DWORD,EVT_HANDLE*,DWORD,DWORD,PDWORD);EVT_HANDLE WINAPI WEVTAPI$EvtCreateRenderContext(DWORD,LPCWSTR*,EVT_RENDER_CONTEXT_FLAGS);BOOL WINAPI WEVTAPI$EvtRender(EVT_HANDLE,EVT_HANDLE,DWORD,DWORD,PVOID,PDWORD,PDWORD);BOOL WINAPI WEVTAPI$EvtClose(EVT_HANDLE);
static BYTE bofbench_event_query_buffer[32768];
static void bofbench_feature_event_log_query(datap *parser){int path_bytes=0,xpath_bytes=0,direction_bytes=0;WCHAR *path=(WCHAR*)BeaconDataExtract(parser,&path_bytes),*xpath=(WCHAR*)BeaconDataExtract(parser,&xpath_bytes);char *direction=BeaconDataExtract(parser,&direction_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:32,flags=EvtQueryChannelPath,shown=0,returned=0;EVT_HANDLE query,context,event=NULL;if(!path||path_bytes<2){BOFBENCH_PRINTF(CALLBACK_ERROR,"[event-log-query] status=bad-arguments");return;}if(limit>512)limit=512;if(direction&&direction_bytes>1&&direction[0]=='r')flags|=EvtQueryReverseDirection;if(path[1]==L':'||path[0]==L'\\')flags=(flags&~EvtQueryChannelPath)|EvtQueryFilePath;query=WEVTAPI$EvtQuery(NULL,path,(xpath&&xpath_bytes>2)?xpath:L"*",flags);if(!query){BOFBENCH_PRINTF(CALLBACK_ERROR,"[event-log-query] status=failed error=%lu",KERNEL32$GetLastError());return;}context=WEVTAPI$EvtCreateRenderContext(0,NULL,EvtRenderContextSystem);if(!context){WEVTAPI$EvtClose(query);BOFBENCH_PRINTF(CALLBACK_ERROR,"[event-log-query] status=failed api=EvtCreateRenderContext error=%lu",KERNEL32$GetLastError());return;}while(shown<limit&&WEVTAPI$EvtNext(query,1,&event,1000,0,&returned)){DWORD used=0,count=0;PEVT_VARIANT values=(PEVT_VARIANT)bofbench_event_query_buffer;if(WEVTAPI$EvtRender(context,event,EvtRenderEventValues,sizeof(bofbench_event_query_buffer),values,&used,&count)&&count>EvtSystemComputer){LPCWSTR provider=values[EvtSystemProviderName].StringVal,computer=values[EvtSystemComputer].StringVal;ULONGLONG record=values[EvtSystemEventRecordId].UInt64Val,filetime=values[EvtSystemTimeCreated].FileTimeVal;BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[event-log-query] provider=%ls event_id=%u level=%u record_id=%llu computer=%ls time=%llu",provider?provider:L"-",values[EvtSystemEventID].UInt16Val,values[EvtSystemLevel].ByteVal,(unsigned long long)record,computer?computer:L"-",(unsigned long long)filetime);shown++;}WEVTAPI$EvtClose(event);event=NULL;}WEVTAPI$EvtClose(context);WEVTAPI$EvtClose(query);BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[event-log-query] status=complete shown=%lu limit=%lu",shown,limit);}`,
		Call: "bofbench_feature_event_log_query($PARSER);",
	},
	{
		Name:        "etw-provider-inventory",
		Description: "enumerate bounded Event Tracing for Windows provider names and identifiers",
		Declaration: `#include <evntrace.h>
#include <tdh.h>
ULONG WINAPI TDH$TdhEnumerateProviders(PPROVIDER_ENUMERATION_INFO,PULONG);
static BYTE bofbench_etw_provider_buffer[262144];
static BOOL bofbench_etw_provider_contains(const WCHAR *value,const WCHAR *filter,int bytes){DWORD i,j,n=bytes>1?(DWORD)(bytes/2-1):0;if(!n)return TRUE;for(i=0;value&&value[i];i++){for(j=0;j<n&&value[i+j];j++){WCHAR a=value[i+j],b=filter[j];if(a>=L'A'&&a<=L'Z')a+=32;if(b>=L'A'&&b<=L'Z')b+=32;if(a!=b)break;}if(j==n)return TRUE;}return FALSE;}
static void bofbench_feature_etw_provider_inventory(datap *parser){int filter_bytes=0;WCHAR *filter=(WCHAR*)BeaconDataExtract(parser,&filter_bytes);DWORD requested=(DWORD)BeaconDataInt(parser),limit=requested?requested:64,shown=0,index;ULONG size=sizeof(bofbench_etw_provider_buffer),status;PPROVIDER_ENUMERATION_INFO info=(PPROVIDER_ENUMERATION_INFO)bofbench_etw_provider_buffer;if(limit>1024)limit=1024;status=TDH$TdhEnumerateProviders(info,&size);if(status!=ERROR_SUCCESS){BOFBENCH_PRINTF(CALLBACK_ERROR,"[etw-provider-inventory] status=failed error=%lu required=%lu",status,size);return;}for(index=0;index<info->NumberOfProviders&&shown<limit;index++){TRACE_PROVIDER_INFO *row=&info->TraceProviderInfoArray[index];WCHAR *name=(WCHAR*)((BYTE*)info+row->ProviderNameOffset);GUID *g=&row->ProviderGuid;if(!bofbench_etw_provider_contains(name,filter,filter_bytes))continue;BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[etw-provider-inventory] name=%ls guid={%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x} schema=%lu",name?name:L"-",g->Data1,g->Data2,g->Data3,g->Data4[0],g->Data4[1],g->Data4[2],g->Data4[3],g->Data4[4],g->Data4[5],g->Data4[6],g->Data4[7],row->SchemaSource);shown++;}BOFBENCH_PRINTF(CALLBACK_OUTPUT,"[etw-provider-inventory] status=complete shown=%lu limit=%lu total=%lu",shown,limit,info->NumberOfProviders);}`,
		Call: "bofbench_feature_etw_provider_inventory($PARSER);",
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
