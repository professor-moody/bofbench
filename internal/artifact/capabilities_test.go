package artifact

import (
	"path/filepath"
	"strings"
	"testing"

	"bofbench/internal/coff"
)

func TestAnalyzeCapabilitiesTrustedSecWhoamiLikeImports(t *testing.T) {
	obj := filepath.Join(t.TempDir(), "whoami.x64.o")
	imports := []string{
		"__imp_ADVAPI32$ConvertSidToStringSidA",
		"__imp_ADVAPI32$GetTokenInformation",
		"__imp_ADVAPI32$LookupAccountSidA",
		"__imp_ADVAPI32$LookupPrivilegeDisplayNameA",
		"__imp_ADVAPI32$LookupPrivilegeNameA",
		"__imp_ADVAPI32$OpenProcessToken",
		"__imp_KERNEL32$GetCurrentProcess",
		"__imp_KERNEL32$GetProcessHeap",
		"__imp_KERNEL32$HeapAlloc",
		"__imp_KERNEL32$HeapFree",
		"__imp_SECUR32$GetUserNameExA",
	}
	if err := coff.CreateMockObject(obj, "x64", "go", imports); err != nil {
		t.Fatal(err)
	}
	a, err := Analyze(obj, "go")
	if err != nil {
		t.Fatal(err)
	}

	identity := requireCapability(t, a.Capabilities, "identity_account_sid")
	for _, evidence := range []string{
		"ADVAPI32$ConvertSidToStringSidA",
		"ADVAPI32$LookupAccountSidA",
		"SECUR32$GetUserNameExA",
	} {
		if !containsString(identity.Evidence, evidence) {
			t.Fatalf("identity capability missing evidence %q: %+v", evidence, identity)
		}
	}
	token := requireCapability(t, a.Capabilities, "token_context")
	for _, evidence := range []string{"ADVAPI32$GetTokenInformation", "ADVAPI32$OpenProcessToken"} {
		if !containsString(token.Evidence, evidence) {
			t.Fatalf("token capability missing evidence %q: %+v", evidence, token)
		}
	}
	for _, unexpected := range []string{"memory_operations", "process_access", "process_inventory"} {
		if hasCapability(a.Capabilities, unexpected) {
			t.Fatalf("ordinary whoami support import caused %s inference: %+v", unexpected, a.Capabilities)
		}
	}
	if identity.Inference != "import analysis" || identity.Impact != "read-only discovery" {
		t.Fatalf("identity labels = %+v", identity)
	}

	markdown := Markdown(a)
	capabilitiesAt := strings.Index(markdown, "## Capabilities")
	runtimeAt := strings.Index(markdown, "## Runtime Compatibility")
	if capabilitiesAt < 0 || runtimeAt < 0 || capabilitiesAt > runtimeAt {
		t.Fatalf("capabilities must appear near top before runtime:\n%s", markdown)
	}
	for _, want := range []string{
		"Identity, account, and SID lookup",
		"Access-token inspection",
		"not proof that a code path executed",
		"ADVAPI32$LookupAccountSidA",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("capability Markdown missing %q:\n%s", want, markdown)
		}
	}
}

func TestInferCapabilitiesDeepInternalImports(t *testing.T) {
	imports := importsFromSymbols([]string{
		"ADVAPI32$EnumServicesStatusExA",
		"ADVAPI32$GetTokenInformation",
		"ADVAPI32$GetUserNameA",
		"ADVAPI32$OpenProcessToken",
		"ADVAPI32$RegCreateKeyExA",
		"ADVAPI32$RegQueryValueExA",
		"ADVAPI32$RegSetValueExA",
		"IPHLPAPI$GetExtendedTcpTable",
		"KERNEL32$CreateFileA",
		"KERNEL32$CreateProcessA",
		"KERNEL32$CreateToolhelp32Snapshot",
		"KERNEL32$Process32First",
		"KERNEL32$Process32Next",
		"KERNEL32$WriteFile",
		"NETAPI32$NetGetJoinInformation",
		"WS2_32$WSAStartup",
		"WS2_32$gethostname",
	})
	capabilities := inferCapabilities(imports, nil)
	want := []string{
		"domain_context",
		"file_write",
		"identity_account_sid",
		"network_tcp",
		"process_inventory",
		"process_launch",
		"registry_read",
		"registry_write",
		"service_inventory",
		"token_context",
	}
	for _, id := range want {
		item := requireCapability(t, capabilities, id)
		if item.Name == "" || item.Summary == "" || item.Impact == "" || item.Inference != "import analysis" || len(item.Evidence) == 0 {
			t.Fatalf("capability %s is not operator-readable and evidenced: %+v", id, item)
		}
	}
	if hasCapability(capabilities, "persistence_mechanism") {
		t.Fatalf("generic Registry writes must not be labeled persistence without specific evidence: %+v", capabilities)
	}
	if hasCapability(capabilities, "file_read") {
		t.Fatalf("CreateFileA alone must not imply file reads: %+v", capabilities)
	}
}

func TestInferCapabilitiesCoversStateChangingAndExecutionAPIs(t *testing.T) {
	tests := []struct {
		id      string
		symbols []string
	}{
		{id: "process_access", symbols: []string{"KERNEL32$OpenProcess", "KERNEL32$WriteProcessMemory", "KERNEL32$CreateRemoteThread"}},
		{id: "service_control", symbols: []string{"ADVAPI32$StartServiceW", "ADVAPI32$ControlService"}},
		{id: "file_read", symbols: []string{"KERNEL32$ReadFile"}},
		{id: "memory_operations", symbols: []string{"KERNEL32$VirtualAlloc", "KERNEL32$VirtualProtect"}},
		{id: "dynamic_loading", symbols: []string{"KERNEL32$LoadLibraryA", "KERNEL32$GetProcAddress"}},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			got := inferCapabilities(importsFromSymbols(test.symbols), nil)
			item := requireCapability(t, got, test.id)
			if len(item.Evidence) != len(test.symbols) {
				t.Fatalf("%s evidence = %+v, want evidence for all APIs", test.id, item.Evidence)
			}
		})
	}
}

func TestInferPersistenceRequiresSpecificMechanismEvidence(t *testing.T) {
	registryImports := importsFromSymbols([]string{"ADVAPI32$RegOpenKeyExA", "ADVAPI32$RegSetValueExA"})
	benign := inferCapabilities(registryImports, []String{{Value: `Software\BOFBench\Marker`, Category: "path"}})
	if hasCapability(benign, "persistence_mechanism") {
		t.Fatalf("benign registry write labeled as persistence: %+v", benign)
	}

	runKey := inferCapabilities(registryImports, []String{{Value: `Software\Microsoft\Windows\CurrentVersion\Run\BOFBenchLab`, Category: "path"}})
	persistence := requireCapability(t, runKey, "persistence_mechanism")
	if persistence.Inference != "imports + visible strings" || !containsString(persistence.Evidence, "ADVAPI32$RegSetValueExA") {
		t.Fatalf("run-key persistence evidence = %+v", persistence)
	}
	foundString := false
	for _, evidence := range persistence.Evidence {
		if strings.HasPrefix(evidence, "string: ") && strings.Contains(evidence, `CurrentVersion\Run`) {
			foundString = true
		}
	}
	if !foundString {
		t.Fatalf("run-key persistence missing corroborating string: %+v", persistence)
	}

	service := inferCapabilities(importsFromSymbols([]string{"ADVAPI32$CreateServiceW"}), nil)
	servicePersistence := requireCapability(t, service, "persistence_mechanism")
	if servicePersistence.Inference != "import analysis" || !containsString(servicePersistence.Evidence, "ADVAPI32$CreateServiceW") {
		t.Fatalf("service persistence inference = %+v", servicePersistence)
	}
}

func TestInferCapabilitiesRejectsAmbiguousSupportImports(t *testing.T) {
	capabilities := inferCapabilities(importsFromSymbols([]string{
		"ADVAPI32$OpenSCManagerA",
		"ADVAPI32$RegOpenKeyExA",
		"KERNEL32$CreateFileA",
		"KERNEL32$CreateToolhelp32Snapshot",
		"KERNEL32$HeapAlloc",
	}), nil)
	if len(capabilities) != 0 {
		t.Fatalf("ambiguous support imports should not overclaim capabilities: %+v", capabilities)
	}
}

func importsFromSymbols(symbols []string) []Import {
	out := make([]Import, 0, len(symbols))
	for _, symbol := range symbols {
		out = append(out, classifyImport(symbol))
	}
	return out
}

func requireCapability(t *testing.T, capabilities []Capability, id string) Capability {
	t.Helper()
	for _, item := range capabilities {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("missing capability %q: %+v", id, capabilities)
	return Capability{}
}

func hasCapability(capabilities []Capability, id string) bool {
	for _, item := range capabilities {
		if item.ID == id {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
