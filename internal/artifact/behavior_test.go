package artifact

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"bofbench/internal/coff"
)

func TestAnalysisCorrelatesObservedOutputByObjectHash(t *testing.T) {
	root := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	object := filepath.Join(root, "observed.x64.o")
	if err := coff.CreateMockObject(object, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	first, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	receiptDir := filepath.Join("runs", "20260713-run-observed")
	if err := os.MkdirAll(receiptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"status":"pass","runtime":"windows-coff","object_fingerprint":{"sha256":"%s"},"output":["[identity] user=LAB\\operator"]}`, first.SHA256)
	if err := os.WriteFile(filepath.Join(receiptDir, "result.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	observed, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Observed) != 1 || observed.Observed[0].Capability != "identity" || observed.Observed[0].Status != "windows-coff/pass" {
		t.Fatalf("observed = %+v", observed.Observed)
	}
}

func TestAnalysisCorrelatesRuntimeReceiptV2ByExactObjectHash(t *testing.T) {
	root := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	object := filepath.Join(root, "receipt-v2.x64.o")
	other := filepath.Join(root, "other.x64.o")
	if err := coff.CreateMockObject(object, "x64", "go", []string{"BeaconPrintf"}); err != nil {
		t.Fatal(err)
	}
	if err := coff.CreateMockObject(other, "x64", "go", []string{"BeaconDataInt"}); err != nil {
		t.Fatal(err)
	}
	analysis, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	otherAnalysis, err := Analyze(other, "go")
	if err != nil {
		t.Fatal(err)
	}
	for id, body := range map[string]string{
		"match":    fmt.Sprintf(`{"status":"pass","runtime":"sliver","object_sha256":"%s","output":["[*] Active session","hello from fixture","[token-inventory] shown=3 status=complete"]}`, analysis.SHA256),
		"mismatch": fmt.Sprintf(`{"status":"pass","runtime":"lab","object_sha256":"%s","output":["[wrong-object] status=complete"]}`, otherAnalysis.SHA256),
	} {
		dir := filepath.Join("runs", id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "result.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	observed, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Observed) != 1 || observed.Observed[0].Capability != "token-inventory" || observed.Observed[0].Status != "sliver/pass" {
		t.Fatalf("observed = %+v", observed.Observed)
	}
}

func TestBehaviorChainsRequireCoLocatedRelocationEvidence(t *testing.T) {
	root := t.TempDir()
	object := filepath.Join(root, "inject.x64.o")
	imports := []string{
		"KERNEL32$OpenProcess",
		"KERNEL32$VirtualAllocEx",
		"KERNEL32$WriteProcessMemory",
		"KERNEL32$CreateRemoteThread",
	}
	relocations := make([]coff.MockRelocation, 0, len(imports))
	for index, symbol := range imports {
		relocations = append(relocations, coff.MockRelocation{VirtualAddress: uint32(index), Symbol: symbol, Type: 4})
	}
	if err := coff.CreateMockObjectWithRelocations(object, "x64", "go", imports, relocations); err != nil {
		t.Fatal(err)
	}
	analysis, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	chain := requireBehavior(t, analysis.BehaviorChains, "process_injection_remote_thread")
	if chain.Confidence != "strong chain" || chain.Function != "go" || len(chain.Steps) != 4 {
		t.Fatalf("chain = %+v", chain)
	}
	if !containsString(analysis.Effects, "writes process memory") || !containsString(analysis.WorksWith, "sliver") || !containsString(analysis.WorksWith, "native") {
		t.Fatalf("effects=%v works=%v", analysis.Effects, analysis.WorksWith)
	}
	if analysis.SchemaVersion != 2 || analysis.SourceAndVersion.ObjectSHA256 == "" {
		t.Fatalf("analysis v2 fields = %+v", analysis)
	}

	importsOnly := filepath.Join(root, "imports-only.x64.o")
	if err := coff.CreateMockObject(importsOnly, "x64", "go", imports); err != nil {
		t.Fatal(err)
	}
	negative, err := Analyze(importsOnly, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(negative.BehaviorChains) != 0 {
		t.Fatalf("imports without function-local relocation evidence produced chains: %+v", negative.BehaviorChains)
	}
}

func TestDeclarativeSignaturesRequireEveryStepInOneFunction(t *testing.T) {
	signature := DeclarativeSignature{
		ID: "section_map_execution", Name: "Section-map execution", Summary: "Map a shared section and start execution",
		Effects: []string{"writes process memory", "starts execution"},
		Steps:   []DeclarativeSignatureStep{{Action: "create section", APIs: []string{"NtCreateSection"}}, {Action: "map section", APIs: []string{"NtMapViewOfSection"}}, {Action: "start execution", APIs: []string{"NtCreateThreadEx"}}},
	}
	positive := Analysis{RelocationDetails: []Relocation{{Function: "go", Symbol: "NTDLL$NtCreateSection"}, {Function: "go", Symbol: "NTDLL$NtMapViewOfSection"}, {Function: "go", Symbol: "NTDLL$NtCreateThreadEx"}}}
	ApplyDeclarativeSignatures(&positive, []DeclarativeSignature{signature})
	chain := requireBehavior(t, positive.BehaviorChains, "section_map_execution")
	if chain.Confidence != "strong chain" || len(chain.Steps) != 3 {
		t.Fatalf("chain = %+v", chain)
	}
	negative := Analysis{RelocationDetails: []Relocation{{Function: "one", Symbol: "NTDLL$NtCreateSection"}, {Function: "two", Symbol: "NTDLL$NtMapViewOfSection"}, {Function: "three", Symbol: "NTDLL$NtCreateThreadEx"}}}
	ApplyDeclarativeSignatures(&negative, []DeclarativeSignature{signature})
	if len(negative.BehaviorChains) != 0 {
		t.Fatalf("split evidence produced a behavior chain: %+v", negative.BehaviorChains)
	}
}

func TestGenericProcessMemoryReadDoesNotClaimCredentialAccess(t *testing.T) {
	root := t.TempDir()
	object := filepath.Join(root, "memory-read.x64.o")
	imports := []string{"KERNEL32$OpenProcess", "KERNEL32$ReadProcessMemory"}
	relocations := []coff.MockRelocation{
		{VirtualAddress: 0, Symbol: imports[0], Type: 4},
		{VirtualAddress: 1, Symbol: imports[1], Type: 4},
	}
	if err := coff.CreateMockObjectWithRelocations(object, "x64", "go", imports, relocations); err != nil {
		t.Fatal(err)
	}
	analysis, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	requireBehavior(t, analysis.BehaviorChains, "process_memory_read")
	for _, chain := range analysis.BehaviorChains {
		if chain.ID == "credential_process_memory" {
			t.Fatalf("generic memory object claimed credential access: %+v", chain)
		}
	}
}

func TestPrivilegeAdjustmentRequiresResolveAndAdjust(t *testing.T) {
	root := t.TempDir()
	object := filepath.Join(root, "privilege.x64.o")
	imports := []string{"ADVAPI32$LookupPrivilegeValueW", "ADVAPI32$AdjustTokenPrivileges"}
	relocations := []coff.MockRelocation{
		{VirtualAddress: 0, Symbol: imports[0], Type: 4},
		{VirtualAddress: 1, Symbol: imports[1], Type: 4},
	}
	if err := coff.CreateMockObjectWithRelocations(object, "x64", "go", imports, relocations); err != nil {
		t.Fatal(err)
	}
	analysis, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	requireBehavior(t, analysis.BehaviorChains, "privilege_adjustment")
}

func TestCredentialReadIsReportedAsConfirmedPrimitive(t *testing.T) {
	chains := inferBehaviorChains(
		[]Relocation{{Function: "go", Symbol: "ADVAPI32$CredReadW"}},
		[]String{{Value: "[credential-read] status=complete"}},
	)
	chain := requireBehavior(t, chains, "credential_manager_read")
	if chain.Confidence != "confirmed primitive" || len(chain.Steps) != 1 {
		t.Fatalf("chain = %+v", chain)
	}
}

func TestAuthenticationBehaviorRulesRequireCompleteFunctionLocalChains(t *testing.T) {
	cases := []struct {
		id   string
		apis []string
	}{
		{"certificate_store_inventory", []string{"CRYPT32$CertOpenStore", "CRYPT32$CertEnumCertificatesInStore", "CRYPT32$CertGetCertificateContextProperty"}},
		{"logon_session_details", []string{"SECUR32$LsaEnumerateLogonSessions", "SECUR32$LsaGetLogonSessionData"}},
		{"kerberos_cache_inventory", []string{"SECUR32$LsaConnectUntrusted", "SECUR32$LsaLookupAuthenticationPackage", "SECUR32$LsaCallAuthenticationPackage"}},
		{"vault_inventory", []string{"VAULTCLI$VaultEnumerateVaults", "VAULTCLI$VaultOpenVault", "VAULTCLI$VaultEnumerateItems"}},
		{"vault_exact_read", []string{"VAULTCLI$VaultOpenVault", "VAULTCLI$VaultEnumerateItems", "VAULTCLI$VaultGetItem"}},
		{"dpapi_file_reprotect", []string{"KERNEL32$ReadFile", "CRYPT32$CryptUnprotectData", "CRYPT32$CryptProtectData", "KERNEL32$WriteFile"}},
		{"certificate_pfx_export", []string{"CRYPT32$CertOpenStore", "CRYPT32$CertFindCertificateInStore", "CRYPT32$PFXExportCertStoreEx", "KERNEL32$WriteFile"}},
	}
	for _, test := range cases {
		t.Run(test.id, func(t *testing.T) {
			var relocations []Relocation
			for _, api := range test.apis {
				relocations = append(relocations, Relocation{Function: "go", Symbol: api})
			}
			chain := requireBehavior(t, inferBehaviorChains(relocations, nil), test.id)
			if chain.Confidence != "strong chain" || len(chain.Steps) != len(test.apis) {
				t.Fatalf("chain = %+v", chain)
			}
			missingFinal := inferBehaviorChains(relocations[:len(relocations)-1], nil)
			for _, candidate := range missingFinal {
				if candidate.ID == test.id {
					t.Fatalf("incomplete API sequence produced %s: %+v", test.id, candidate)
				}
			}
		})
	}
	primitive := requireBehavior(t, inferBehaviorChains([]Relocation{{Function: "go", Symbol: "SECUR32$EnumerateSecurityPackagesW"}}, nil), "security_package_inventory")
	if primitive.Confidence != "confirmed primitive" {
		t.Fatalf("SSPI primitive = %+v", primitive)
	}
}

func TestNewPublicInventoryRulesRequireCompleteEvidence(t *testing.T) {
	cases := []struct {
		id      string
		apis    []string
		strings []String
	}{
		{"process_access_check", []string{"KERNEL32$OpenProcess", "KERNEL32$CloseHandle"}, []String{{Value: "[process-access-check]"}}},
		{"module_export_inventory", []string{"KERNEL32$CreateToolhelp32Snapshot", "KERNEL32$ReadProcessMemory"}, []String{{Value: "[module-export-inventory]"}}},
		{"network_neighbor_inventory", []string{"IPHLPAPI$GetIpNetTable2", "IPHLPAPI$FreeMibTable"}, []String{{Value: "[network-neighbor-inventory]"}}},
	}
	for _, test := range cases {
		t.Run(test.id, func(t *testing.T) {
			var relocations []Relocation
			for _, api := range test.apis {
				relocations = append(relocations, Relocation{Function: "go", Symbol: api})
			}
			requireBehavior(t, inferBehaviorChains(relocations, test.strings), test.id)
			for _, chain := range inferBehaviorChains(relocations[:len(relocations)-1], test.strings) {
				if chain.ID == test.id {
					t.Fatalf("incomplete API evidence produced %s: %+v", test.id, chain)
				}
			}
		})
	}
	primitive := requireBehavior(t, inferBehaviorChains([]Relocation{{Function: "go", Symbol: "NETAPI32$NetUserModalsGet"}}, []String{{Value: "[local-account-policy-inventory]"}}), "local_account_policy_inventory")
	if primitive.Confidence != "confirmed primitive" {
		t.Fatalf("account policy primitive = %+v", primitive)
	}
}

func TestRuntimeAccessRulesRequireCompleteSameFunctionEvidence(t *testing.T) {
	cases := []struct {
		id, tag string
		apis    []string
	}{
		{"process_handle_duplicate", "[process-handle-duplicate]", []string{"KERNEL32$OpenProcess", "KERNEL32$DuplicateHandle"}},
		{"process_handle_close", "[process-handle-close]", []string{"KERNEL32$OpenProcess", "KERNEL32$DuplicateHandle"}},
		{"process_command_line_set", "[process-command-line-set]", []string{"NTDLL$NtQueryInformationProcess", "KERNEL32$ReadProcessMemory", "KERNEL32$WriteProcessMemory"}},
		{"process_command_line_restore", "[process-command-line-restore]", []string{"NTDLL$NtQueryInformationProcess", "KERNEL32$ReadProcessMemory", "KERNEL32$WriteProcessMemory"}},
		{"threadpool_wait_execute", "[threadpool-wait-execute]", []string{"KERNEL32$VirtualAlloc", "KERNEL32$VirtualProtect", "KERNEL32$CreateThreadpoolWait", "KERNEL32$SetThreadpoolWait", "KERNEL32$SetEvent"}},
		{"service_config_set", "[service-config-set]", []string{"ADVAPI32$OpenServiceW", "ADVAPI32$QueryServiceConfigW", "ADVAPI32$ChangeServiceConfigW"}},
		{"service_config_restore", "[service-config-restore]", []string{"ADVAPI32$OpenServiceW", "ADVAPI32$ChangeServiceConfigW"}},
	}
	for _, test := range cases {
		t.Run(test.id, func(t *testing.T) {
			var relocations []Relocation
			for _, api := range test.apis {
				relocations = append(relocations, Relocation{Function: "go", Symbol: api})
			}
			requireBehavior(t, inferBehaviorChains(relocations, []String{{Value: test.tag}}), test.id)
			for _, chain := range inferBehaviorChains(relocations[:len(relocations)-1], []String{{Value: test.tag}}) {
				if chain.ID == test.id {
					t.Fatalf("incomplete API evidence produced %s", test.id)
				}
			}
		})
	}
}

func TestAtomicOperationRulesRequireCompleteSameFunctionEvidence(t *testing.T) {
	cases := []struct {
		id, tag string
		apis    []string
	}{
		{"network_route_inventory", "[network-route-inventory]", []string{"IPHLPAPI$GetIpForwardTable2", "IPHLPAPI$FreeMibTable"}},
		{"process_memory_allocate", "[process-memory-allocate]", []string{"KERNEL32$OpenProcess", "KERNEL32$VirtualAllocEx"}},
		{"process_memory_free", "[process-memory-free]", []string{"KERNEL32$OpenProcess", "KERNEL32$VirtualFreeEx"}},
		{"process_thread_suspend", "[process-thread-suspend]", []string{"KERNEL32$OpenThread", "KERNEL32$SuspendThread"}},
		{"process_thread_resume", "[process-thread-resume]", []string{"KERNEL32$OpenThread", "KERNEL32$ResumeThread"}},
		{"thread_context_set", "[thread-context-set]", []string{"KERNEL32$OpenThread", "KERNEL32$GetThreadContext", "KERNEL32$SetThreadContext"}},
		{"thread_context_restore", "[thread-context-restore]", []string{"KERNEL32$CreateFileW", "KERNEL32$ReadFile", "KERNEL32$OpenThread", "KERNEL32$SetThreadContext"}},
		{"named_pipe_exchange", "[named-pipe-exchange]", []string{"KERNEL32$WaitNamedPipeW", "KERNEL32$CreateFileW", "KERNEL32$WriteFile", "KERNEL32$ReadFile"}},
	}
	for _, test := range cases {
		t.Run(test.id, func(t *testing.T) {
			var relocations []Relocation
			for _, api := range test.apis {
				relocations = append(relocations, Relocation{Function: "go", Symbol: api})
			}
			chain := requireBehavior(t, inferBehaviorChains(relocations, []String{{Value: test.tag}}), test.id)
			if chain.Confidence != "strong chain" || len(chain.Steps) != len(test.apis) {
				t.Fatalf("chain = %+v", chain)
			}
			for _, candidate := range inferBehaviorChains(relocations[:len(relocations)-1], []String{{Value: test.tag}}) {
				if candidate.ID == test.id {
					t.Fatalf("incomplete API sequence produced %s", test.id)
				}
			}
			split := append([]Relocation(nil), relocations...)
			split[len(split)-1].Function = "helper"
			for _, candidate := range inferBehaviorChains(split, []String{{Value: test.tag}}) {
				if candidate.ID == test.id {
					t.Fatalf("split API evidence produced %s", test.id)
				}
			}
		})
	}
	for _, primitive := range []struct {
		id, api, tag string
	}{{"network_adapter_inventory", "IPHLPAPI$GetAdaptersAddresses", "[network-adapter-inventory]"}, {"proxy_configuration_inventory", "WINHTTP$WinHttpGetIEProxyConfigForCurrentUser", "[proxy-configuration-inventory]"}} {
		chain := requireBehavior(t, inferBehaviorChains([]Relocation{{Function: "go", Symbol: primitive.api}}, []String{{Value: primitive.tag}}), primitive.id)
		if chain.Confidence != "confirmed primitive" {
			t.Fatalf("%s = %+v", primitive.id, chain)
		}
	}
}

func TestRemoteOperationRulesRequireCompleteFunctionLocalChains(t *testing.T) {
	cases := []struct {
		id      string
		apis    []string
		strings []String
	}{
		{"remote_host_information", []string{"NETAPI32$NetWkstaGetInfo", "NETAPI32$NetServerGetInfo"}, nil},
		{"remote_service_inventory", []string{"ADVAPI32$OpenSCManagerW", "ADVAPI32$EnumServicesStatusExW"}, nil},
		{"remote_registry_read", []string{"ADVAPI32$RegConnectRegistryW", "ADVAPI32$RegOpenKeyExW", "ADVAPI32$RegQueryValueExW"}, nil},
		{"remote_wmi_query", []string{"OLE32$CoCreateInstance", "OLE32$CoSetProxyBlanket", "OLEAUT32$SysAllocString"}, []String{{Value: "[remote-wmi-query]"}}},
		{"remote_file_stage", []string{"ADVAPI32$CryptCreateHash", "KERNEL32$CreateFileW", "KERNEL32$WriteFile"}, []String{{Value: "[remote-file-stage]"}}},
		{"remote_file_cleanup", []string{"KERNEL32$CreateFileW", "ADVAPI32$CryptCreateHash", "KERNEL32$DeleteFileW"}, []String{{Value: "[remote-file-remove]"}}},
		{"remote_task_execution", []string{"OLE32$CoCreateInstance", "OLEAUT32$SysAllocString"}, []String{{Value: "[remote-task-execute]"}}},
		{"remote_task_cleanup", []string{"OLE32$CoCreateInstance", "OLEAUT32$SysAllocString"}, []String{{Value: "[remote-task-cleanup]"}}},
	}
	for _, test := range cases {
		t.Run(test.id, func(t *testing.T) {
			var relocations []Relocation
			function := "go"
			if test.id == "remote_wmi_query" {
				function = "Wmi_Query"
			}
			for _, api := range test.apis {
				relocations = append(relocations, Relocation{Function: function, Symbol: api})
			}
			chain := requireBehavior(t, inferBehaviorChains(relocations, test.strings), test.id)
			if chain.Confidence != "strong chain" || len(chain.Steps) != len(test.apis) {
				t.Fatalf("chain = %+v", chain)
			}
			for _, candidate := range inferBehaviorChains(relocations[:len(relocations)-1], test.strings) {
				if candidate.ID == test.id {
					t.Fatalf("incomplete API sequence produced %s: %+v", test.id, candidate)
				}
			}
		})
	}
	primitive := requireBehavior(t, inferBehaviorChains([]Relocation{{Function: "go", Symbol: "NETAPI32$NetSessionEnum"}}, nil), "remote_session_inventory")
	if primitive.Confidence != "confirmed primitive" {
		t.Fatalf("session primitive = %+v", primitive)
	}
}

func TestIPCActivationRulesRequireFunctionLocalEvidence(t *testing.T) {
	chains := []struct {
		id   string
		apis []string
		tag  string
	}{
		{"com_running_object_inventory", []string{"OLE32$GetRunningObjectTable", "OLE32$CreateBindCtx"}, "[com-running-object-inventory]"},
		{"named_pipe_client_open", []string{"KERNEL32$WaitNamedPipeW", "KERNEL32$CreateFileW", "KERNEL32$DuplicateHandle"}, "[named-pipe-client-open]"},
		{"named_pipe_mode_set", []string{"KERNEL32$DuplicateHandle", "KERNEL32$SetNamedPipeHandleState"}, "[named-pipe-mode-set]"},
		{"named_pipe_transact", []string{"KERNEL32$DuplicateHandle", "KERNEL32$TransactNamedPipe"}, "[named-pipe-transact]"},
		{"alpc_client_open", []string{"NTDLL$NtAlpcConnectPort", "KERNEL32$DuplicateHandle"}, "[alpc-client-open]"},
		{"alpc_client_exchange", []string{"KERNEL32$DuplicateHandle", "NTDLL$NtAlpcSendWaitReceivePort"}, "[alpc-client-exchange]"},
		{"com_moniker_dispatch_invoke", []string{"OLE32$CreateBindCtx", "OLE32$MkParseDisplayName"}, "[com-moniker-dispatch-invoke]"},
	}
	for _, test := range chains {
		t.Run(test.id, func(t *testing.T) {
			relocations := make([]Relocation, 0, len(test.apis))
			for _, api := range test.apis {
				relocations = append(relocations, Relocation{Function: "go", Symbol: api})
			}
			requireBehavior(t, inferBehaviorChains(relocations, []String{{Value: test.tag}}), test.id)
			split := append([]Relocation(nil), relocations...)
			split[len(split)-1].Function = "helper"
			for _, candidate := range inferBehaviorChains(split, []String{{Value: test.tag}}) {
				if candidate.ID == test.id {
					t.Fatalf("split evidence produced %s", test.id)
				}
			}
		})
	}
	for _, primitive := range []struct {
		id, api, tag string
	}{
		{"com_class_detail_inventory", "OLE32$CLSIDFromProgID", "[com-class-detail-inventory]"},
		{"window_inventory", "USER32$EnumWindows", "[window-inventory]"},
		{"window_message_send", "USER32$SendMessageTimeoutW", "[window-message-send]"},
		{"window_message_post", "USER32$PostMessageW", "[window-message-post]"},
		{"window_copydata_send", "USER32$SendMessageTimeoutW", "[window-copydata-send]"},
		{"window_text_set", "USER32$SendMessageTimeoutW", "[window-text-set]"},
	} {
		chain := requireBehavior(t, inferBehaviorChains([]Relocation{{Function: "go", Symbol: primitive.api}}, []String{{Value: primitive.tag}}), primitive.id)
		if chain.Confidence != "confirmed primitive" {
			t.Fatalf("%s = %+v", primitive.id, chain)
		}
	}
}

func TestWMIClassificationDoesNotInventRemoteTarget(t *testing.T) {
	relocations := []Relocation{{Function: "Wmi_Query", Symbol: "OLE32$CoCreateInstance"}, {Function: "Wmi_Query", Symbol: "OLE32$CoSetProxyBlanket"}, {Function: "Wmi_Query", Symbol: "OLEAUT32$SysAllocString"}}
	chains := inferBehaviorChains(relocations, nil)
	requireBehavior(t, chains, "wmi_query")
	for _, chain := range chains {
		if chain.ID == "remote_wmi_query" {
			t.Fatalf("untagged WMI query classified as remote: %+v", chain)
		}
	}
}

func TestTrustedSecAuthenticationCorpusMatchesX64X86Golden(t *testing.T) {
	type expectedAnalysis struct {
		Loader       string   `json:"loader"`
		Capabilities []string `json:"capabilities"`
		Chains       []string `json:"chains"`
	}
	type goldenCase struct {
		Name string           `json:"name"`
		X64  expectedAnalysis `json:"x64"`
		X86  expectedAnalysis `json:"x86"`
	}
	data, err := os.ReadFile(filepath.Join("testdata", "auth_corpus_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	corpus := filepath.Join("..", "..", "arsenal", "trustedsec-sa-smoke", "SA")
	if _, err := os.Stat(corpus); os.IsNotExist(err) {
		t.Skip("local TrustedSec compatibility corpus is not installed")
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			for arch, expected := range map[string]expectedAnalysis{"x64": test.X64, "x86": test.X86} {
				analysis, err := Analyze(filepath.Join(corpus, test.Name, test.Name+"."+arch+".o"), "go")
				if err != nil {
					t.Fatal(err)
				}
				var capabilities, chains []string
				for _, capability := range analysis.Capabilities {
					capabilities = append(capabilities, capability.ID)
				}
				for _, chain := range analysis.BehaviorChains {
					chains = append(chains, chain.ID)
				}
				loader := ""
				if analysis.LoaderCompatibility != nil {
					loader = analysis.LoaderCompatibility.Status
				}
				if loader != expected.Loader || !slices.Equal(capabilities, expected.Capabilities) || !slices.Equal(chains, expected.Chains) {
					t.Fatalf("%s analysis loader=%s capabilities=%v chains=%v; expected %+v", arch, loader, capabilities, chains, expected)
				}
			}
		})
	}
}

func TestTrustedSecRemoteCorpusMatchesX64X86Golden(t *testing.T) {
	type expectedAnalysis struct {
		Loader       string   `json:"loader"`
		Capabilities []string `json:"capabilities"`
		Chains       []string `json:"chains"`
	}
	type goldenCase struct {
		Name string           `json:"name"`
		X64  expectedAnalysis `json:"x64"`
		X86  expectedAnalysis `json:"x86"`
	}
	data, err := os.ReadFile(filepath.Join("testdata", "remote_corpus_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	corpus := filepath.Join("..", "..", "arsenal", "trustedsec-sa", "SA")
	if _, err := os.Stat(corpus); os.IsNotExist(err) {
		t.Skip("local TrustedSec remote-operation corpus is not installed")
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			for arch, expected := range map[string]expectedAnalysis{"x64": test.X64, "x86": test.X86} {
				analysis, err := Analyze(filepath.Join(corpus, test.Name, test.Name+"."+arch+".o"), "go")
				if err != nil {
					t.Fatal(err)
				}
				var capabilities, chains []string
				for _, capability := range analysis.Capabilities {
					capabilities = append(capabilities, capability.ID)
				}
				for _, chain := range analysis.BehaviorChains {
					chains = append(chains, chain.ID)
				}
				loader := ""
				if analysis.LoaderCompatibility != nil {
					loader = analysis.LoaderCompatibility.Status
				}
				if loader != expected.Loader || !slices.Equal(capabilities, expected.Capabilities) || !slices.Equal(chains, expected.Chains) {
					t.Fatalf("%s analysis loader=%s capabilities=%v chains=%v; expected %+v", arch, loader, capabilities, chains, expected)
				}
			}
		})
	}
}

func TestAnalysisReadsSliverArgumentContract(t *testing.T) {
	root := t.TempDir()
	object := filepath.Join(root, "who.x64.o")
	if err := coff.CreateMockObject(object, "x64", "go", []string{"BeaconDataParse", "BeaconDataInt", "BeaconDataExtract"}); err != nil {
		t.Fatal(err)
	}
	manifest := `{"arguments":[{"name":"pid","type":"int","optional":false},{"name":"label","type":"string","optional":true}]}`
	if err := os.WriteFile(filepath.Join(root, "extension.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Arguments) != 2 || analysis.Arguments[0].Name != "pid" || !analysis.Arguments[0].Required || analysis.Arguments[1].Required {
		t.Fatalf("arguments = %+v", analysis.Arguments)
	}
}

func TestAnalysisReadsPackLockArgumentsForDistObject(t *testing.T) {
	root := t.TempDir()
	objectDir := filepath.Join(root, "dist")
	projectDir := filepath.Join(root, "bofs", "credential-proof")
	if err := os.MkdirAll(objectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(objectDir, "credential-proof.x64.o")
	if err := coff.CreateMockObject(object, "x64", "go", []string{"ADVAPI32$CredReadW"}); err != nil {
		t.Fatal(err)
	}
	lock := `{"schema":"bofbench.pack-lock","packs":[{"arguments":[{"name":"target_name","type":"wstring","required":true},{"name":"max_bytes","type":"int","required":true}]}]}`
	if err := os.WriteFile(filepath.Join(projectDir, "bofbench.lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := Analyze(object, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.Arguments) != 2 || analysis.Arguments[0].Name != "target_name" || analysis.Arguments[0].Source != "pack lock" || analysis.Arguments[1].Type != "int" {
		t.Fatalf("arguments = %+v", analysis.Arguments)
	}
}

func requireBehavior(t *testing.T, chains []BehaviorChain, id string) BehaviorChain {
	t.Helper()
	for _, chain := range chains {
		if chain.ID == id {
			return chain
		}
	}
	t.Fatalf("missing behavior %s: %+v", id, chains)
	return BehaviorChain{}
}
