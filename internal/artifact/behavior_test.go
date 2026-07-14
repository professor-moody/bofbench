package artifact

import (
	"fmt"
	"os"
	"path/filepath"
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
