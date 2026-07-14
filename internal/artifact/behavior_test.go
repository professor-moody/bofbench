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
