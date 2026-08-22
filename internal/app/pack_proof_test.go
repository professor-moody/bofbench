package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/professor-moody/bofbench/internal/lab"
	packsvc "github.com/professor-moody/bofbench/internal/pack"
)

func TestResolveProofArgumentsSupportsEmbeddedPlaceholders(t *testing.T) {
	target := lab.TargetReport{
		Host:     "bofbench-winvm",
		State:    lab.TargetState{PID: 42, AlertableTID: 84, MemoryCanaryAddress: "0x1234", MemoryCanarySize: 64, CanaryFile: `C:\bofbench\target\canary.txt`},
		Fixtures: lab.TargetFixtureState{DPAPIUserPath: `C:\bofbench\target\fixtures\user.bin`, DPAPIMachinePath: `C:\bofbench\target\fixtures\machine.bin`, RemoteComputerName: "DEVBOX", RemoteStageShare: "C$", RemoteStageRelative: `bofbench\proof`, RemoteStageLocal: `C:\bofbench\proof`, RemoteRegistryHive: "HKLM", RemoteRegistryPath: `Software\BOFBench`, RemoteRegistryName: "RemoteCanary", RemoteRegistrySHA256: "abc", RemoteRegistrySize: 48},
	}
	resolved, err := resolveProofArguments(map[string]string{"pid": "$TARGET_PID", "artifact": "BOFBench-$RUN_ID.cmd", "host": "$LAB_HOST", "remote": "$REMOTE_STAGE_RELATIVE", "task": "$REMOTE_TASK_NAME", "registry": "$REMOTE_REGISTRY_PATH"}, target, "run-123")
	if err != nil {
		t.Fatal(err)
	}
	if resolved["pid"] != "42" || resolved["artifact"] != "BOFBench-run-123.cmd" || resolved["host"] != "DEVBOX" || resolved["remote"] != `bofbench\proof\remote-stage-run-123.bin` || resolved["task"] != "BOFBench-Remote-run-123" || resolved["registry"] != `Software\BOFBench` {
		t.Fatalf("resolved = %#v", resolved)
	}
}

func TestReceiptOutputExpandsFullRuntimeEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lab-run.json")
	document := map[string]any{"schema": "bofbench.lab-run", "receipt": map[string]any{"schema": "bofbench.runtime-receipt", "object_sha256": "abc123", "output": []string{"[thread-inventory] status=complete shown=12"}}}
	data, _ := json.Marshal(document)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	output, receipt, sha := receiptOutputFromLines([]string{"reports " + path})
	if len(output) != 1 || receipt != path || sha != "abc123" {
		t.Fatalf("output=%v receipt=%q sha=%q", output, receipt, sha)
	}
}

func TestMatchesProofOutputRequiresTagAndFields(t *testing.T) {
	expect := packsvc.ProofExpectation{Tag: "process-tree", Fields: map[string]string{"status": "complete", "count": "*"}}
	if !matchesProofOutput([]string{"[process-tree] status=complete count=4 limit=25"}, expect) {
		t.Fatal("expected structured output match")
	}
	if matchesProofOutput([]string{"[other] status=complete count=4"}, expect) || matchesProofOutput([]string{"[process-tree] status=failed count=0"}, expect) {
		t.Fatal("unexpected structured output match")
	}
}

func TestResolveProofExpectationSupportsPlaceholders(t *testing.T) {
	input := packsvc.ProofExpectation{Tag: "remote-file-stage", Fields: map[string]string{"status": "complete", "sha256": "$PROOF_SECRET_SHA256"}}
	resolved, err := resolveProofExpectation(input, map[string]string{"$PROOF_SECRET_SHA256": "abc123"})
	if err != nil {
		t.Fatal(err)
	}
	if !matchesProofOutput([]string{"[remote-file-stage] status=complete sha256=abc123"}, resolved) {
		t.Fatalf("resolved = %+v", resolved)
	}
}

func TestProofPayloadVerifiesBeforeSensitiveOutputRedaction(t *testing.T) {
	payload := []byte("known-proof-secret")
	sum := sha256.Sum256(payload)
	lines := []string{"[secret-data] offset=0 hex=" + hex.EncodeToString(payload)}
	expectation := packsvc.ProofPayloadExpectation{Tag: "secret-data", Field: "hex", Encoding: "hex", SHA256: hex.EncodeToString(sum[:])}
	if err := verifyProofPayload(lines, expectation, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	redacted := redactRuntimeLines(lines, []string{"hex"}, nil)
	if !strings.Contains(redacted[0], "hex=<redacted>") || strings.Contains(redacted[0], hex.EncodeToString(payload)) {
		t.Fatalf("redacted output = %q", redacted[0])
	}
}

func TestProofCapturesAndTopologyDefaults(t *testing.T) {
	placeholders := map[string]string{}
	captures := map[string]packsvc.ProofCapture{"$SPAWNED_PID": {Tag: "spawn", Field: "pid"}}
	if err := applyProofCaptures([]string{"[spawn] status=complete pid=4242"}, captures, placeholders); err != nil {
		t.Fatal(err)
	}
	if placeholders["$SPAWNED_PID"] != "4242" {
		t.Fatalf("capture = %#v", placeholders)
	}
	document := packsvc.Document{Arguments: []packsvc.Argument{{Name: "target_host", TopologyValue: "target.computer_name"}, {Name: "domain", TopologyValue: "domain.name"}}}
	arguments := topologyProofArguments(document, map[string]string{"domain": "explicit.example"}, map[string]string{"target.computer_name": "TARGET", "domain.name": "LAB"})
	if arguments["target_host"] != "TARGET" || arguments["domain"] != "explicit.example" {
		t.Fatalf("topology arguments = %#v", arguments)
	}
}

func TestEventingProofStateChecksProduceIndependentProbes(t *testing.T) {
	tests := []struct {
		kind       string
		expect     string
		parameters map[string]string
		needle     string
	}{
		{"file_sha256", "matches", map[string]string{"path": `C:\bofbench\proof\event.bin`, "sha256": "abc"}, "Get-FileHash"},
		{"service_state", "matches", map[string]string{"name": "BOFBench-Async", "state": "Running"}, "Get-Service"},
		{"process_id", "absent", map[string]string{"pid": "4242"}, "Get-Process"},
		{"process_image_path", "absent", map[string]string{"path": `C:\bofbench\target\fixture.exe`}, "ExecutablePath"},
		{"etw_session", "absent", map[string]string{"name": "BOFBench-ETW"}, "logman.exe"},
		{"event_log_record", "matches", map[string]string{"channel": "Application", "message": "BOFBench-run"}, "Get-WinEvent"},
		{"active_loader_tasks", "absent", map[string]string{}, "bofbench-loader"},
	}
	for _, test := range tests {
		script, err := proofStateCheckScript(test.kind, test.expect, test.parameters)
		if err != nil {
			t.Fatalf("%s: %v", test.kind, err)
		}
		if !strings.Contains(script, test.needle) || !strings.Contains(script, "BOFBENCH_STATE_VERIFIED") {
			t.Fatalf("%s script does not contain %q: %s", test.kind, test.needle, script)
		}
	}
}

func TestMemoryProofStateChecksUseExplicitUIntPtrConstruction(t *testing.T) {
	tests := []struct {
		kind       string
		expect     string
		parameters map[string]string
	}{
		{"process_memory", "matches", map[string]string{"pid": "42", "address": "0x1000", "size": "18", "sha256": "abc"}},
		{"process_protection", "matches", map[string]string{"pid": "42", "address": "0x1000", "protection": "04"}},
		{"process_memory_region", "absent", map[string]string{"pid": "42", "address": "0x1000"}},
	}
	for _, test := range tests {
		script, err := proofStateCheckScript(test.kind, test.expect, test.parameters)
		if err != nil {
			t.Fatalf("%s: %v", test.kind, err)
		}
		if strings.Contains(script, "[UIntPtr]$size") || strings.Contains(script, "[UIntPtr]$bytes") {
			t.Fatalf("%s retains an unsupported direct Int32-to-UIntPtr cast: %s", test.kind, script)
		}
		if !strings.Contains(script, "[UIntPtr]::new([uint64]") {
			t.Fatalf("%s does not construct UIntPtr from uint64: %s", test.kind, script)
		}
	}
}

func TestProofStateChecksUsePowerShellFiveCompatibleHashing(t *testing.T) {
	tests := []struct {
		kind       string
		expect     string
		parameters map[string]string
	}{
		{"registry_value", "matches", map[string]string{"hive": "HKLM", "path": `Software\BOFBench`, "name": "Canary", "sha256": "abc", "type": "3"}},
		{"dpapi_file", "matches", map[string]string{"path": `C:\bofbench\proof\blob.bin`, "sha256": "abc"}},
		{"process_memory", "matches", map[string]string{"pid": "42", "address": "0x1000", "size": "18", "sha256": "abc"}},
		{"named_pipe_queue", "matches", map[string]string{"holder_pid": "42", "handle": "0x100", "sha256": "abc"}},
		{"section_payload", "matches", map[string]string{"name": `Global\BOFBench`, "offset": "0", "size": "18", "sha256": "abc"}},
	}
	for _, test := range tests {
		script, err := proofStateCheckScript(test.kind, test.expect, test.parameters)
		if err != nil {
			t.Fatalf("%s: %v", test.kind, err)
		}
		if strings.Contains(script, "SHA256]::HashData") || strings.Contains(script, "Convert]::ToHexString") {
			t.Fatalf("%s uses a hashing API unavailable in Windows PowerShell 5.1: %s", test.kind, script)
		}
		if !strings.Contains(script, "SHA256]::Create") || !strings.Contains(script, "BitConverter]::ToString") {
			t.Fatalf("%s does not use the compatible hashing path: %s", test.kind, script)
		}
	}
}
