package lab

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTargetStateVersionOneRemainsReadable(t *testing.T) {
	data := []byte(`{"schema":"bofbench.target","schema_version":1,"service":"BOFBenchTarget","pid":42,"alertable_tid":7,"user":"NT AUTHORITY\\SYSTEM","canary_file":"C:\\bofbench\\target\\canary.txt","started_at":"2026-07-14T00:00:00Z"}`)
	var state TargetState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.SchemaVersion != 1 || state.PID != 42 || state.CanaryFile == "" || state.MemoryCanaryAddress != "" {
		t.Fatalf("state = %+v", state)
	}
}

func TestTargetReportTextIncludesCapabilityFixtures(t *testing.T) {
	report := TargetReport{
		Operation: "status", Status: "pass", Profile: "devbox", Host: "DEVBOX", Service: TargetServiceName,
		State: TargetState{
			PID: 42, AlertableTID: 7, NamedPipe: `\\.\pipe\BOFBenchTarget-42`, NamedPipeClientHandle: "0x22",
			ALPCPort: `\RPC Control\BOFBenchTargetALPC-42`, ALPCHandle: "0x33",
			WindowHandle: "0x44", WindowTextHandle: "0x45", WindowClass: "BOFBenchTargetWindow-42", WindowMessage: 32834, WindowPostMessage: 32835,
			CanaryFile: `C:\bofbench\target\canary.txt`, MemoryCanaryAddress: "0x12340000", MemoryCanarySize: 64, MemoryCanarySHA256: "abc",
		},
		Fixtures: TargetFixtureState{User: `LAB\operator`, CredentialTarget: "BOFBench-LiveProof", CredentialSize: 48, DPAPIUserPath: `C:\bofbench\target\fixtures\dpapi-user.bin`, DPAPIMachinePath: `C:\bofbench\target\fixtures\dpapi-machine.bin`, WMIMarkerPath: `C:\bofbench\target\fixtures\wmi-marker.txt`, RemoteComputerName: "DEVBOX", RemoteRegistryHive: "HKLM", RemoteRegistryPath: `Software\BOFBench`, RemoteRegistryName: "RemoteCanary", RemoteRegistrySHA256: "def", RemoteRegistrySize: 48, RemoteRegistryStatus: "Stopped", RemoteRegistryStart: "Disabled", RemoteStageShare: "C$", RemoteStageRelative: `bofbench\proof`, RemoteStageLocal: `C:\bofbench\proof`},
	}
	text := TargetReportText(report)
	for _, want := range []string{"computer    DEVBOX", `\\.\pipe\BOFBenchTarget-42`, `\RPC Control\BOFBenchTargetALPC-42`, "BOFBenchTargetWindow-42", "0x12340000", "BOFBench-LiveProof", "dpapi-user.bin", "wmi-marker.txt", `HKLM\Software\BOFBench\RemoteCanary`, `share=C$`, `previous=Stopped/Disabled`} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
}

func TestDecodeTargetJSONIgnoresTransportDecoration(t *testing.T) {
	var state TargetState
	data := []byte("\x1b[?25ltransport banner\r\n{\"schema\":\"bofbench.target\",\"schema_version\":9,\"pid\":4242}\r\n\x1b[?25h")
	if err := decodeTargetJSON(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.SchemaVersion != 9 || state.PID != 4242 {
		t.Fatalf("state = %+v", state)
	}
}
