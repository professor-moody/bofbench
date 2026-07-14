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
		State:    TargetState{PID: 42, AlertableTID: 7, CanaryFile: `C:\bofbench\target\canary.txt`, MemoryCanaryAddress: "0x12340000", MemoryCanarySize: 64, MemoryCanarySHA256: "abc"},
		Fixtures: TargetFixtureState{User: `LAB\operator`, CredentialTarget: "BOFBench-LiveProof", CredentialSize: 48, DPAPIUserPath: `C:\bofbench\target\fixtures\dpapi-user.bin`, DPAPIMachinePath: `C:\bofbench\target\fixtures\dpapi-machine.bin`, WMIMarkerPath: `C:\bofbench\target\fixtures\wmi-marker.txt`},
	}
	text := TargetReportText(report)
	for _, want := range []string{"0x12340000", "BOFBench-LiveProof", "dpapi-user.bin", "wmi-marker.txt"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
}
