package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	packsvc "bofbench/internal/pack"
)

func TestResolveNamedPackArgumentsPreservesContractOrder(t *testing.T) {
	project := t.TempDir()
	lock := packsvc.Lock{Schema: packsvc.LockSchema, SchemaVersion: packsvc.LockSchemaVersion, Packs: []packsvc.LockRecord{{
		ID: "operator", Qualified: "internal/operator", Catalog: "internal", Version: "1", SHA256: "sha",
		Arguments: []packsvc.Argument{{Name: "target_pid", Type: "int", Required: true}, {Name: "command", Type: "wstring", Required: true}, {Name: "limit", Type: "short", Default: "25"}},
	}}}
	data, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, packsvc.LockName), data, 0o644); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveRunArguments(project, []string{"command=whoami /all", "target_pid=1234"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"i:1234", "Z:whoami /all", "s:25"}
	if !reflect.DeepEqual(resolved.Tokens, want) || !reflect.DeepEqual(resolved.CLIValues, []string{"1234", "whoami /all", "25"}) {
		t.Fatalf("resolved = %+v want tokens=%v", resolved, want)
	}
	if _, err := resolveRunArguments(project, []string{"command=whoami"}, nil); err == nil || !strings.Contains(err.Error(), "target_pid") {
		t.Fatalf("missing required argument error = %v", err)
	}
}

func TestPackFileArgumentReadsBytesForNativeAndKeepsPathForC2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, []byte{0xde, 0xad, 0xbe, 0xef}, 0o600); err != nil {
		t.Fatal(err)
	}
	token, cli, err := packArgumentToken("file", path)
	if err != nil {
		t.Fatal(err)
	}
	if token != "x:deadbeef" || cli != path {
		t.Fatalf("token=%q cli=%q", token, cli)
	}
}

func TestCobaltAutomationUsesTypedArgumentsWithoutCredentials(t *testing.T) {
	script, types, err := cobaltAutomationScript("beacon-1", `C:\work\demo.o`, "go", []string{"z:hello", "i:7"}, []string{"hello", "7"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bof_pack", `"zi"`, "beacon_inline_execute", "BOFBENCH_TASK_SUBMITTED", "closeClient"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	if !reflect.DeepEqual(types, []string{"z", "i"}) {
		t.Fatalf("types = %v", types)
	}
}
