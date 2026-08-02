package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	packsvc "github.com/professor-moody/bofbench/internal/pack"
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

func TestResolveNamedPackArgumentsPadsOptionalPositionalGaps(t *testing.T) {
	project := t.TempDir()
	lock := packsvc.Lock{Schema: packsvc.LockSchema, SchemaVersion: packsvc.LockSchemaVersion, Packs: []packsvc.LockRecord{{
		ID: "remote", Qualified: "internal/remote", Catalog: "internal", Version: "1", SHA256: "sha",
		Arguments: []packsvc.Argument{
			{Name: "auth_mode", Type: "string", Default: "current"},
			{Name: "domain", Type: "wstring"},
			{Name: "username", Type: "wstring", Sensitive: true},
			{Name: "password", Type: "wstring", Sensitive: true},
			{Name: "target_host", Type: "wstring", Required: true},
			{Name: "limit", Type: "integer"},
		},
	}}}
	data, _ := json.Marshal(lock)
	if err := os.WriteFile(filepath.Join(project, packsvc.LockName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveRunArguments(project, []string{"target_host=DEVBOX"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"z:current", "Z:", "Z:", "Z:", "Z:DEVBOX"}
	if !reflect.DeepEqual(resolved.Tokens, want) {
		t.Fatalf("tokens = %v want %v", resolved.Tokens, want)
	}
	if len(resolved.Sensitive) != len(want) || !resolved.Sensitive[2] || !resolved.Sensitive[3] {
		t.Fatalf("sensitive metadata = %v", resolved.Sensitive)
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
	token, cli, err = packArgumentToken("file", "@file:"+path)
	if err != nil || token != "x:deadbeef" || cli != path {
		t.Fatalf("@file token=%q cli=%q err=%v", token, cli, err)
	}
}

func TestSensitiveFileArgumentKeepsPathWhileRedactingReceiptMetadata(t *testing.T) {
	project := t.TempDir()
	lock := packsvc.Lock{Schema: packsvc.LockSchema, SchemaVersion: packsvc.LockSchemaVersion, Packs: []packsvc.LockRecord{{
		ID: "mapper", Qualified: "internal/mapper", Catalog: "internal", Version: "1", SHA256: "sha",
		Arguments: []packsvc.Argument{{Name: "payload", Type: "file", Required: true, Sensitive: true}},
	}}}
	data, _ := json.Marshal(lock)
	if err := os.WriteFile(filepath.Join(project, packsvc.LockName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "payload.bin")
	if err := os.WriteFile(path, []byte{0xc3}, 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveRunArguments(project, []string{"payload=@file:" + path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Tokens[0] != "x:c3" || resolved.CLIValues[0] != path || !resolved.Sensitive[0] {
		t.Fatalf("resolved sensitive file = %+v", resolved)
	}
}

func TestSensitivePackArgumentsResolveEnvironmentAndFileWithoutLosingMetadata(t *testing.T) {
	project := t.TempDir()
	lock := packsvc.Lock{Schema: packsvc.LockSchema, SchemaVersion: packsvc.LockSchemaVersion, Packs: []packsvc.LockRecord{{
		ID: "pfx", Qualified: "internal/pfx", Catalog: "internal", Version: "1", SHA256: "sha",
		Arguments: []packsvc.Argument{{Name: "password", Type: "wstring", Required: true, Sensitive: true}},
	}}}
	data, _ := json.Marshal(lock)
	if err := os.WriteFile(filepath.Join(project, packsvc.LockName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOFBENCH_TEST_SECRET", "environment-secret")
	resolved, err := resolveRunArguments(project, []string{"password=@env:BOFBENCH_TEST_SECRET"}, nil)
	if err != nil || !reflect.DeepEqual(resolved.CLIValues, []string{"environment-secret"}) || !reflect.DeepEqual(resolved.Sensitive, []bool{true}) {
		t.Fatalf("environment resolution = %+v err=%v", resolved, err)
	}
	secretPath := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secretPath, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err = resolveRunArguments(project, []string{"password=@file:" + secretPath}, nil)
	if err != nil || resolved.CLIValues[0] != "file-secret" || resolved.Tokens[0] != "Z:file-secret" {
		t.Fatalf("file resolution = %+v err=%v", resolved, err)
	}
}

func TestCredentialProjectsSelectInteractiveLabContext(t *testing.T) {
	project := t.TempDir()
	lock := packsvc.Lock{Schema: packsvc.LockSchema, SchemaVersion: packsvc.LockSchemaVersion, Packs: []packsvc.LockRecord{{ID: "credential-read", Qualified: "internal/credential-read"}}}
	data, _ := json.Marshal(lock)
	if err := os.WriteFile(filepath.Join(project, packsvc.LockName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if !requiresInteractiveLabSession(project) {
		t.Fatal("credential project did not select the interactive Windows session")
	}
}

func TestCobaltAutomationUsesTypedArgumentsWithoutCredentials(t *testing.T) {
	script, types, err := cobaltAutomationScript("beacon-1", `C:\work\demo.o`, "go", []string{"z:hello", "i:7"}, []string{"hello", "7"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bof_pack", `"zi"`, "beacon_inline_execute", "BOFBENCH_TASK_SUBMITTED", "task_completed", "BOFBENCH_CALLBACK_TIMEOUT", "closeClient"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	if !reflect.DeepEqual(types, []string{"z", "i"}) {
		t.Fatalf("types = %v", types)
	}
}

func TestParseCobaltCallbacksTracksChunksAndTerminalStates(t *testing.T) {
	tests := []struct {
		name      string
		lines     []string
		state     string
		task      string
		chunks    int
		final     bool
		remoteErr string
	}{
		{
			name: "completed",
			lines: []string{
				"BOFBENCH_CALLBACK type=output chunk=0 final=0 task=task-1",
				"[window-message-send] status=complete",
				"BOFBENCH_CALLBACK type=task_completed chunk=1 final=1 task=task-1",
			},
			state: "completed", task: "task-1", chunks: 2, final: true,
		},
		{
			name: "failed",
			lines: []string{
				"BOFBENCH_CALLBACK type=error chunk=0 final=1 task=task-2",
				"remote BOF error",
			},
			state: "failed", task: "task-2", chunks: 1, final: true, remoteErr: "remote BOF error",
		},
		{name: "running", lines: []string{"BOFBENCH_CALLBACK type=output chunk=0 final=0 task=task-3"}, state: "submitted", task: "task-3", chunks: 1},
		{name: "timeout", lines: []string{cobaltTimeoutMarker}, state: "timeout"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, chunks, task, remoteErr := parseCobaltCallbacks(test.lines)
			if state != test.state || task != test.task || len(chunks) != test.chunks || remoteErr != test.remoteErr {
				t.Fatalf("state=%q task=%q chunks=%+v error=%q", state, task, chunks, remoteErr)
			}
			if test.chunks > 0 && chunks[len(chunks)-1].Final != test.final {
				t.Fatalf("final chunk = %+v", chunks[len(chunks)-1])
			}
		})
	}
}
