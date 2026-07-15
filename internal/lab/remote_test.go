package lab

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimesvc "bofbench/internal/runtime"
)

func TestRemoteEvidenceRedactsSensitiveFieldsAndEventMessages(t *testing.T) {
	report := RemoteRunReport{Arguments: []string{"Z:fixture-password"}, RemoteDev: &RemoteDevReport{Run: &runtimesvc.Result{
		Output: []string{"[vault-read-data] hex=736563726574"},
		Events: []runtimesvc.Event{{Type: "beacon_output", Message: "[vault-read-data] hex=736563726574"}},
	}}}
	persisted := redactRemoteRunReport(report, RemoteRunOptions{SensitiveArguments: []bool{true}, SensitiveOutputFields: []string{"hex"}, SensitiveValues: []string{"fixture-password"}})
	if persisted.Arguments[0] != "Z:<redacted>" || persisted.RemoteDev.Run.Output[0] != "[vault-read-data] hex=<redacted>" || persisted.RemoteDev.Run.Events[0].Message != "[vault-read-data] hex=<redacted>" {
		t.Fatalf("persisted report was not fully redacted: %+v", persisted)
	}
}

func TestRemoteCompilerProbeIsArchitectureSpecific(t *testing.T) {
	if script := remoteCompilerProbeScript("x86"); !strings.Contains(script, "i686-w64-mingw32-gcc") || strings.Contains(script, "cl.exe") {
		t.Fatalf("x86 compiler probe = %q", script)
	}
	if script := remoteCompilerProbeScript("x64"); !strings.Contains(script, "cl.exe") || !strings.Contains(script, "x86_64-w64-mingw32-gcc") {
		t.Fatalf("x64 compiler probe = %q", script)
	}
}

func TestRemoteStatusPersistsDoctorAndLoaderState(t *testing.T) {
	withRemoteTestWorkspace(t)
	withFakeTransport(t, func(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
		if executable != "ssh-test" || len(args) < 2 || args[0] != "lab.test" {
			return nil, nil, fmt.Errorf("unexpected transport: %s %v", executable, args)
		}
		payload := `{"computer_name":"WINDOWS-LAB","powershell":"7.5.2","loader_ready":true,"loader_x86_ready":true,"version":{"tool":{"version":"dev"}},"doctor":{"checks":[{"name":"runtime","status":"pass"},{"name":"docs","status":"warn"}]}}`
		return []byte(payload), nil, nil
	})
	opts := testRemoteOptions()
	report, err := RemoteStatus(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "pass" || report.ComputerName != "WINDOWS-LAB" || !report.LoaderReady || report.Schema != "bofbench.lab-remote-status" {
		t.Fatalf("status report = %+v", report)
	}
	if _, err := os.Stat(report.EvidencePath); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteSyncUsesManagedProjectPathAndFingerprintsSource(t *testing.T) {
	withRemoteTestWorkspace(t)
	project := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "demo.c"), []byte("void go(char *a, int l) {(void)a;(void)l;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls []string
	withFakeTransport(t, func(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
		calls = append(calls, executable+" "+strings.Join(args, " "))
		return nil, nil, nil
	})
	report, err := RemoteSync(context.Background(), project, testRemoteOptions())
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "pass" || report.SourceTree.Files != 1 || report.RemoteProject != `C:\bofbench\work\projects\demo` || len(report.TransportEvents) != 3 {
		t.Fatalf("sync report = %+v", report)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"ssh-test lab.test", "scp-test -r", `work\projects\demo`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("transport missing %q:\n%s", want, joined)
		}
	}
}

func TestRemoteRunCollectsCompleteDevEvidence(t *testing.T) {
	withRemoteTestWorkspace(t)
	project := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "demo.c"), []byte("void go(char *a, int l) {(void)a;(void)l;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withFakeTransport(t, fakeRemoteRunTransport)
	report, err := RemoteRun(context.Background(), project, RemoteRunOptions{RemoteOptions: testRemoteOptions(), Compiler: "msvc", Runtime: "windows-coff"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "pass" || report.RemoteDev == nil || report.RemoteDev.RuntimeState != "pass" || len(report.Collected) != 9 {
		t.Fatalf("run report = %+v", report)
	}
	for _, file := range report.Collected {
		if file.SHA256 == "" || file.Size == 0 {
			t.Fatalf("collected file missing fingerprint: %+v", file)
		}
	}
	for _, path := range []string{report.EvidencePath, report.MarkdownPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRemoteRunIsolatesNamedProfileAndRunWorkspace(t *testing.T) {
	withRemoteTestWorkspace(t)
	project := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "demo.c"), []byte("void go(char *a, int l) {(void)a;(void)l;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := testRemoteOptions()
	opts.ProfileName = "dedicated"
	var calls []string
	withFakeTransport(t, func(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
		calls = append(calls, executable+" "+strings.Join(args, " "))
		return fakeRemoteRunTransport(ctx, executable, args...)
	})
	report, err := RemoteRun(context.Background(), project, RemoteRunOptions{RemoteOptions: opts, Compiler: "msvc", Runtime: "windows-coff"})
	if err != nil {
		t.Fatal(err)
	}
	profileRun := `C:\bofbench\runs\dedicated\` + report.RunID
	if report.RemoteRunPath != profileRun {
		t.Fatalf("remote run path = %q, want %q", report.RemoteRunPath, profileRun)
	}
	projectPrefix := `C:\bofbench\work\projects\dedicated\` + report.RunID + `\`
	if !strings.HasPrefix(report.RemoteProject, projectPrefix) {
		t.Fatalf("remote project = %q, want prefix %q", report.RemoteProject, projectPrefix)
	}
	if report.Receipt == nil || report.Receipt.Profile != "dedicated" {
		t.Fatalf("receipt = %+v", report.Receipt)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"BOFBENCH_LOADER", `runs\dedicated\` + report.RunID} {
		if !strings.Contains(joined, want) {
			t.Fatalf("remote execution missing %q:\n%s", want, joined)
		}
	}
}

func TestRemoteCollectAndResetAreScoped(t *testing.T) {
	withRemoteTestWorkspace(t)
	withFakeTransport(t, fakeRemoteRunTransport)
	collected, err := RemoteCollect(context.Background(), "20260710-120000-dev-demo", testRemoteOptions())
	if err != nil {
		t.Fatal(err)
	}
	if collected.Status != "pass" || collected.Fingerprint.Files != 1 {
		t.Fatalf("collect report = %+v", collected)
	}
	reset, err := RemoteReset(context.Background(), "artifacts", testRemoteOptions())
	if err != nil {
		t.Fatal(err)
	}
	if reset.Status != "pass" || len(reset.Removed) != 4 {
		t.Fatalf("reset report = %+v", reset)
	}
	if _, err := RemoteReset(context.Background(), "everything", testRemoteOptions()); err == nil {
		t.Fatal("invalid reset scope unexpectedly passed")
	}
	if _, err := RemoteCollect(context.Background(), "../escape", testRemoteOptions()); err == nil {
		t.Fatal("unsafe run id unexpectedly passed")
	}
}

func TestRemoteSyncRejectsSymlinkAndDerivesExecutableFromRoot(t *testing.T) {
	withRemoteTestWorkspace(t)
	project := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(project, "real.c")
	if err := os.WriteFile(target, []byte("void go(void) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(project, "linked.c")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := RemoteSync(context.Background(), project, testRemoteOptions()); err == nil || !strings.Contains(err.Error(), "rejects symlink") {
		t.Fatalf("symlink sync error = %v", err)
	}
	normalized, err := normalizeRemoteOptions(RemoteOptions{Host: "lab.test", RemoteRoot: `D:\lab`, SSH: "ssh", SCP: "scp"})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Executable != `D:\lab\work\bin\bofbench.exe` {
		t.Fatalf("derived executable = %q", normalized.Executable)
	}
}

func fakeRemoteRunTransport(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
	if executable == "ssh-test" {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "'dev'") {
			payload := `{
  "schema":"bofbench.dev","schema_version":1,"run_id":"20260710-120000-dev-demo","status":"pass",
  "evidence_path":"runs\\20260710-120000-dev-demo\\dev.json","markdown_path":"runs\\20260710-120000-dev-demo\\dev.md",
  "source_json_path":"runs\\20260710-120001-source-demo\\source.json","source_md_path":"runs\\20260710-120001-source-demo\\source.md",
  "analysis_json_path":"runs\\20260710-120002-analysis-demo\\analysis.json","analysis_md_path":"runs\\20260710-120002-analysis-demo\\analysis.md",
  "build":{"object":"dist\\demo.x64.o","evidence_path":"runs\\20260710-115959-build-demo\\build.json","log_path":"runs\\20260710-115959-build-demo\\build.log"},
  "runtime_state":"pass"
}`
			return []byte(payload), nil, nil
		}
		return nil, nil, nil
	}
	if executable != "scp-test" {
		return nil, nil, fmt.Errorf("unexpected executable %s", executable)
	}
	if len(args) == 2 && strings.HasPrefix(args[0], "lab.test:") {
		if err := os.MkdirAll(filepath.Dir(args[1]), 0o755); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(args[1], []byte("remote evidence\n"), 0o644); err != nil {
			return nil, nil, err
		}
	}
	if len(args) == 3 && args[0] == "-r" && strings.HasPrefix(args[1], "lab.test:") {
		if err := os.MkdirAll(args[2], 0o755); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(filepath.Join(args[2], "result.json"), []byte("{}\n"), 0o644); err != nil {
			return nil, nil, err
		}
	}
	return nil, nil, nil
}

func testRemoteOptions() RemoteOptions {
	return RemoteOptions{Host: "lab.test", RemoteRoot: `C:\bofbench`, Executable: `C:\bofbench\work\bin\bofbench.exe`, SSH: "ssh-test", SCP: "scp-test"}
}

func withFakeTransport(t *testing.T, fake transportFunc) {
	t.Helper()
	previous := executeRemoteTransport
	executeRemoteTransport = fake
	t.Cleanup(func() { executeRemoteTransport = previous })
}

func withRemoteTestWorkspace(t *testing.T) {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
}
