package lab

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLabConfigRoundTripAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lab.json")
	config := DefaultConfig("existing")
	config.Host = "winlab.test"
	if err := SaveConfig(path, config); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Host != "winlab.test" || loaded.Provider != "existing" || loaded.Transport != "ssh" {
		t.Fatalf("loaded config = %+v", loaded)
	}
	if err := os.WriteFile(path, []byte(`{"schema":"bofbench.lab","schema_version":1,"provider":"existing","topology":"standalone","transport":"ssh","host":"x","remote_root":"x","executable":"x","updated_at":"x","secret":"no"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestExistingVMBootstrapDeploysCLIAndLoader(t *testing.T) {
	withRemoteTestWorkspace(t)
	files := t.TempDir()
	executable := filepath.Join(files, "bofbench.exe")
	loader := filepath.Join(files, "bofbench-loader.exe")
	loaderX86 := filepath.Join(files, "bofbench-loader-x86.exe")
	for _, path := range []string{executable, loader, loaderX86} {
		if err := os.WriteFile(path, []byte("fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	withFakeTransport(t, func(ctx context.Context, executable string, args ...string) ([]byte, []byte, error) {
		calls = append(calls, executable+" "+strings.Join(args, " "))
		if executable == "ssh" && len(args) > 1 && strings.Contains(args[1], "ConvertTo-Json") {
			return []byte(`{"compile":true,"compiler":"msvc","native_x64":true,"native_x86":true,"sliver":true,"debugging":true,"snapshot_support":false}`), nil, nil
		}
		return nil, nil, nil
	})
	config := DefaultConfig("existing")
	config.Host = "lab.test"
	report, err := Bootstrap(context.Background(), BootstrapOptions{Config: config, Executable: executable, LoaderX64: loader, LoaderX86: loaderX86, Repository: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "pass" || !report.Capabilities.Compile || !report.Capabilities.NativeX64 || len(report.Files) != 3 {
		t.Fatalf("bootstrap report = %+v", report)
	}
	joined := strings.Join(calls, "\n")
	for _, want := range []string{"ssh lab.test", "scp " + executable, "scp " + loader, "scp " + loaderX86} {
		if !strings.Contains(joined, want) {
			t.Fatalf("bootstrap calls missing %q:\n%s", want, joined)
		}
	}
}
