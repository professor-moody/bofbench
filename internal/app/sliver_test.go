package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSliverExtensionCommandLineUsesNamedFlags(t *testing.T) {
	extension := sliverExtension{CommandName: "survey"}
	extension.Arguments = append(extension.Arguments,
		struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Optional bool   `json:"optional"`
		}{Name: "process_filter", Type: "string", Optional: true},
		struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Optional bool   `json:"optional"`
		}{Name: "result_limit", Type: "int", Optional: true},
	)

	got, err := sliverExtensionCommandLine("survey", extension, []string{"lsass", "5"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `survey -- --process_filter lsass --result_limit 5`; got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
}

func TestSliverExtensionCommandLineQuotesValues(t *testing.T) {
	extension := sliverExtension{}
	extension.Arguments = append(extension.Arguments, struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Optional bool   `json:"optional"`
	}{Name: "command", Type: "string"})

	got, err := sliverExtensionCommandLine("run_bof", extension, []string{`whoami /all`})
	if err != nil {
		t.Fatal(err)
	}
	if want := `run_bof -- --command "whoami /all"`; got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
}

func TestSliverExtensionCommandLineQuotesWindowsPaths(t *testing.T) {
	extension := sliverExtension{}
	extension.Arguments = append(extension.Arguments, struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Optional bool   `json:"optional"`
	}{Name: "blob_path", Type: "wstring"})
	got, err := sliverExtensionCommandLine("dpapi", extension, []string{`C:\bofbench\fixture.bin`})
	if err != nil {
		t.Fatal(err)
	}
	if want := `dpapi -- --blob_path "C:\\bofbench\\fixture.bin"`; got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
}

func TestConciseSliverLinesAcceptsAnyStructuredPackOutput(t *testing.T) {
	output := "[*] Successfully executed\n[credential-list] target=BOFBench-LiveProof secret_bytes=48\n[wmi-query] property=Name value=DEVBOX\n"
	lines := conciseSliverLines(output, "ignored")
	if len(lines) != 2 || lines[0] != "[credential-list] target=BOFBench-LiveProof secret_bytes=48" || lines[1] != "[wmi-query] property=Name value=DEVBOX" {
		t.Fatalf("lines = %#v", lines)
	}
}

func TestDiscoverSliverConfigsPrefersExplicitConfig(t *testing.T) {
	home := t.TempDir()
	configs := filepath.Join(home, "configs")
	if err := os.MkdirAll(configs, 0o700); err != nil {
		t.Fatal(err)
	}
	discovered := filepath.Join(configs, "automatic.cfg")
	explicit := filepath.Join(t.TempDir(), "operator.cfg")
	for _, path := range []string{discovered, explicit} {
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SLIVER_CLIENT_HOME", home)
	t.Setenv("BOFBENCH_SLIVER_CONFIG", explicit)

	got := discoverSliverConfigs()
	if len(got) != 2 || got[0] != explicit || got[1] != discovered {
		t.Fatalf("configs = %#v, want explicit config first", got)
	}
}
