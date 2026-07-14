package app

import "testing"

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
