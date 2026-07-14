package recipe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinsAreValidAndOperationallyExplicit(t *testing.T) {
	for _, document := range Builtins() {
		report := Validate("builtin", document, document.Features)
		if report.Status != "pass" || len(report.Errors) != 0 || len(report.Warnings) != 0 {
			t.Fatalf("builtin %s validation = %+v", document.Name, report)
		}
		for _, field := range [][]string{document.Prerequisites, document.StateChanges, document.Artifacts, document.Cleanup} {
			if len(field) == 0 {
				t.Fatalf("builtin %s has incomplete operational metadata", document.Name)
			}
		}
	}
}

func TestApplyComposesFeaturesAndStrictlyLoadsSidecar(t *testing.T) {
	dir := t.TempDir()
	source := `#include "beacon.h"
/* bofbench:feature-includes */
void go(char *args, int len) {(void)args;(void)len;
    /* bofbench:feature-calls */
}
`
	if err := os.WriteFile(filepath.Join(dir, "demo.c"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "beacon.h"), []byte("#pragma once\n#define CALLBACK_OUTPUT 0\nvoid BeaconPrintf(int, const char *, ...);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Apply(dir, "host-survey", false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Recipe.Name != "host-survey" || len(result.Features.Added) != 4 {
		t.Fatalf("apply result = %+v", result)
	}
	loaded, path, err := LoadFor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Name != "host-survey" || path != filepath.Join(dir, SidecarName) {
		t.Fatalf("loaded recipe = %+v path=%s", loaded, path)
	}
	if _, err := Apply(dir, "network-survey", false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("recipe overwrite error = %v", err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(original), "{", `{"unknown_field":true,`, 1)
	if err := os.WriteFile(path, []byte(unknown), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFor(dir); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
	if err := os.WriteFile(path, append(original, []byte("{}\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFor(dir); err == nil || !strings.Contains(err.Error(), "trailing JSON value") {
		t.Fatalf("trailing value error = %v", err)
	}
}

func TestValidationFindsMissingFeaturesAndUnsafeMetadata(t *testing.T) {
	document, _ := Builtin("full-survey")
	document.Impact = "modifies_state"
	document.Cleanup = []string{"none"}
	report := Validate("demo", document, []string{"process"})
	if report.Status != "fail" || len(report.MissingFeatures) != 5 || len(report.Errors) < 2 {
		t.Fatalf("validation = %+v", report)
	}
	text := ValidationText(report)
	for _, want := range []string{"missing required recipe features", "state-changing recipes require explicit cleanup"} {
		if !strings.Contains(text, want) {
			t.Fatalf("validation text missing %q:\n%s", want, text)
		}
	}
}

func TestPersistValidationWritesJSONAndMarkdown(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	document, _ := Builtin("network-survey")
	report, err := PersistValidation(Validate("demo", document, document.Features))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{report.EvidencePath, report.MarkdownPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}
