package sourceaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeFeatureAwareBOFSource(t *testing.T) {
	dir := t.TempDir()
	source := `#include "beacon.h"
#include "bofbench_features.h"
void go(char *args, int len) {
    (void)args; (void)len;
    BeaconPrintf(0, "ok");
    KERNEL32$GetCurrentProcessId();
    WS2_32$gethostname(0, 0);
}
`
	header := `/* bofbench:feature process begin */
DWORD WINAPI KERNEL32$GetCurrentProcessId(void);
int WSAAPI WS2_32$gethostname(char *, int);
/* bofbench:feature process end */
`
	writeTestFile(t, filepath.Join(dir, "demo.c"), source)
	writeTestFile(t, filepath.Join(dir, "bofbench_features.h"), header)
	report, err := Analyze(dir, Options{Entrypoint: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "pass" || report.Summary.Entrypoints != 1 || report.Summary.BeaconAPIs != 1 || report.Summary.DynamicImports != 2 || report.Summary.Features != 1 || report.Summary.Errors != 0 || report.Summary.Warnings != 0 {
		t.Fatalf("report summary = %+v findings=%+v", report.Summary, report.Findings)
	}
	if report.Summary.Review != 2 {
		t.Fatalf("review findings = %+v", report.Findings)
	}
	persisted, err := AnalyzeAndPersist(dir, Options{Entrypoint: "go"})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{persisted.JSONPath, persisted.MDPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnalyzeReportsActionableBOFPitfalls(t *testing.T) {
	dir := t.TempDir()
	source := `#include <windows.h>
#pragma comment(lib, "kernel32.lib")
int main(void) {
    printf("pid=%lu", GetCurrentProcessId());
    BeaconUseToken(0);
    return 0;
}
`
	writeTestFile(t, filepath.Join(dir, "bad.c"), source)
	report, err := Analyze(dir, Options{Entrypoint: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "fail" || report.Summary.Errors != 2 || report.Summary.Warnings < 4 {
		t.Fatalf("report summary = %+v findings=%+v", report.Summary, report.Findings)
	}
	text := Text(report)
	for _, want := range []string{"missing_entrypoint", "unsupported_beacon_api", "implicit_winapi_import", "crt_dependency", "linker_dependency", "fix:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text missing %q:\n%s", want, text)
		}
	}
}

func TestSanitizeCIgnoresCommentsAndStringCalls(t *testing.T) {
	source := "// GetCurrentProcessId()\nvoid go(char *args, int len) { /* printf() */ const char *s = \"BeaconFormatPrintf()\"; (void)s; (void)args; (void)len; }\n"
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "clean.c"), source)
	report, err := Analyze(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "pass" || len(report.Findings) != 0 {
		t.Fatalf("comment/string produced findings: %+v", report.Findings)
	}
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
