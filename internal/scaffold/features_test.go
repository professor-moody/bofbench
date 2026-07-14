package scaffold

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddFeaturesCreatesComposableHeaderAndCalls(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "demo.c")
	source := `#include "beacon.h"

void go(char *args, int len) {
    (void)args;
    (void)len;
}
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := AddFeatures(dir, []string{"process", "host"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Added, ",") != "process,host" {
		t.Fatalf("added = %v", result.Added)
	}
	body, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`#include "bofbench_features.h"`, "bofbench_feature_process();", "bofbench_feature_host();", includeMarker, callMarker} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("source missing %q:\n%s", want, body)
		}
	}
	header, err := os.ReadFile(result.Header)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"KERNEL32$GetCurrentProcessId", "KERNEL32$GetComputerNameA"} {
		if !strings.Contains(string(header), want) {
			t.Fatalf("header missing %q:\n%s", want, header)
		}
	}
}

func TestAddFeaturesIsIdempotentAndRejectsUnknownFeature(t *testing.T) {
	dir := t.TempDir()
	source := `#include "beacon.h"
` + includeMarker + `
void go(char *args, int len) {
    (void)args;
    (void)len;
` + callMarker + `
}
`
	if err := os.WriteFile(filepath.Join(dir, "demo.c"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AddFeatures(dir, []string{"registry"}); err != nil {
		t.Fatal(err)
	}
	result, err := AddFeatures(dir, []string{"registry"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Added) != 0 || len(result.Existing) != 1 || result.Existing[0] != "registry" {
		t.Fatalf("second add = %+v", result)
	}
	if _, err := AddFeatures(dir, []string{"not-real"}); err == nil || !strings.Contains(err.Error(), "unknown feature") {
		t.Fatalf("unknown feature error = %v", err)
	}
}

func TestDeepFeaturePackComposesEveryTechnique(t *testing.T) {
	dir := t.TempDir()
	source := `#include "beacon.h"
` + includeMarker + `
void go(char *args, int len) {
    (void)args;
    (void)len;
` + callMarker + `
}
`
	if err := os.WriteFile(filepath.Join(dir, "demo.c"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := AddFeaturePack(dir, "deep-discovery")
	if err != nil {
		t.Fatal(err)
	}
	pack, ok := FeaturePackByName("deep-discovery")
	if !ok || len(pack.Features) != 11 || len(result.Added) != len(pack.Features) {
		t.Fatalf("pack=%+v result=%+v", pack, result)
	}
	header, err := os.ReadFile(result.Header)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CreateToolhelp32Snapshot", "GetTokenInformation", "EnumServicesStatusExA", "GetExtendedTcpTable", "NetGetJoinInformation"} {
		if !strings.Contains(string(header), want) {
			t.Fatalf("deep header missing %q:\n%s", want, header)
		}
	}
	for _, want := range []string{"DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot", "DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetGetJoinInformation"} {
		if !strings.Contains(string(header), want) {
			t.Fatalf("deep header missing loader-compatible import %q:\n%s", want, header)
		}
	}
	if _, err := AddFeaturePack(dir, "not-real"); err == nil || !strings.Contains(err.Error(), "unknown feature pack") {
		t.Fatalf("unknown pack error = %v", err)
	}
}

func TestOffensivePackIsStateChangingAndHasCleanup(t *testing.T) {
	pack, ok := FeaturePackByName("offensive-lab")
	if !ok || pack.Impact != "modifies_state" || len(pack.Features) != 15 {
		t.Fatalf("offensive pack = %+v", pack)
	}
	for _, want := range []string{"lab-file-write", "lab-registry-write", "lab-run-key", "lab-process-launch"} {
		if !containsFeature(pack.Features, want) {
			t.Fatalf("offensive pack missing %s: %+v", want, pack)
		}
	}
	cleanup, ok := FeaturePackByName("active-cleanup")
	if !ok || cleanup.Impact != "modifies_state" || strings.Join(cleanup.Features, ",") != "lab-cleanup" {
		t.Fatalf("cleanup pack = %+v", cleanup)
	}
}

func containsFeature(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
