package capability

import "testing"

func TestAssessWindowsCOFFSupported(t *testing.T) {
	result := AssessWindowsCOFF(COFFInput{
		Arch:         "x64",
		Entrypoint:   "go",
		EntrypointOK: true,
		Relocations: []RelocationUse{
			{Code: 0x0004, Name: "REL32", Section: ".text", Symbol: "BeaconPrintf"},
		},
		Unresolved: []string{"__imp__BeaconPrintf", "KERNEL32$VirtualAlloc", "__imp_FreeLibrary", "__imp_GetProcAddress", "__imp_LoadLibraryA"},
	})
	if !result.Compatible || result.Status != "compatible" || len(result.Blockers) != 0 || len(result.Warnings) != 0 {
		t.Fatalf("compatibility = %+v", result)
	}
}

func TestAssessWindowsCOFFStructuredBlockers(t *testing.T) {
	result := AssessWindowsCOFF(COFFInput{
		Arch:         "x86",
		Entrypoint:   "go",
		EntrypointOK: false,
		LayoutIssues: []LayoutIssue{{Code: "section_data_range", Detail: "section data extends beyond file", Section: ".text"}},
		Relocations: []RelocationUse{
			{Code: 0x000c, Name: "SECREL", Section: ".data", Symbol: "value"},
			{Code: 0x7777, Name: "AMD64_0x7777", Section: ".text", Symbol: "other"},
		},
		Unresolved: []string{"BeaconFormatAlloc", "$Broken"},
	})
	if result.Compatible || result.Status != "unsupported_arch" {
		t.Fatalf("compatibility = %+v", result)
	}
	for _, category := range []string{"unsupported_arch", "malformed_object", "missing_entrypoint"} {
		if !hasIssue(result.Blockers, category) {
			t.Fatalf("missing %s blocker: %+v", category, result.Blockers)
		}
	}
	for _, category := range []string{"unsupported_relocation", "unsupported_beacon_api", "malformed_dynamic_import"} {
		if hasIssue(result.Blockers, category) {
			t.Fatalf("unsupported architecture should not be interpreted with AMD64 capability rules: %+v", result.Blockers)
		}
	}
	amd64 := AssessWindowsCOFF(COFFInput{
		Arch:         "x64",
		Entrypoint:   "go",
		EntrypointOK: true,
		Relocations:  []RelocationUse{{Code: 0x000c, Name: "SECREL", Section: ".data", Symbol: "value"}},
		Unresolved:   []string{"BeaconFormatAlloc", "$Broken"},
	})
	for _, category := range []string{"unsupported_relocation", "unsupported_beacon_api", "malformed_dynamic_import"} {
		if !hasIssue(amd64.Blockers, category) {
			t.Fatalf("missing AMD64 %s blocker: %+v", category, amd64.Blockers)
		}
	}
}

func TestAssessWindowsCOFFFallbackLookupWarning(t *testing.T) {
	result := AssessWindowsCOFF(COFFInput{
		Arch:         "x64",
		Entrypoint:   "go",
		EntrypointOK: true,
		Unresolved:   []string{"__imp__MissingExternal", "MissingExternal"},
	})
	if !result.Compatible || result.Status != "compatible_runtime_lookup" || len(result.Warnings) != 2 {
		t.Fatalf("compatibility = %+v", result)
	}
	if !hasIssue(result.Warnings, "fallback_lookup") {
		t.Fatalf("missing fallback warning: %+v", result.Warnings)
	}
}

func TestAssessWindowsCOFFNonExecutableEntrypoint(t *testing.T) {
	executable := false
	result := AssessWindowsCOFF(COFFInput{
		Arch:                 "x64",
		Entrypoint:           "go",
		EntrypointOK:         true,
		EntrypointExecutable: &executable,
	})
	if result.Compatible || result.Status != "entrypoint_nonexecutable" || !hasIssue(result.Blockers, "entrypoint_nonexecutable") {
		t.Fatalf("compatibility = %+v", result)
	}
}

func hasIssue(issues []Issue, category string) bool {
	for _, issue := range issues {
		if issue.Category == category {
			return true
		}
	}
	return false
}
