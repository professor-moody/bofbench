package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProofResumeSelection(t *testing.T) {
	dir := t.TempDir()
	report := packProofReport{Status: "pass_with_unavailable", Runtime: "sliver", Lab: "devbox", Results: []packProofResult{
		{Pack: "internal/one", Case: "live", Runtime: "sliver", Status: "unavailable"},
		{Pack: "internal/two", Case: "live", Runtime: "sliver", Status: "pass"},
		{Pack: "internal/three", Case: "live", Runtime: "sliver", Status: "fail"},
	}}
	report.Schema = "bofbench.pack-proof"
	data, _ := json.Marshal(report)
	if err := os.WriteFile(filepath.Join(dir, "pack-proof.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	selection, err := loadProofResumeSelection(dir, nil, "sliver", "devbox", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Keys) != 2 || !selection.Keys[proofResumeKey("internal/one", "live", "sliver")] || !selection.Keys[proofResumeKey("internal/three", "live", "sliver")] {
		t.Fatalf("selection = %+v", selection)
	}
	passed, err := loadProofResumeSelection(dir, []string{"passed"}, "sliver", "devbox", "")
	if err != nil || len(passed.Keys) != 1 || !passed.Keys[proofResumeKey("internal/two", "live", "sliver")] {
		t.Fatalf("passed selection = %+v err=%v", passed, err)
	}
}

func TestLoadProofResumeSelectionRejectsRuntimeMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pack-proof.json")
	report := packProofReport{Runtime: "lab"}
	report.Schema = "bofbench.pack-proof"
	data, _ := json.Marshal(report)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProofResumeSelection(path, nil, "sliver", "devbox", ""); err == nil {
		t.Fatal("expected runtime mismatch")
	}
}
