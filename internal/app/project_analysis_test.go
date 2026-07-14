package app

import (
	"testing"

	packsvc "bofbench/internal/pack"
)

func TestDeclarativeSignaturesDeduplicateAndQualifyConflicts(t *testing.T) {
	signature := packsvc.AnalysisSignature{ID: "selected_access", Name: "Selected access", Summary: "Open one target", Steps: []packsvc.AnalysisStep{{Action: "open", APIs: []string{"OpenProcess"}}}, Effects: []string{"accesses another process"}}
	first := packsvc.Resolved{Catalog: "first", Document: packsvc.Document{AnalysisSignatures: []packsvc.AnalysisSignature{signature}}}
	second := packsvc.Resolved{Catalog: "second", Document: packsvc.Document{AnalysisSignatures: []packsvc.AnalysisSignature{signature}}}
	identical := declarativeSignatures([]packsvc.Resolved{first, second})
	if len(identical) != 1 || identical[0].ID != "selected_access" {
		t.Fatalf("identical signatures = %+v", identical)
	}
	second.Document.AnalysisSignatures[0].Summary = "Different target semantics"
	conflicting := declarativeSignatures([]packsvc.Resolved{first, second})
	if len(conflicting) != 2 || conflicting[0].ID != "first/selected_access" || conflicting[1].ID != "second/selected_access" {
		t.Fatalf("conflicting signatures = %+v", conflicting)
	}
}
