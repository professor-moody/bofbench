package runtimecomparison

import (
	"testing"
	"time"

	"bofbench/internal/pack"
)

func TestCompareRequiresExactHashAndHonorsContracts(t *testing.T) {
	results := []RuntimeResult{
		{Runtime: "lab", Status: "completed", OutputComplete: true, ObjectSHA256: "abc", Output: []string{"[host] status=complete host=DEVBOX pid=10"}},
		{Runtime: "sliver", Status: "completed", OutputComplete: true, ObjectSHA256: "ABC", Output: []string{"[host] status=complete host=devbox. pid=20"}},
	}
	contracts := []pack.ComparisonContract{{Tag: "host", Fields: []pack.ComparisonField{{Name: "status", Behavior: "exact"}, {Name: "host", Behavior: "normalized", Normalizer: "hostname"}, {Name: "pid", Behavior: "presence"}, {Name: "pid", Behavior: "ignore"}}}}
	receipt := Compare("survey", "pack", "run", results, contracts, time.Now())
	if receipt.Status != "pass" || !receipt.ExactObject {
		t.Fatalf("comparison = %+v", receipt)
	}
	results[1].ObjectSHA256 = "different"
	receipt = Compare("survey", "pack", "run", results, contracts, time.Now())
	if receipt.Status != "failed" || receipt.ExactObject {
		t.Fatalf("hash mismatch = %+v", receipt)
	}
}

func TestCompareDoesNotTreatIncompleteAsComplete(t *testing.T) {
	results := []RuntimeResult{{Runtime: "lab", Status: "completed", OutputComplete: true, ObjectSHA256: "same"}, {Runtime: "sliver", Status: "submitted", ObjectSHA256: "same"}}
	receipt := Compare("survey", "pack", "run", results, nil, time.Now())
	if receipt.Status != "incomplete" {
		t.Fatalf("status = %s", receipt.Status)
	}
}
