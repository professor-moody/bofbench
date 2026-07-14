package app

import (
	"strings"
	"testing"

	packsvc "bofbench/internal/pack"
)

func TestPackReferenceMarkdownUsesManifestContracts(t *testing.T) {
	items := []packsvc.Resolved{{
		Catalog: "internal", Qualified: "internal/example",
		Document: packsvc.Document{
			ID: "example", Version: "1.2.3", Summary: "Run one explicit operation.",
			Capabilities: []string{"selected operation"}, Effects: []string{"starts execution"},
			Privilege: "operator rights", Network: "none", Platforms: []string{"windows"}, Architecture: []string{"x64"},
			TargetSupport: []string{"lab", "sliver"}, CleanupPack: "example-cleanup",
			Arguments: []packsvc.Argument{{Name: "target_pid", Type: "int", Description: "exact target", Required: true}},
		},
	}}
	body := packReferenceMarkdown(items)
	for _, want := range []string{"`internal/example`", "selected operation", "starts execution", "target_pid", "example-cleanup", "lab, sliver"} {
		if !strings.Contains(body, want) {
			t.Fatalf("reference missing %q:\n%s", want, body)
		}
	}
}
