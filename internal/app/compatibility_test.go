package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	packsvc "github.com/professor-moody/bofbench/internal/pack"
	"github.com/professor-moody/bofbench/internal/recipe"
	"github.com/professor-moody/bofbench/internal/scaffold"
)

func TestCompatibilityPolicyIsCompleteAndVersioned(t *testing.T) {
	policy := compatibilityPolicy()
	if policy.Schema != commandCompatibilitySchema || policy.SchemaVersion != commandCompatibilitySchemaVersion {
		t.Fatalf("unexpected policy identity: %s v%d", policy.Schema, policy.SchemaVersion)
	}
	if policy.RemovalReady || policy.RemovalNotBefore != "1.0.0" || policy.SupportedThrough != "0.x" {
		t.Fatalf("unexpected removal boundary: %+v", policy)
	}
	want := []string{"feature", "recipe", "dev", "preflight", "stage"}
	if len(policy.Commands) != len(want) {
		t.Fatalf("got %d commands, want %d", len(policy.Commands), len(want))
	}
	for i, contract := range policy.Commands {
		if contract.Command != want[i] {
			t.Fatalf("command %d = %q, want %q", i, contract.Command, want[i])
		}
		if contract.RemovalReady || len(contract.Mappings) == 0 || len(contract.RemovalCriteria) == 0 {
			t.Fatalf("incomplete contract for %s: %+v", contract.Command, contract)
		}
		for _, mapping := range contract.Mappings {
			if mapping.Legacy == "" || mapping.Replacement == "" {
				t.Fatalf("empty mapping for %s: %+v", contract.Command, mapping)
			}
		}
	}
	if contract, _ := compatibilityContract("stage"); contract.ReplacementCoverage != "complete" {
		t.Fatalf("stage must retain complete replacement coverage: %+v", contract)
	}
	for _, name := range []string{"recipe", "dev", "preflight"} {
		contract, _ := compatibilityContract(name)
		if contract.ReplacementCoverage != "partial" || len(contract.OpenGaps) == 0 {
			t.Fatalf("%s must retain explicit open gaps: %+v", name, contract)
		}
	}
}

func TestCompatibilityCommandFormats(t *testing.T) {
	var stdout bytes.Buffer
	if err := Run([]string{"compatibility", "--format", "json"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var policy commandCompatibilityPolicy
	if err := json.Unmarshal(stdout.Bytes(), &policy); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout.String())
	}
	if policy.Schema != commandCompatibilitySchema {
		t.Fatalf("unexpected JSON policy: %+v", policy)
	}
	firstJSON := append([]byte(nil), stdout.Bytes()...)
	stdout.Reset()
	if err := Run([]string{"compatibility", "--format", "json"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, stdout.Bytes()) {
		t.Fatal("compatibility JSON changed between identical renders")
	}

	stdout.Reset()
	if err := Run([]string{"compatibility", "--format", "md"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Legacy command compatibility", "## `preflight`", "docs/evidence/command-compatibility-v1.json"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("Markdown missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestLegacyCommandHelpNamesCompatibilityPolicy(t *testing.T) {
	root := rootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	for _, name := range []string{"feature", "recipe", "dev", "preflight"} {
		command, _, err := root.Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		if command.Annotations["bofbench.io/compatibility"] != name || !strings.Contains(command.Long, "bofbench compatibility") {
			t.Fatalf("%s help does not expose its compatibility contract", name)
		}
	}
	export, _, err := root.Find([]string{"export"})
	if err != nil {
		t.Fatal(err)
	}
	if len(export.Aliases) != 1 || export.Aliases[0] != "stage" {
		t.Fatalf("stage must remain the export alias: %v", export.Aliases)
	}
	if !strings.Contains(export.Long, "bofbench compatibility") {
		t.Fatal("stage/export help does not expose its compatibility contract")
	}
}

func TestCompleteFeatureAndRecipeMappingsResolveAsPacks(t *testing.T) {
	registry, err := packsvc.Load(packsvc.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, feature := range scaffold.Features() {
		if _, err := registry.Resolve(feature.Name); err != nil {
			t.Fatalf("feature %s does not resolve as a pack: %v", feature.Name, err)
		}
	}
	for _, featurePack := range scaffold.FeaturePacks() {
		if _, err := registry.Resolve(featurePack.Name); err != nil {
			t.Fatalf("feature pack %s does not resolve as a pack: %v", featurePack.Name, err)
		}
	}
	for _, document := range recipe.Builtins() {
		if _, err := registry.Resolve(document.Name); err != nil {
			t.Fatalf("recipe %s does not resolve as a pack: %v", document.Name, err)
		}
	}
}
