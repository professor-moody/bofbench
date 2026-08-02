package app

import (
	"context"
	"testing"

	"github.com/professor-moody/bofbench/internal/lab"
)

func TestTopologyProviderRoleOrdering(t *testing.T) {
	resolved := lab.ResolvedTopology{
		Execution:        lab.ResolvedProfile{Name: "exec"},
		Target:           &lab.ResolvedProfile{Name: "target"},
		DomainController: &lab.ResolvedProfile{Name: "dc"},
	}
	up := orderedTopologyProviderRoles(resolved, false)
	if len(up) != 3 || up[0].role != "domain_controller" || up[1].role != "target" || up[2].role != "execution" {
		t.Fatalf("unexpected startup order: %#v", up)
	}
	down := orderedTopologyProviderRoles(resolved, true)
	if down[0].role != "execution" || down[2].role != "domain_controller" {
		t.Fatalf("unexpected shutdown order: %#v", down)
	}
}

func TestTopologyLifecycleNeverControlsExistingHosts(t *testing.T) {
	resolved := lab.ResolvedProfile{Name: "external", Profile: lab.Profile{Provider: "existing", Transport: "ssh", Host: "example"}}
	result, err := runTopologyProviderRole(context.Background(), "execution", resolved, "down", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Receipts) != 0 {
		t.Fatalf("existing host received a provider action: %#v", result.Receipts)
	}
}
