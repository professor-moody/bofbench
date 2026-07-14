package app

import (
	"context"
	"io"
	"strings"
	"testing"

	"bofbench/internal/runtimeadapter"
)

func TestRuntimeAdapterRegistry(t *testing.T) {
	registry, err := runtimeAdapterRegistry(&runtimeRunContext{stdout: io.Discard, input: "."})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "native", "lab", "sliver", "cobaltstrike", "SLIVER"} {
		resolved, err := registry.Resolve(name)
		if err != nil || resolved.Name() == "" {
			t.Fatalf("resolve %q = %v, %v", name, resolved, err)
		}
	}
	if _, err := registry.Resolve("unknown"); err == nil || !strings.Contains(err.Error(), "cobaltstrike, lab, native, sliver") {
		t.Fatalf("unknown adapter error = %v", err)
	}
	native, _ := registry.Resolve("native")
	available, err := native.Detect(context.Background())
	if err != nil || !available.Available || available.Version == "" {
		t.Fatalf("native availability=%+v err=%v", available, err)
	}
	sessions, err := native.Sessions(context.Background())
	if err != nil || len(sessions) != 1 || !sessions[0].Selected {
		t.Fatalf("native sessions=%+v err=%v", sessions, err)
	}
	tokens, err := native.ConvertArguments([]runtimeadapter.Argument{{Name: "filter", Type: "string", Value: "lsass", Required: true}, {Name: "limit", Type: "int", Value: "5", Required: true}})
	if err != nil || strings.Join(tokens, " ") != "z:lsass i:5" {
		t.Fatalf("converted arguments=%v err=%v", tokens, err)
	}
}
