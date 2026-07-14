package app

import (
	"strings"
	"testing"
)

func TestResolveRuntimeAdapter(t *testing.T) {
	for _, name := range []string{"", "native", "lab", "sliver", "cobaltstrike", "SLIVER"} {
		resolved, err := resolveRuntimeAdapter(name)
		if err != nil || resolved == "" {
			t.Fatalf("resolve %q = %q, %v", name, resolved, err)
		}
	}
	if _, err := resolveRuntimeAdapter("unknown"); err == nil || !strings.Contains(err.Error(), "cobaltstrike, lab, native, sliver") {
		t.Fatalf("unknown adapter error = %v", err)
	}
}
