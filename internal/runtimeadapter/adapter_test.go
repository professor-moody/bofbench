package runtimeadapter

import (
	"context"
	"strings"
	"testing"
)

func TestRegistryAndFunctionalAdapterContract(t *testing.T) {
	adapter, err := New("Sliver", Hooks{
		Detect: func(context.Context) (Availability, error) {
			return Availability{Available: true, Version: "1.7.3"}, nil
		},
		Execute: func(_ context.Context, prepared Prepared) (Receipt, error) {
			return Receipt{Schema: ReceiptSchema, SchemaVersion: ReceiptSchemaVersion, Runtime: prepared.Runtime, Status: "pass", Session: prepared.Request.Session}, nil
		},
		Cleanup: func(_ context.Context, prepared Prepared) (Receipt, error) {
			return Receipt{Schema: ReceiptSchema, SchemaVersion: ReceiptSchemaVersion, Runtime: prepared.Runtime, Status: "clean", Session: prepared.Request.Session}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapter)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := registry.Resolve("sliver")
	if err != nil {
		t.Fatal(err)
	}
	available, err := selected.Detect(context.Background())
	if err != nil || !available.Available || available.Version != "1.7.3" {
		t.Fatalf("availability=%+v err=%v", available, err)
	}
	if _, err := selected.ConvertArguments([]Argument{{Name: "pid", Type: "int", Required: true}}); err == nil || !strings.Contains(err.Error(), "pid") {
		t.Fatalf("missing argument error = %v", err)
	}
	prepared, err := selected.Prepare(context.Background(), Request{Input: "bofs/example", Session: "WINDOWS-SESSION"})
	if err != nil || prepared.Runtime != "sliver" || prepared.PreparedAt == "" {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	receipt, err := selected.Execute(context.Background(), prepared)
	if err != nil || receipt.Runtime != "sliver" || receipt.Session != "WINDOWS-SESSION" {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
}
