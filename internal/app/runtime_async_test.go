package app

import (
	"context"
	"os"
	"testing"
	"time"

	"bofbench/internal/runtimeadapter"
)

func TestAsyncRuntimeTaskProgressRefreshAndCancel(t *testing.T) {
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)

	run := &runtimeRunContext{}
	started, err := run.startRuntimeTask(context.Background(), "native", runtimeadapter.Prepared{Runtime: "native"}, func(ctx context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
		run.progress("[watch] status=ready")
		<-ctx.Done()
		return runtimeadapter.Receipt{Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion, Runtime: "native"}, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var refreshed runtimeadapter.Receipt
	for time.Now().Before(deadline) {
		refreshed, err = run.refreshRuntimeReceipt(context.Background(), started)
		if err == nil && len(refreshed.Output) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(refreshed.Output) != 1 || refreshed.Output[0] != "[watch] status=ready" {
		t.Fatalf("progress receipt = %+v err=%v", refreshed, err)
	}
	if _, err := run.cancelRuntimeReceipt(context.Background(), refreshed); err != nil {
		t.Fatal(err)
	}
	for time.Now().Before(deadline) {
		refreshed, err = run.refreshRuntimeReceipt(context.Background(), refreshed)
		if err == nil && refreshed.ExecutionState == "canceled" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if refreshed.ExecutionState != "canceled" || refreshed.CanceledAt == "" {
		t.Fatalf("canceled receipt = %+v err=%v", refreshed, err)
	}
}
