package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/professor-moody/bofbench/internal/runtimeadapter"
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
	if err := os.WriteFile("fixture.o", []byte("object"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared := runtimeadapter.Prepared{Runtime: "native", Request: runtimeadapter.Request{Object: "fixture.o", Entrypoint: "go"}}
	started, err := run.startRuntimeTask(context.Background(), "native", prepared, func(ctx context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
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
	if refreshed.ExecutionState != "canceled" || refreshed.CanceledAt == "" || refreshed.CancelRequestedAt == "" || refreshed.ObjectSHA256 != started.ObjectSHA256 || refreshed.Object != "fixture.o" {
		t.Fatalf("canceled receipt = %+v err=%v", refreshed, err)
	}
}

func TestAsyncRuntimeTaskHonorsCrossProcessCancelMarker(t *testing.T) {
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)

	run := &runtimeRunContext{}
	started, err := run.startRuntimeTask(context.Background(), "lab", runtimeadapter.Prepared{Runtime: "lab"}, func(ctx context.Context, _ runtimeadapter.Prepared) (runtimeadapter.Receipt, error) {
		<-ctx.Done()
		return runtimeadapter.Receipt{Runtime: "lab"}, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(started.ReceiptPath+".cancel", []byte("cancel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	refreshed := started
	for time.Now().Before(deadline) {
		refreshed, err = run.refreshRuntimeReceipt(context.Background(), refreshed)
		if err == nil && refreshed.ExecutionState == "canceled" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if refreshed.ExecutionState != "canceled" {
		t.Fatalf("marker cancellation receipt = %+v err=%v", refreshed, err)
	}
	if _, err := os.Stat(started.ReceiptPath + ".cancel"); !os.IsNotExist(err) {
		t.Fatalf("cancel marker was not removed: %v", err)
	}
}

func TestCancelDoesNotResurrectTerminalTaskReceipt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	terminal := runtimeadapter.Receipt{
		Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion,
		Runtime: "lab", Status: "canceled", ExecutionState: "canceled", TaskID: "task-one",
		ReceiptPath: path, CancelSupported: true, CanceledAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeRuntimeTaskReceipt(path, terminal); err != nil {
		t.Fatal(err)
	}
	stale := terminal
	stale.Status, stale.ExecutionState, stale.CanceledAt = "running", "running", ""
	updated, err := (&runtimeRunContext{}).cancelRuntimeReceipt(context.Background(), stale)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ExecutionState != "canceled" {
		t.Fatalf("terminal task was resurrected: %+v", updated)
	}
	persisted, err := loadRuntimeTaskReceipt(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ExecutionState != "canceled" {
		t.Fatalf("persisted task was resurrected: %+v", persisted)
	}
}
