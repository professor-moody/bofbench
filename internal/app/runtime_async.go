package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"bofbench/internal/evidence"
	"bofbench/internal/runlog"
	"bofbench/internal/runtimeadapter"
)

type activeRuntimeTask struct {
	cancel context.CancelFunc
	path   string
}

var runtimeTasks = struct {
	sync.Mutex
	items map[string]activeRuntimeTask
}{items: map[string]activeRuntimeTask{}}

func (run *runtimeRunContext) startRuntimeTask(parent context.Context, runtimeName string, prepared runtimeadapter.Prepared, execute func(context.Context, runtimeadapter.Prepared) (runtimeadapter.Receipt, error)) (runtimeadapter.Receipt, error) {
	runDir, err := runlog.NewDir("task-" + runtimeName)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	path := filepath.Join(runDir, "result.json")
	taskID := runlog.ID(runDir)
	ctx, cancel := context.WithCancel(parent)
	started := time.Now().UTC()
	receipt := runtimeadapter.Receipt{
		Schema: runtimeadapter.ReceiptSchema, SchemaVersion: runtimeadapter.ReceiptSchemaVersion,
		Runtime: runtimeName, Status: "running", ExecutionState: "running", OutputComplete: false,
		TaskID: taskID, ReceiptPath: path, WorkerPID: os.Getpid(), CancelSupported: runtimeName == "native" || runtimeName == "lab",
		StartedAt: started.Format(time.RFC3339Nano), OutputClassification: "partial", Object: prepared.Request.Object,
	}
	if prepared.Request.Object != "" {
		if fingerprint, fingerprintErr := evidence.FingerprintFile(prepared.Request.Object); fingerprintErr == nil {
			receipt.ObjectSHA256 = fingerprint.SHA256
		}
	}
	runtimeadapter.AddTransition(&receipt, "submitted", "asynchronous runtime task created", started)
	runtimeadapter.AddTransition(&receipt, "running", "runtime task worker started", started)
	if err := writeRuntimeTaskReceipt(path, receipt); err != nil {
		cancel()
		return runtimeadapter.Receipt{}, err
	}
	runtimeTasks.Lock()
	runtimeTasks.items[taskID] = activeRuntimeTask{cancel: cancel, path: path}
	runtimeTasks.items[path] = activeRuntimeTask{cancel: cancel, path: path}
	runtimeTasks.Unlock()

	previousProgress := run.progress
	run.progress = func(line string) {
		if previousProgress != nil {
			previousProgress(line)
		}
		current, loadErr := loadRuntimeTaskReceipt(path)
		if loadErr != nil {
			return
		}
		current.Output = append(current.Output, line)
		current.LastOutputAt = time.Now().UTC().Format(time.RFC3339Nano)
		current.OutputChunks = append(current.OutputChunks, runtimeadapter.OutputChunk{
			Number: len(current.OutputChunks) + 1, LineCount: 1, ReceivedAt: current.LastOutputAt,
		})
		current = run.redactReceipt(current)
		_ = writeRuntimeTaskReceipt(path, current)
	}

	go func() {
		defer cancel()
		final, executeErr := execute(ctx, prepared)
		current, _ := loadRuntimeTaskReceipt(path)
		if current.Schema == "" {
			current = receipt
		}
		final.Schema, final.SchemaVersion = runtimeadapter.ReceiptSchema, runtimeadapter.ReceiptSchemaVersion
		final.Runtime, final.TaskID, final.ReceiptPath = runtimeName, taskID, path
		final.WorkerPID, final.CancelSupported = receipt.WorkerPID, receipt.CancelSupported
		if final.StartedAt == "" {
			final.StartedAt = receipt.StartedAt
		}
		if len(final.Output) == 0 && len(current.Output) > 0 {
			final.Output = current.Output
		}
		if len(final.OutputChunks) == 0 && len(current.OutputChunks) > 0 {
			final.OutputChunks = current.OutputChunks
		}
		if ctx.Err() != nil {
			now := time.Now().UTC()
			final.Status, final.ExecutionState, final.OutputComplete = "canceled", "canceled", false
			final.CancelSupported, final.CanceledAt, final.TerminalReason = true, now.Format(time.RFC3339Nano), "operator_canceled"
			final.OutputClassification = "partial"
			runtimeadapter.AddTransition(&final, "canceled", "runtime task canceled", now)
		} else if executeErr != nil && final.ExecutionState == "" {
			final.Status, final.ExecutionState, final.Error = "failed", "failed", executeErr.Error()
		}
		final = run.redactReceipt(final)
		_ = writeRuntimeTaskReceipt(path, final)
		runtimeTasks.Lock()
		delete(runtimeTasks.items, taskID)
		delete(runtimeTasks.items, path)
		runtimeTasks.Unlock()
	}()

	go watchRuntimeCancelFile(ctx, path, cancel)
	return receipt, nil
}

func (run *runtimeRunContext) cancelRuntimeReceipt(_ context.Context, receipt runtimeadapter.Receipt) (runtimeadapter.Receipt, error) {
	if receipt.ExecutionState == "completed" || receipt.ExecutionState == "failed" || receipt.ExecutionState == "timeout" || receipt.ExecutionState == "canceled" || receipt.ExecutionState == "cancelled" {
		return receipt, nil
	}
	if !receipt.CancelSupported {
		return receipt, fmt.Errorf("runtime %s does not expose safe task cancellation", receipt.Runtime)
	}
	now := time.Now().UTC()
	receipt.CancelRequestedAt, receipt.CancelSource = now.Format(time.RFC3339Nano), "operator"
	runtimeadapter.AddTransition(&receipt, "canceling", "operator requested cancellation", now)
	if receipt.ReceiptPath != "" {
		if err := writeRuntimeTaskReceipt(receipt.ReceiptPath, receipt); err != nil {
			return receipt, err
		}
	}
	runtimeTasks.Lock()
	task, ok := runtimeTasks.items[receipt.TaskID]
	if !ok {
		task, ok = runtimeTasks.items[receipt.ReceiptPath]
	}
	runtimeTasks.Unlock()
	if ok {
		task.cancel()
		return receipt, nil
	}
	if receipt.ReceiptPath == "" {
		return receipt, fmt.Errorf("runtime task has no receipt path for cancellation")
	}
	if err := os.WriteFile(receipt.ReceiptPath+".cancel", []byte(receipt.CancelRequestedAt+"\n"), 0o600); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func watchRuntimeCancelFile(ctx context.Context, path string, cancel context.CancelFunc) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := os.Stat(path + ".cancel"); err == nil {
				_ = os.Remove(path + ".cancel")
				cancel()
				return
			}
		}
	}
}

func loadRuntimeTaskReceipt(path string) (runtimeadapter.Receipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return runtimeadapter.Receipt{}, err
	}
	var receipt runtimeadapter.Receipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return runtimeadapter.Receipt{}, err
	}
	return receipt, nil
}

func writeRuntimeTaskReceipt(path string, receipt runtimeadapter.Receipt) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.CreateTemp(filepath.Dir(path), ".runtime-*.json")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
