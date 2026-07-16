package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	operationsvc "bofbench/internal/operation"
	"bofbench/internal/runtimeadapter"
)

type dagPreparedStep struct {
	index     int
	arguments map[string]string
	pack      *preparedOperationPack
}

type dagStepResult struct {
	index   int
	receipt operationsvc.StepReceipt
	child   *operationsvc.Receipt
	output  []string
	display []byte
	err     error
}

func runDAGOperation(ctx context.Context, stdout io.Writer, registry *operationsvc.Registry, item operationsvc.Resolved, inputs, topology map[string]string, opts operationOptions, receipt *operationsvc.Receipt, path string, resumed bool) error {
	ready, err := operationsvc.ReadyDAGSteps(item.Document, *receipt)
	if err != nil {
		return err
	}
	if resumed && len(ready) == 0 {
		if opts.cleanup && receipt.CleanupState != "completed" {
			return cleanupOperation(ctx, stdout, registry, item, inputs, receipt, path, opts)
		}
		fmt.Fprintf(stdout, "operation  %s\nreceipt    %s\n", receipt.Status, path)
		return nil
	}
	receipt.Status, receipt.Error = "running", ""
	if err := operationsvc.SaveReceipt(path, receipt); err != nil {
		return err
	}
	work := filepath.Join("work", "operations", filepath.Base(filepath.Dir(path)))
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	for {
		ready, err = operationsvc.ReadyDAGSteps(item.Document, *receipt)
		if err != nil {
			return err
		}
		if len(ready) == 0 {
			break
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		wave := operationsvc.ExecutionWave{Index: len(receipt.ExecutionWaves) + 1, State: "preparing", ReadyAt: now}
		for _, index := range ready {
			wave.Steps = append(wave.Steps, item.Document.Steps[index].ID)
			receipt.Steps[index].ReadyAt = now
		}
		prepared, prepErr := prepareDAGWave(ctx, registry, item, inputs, topology, opts, *receipt, ready, work)
		if prepErr != nil {
			failed := ready[0]
			for _, candidate := range ready {
				if prepared[candidate].index == -1 {
					failed = candidate
					break
				}
			}
			receipt.Steps[failed].State, receipt.Steps[failed].ContractState = "failed", "failed"
			receipt.Steps[failed].Error = prepErr.Error()
			wave.State, wave.CompletedAt = "failed", time.Now().UTC().Format(time.RFC3339Nano)
			receipt.ExecutionWaves = append(receipt.ExecutionWaves, wave)
			operationsvc.BlockDAGDescendants(item.Document, receipt, []string{item.Document.Steps[failed].ID})
			receipt.Status, receipt.Error = "failed", prepErr.Error()
			_ = operationsvc.SaveReceipt(path, receipt)
			if opts.cleanupOnFailure {
				_ = cleanupOperation(ctx, stdout, registry, item, inputs, receipt, path, opts)
			}
			return prepErr
		}
		wave.State, wave.StartedAt = "running", time.Now().UTC().Format(time.RFC3339Nano)
		for _, index := range ready {
			if receipt.Steps[index].State == "pending" {
				receipt.Steps[index].State = "running"
			}
			if receipt.Steps[index].StartedAt == "" {
				receipt.Steps[index].StartedAt = wave.StartedAt
			}
		}
		if err := operationsvc.SaveReceipt(path, receipt); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wave %d/%d  ready=%s\n", wave.Index, len(item.Document.Steps), joinDAGStepIDs(item.Document, ready))
		results := executeDAGWave(ctx, registry, item, inputs, topology, opts, *receipt, path, prepared, ready)
		sort.Slice(results, func(i, j int) bool { return results[i].index < results[j].index })
		var failed, incomplete, active, canceled []string
		for _, result := range results {
			receipt.Steps[result.index] = result.receipt
			if len(result.display) > 0 {
				_, _ = stdout.Write(result.display)
			}
			switch result.receipt.State {
			case "completed":
				for name, value := range result.receipt.Captures {
					receipt.Captures[name] = value
				}
				receipt.ActualPath = append(receipt.ActualPath, result.receipt.ID)
				if result.child != nil {
					operationsvc.RecordChildPath(receipt, result.receipt.ID, *result.child)
				} else {
					receipt.ExpandedPath = append(receipt.ExpandedPath, result.receipt.ID)
				}
			case "incomplete":
				incomplete = append(incomplete, result.receipt.ID)
			case "running", "ready":
				active = append(active, result.receipt.ID)
				if result.receipt.State == "ready" {
					for name, value := range result.receipt.ReadyCaptures {
						receipt.Captures[name] = value
					}
				}
			case "failed":
				failed = append(failed, result.receipt.ID)
			case "canceled":
				canceled = append(canceled, result.receipt.ID)
			}
		}
		if len(failed) == 0 && len(incomplete) == 0 {
			operationsvc.UnblockDAGSteps(item.Document, receipt)
		}
		wave.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		switch {
		case len(canceled) > 0:
			wave.State, receipt.Status = "canceled", "canceled"
			receipt.CancellationState, receipt.CanceledAt = "completed", time.Now().UTC().Format(time.RFC3339Nano)
			receipt.Error = fmt.Sprintf("dag wave canceled at %s", canceled)
			operationsvc.BlockDAGDescendants(item.Document, receipt, canceled)
		case len(failed) > 0:
			wave.State, receipt.Status = "failed", "failed"
			receipt.Error = fmt.Sprintf("dag wave failed at %s", failed)
			operationsvc.BlockDAGDescendants(item.Document, receipt, failed)
		case len(incomplete) > 0:
			wave.State, receipt.Status = "incomplete", "incomplete"
			receipt.Error = fmt.Sprintf("dag wave has incomplete runtime work at %s", incomplete)
			operationsvc.BlockDAGDescendants(item.Document, receipt, incomplete)
		case len(active) > 0:
			wave.State, receipt.Status = "active", "running"
			receipt.Error = ""
		default:
			wave.State = "completed"
			receipt.Status, receipt.Error = "running", ""
		}
		receipt.ExecutionWaves = append(receipt.ExecutionWaves, wave)
		concurrency := len(ready)
		if concurrency > opts.parallelism {
			concurrency = opts.parallelism
		}
		if concurrency > receipt.MaxConcurrency {
			receipt.MaxConcurrency = concurrency
		}
		if err := operationsvc.SaveReceipt(path, receipt); err != nil {
			return err
		}
		if len(failed) > 0 {
			if opts.cleanupOnFailure {
				_ = cleanupOperation(ctx, stdout, registry, item, inputs, receipt, path, opts)
			}
			return fmt.Errorf("%s", receipt.Error)
		}
		if len(canceled) > 0 {
			fmt.Fprintf(stdout, "operation  canceled\nreceipt    %s\n", path)
			return nil
		}
		if len(incomplete) > 0 {
			fmt.Fprintf(stdout, "operation  incomplete\nreceipt    %s\n", path)
			return fmt.Errorf("%s; resume %s after the runtime tasks complete", receipt.Error, path)
		}
		if len(active) > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if !operationsvc.DAGComplete(*receipt) {
		return fmt.Errorf("dag operation has no ready steps but is not complete")
	}
	receipt.Status, receipt.CompletedAt = "completed", time.Now().UTC().Format(time.RFC3339Nano)
	if err := operationsvc.SaveReceipt(path, receipt); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "operation  completed\nreceipt    %s\n", path)
	if opts.cleanup {
		return cleanupOperation(ctx, stdout, registry, item, inputs, receipt, path, opts)
	}
	return nil
}

func prepareDAGWave(ctx context.Context, registry *operationsvc.Registry, item operationsvc.Resolved, inputs, topology map[string]string, opts operationOptions, receipt operationsvc.Receipt, ready []int, work string) (map[int]dagPreparedStep, error) {
	prepared := map[int]dagPreparedStep{}
	for _, index := range ready {
		prepared[index] = dagPreparedStep{index: -1}
		step, state := item.Document.Steps[index], receipt.Steps[index]
		if state.State == "incomplete" || state.State == "running" || state.State == "ready" {
			prepared[index] = dagPreparedStep{index: index}
			continue
		}
		if err := requireReferencedSensitiveInputs(item.Document, receipt, inputs, step.Arguments); err != nil {
			return prepared, fmt.Errorf("prepare dag step %s: %w", step.ID, err)
		}
		arguments, err := resolveOperationArguments(step.Arguments, inputs, receipt.Captures, topology)
		if err != nil {
			return prepared, fmt.Errorf("prepare dag step %s: %w", step.ID, err)
		}
		entry := dagPreparedStep{index: index, arguments: arguments}
		if step.Pack != "" {
			packItem, err := registry.PackRegistry().Resolve(step.Pack)
			if err != nil {
				return prepared, fmt.Errorf("prepare dag step %s: %w", step.ID, err)
			}
			if state.PackSHA256 == "" || state.PackSHA256 != packItem.SHA256 {
				return prepared, fmt.Errorf("prepare dag step %s: pack changed since operation start", step.ID)
			}
			stepWork := filepath.Join(work, "waves", fmt.Sprintf("%03d-%s", len(receipt.ExecutionWaves)+1, step.ID))
			packPreparation, err := prepareOperationPack(ctx, registry.PackRegistry(), packItem, arguments, operationArgumentSensitivity(item.Document, step.Arguments), opts, stepWork)
			if err != nil {
				return prepared, fmt.Errorf("prepare dag step %s: %w", step.ID, err)
			}
			entry.pack = &packPreparation
		}
		prepared[index] = entry
	}
	return prepared, nil
}

func executeDAGWave(ctx context.Context, registry *operationsvc.Registry, item operationsvc.Resolved, inputs, topology map[string]string, opts operationOptions, receipt operationsvc.Receipt, path string, prepared map[int]dagPreparedStep, ready []int) []dagStepResult {
	results := make(chan dagStepResult, len(ready))
	var wait sync.WaitGroup
	for _, index := range ready {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			var display bytes.Buffer
			result := executeDAGStep(ctx, &display, registry, item, inputs, topology, opts, receipt, path, prepared[index], index)
			result.display = append([]byte(nil), display.Bytes()...)
			results <- result
		}()
	}
	wait.Wait()
	close(results)
	var collected []dagStepResult
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func executeDAGStep(ctx context.Context, stdout io.Writer, registry *operationsvc.Registry, item operationsvc.Resolved, inputs, topology map[string]string, opts operationOptions, receipt operationsvc.Receipt, path string, prepared dagPreparedStep, index int) dagStepResult {
	step := item.Document.Steps[index]
	state := receipt.Steps[index]
	if state.StartedAt == "" {
		state.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	result := dagStepResult{index: index, receipt: state}
	if step.Operation != "" {
		return executeDAGChild(ctx, stdout, registry, item, step, inputs, topology, opts, receipt, path, index)
	}
	var runtimeOutput []string
	if prepared.pack == nil && (state.State == "incomplete" || state.State == "running" || state.State == "ready") {
		updated, err := refreshOperationRuntimeReceipt(ctx, state.Runtime, opts)
		if err != nil {
			result.err = err
			result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", err.Error()
			return result
		}
		if state.ObjectSHA256 != "" && updated.ObjectSHA256 != state.ObjectSHA256 {
			err := fmt.Errorf("runtime task object hash changed for step %s", step.ID)
			result.err = err
			result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", err.Error()
			return result
		}
		result.receipt.Runtime, result.receipt.OutputComplete = updated, updated.OutputComplete
		result.receipt.State, _ = operationsvc.ClassifyExecution(updated.ExecutionState, updated.OutputComplete, false)
		runtimeOutput = updated.TransientOutput
		if len(runtimeOutput) == 0 {
			runtimeOutput = updated.Output
		}
	} else {
		if prepared.pack == nil {
			err := fmt.Errorf("dag step %s was not prepared", step.ID)
			result.err = err
			result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", err.Error()
			return result
		}
		var updated runtimeadapter.Receipt
		var err error
		if step.Mode == "background" {
			updated, err = startPreparedOperationPack(ctx, *prepared.pack, opts)
		} else {
			updated, err = executePreparedOperationPack(ctx, *prepared.pack, opts)
		}
		result.receipt.Runtime, result.receipt.ObjectSHA256, result.receipt.OutputComplete = updated, updated.ObjectSHA256, updated.OutputComplete
		result.receipt.State, _ = operationsvc.ClassifyExecution(updated.ExecutionState, updated.OutputComplete, err != nil)
		if err != nil {
			result.err, result.receipt.Error = err, err.Error()
		}
		runtimeOutput = updated.TransientOutput
		if len(runtimeOutput) == 0 {
			runtimeOutput = updated.Output
		}
	}
	result.output = runtimeOutput
	if step.Mode == "background" {
		if result.receipt.StartedAt != "" && step.TimeoutMS > 0 {
			if started, parseErr := time.Parse(time.RFC3339Nano, result.receipt.StartedAt); parseErr == nil && time.Since(started) > time.Duration(step.TimeoutMS)*time.Millisecond {
				result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", "background step timed out"
				result.err = fmt.Errorf("background step %s timed out after %dms", step.ID, step.TimeoutMS)
				return result
			}
		}
		if result.receipt.ReadyState != "ready" {
			fields, _, readyErr := operationsvc.EvaluateExpectation(runtimeOutput, step.Ready, inputs, receipt.Captures, topology)
			if readyErr == nil {
				captured, captureErr := operationsvc.CaptureOutput(runtimeOutput, step.ReadyCaptures)
				if captureErr != nil {
					result.err = captureErr
					result.receipt.State, result.receipt.ReadyContractState, result.receipt.Error = "failed", "failed", captureErr.Error()
					return result
				}
				now := time.Now().UTC().Format(time.RFC3339Nano)
				result.receipt.ReadyState, result.receipt.ReadyContractState = "ready", "matched"
				result.receipt.ReadyMatchedTag, result.receipt.ReadyMatchedFields = step.Ready.Tag, fields
				result.receipt.ReadyCaptures, result.receipt.ReadyAt, result.receipt.LastProgressAt = captured, now, now
			}
		}
		if !result.receipt.OutputComplete && result.receipt.State != "failed" {
			if result.receipt.ReadyState == "ready" {
				result.receipt.State = "ready"
			} else {
				result.receipt.State = "running"
			}
			return result
		}
		if result.receipt.ReadyState != "ready" {
			err := fmt.Errorf("background step %s completed before its readiness contract matched", step.ID)
			result.err = err
			result.receipt.State, result.receipt.ReadyContractState, result.receipt.Error = "failed", "failed", err.Error()
			return result
		}
	}
	if result.receipt.State != "completed" {
		if result.receipt.State == "failed" {
			result.receipt.ContractState = "failed"
		}
		return result
	}
	if err := applyOperationContract(step, &result.receipt, runtimeOutput, inputs, receipt.Captures, topology); err != nil {
		result.err = err
		result.receipt.State, result.receipt.Error = "failed", err.Error()
		return result
	}
	captured, err := operationsvc.CaptureOutput(runtimeOutput, step.Captures)
	if err != nil {
		result.err = err
		result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", err.Error()
		return result
	}
	result.receipt.Captures, result.receipt.State, result.receipt.Error = captured, "completed", ""
	result.receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	printOperationResult(stdout, result.receipt.Runtime.Output, captured)
	return result
}

func executeDAGChild(ctx context.Context, stdout io.Writer, registry *operationsvc.Registry, parent operationsvc.Resolved, step operationsvc.Step, inputs, topology map[string]string, opts operationOptions, receipt operationsvc.Receipt, path string, index int) dagStepResult {
	state := receipt.Steps[index]
	result := dagStepResult{index: index, receipt: state}
	child, err := registry.Resolve(step.Operation)
	if err != nil || state.OperationSHA256 == "" || state.OperationSHA256 != child.SHA256 {
		if err == nil {
			err = fmt.Errorf("child operation %s changed since operation start", step.Operation)
		}
		result.err = err
		result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", err.Error()
		return result
	}
	childInputs, err := resolveOperationArguments(step.Arguments, inputs, receipt.Captures, topology)
	if err != nil {
		result.err = err
		result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", err.Error()
		return result
	}
	childPath := state.ChildReceipt
	if childPath == "" {
		childPath = filepath.Join(filepath.Dir(path), "children", step.ID, "operation.json")
		result.receipt.ChildReceipt = childPath
	}
	childOpts := opts
	childOpts.cleanup, childOpts.cleanupOnFailure = false, false
	runErr := runOperation(ctx, stdout, registry, child, childInputs, childOpts, childPath)
	childReceipt, loadErr := operationsvc.LoadReceipt(childPath)
	if loadErr != nil {
		if runErr != nil {
			loadErr = runErr
		}
		result.err = loadErr
		result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", loadErr.Error()
		return result
	}
	result.child = &childReceipt
	result.receipt.ChildCleanupState = childReceipt.CleanupState
	if childReceipt.Status == "running" || childReceipt.Status == "incomplete" || childReceipt.Status == "pending" {
		result.receipt.State, result.receipt.Error = "incomplete", childReceipt.Error
		return result
	}
	if childReceipt.Status != "completed" && childReceipt.Status != "cleaned" {
		if runErr == nil {
			runErr = fmt.Errorf("child operation %s ended in %s: %s", child.Qualified, childReceipt.Status, childReceipt.Error)
		}
		result.err = runErr
		result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", runErr.Error()
		return result
	}
	output := []string{fmt.Sprintf("[operation] status=complete operation=%s receipt=%s cleanup=%s", child.Qualified, childPath, childReceipt.CleanupState)}
	if err := applyOperationContract(step, &result.receipt, output, inputs, receipt.Captures, topology); err != nil {
		result.err = err
		result.receipt.State, result.receipt.Error = "failed", err.Error()
		return result
	}
	captured, err := operationsvc.CaptureChildOutput(childReceipt, step.Captures)
	if err != nil {
		result.err = err
		result.receipt.State, result.receipt.ContractState, result.receipt.Error = "failed", "failed", err.Error()
		return result
	}
	result.receipt.Captures, result.receipt.State, result.receipt.Error = captured, "completed", ""
	result.receipt.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	printOperationResult(stdout, output, captured)
	return result
}

func joinDAGStepIDs(document operationsvc.Document, indexes []int) string {
	ids := make([]string, 0, len(indexes))
	for _, index := range indexes {
		ids = append(ids, document.Steps[index].ID)
	}
	return fmt.Sprintf("%v", ids)
}
