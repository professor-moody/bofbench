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
	defer os.Remove(path + ".cancel")
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
		cancelRequested := syncDAGCancellationRequest(path, receipt)
		ready, err = operationsvc.ReadyDAGSteps(item.Document, *receipt)
		if err != nil {
			return err
		}
		if cancelRequested {
			ready = activeDAGStepIndexes(*receipt)
			requestDAGActiveCancellation(ctx, receipt, ready, opts)
			if len(ready) == 0 {
				now := time.Now().UTC().Format(time.RFC3339Nano)
				for index := range receipt.Steps {
					if receipt.Steps[index].State == "pending" || receipt.Steps[index].State == "retry_wait" {
						receipt.Steps[index].State = "blocked"
						receipt.Steps[index].ContractState = "blocked"
						receipt.Steps[index].BlockedBy = []string{"operator-cancel"}
					}
				}
				receipt.Status, receipt.CancellationState, receipt.CanceledAt = "canceled", "completed", now
				receipt.CompletedAt = now
				if err := operationsvc.SaveReceipt(path, receipt); err != nil {
					return err
				}
				fmt.Fprintf(stdout, "operation  canceled\nreceipt    %s\n", path)
				return nil
			}
		}
		if len(ready) == 0 {
			if delay, waiting := operationsvc.NextRetryDelay(*receipt, time.Now()); waiting {
				if delay > 250*time.Millisecond {
					delay = 250 * time.Millisecond
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
					continue
				}
			}
			break
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		wave := operationsvc.ExecutionWave{Index: len(receipt.ExecutionWaves) + 1, State: "preparing", ReadyAt: now}
		recordWave := false
		for _, index := range ready {
			if receipt.Steps[index].State == "pending" || receipt.Steps[index].State == "retry_wait" {
				recordWave = true
				wave.Steps = append(wave.Steps, item.Document.Steps[index].ID)
			}
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
			if recordWave {
				receipt.ExecutionWaves = append(receipt.ExecutionWaves, wave)
			}
			operationsvc.BlockDAGDescendants(item.Document, receipt, []string{item.Document.Steps[failed].ID})
			receipt.Status, receipt.Error = "failed", prepErr.Error()
			settleDAGRuntimeTasks(ctx, receipt, opts, path, 30*time.Second)
			_ = operationsvc.SaveReceipt(path, receipt)
			if opts.cleanupOnFailure {
				_ = cleanupOperation(ctx, stdout, registry, item, inputs, receipt, path, opts)
			}
			return prepErr
		}
		if syncDAGCancellationRequest(path, receipt) {
			active := ready[:0]
			for _, index := range ready {
				switch receipt.Steps[index].State {
				case "running", "ready", "incomplete":
					active = append(active, index)
				case "pending", "retry_wait":
					receipt.Steps[index].State = "blocked"
					receipt.Steps[index].ContractState = "blocked"
					receipt.Steps[index].BlockedBy = []string{"operator-cancel"}
				}
			}
			ready = active
			wave.Steps = wave.Steps[:0]
			recordWave = false
			requestDAGActiveCancellation(ctx, receipt, ready, opts)
			if len(ready) == 0 {
				now := time.Now().UTC().Format(time.RFC3339Nano)
				receipt.Status, receipt.CancellationState, receipt.CanceledAt = "canceled", "completed", now
				receipt.CompletedAt = now
				if err := operationsvc.SaveReceipt(path, receipt); err != nil {
					return err
				}
				fmt.Fprintf(stdout, "operation  canceled\nreceipt    %s\n", path)
				return nil
			}
		}
		wave.State, wave.StartedAt = "running", time.Now().UTC().Format(time.RFC3339Nano)
		for _, index := range ready {
			if receipt.Steps[index].State == "pending" || receipt.Steps[index].State == "retry_wait" {
				receipt.Steps[index].State = "running"
			}
			if receipt.Steps[index].StartedAt == "" {
				receipt.Steps[index].StartedAt = wave.StartedAt
			}
		}
		if err := operationsvc.SaveReceipt(path, receipt); err != nil {
			return err
		}
		if recordWave {
			fmt.Fprintf(stdout, "wave %d/%d  ready=%v\n", wave.Index, len(item.Document.Steps), wave.Steps)
		}
		results := executeDAGWave(ctx, registry, item, inputs, topology, opts, *receipt, path, prepared, ready)
		sort.Slice(results, func(i, j int) bool { return results[i].index < results[j].index })
		var failed, incomplete, active, retrying, canceled []string
		for _, result := range results {
			result = applyDAGRetry(item.Document.Steps[result.index], result, inputs, receipt.Captures, topology)
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
			case "retry_wait":
				retrying = append(retrying, result.receipt.ID)
			case "canceled":
				canceled = append(canceled, result.receipt.ID)
			}
		}
		if len(failed) == 0 && len(incomplete) == 0 {
			operationsvc.UnblockDAGSteps(item.Document, receipt)
		}
		wave.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		switch {
		case len(canceled) > 0 && len(active) > 0:
			wave.State, receipt.Status = "canceling", "running"
			receipt.CancellationState = "canceling"
			receipt.Error = fmt.Sprintf("waiting for active tasks %s after cancellation at %s", active, canceled)
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
		case len(retrying) > 0:
			wave.State, receipt.Status = "retry_wait", "running"
			receipt.Error = ""
		default:
			wave.State = "completed"
			receipt.Status, receipt.Error = "running", ""
		}
		if recordWave {
			wave.State = dagWaveState(wave.Steps, receipt.Steps)
		}
		refreshRecordedDAGWaves(receipt)
		if recordWave {
			receipt.ExecutionWaves = append(receipt.ExecutionWaves, wave)
		}
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
			settleDAGRuntimeTasks(ctx, receipt, opts, path, 30*time.Second)
			if opts.cleanupOnFailure {
				_ = cleanupOperation(ctx, stdout, registry, item, inputs, receipt, path, opts)
			}
			return fmt.Errorf("%s", receipt.Error)
		}
		remainingActive := activeDAGStepIndexes(*receipt)
		if len(canceled) > 0 && len(remainingActive) > 0 {
			requestDAGActiveCancellation(ctx, receipt, remainingActive, opts)
			receipt.Status, receipt.CancellationState, receipt.CanceledAt = "running", "canceling", ""
			if err := operationsvc.SaveReceipt(path, receipt); err != nil {
				return err
			}
		}
		if len(canceled) > 0 && len(remainingActive) == 0 {
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
		if len(retrying) > 0 && len(active) == 0 {
			if delay, waiting := operationsvc.NextRetryDelay(*receipt, time.Now()); waiting {
				fmt.Fprintf(stdout, "retry     steps=%v wait=%s\n", retrying, delay.Round(time.Millisecond))
				if delay > 250*time.Millisecond {
					delay = 250 * time.Millisecond
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
				}
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

func applyDAGRetry(step operationsvc.Step, result dagStepResult, inputs, captures, topology map[string]string) dagStepResult {
	if result.receipt.Attempt <= 0 {
		result.receipt.Attempt = 1
	}
	if result.receipt.MaxAttempts <= 0 {
		result.receipt.MaxAttempts = 1
	}
	if result.receipt.State != "completed" && result.receipt.State != "failed" {
		return result
	}
	now := time.Now().UTC()
	attempt := operationsvc.AttemptReceipt{
		Number:         result.receipt.Attempt,
		State:          result.receipt.State,
		ObjectSHA256:   result.receipt.ObjectSHA256,
		OutputComplete: result.receipt.OutputComplete,
		Runtime:        result.receipt.Runtime,
		ContractState:  result.receipt.ContractState,
		MatchedTag:     result.receipt.MatchedTag,
		MatchedFields:  append([]string(nil), result.receipt.MatchedFields...),
		Captures:       cloneStringMap(result.receipt.Captures),
		StartedAt:      result.receipt.StartedAt,
		CompletedAt:    now.Format(time.RFC3339Nano),
	}
	if result.receipt.State == "failed" && step.Retry != nil && result.receipt.OutputComplete && result.receipt.Runtime.ExecutionState == "completed" && result.receipt.ReadyState != "ready" {
		if reason, matched := operationsvc.MatchRetry(result.output, step.Retry, inputs, captures, topology); matched {
			attempt.RetryReason = reason
			if result.receipt.Attempt < step.Retry.MaxAttempts {
				delay := operationsvc.RetryDelay(step.Retry, result.receipt.Attempt)
				next := now.Add(delay)
				attempt.State, attempt.DelayMS, attempt.NextEligibleAt = "retry", int(delay/time.Millisecond), next.Format(time.RFC3339Nano)
				result.receipt.Attempts = append(result.receipt.Attempts, attempt)
				result.receipt.Attempt++
				result.receipt.State, result.receipt.ContractState = "retry_wait", "pending"
				result.receipt.RetryState, result.receipt.RetryReason, result.receipt.NextAttemptAt = "waiting", reason, attempt.NextEligibleAt
				result.receipt.Runtime, result.receipt.ObjectSHA256 = runtimeadapter.Receipt{}, ""
				result.receipt.OutputComplete, result.receipt.Captures = false, nil
				result.receipt.Error, result.receipt.StartedAt, result.receipt.CompletedAt = "", "", ""
				result.receipt.MatchedTag, result.receipt.MatchedFields = "", nil
				result.receipt.ReadyState, result.receipt.ReadyContractState = "pending", "pending"
				result.receipt.ReadyAt, result.receipt.ReadyCaptures = "", nil
				result.err = nil
				return result
			}
			result.receipt.RetryState, result.receipt.RetryReason = "exhausted", reason
			if result.receipt.Error == "" {
				result.receipt.Error = fmt.Sprintf("retry limit exhausted after %d attempts (%s)", result.receipt.Attempt, reason)
			}
		}
	}
	result.receipt.Attempts = append(result.receipt.Attempts, attempt)
	if result.receipt.State == "completed" && len(result.receipt.Attempts) > 1 {
		result.receipt.RetryState = "completed"
	}
	return result
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func settleDAGRuntimeTasks(ctx context.Context, receipt *operationsvc.Receipt, opts operationOptions, path string, timeout time.Duration) {
	if receipt == nil {
		return
	}
	for index := range receipt.Steps {
		step := &receipt.Steps[index]
		if step.Runtime.Runtime == "" || step.Runtime.ReceiptPath == "" || runtimeTaskTerminal(step.Runtime.ExecutionState) {
			continue
		}
		updated, err := cancelOperationRuntimeReceipt(ctx, step.Runtime, opts)
		if err != nil {
			step.CancellationState = "unsupported"
			if step.Error == "" {
				step.Error = err.Error()
			}
			continue
		}
		step.Runtime, step.CancellationState = updated, "requested"
	}
	deadline := time.Now().Add(timeout)
	for {
		active := false
		for index := range receipt.Steps {
			step := &receipt.Steps[index]
			if step.Runtime.Runtime == "" || step.Runtime.ReceiptPath == "" || runtimeTaskTerminal(step.Runtime.ExecutionState) {
				continue
			}
			active = true
			updated, err := refreshOperationRuntimeReceipt(ctx, step.Runtime, opts)
			if err == nil {
				step.Runtime = updated
				if runtimeTaskTerminal(updated.ExecutionState) {
					step.CancellationState = "completed"
					if step.State == "running" || step.State == "ready" || step.State == "incomplete" {
						step.State = "canceled"
					}
				}
			}
		}
		_ = operationsvc.SaveReceipt(path, receipt)
		if !active || time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func activeDAGStepIndexes(receipt operationsvc.Receipt) []int {
	var indexes []int
	for index, step := range receipt.Steps {
		switch step.State {
		case "running", "ready", "incomplete":
			indexes = append(indexes, index)
		}
	}
	return indexes
}

func requestDAGActiveCancellation(ctx context.Context, receipt *operationsvc.Receipt, indexes []int, opts operationOptions) {
	if receipt == nil {
		return
	}
	for _, index := range indexes {
		step := &receipt.Steps[index]
		if step.Runtime.Runtime == "" || step.Runtime.ReceiptPath == "" || runtimeTaskTerminal(step.Runtime.ExecutionState) {
			continue
		}
		updated, err := cancelOperationRuntimeReceipt(ctx, step.Runtime, opts)
		if err != nil {
			step.CancellationState = "unsupported"
			if step.Error == "" {
				step.Error = err.Error()
			}
			continue
		}
		step.Runtime, step.CancellationState = updated, "requested"
	}
}

func dagWaveState(ids []string, steps []operationsvc.StepReceipt) string {
	state := "completed"
	for _, id := range ids {
		for _, step := range steps {
			if step.ID != id {
				continue
			}
			switch step.State {
			case "failed":
				return "failed"
			case "canceled":
				state = "canceled"
			case "incomplete":
				if state != "canceled" {
					state = "incomplete"
				}
			case "pending", "running", "ready", "retry_wait":
				if state == "completed" {
					state = "active"
				}
			}
			break
		}
	}
	return state
}

func refreshRecordedDAGWaves(receipt *operationsvc.Receipt) {
	if receipt == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for index := range receipt.ExecutionWaves {
		wave := &receipt.ExecutionWaves[index]
		state := dagWaveState(wave.Steps, receipt.Steps)
		wave.State = state
		if state != "active" && wave.CompletedAt == "" {
			wave.CompletedAt = now
		}
	}
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
		if step.Mode == "background" || item.Document.SchemaVersion >= 7 {
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
	if step.Mode != "background" && item.Document.SchemaVersion >= 7 && !result.receipt.OutputComplete &&
		(result.receipt.Runtime.Runtime == "native" || result.receipt.Runtime.Runtime == "lab") &&
		(result.receipt.Runtime.ExecutionState == "submitted" || result.receipt.Runtime.ExecutionState == "running") {
		result.receipt.State = "running"
		return result
	}
	if step.Mode == "background" {
		if result.receipt.State == "canceled" {
			return result
		}
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
		if !result.receipt.OutputComplete && (result.receipt.State == "running" || result.receipt.State == "incomplete" || result.receipt.State == "ready") {
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

func syncDAGCancellationRequest(path string, receipt *operationsvc.Receipt) bool {
	if receipt == nil {
		return false
	}
	latest, err := operationsvc.LoadReceipt(path)
	if err == nil && latest.CancelRequestedAt != "" {
		receipt.CancelRequestedAt = latest.CancelRequestedAt
		receipt.CancellationState = latest.CancellationState
	}
	if _, err := os.Stat(path + ".cancel"); err == nil {
		if receipt.CancelRequestedAt == "" {
			receipt.CancelRequestedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		receipt.CancellationState = "requested"
	}
	return receipt.CancelRequestedAt != ""
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
