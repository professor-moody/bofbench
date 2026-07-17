package app

import (
	"testing"

	operationsvc "bofbench/internal/operation"
	packsvc "bofbench/internal/pack"
	"bofbench/internal/runtimeadapter"
)

func retryTestStep() operationsvc.Step {
	return operationsvc.Step{
		ID:     "request",
		Expect: &packsvc.ProofExpectation{Tag: "request", Fields: map[string]string{"status": "complete", "http_status": "200"}},
		Retry: &operationsvc.RetryPolicy{
			MaxAttempts: 3,
			DelayMS:     1,
			Backoff:     "fixed",
			When:        []operationsvc.RetryContract{{ID: "transient-http", Expect: packsvc.ProofExpectation{Tag: "request", Fields: map[string]string{"status": "complete", "http_status": "503"}}}},
		},
	}
}

func TestApplyDAGRetrySchedulesOnlyDeclaredCompleteResult(t *testing.T) {
	base := dagStepResult{receipt: operationsvc.StepReceipt{
		ID: "request", State: "failed", ContractState: "failed", Attempt: 1, MaxAttempts: 3, OutputComplete: true,
		Runtime: runtimeadapter.Receipt{ExecutionState: "completed", OutputComplete: true},
	}, output: []string{"[request] status=complete http_status=503"}}
	retried := applyDAGRetry(retryTestStep(), base, nil, nil, nil)
	if retried.receipt.State != "retry_wait" || retried.receipt.Attempt != 2 || retried.receipt.RetryReason != "transient-http" || len(retried.receipt.Attempts) != 1 {
		t.Fatalf("declared transient result was not scheduled: %#v", retried.receipt)
	}

	nonmatching := base
	nonmatching.output = []string{"[request] status=complete http_status=500"}
	nonmatchingResult := applyDAGRetry(retryTestStep(), nonmatching, nil, nil, nil)
	if nonmatchingResult.receipt.State != "failed" || nonmatchingResult.receipt.RetryState != "" {
		t.Fatalf("undeclared result was retried: %#v", nonmatchingResult.receipt)
	}

	runtimeFailure := base
	runtimeFailure.receipt.Runtime.ExecutionState = "failed"
	runtimeFailureResult := applyDAGRetry(retryTestStep(), runtimeFailure, nil, nil, nil)
	if runtimeFailureResult.receipt.State != "failed" || runtimeFailureResult.receipt.RetryState != "" {
		t.Fatalf("runtime failure was retried: %#v", runtimeFailureResult.receipt)
	}
}

func TestApplyDAGRetryNeverRestartsReadyBackgroundStepAndExhausts(t *testing.T) {
	base := dagStepResult{receipt: operationsvc.StepReceipt{
		ID: "request", State: "failed", ContractState: "failed", Attempt: 1, MaxAttempts: 3, OutputComplete: true, ReadyState: "ready",
		Runtime: runtimeadapter.Receipt{ExecutionState: "completed", OutputComplete: true},
	}, output: []string{"[request] status=complete http_status=503"}}
	ready := applyDAGRetry(retryTestStep(), base, nil, nil, nil)
	if ready.receipt.State != "failed" || ready.receipt.RetryState != "" {
		t.Fatalf("ready background step restarted: %#v", ready.receipt)
	}

	base.receipt.ReadyState, base.receipt.Attempt = "pending", 3
	exhausted := applyDAGRetry(retryTestStep(), base, nil, nil, nil)
	if exhausted.receipt.State != "failed" || exhausted.receipt.RetryState != "exhausted" || exhausted.receipt.RetryReason != "transient-http" {
		t.Fatalf("retry limit was not exhausted: %#v", exhausted.receipt)
	}
}

func TestOperationProofRetryExpectations(t *testing.T) {
	receipt := operationsvc.Receipt{Steps: []operationsvc.StepReceipt{{
		ID: "request", Attempt: 2, Attempts: []operationsvc.AttemptReceipt{
			{Number: 1, RetryReason: "transient-http"},
			{Number: 2},
		},
	}}}
	attempts, reasons := operationRetryResults(receipt)
	if err := matchOperationProofAttempts(map[string]int{"request": 2}, attempts); err != nil {
		t.Fatal(err)
	}
	if err := matchOperationProofRetryReasons(map[string][]string{"request": {"transient-http"}}, reasons); err != nil {
		t.Fatal(err)
	}
	if err := matchOperationProofAttempts(map[string]int{"request": 1}, attempts); err == nil {
		t.Fatal("expected attempt mismatch")
	}
}
