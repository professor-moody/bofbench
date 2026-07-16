# Refresh and Complete a C2 Task

## Objective

Turn a submitted or partially collected Sliver/Cobalt Strike task receipt into a terminal, output-complete receipt before an operation contract advances.

## Inspect runtime readiness

```bash
bofbench runtime status --lab devbox
bofbench runtime sessions --via sliver --lab devbox
bofbench runtime tasks --via sliver --lab devbox
```

No live session is represented as unavailable. Deterministic adapter fixtures used by tests are not live C2 evidence.

## Refresh one task

Use either its task ID or receipt path:

```bash
bofbench runtime task <TASK_ID> --refresh
bofbench runtime task runs/<runtime-run>/result.json --refresh
```

Wait for a terminal result:

```bash
bofbench runtime task <TASK_ID> \
  --refresh --wait --timeout 10m --interval 2s
```

Runtime-receipt version 5 records:

- last refresh time and completion source;
- session and task ID;
- numbered output chunks and final-chunk state;
- complete versus partial output classification;
- remote task error and terminal reason;
- exact object hash and redaction metadata.

Sliver refresh retrieves the exact persisted task using the recorded session/task pair. Cobalt Strike live completion requires the licensed callback path and waits for `task_completed`, error, or timeout.

## Watch all incomplete tasks

```bash
bofbench runtime watch \
  --via sliver --lab devbox --refresh \
  --timeout 10m --interval 2s
```

The display changes only when session or task state changes.

## Resume an operation

```bash
bofbench operation resume runs/<operation-run>/operation.json \
  --parallelism 4
```

Resume refreshes incomplete C2 step receipts before contract evaluation. Completed steps are not rerun. A task must be terminal, output-complete, and contract-matched before dependents enter the next ready wave.

## Interpret states

| State | Meaning |
| --- | --- |
| `submitted` | Runtime accepted work; completion is unknown. |
| `running` | Remote work is active or retained output is not final. |
| `completed` | Terminal success with complete output. |
| `failed` / `canceled` | Terminal remote failure. |
| `timeout` | No terminal result arrived before the selected limit. |

`output_classification=partial` or `final_chunk=false` is never a pass.

## Sensitive output

Recovered sensitive bytes may be verified in memory before redaction. Persisted receipts keep field names, sizes, and hashes, not the sensitive value.

## Common failures

- missing task ID: the original runtime output did not provide a refreshable task reference;
- session mismatch: use the profile/session recorded in the receipt;
- task expired from remote storage: retain the incomplete receipt and record coverage as unavailable or failed according to the runtime response;
- callback timeout: do not treat submission as completion;
- object hash mismatch: observed output cannot be correlated to a different analyzed object.

