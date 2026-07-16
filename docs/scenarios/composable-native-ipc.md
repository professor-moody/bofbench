# Compose Native IPC Operations

## Objective

Use BOFBench's public coordination inventory and schema-version-4 operation graph to understand a Windows process's synchronization surface, then inspect a composed private operation without flattening it into one large definition.

The public lane is read-only. The private `coordination-matrix` lane creates exact operator-selected mutex, semaphore, timer, and mailslot objects; passes retained handles across child operations; launches one supplied child command with an explicit inherited handle; and retains recursive reverse cleanup.

## Prerequisites

- BOFBench and MinGW available on the operator workstation.
- A named Windows lab profile for live execution.
- The private catalog configured only for the private lane.
- A holder PID that the selected token may open with `PROCESS_DUP_HANDLE`.
- An input file and its byte count/SHA-256 for the mailslot request.

Confirm the surfaces first:

```bash
bofbench lab status --lab devbox
bofbench pack show process-handle-detail-inventory
bofbench pack show synchronization-object-state
bofbench pack show mailslot-inventory
bofbench operation show coordination-surface-triage
```

## Run public coordination triage

```bash
bofbench operation run coordination-surface-triage \
  --via lab --lab devbox --arch x64 \
  --arg target_pid=<HOLDER_PID> \
  --arg object_type=mutex \
  --arg object_name='Global\SelectedMutex' \
  --arg mailslot_prefix=BOFBench \
  --arg result_limit=32
```

Expected terminal shape:

```text
step 1/3  handles → builtin/process-handle-detail-inventory
[process-handle-detail-inventory] status=complete target_pid=4312 shown=4 limit=32
step 2/3  state → builtin/synchronization-object-state
[synchronization-object-state] status=complete object_type=mutex count=1 owned=0 abandoned=0
step 3/3  mailslots → builtin/mailslot-inventory
[mailslot-inventory] status=complete shown=1 limit=32
operation  completed
```

`count=1` indicates the mutex was available when queried. The inspection does not wait on or acquire it. The handle and mailslot inventories are bounded by `result_limit`.

## Inspect the composed private graph

```bash
bofbench operation graph internal/coordination-matrix
bofbench operation graph internal/coordination-matrix --expand
bofbench operation show internal/coordination-matrix --expand
```

The collapsed graph treats each lifecycle as an atomic node. The expanded graph exposes `mutex/create`, `mutex/query_before`, `mutex/acquire_release`, and `mutex/query_after` without changing the parent definition. Direct and indirect operation-call cycles are rejected during catalog loading.

## Run the composed matrix

```bash
printf 'operator request' > /secure/request.bin
REQUEST_SIZE=$(wc -c < /secure/request.bin | tr -d ' ')
REQUEST_SHA256=$(shasum -a 256 /secure/request.bin | awk '{print $1}')

bofbench operation run internal/coordination-matrix \
  --via lab --lab devbox --arch x64 --cleanup \
  --arg holder_pid=<HOLDER_PID> \
  --arg mutex_name='Global\OperatorMutex' \
  --arg semaphore_name='Global\OperatorSemaphore' \
  --arg timer_name='Global\OperatorTimer' \
  --arg mailslot_name='\\.\mailslot\OperatorRequest' \
  --arg message=@file:/secure/request.bin \
  --arg message_size="$REQUEST_SIZE" \
  --arg message_sha256="$REQUEST_SHA256" \
  --arg command='C:\Windows\System32\cmd.exe /d /c ping -t 127.0.0.1'
```

The request bytes are available to the live pack but remain redacted in stored receipts. The mailslot read step reassembles live hex output in memory and checks the supplied SHA-256 before it advances.

## Read the receipts

Open the printed `runs/<run-id>/operation.json` and inspect:

- `dependency_sha256`: the transitive parent, child-operation, pack, and cleanup hashes;
- `actual_path`: the six parent steps;
- `expanded_path`: slash-qualified child steps in execution order;
- `steps[].child_receipt`: the durable child checkpoint;
- `steps[].captures`: only explicitly exported, non-sensitive values;
- `steps[].child_cleanup_state`: recursive cleanup progress.

If a C2 child remains submitted or running, the parent is `incomplete`. Resume the parent receipt; BOFBench delegates to the child before considering the next parent step:

```bash
bofbench operation resume runs/<run-id>/operation.json
```

## Cleanup and recovery

With `--cleanup`, BOFBench first terminates the captured child, then cleans the mailslot, timer, semaphore, and mutex children in reverse order. Cleanup can also be requested later:

```bash
bofbench operation cleanup runs/<run-id>/operation.json
```

If cleanup stops, keep the receipt. Rerunning `operation cleanup` skips already completed cleanup steps and resumes from the first incomplete nested cleanup. Definition or dependency hash changes are rejected because the recorded captures belong to the pinned code.

## Variations

- Use `--arch x86` to prove the same contracts against the x86 loader and target helper.
- Run `named-mutex-lifecycle`, `named-semaphore-lifecycle`, `named-timer-lifecycle`, or `mailslot-roundtrip` directly when only one IPC primitive is needed.
- Change the object names and child command freely; the proof fixture names are not normal runtime requirements.
- Omit `--cleanup` when retained objects are intentional, then use the receipt for explicit later cleanup.

Related guidance: [Composable operations](../operations.md), [runtime receipts](../evidence.md), [operator TUI](../tui.md), and [troubleshooting](../troubleshooting.md).
