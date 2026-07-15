# Multi-Step Operation Lifecycle

## Objective and result

Use a catalog-backed operation to pass structured output between BOFs, inspect its checkpoint, resume incomplete runtime work, and perform reverse cleanup. The section lifecycle example maps supplied bytes, captures the remote base, starts a thread at that base, and retains exact unmap cleanup.

## Prerequisites

- The internal catalog is configured.
- `devbox` is a reachable Windows lab profile.
- The selected PID is an authorized process for which the operator has the required process rights.
- The payload matches the selected architecture.

Use an existing architecture-matched payload file. Automated proof uses a one-byte return payload; ordinary operation accepts the operator-selected file.

## Inspect the operation

```bash
bofbench operation show internal/section-map-start-unmap
```

Confirm that `map` captures `remote_base` and `mapped_bytes`, and that `start` consumes the captured base.

## Execute

```bash
bofbench operation run internal/section-map-start-unmap \
  --via lab --lab devbox --arch x64 \
  --arg target_pid=1234 \
  --arg payload=@file:/tmp/ret.bin \
  --arg wait_ms=5000
```

Annotated output:

```text
step 1/2  map → bofbench-packs-internal/process-section-map
  result     [process-section-map] status=complete target_pid=1234 remote_base=0x000001F400000000 bytes=1 protection=0x00000020
  captured   mapped_bytes=1
  captured   remote_base=0x000001F400000000
step 2/2  start → bofbench-packs-internal/process-thread-start
  result     [process-thread-start] status=complete target_pid=1234 thread_id=5678 start_address=0x000001F400000000 exit_code=0
  captured   thread_id=5678
operation  completed
receipt    runs/<run-id>/operation.json
```

The `remote_base` in the second line must equal the captured base from the first line. Each step runtime receipt records complete output and an exact object hash.

## Inspect and resume

```bash
bofbench runtime task runs/<runtime-run-id>/result.json
bofbench operation resume runs/<run-id>/operation.json
```

For a completed native or lab run, resume skips both steps. For an incomplete Sliver task, resume continues at the incomplete step after complete output becomes available. Sensitive payload data is not stored; resupply it only when the unfinished step requires it.

## Cleanup

```bash
bofbench operation cleanup runs/<run-id>/operation.json
```

Expected cleanup output:

```text
cleanup     map → bofbench-packs-internal/process-section-unmap
  result     [process-section-unmap] status=complete target_pid=1234 remote_base=0x000001F400000000
cleanup     completed
receipt     runs/<run-id>/operation.json
```

Cleanup uses the persisted non-sensitive base capture and runs in reverse step order. It remains optional; `--cleanup` and `--cleanup-on-failure` are convenience controls.

## Variations

- Use `--arch x86` with an x86 target and payload.
- Use `guard_mode=none` in a custom operation for unguarded unmap, or keep the starter operation's identity check.
- Use `memory-find-read` to pass a discovered address into a bounded read.
- Use `memory-patch-restore --cleanup` to patch and restore an exact range in one invocation.
- Use `remote-service-lifecycle` with a topology to pass exact host and credential context through create/start/cleanup.

## Failures and recovery

- `capture remote_base did not find`: inspect the map step output; it did not complete successfully or its output contract changed.
- `operation definition changed`: begin a new run after the catalog update.
- `output was incomplete`: inspect the runtime task and resume the operation.
- cleanup access denied: confirm the selected lab context still has access to the same PID and mapping.

Related: [multi-step operations](../operations.md), [runtime receipts](../evidence.md), and [process execution depth](../operator-execution-depth.md).
