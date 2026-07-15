# Multi-Step Operation Lifecycle

## Objective and result

Use a catalog-backed operation to validate every participating pack, pass structured output between BOFs, route an explicitly understood result, inspect its checkpoint, prove live behavior, and perform reverse cleanup. The virtual-memory example remains linear; the adaptive-memory example prefers section mapping and routes a declared clean failure to allocation, write, protection, and thread start.

## Prerequisites

- The internal catalog is configured.
- `devbox` is a reachable Windows lab profile.
- The selected PID is an authorized process for which the operator has the required process rights.
- The payload matches the selected architecture.

Use an existing architecture-matched payload file. Automated proof uses a one-byte return payload; ordinary operation accepts the operator-selected file.

## Inspect and test the operation

```bash
bofbench operation show internal/virtual-memory-execute
bofbench operation graph internal/adaptive-memory-execute
bofbench operation test internal/virtual-memory-execute \
  --catalog ~/bofbench-packs-internal \
  --compiler mingw --compiler msvc
```

Confirm that `allocate` captures `remote_base`, later steps consume that value, every step requires `status=complete`, and `allocate` retains `process-memory-free` as optional reverse cleanup. Static test builds each unique action and cleanup pack, checks its analyzer contract, and verifies all three export formats.

## Prove the declared workflow

```bash
bofbench operation prove internal/virtual-memory-execute \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox --arch x64
```

The proof engine resolves a disposable target PID and benign return payload, verifies the allocated region after the action, frees the captured region in reverse cleanup, then independently confirms that the exact captured base is absent. The report is written to:

```text
runs/<run-id>/operation-proof.json
```

Repeat with `--arch x86` to exercise the x86 target helper and loader path.

## Execute

```bash
bofbench operation run internal/virtual-memory-execute \
  --via lab --lab devbox --arch x64 \
  --arg target_pid=1234 \
  --arg payload=@file:/absolute/path/payload.bin \
  --arg payload_size=1 \
  --arg payload_sha256=<sha256> \
  --arg wait_ms=5000
```

Annotated output:

```text
step 1/4  allocate → bofbench-packs-internal/process-memory-allocate
  result     [process-memory-allocate] status=complete target_pid=1234 remote_base=0x000001F400000000 bytes=1 protection=0x4
  captured   allocated_bytes=1
  captured   remote_base=0x000001F400000000
step 2/4  write → bofbench-packs-internal/process-memory-write
  result     [process-memory-write] status=complete target_pid=1234 address=0x000001F400000000 bytes=1 after_sha256=<sha256> backup=skipped
step 3/4  protect → bofbench-packs-internal/process-memory-protect
  result     [process-memory-protect] status=complete target_pid=1234 address=0x000001F400000000 before=0x4 after=0x20
step 4/4  start → bofbench-packs-internal/process-thread-start
  result     [process-thread-start] status=complete target_pid=1234 thread_id=5678 start_address=0x000001F400000000 exit_code=0
  captured   thread_id=5678
operation  completed
receipt    runs/<run-id>/operation.json
```

The address in every later step must equal the captured base from `allocate`. Each step receipt records runtime completion separately from contract matching. If a BOF emits `[process-memory-protect] status=failed`, the operation stops even when the loader itself exits normally.

For a result-routed operation, inspect `actual_path`, `matched_outcome`, and `skipped_steps` in the version-3 receipt. Only declared complete output selects a route. Runtime crashes, timeouts, and incomplete C2 work stop without fallback because their effects are unknown.

## Inspect and resume

```bash
bofbench runtime task runs/<runtime-run-id>/result.json
bofbench operation resume runs/<run-id>/operation.json
```

For a completed native or lab run, resume skips completed steps. For an incomplete Sliver task, resume refreshes the task, reevaluates the result contract, and continues only after complete successful output. Sensitive payload data is not stored; resupply it only when the unfinished step requires it.

## Cleanup

```bash
bofbench operation cleanup runs/<run-id>/operation.json
```

Expected cleanup output:

```text
cleanup     allocate → bofbench-packs-internal/process-memory-free
  result     [process-memory-free] status=complete target_pid=1234 remote_base=0x000001F400000000 free_type=32768
cleanup     completed
receipt     runs/<run-id>/operation.json
```

Cleanup uses the persisted non-sensitive base capture and runs in reverse step order. It remains optional for ordinary operation; declared proof cases can require it and independently confirm that the region no longer exists.

## Variations

- Use `--arch x86` with an x86 target and payload.
- Use `memory-allocation-roundtrip` to allocate, write, read, hash-verify, and free without starting execution.
- Use `named-pipe-roundtrip` to capture a generated pipe path and verify a bounded sensitive response hash.
- Use `thread-context-lifecycle` to suspend, inspect, selectively modify, resume, and retain restore cleanup.
- Use `memory-find-read` to pass a discovered address into a bounded read.
- Use `memory-patch-restore --cleanup` to patch and restore an exact range in one invocation.
- Use `remote-service-lifecycle` with a topology to pass exact host and credential context through create/start/cleanup.
- Use `adaptive-memory-execute` to prove a primary section-map path and a controlled allocation fallback.
- Use `named-event-lifecycle`, `shared-section-roundtrip`, and `job-contained-process` to pass object names and retained handles through native coordination steps.

## Failures and recovery

- `step ... result contract`: inspect the structured result. Runtime completion alone does not mean the BOF reported success.
- `capture remote_base did not find`: inspect the allocation output; captures are extracted only after its contract matches.
- `operation definition changed`: begin a new run after the catalog update.
- `output was incomplete`: inspect the runtime task and resume the operation.
- cleanup access denied: confirm the selected lab context still has access to the same PID and region.

Related: [multi-step operations](../operations.md), [runtime receipts](../evidence.md), and [process execution depth](../operator-execution-depth.md).
