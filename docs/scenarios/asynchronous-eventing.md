# Asynchronous Eventing and Cancellation

## Objective

Use a version-7 operation to arm a Windows watcher, confirm that it is ready, perform an exact change, observe the notification, and inspect or cancel the active work. Use this pattern when the event consumer must already be listening before the action occurs.

## Resulting capability

This scenario demonstrates:

- atomically readable live operation receipts;
- native/lab runtime task start, refresh, progress, and cancellation;
- `depends_on_ready` scheduling;
- exact-hash action and cleanup correlation;
- Event Log, ETW, registry, directory, service, process-exit, and event-callback workflows.

## Prerequisites

- a bootstrapped Windows profile named `devbox`;
- the private catalog configured or passed with `--catalog`;
- the disposable target deployed for proof placeholders;
- x64 or x86 MinGW on the operator workstation.

```bash
bofbench lab bootstrap --lab devbox
bofbench lab target deploy --lab devbox
bofbench runtime status --lab devbox
```

## Inspect and prove a registry watcher

```bash
bofbench operation show internal/registry-change-observe
bofbench operation graph internal/registry-change-observe --format mermaid
bofbench operation prove internal/registry-change-observe \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox --arch x64
```

Expected scheduling:

```text
wave 1  watch
watch   status=ready
wave 2  trigger
trigger status=created|replaced
watch   status=complete changed=1
cleanup status=removed
```

The trigger cannot enter wave two until `[registry-change-wait] status=ready` matches. The watcher remains active while the write executes, then must emit its separate terminal `status=complete` result.

## Watch a live receipt

Start an ordinary operation in one terminal:

```bash
bofbench operation run internal/filesystem-change-observe \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox \
  --arg target_host=DEVBOX \
  --arg directory='C:\bofbench\proof' \
  --arg share=C$ \
  --arg relative_path='bofbench\proof\operator-change.bin' \
  --arg content=@file:/absolute/path/request.bin \
  --arg content_sha256=<SHA256> \
  --arg timeout_ms=120000
```

Follow its receipt from another terminal:

```bash
bofbench operation watch runs/<run-id>/operation.json --follow
bofbench runtime tasks --via lab
```

Read `ready_state`, `ready_at`, `last_progress_at`, the worker/task ID, and the final runtime/contract state separately. A ready watcher has not completed; it has only authorized its readiness-dependent descendants to start.

## Cancel and optionally clean

```bash
bofbench operation cancel runs/<run-id>/operation.json
bofbench operation cancel runs/<run-id>/operation.json --cleanup
```

Cancellation stops new scheduling and requests cancellation for every active isolated loader task. On a named lab, the receipt identifies a run-specific Windows controller task and remote worker PID; BOFBench removes that exact process tree before optional cleanup begins. Cleanup applies only to completed stateful steps. A completed operation is not relabeled canceled; unsupported C2 task cancellation is recorded as unsupported.

## Event Log and ETW session

```bash
bofbench operation prove internal/event-stream-session \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox --arch x64
```

This operation starts and queries an exact ETW session, arms Event Log and ETW consumers concurrently, waits for both readiness contracts, triggers known process/event activity, then stops the exact session during cleanup. Automated proof resolves `$TARGET_ETW_PROVIDER_GUID` to the disposable target's registered provider, which emits bounded fixture events continuously while the target is active. The resulting proof is deterministic without restricting an ordinary run from selecting another provider.

## Architecture variation

Repeat any proof with `--arch x86`. Registry operations expose `view=native|32|64`, so the selected object architecture does not silently change which registry view is observed.

## Evidence and recovery

- Operation receipt: `runs/<id>/operation.json`
- Runtime task receipt: `runs/<id>/result.json`
- Proof report: `runs/<id>/operation-proof.json`

If readiness never arrives, verify the exact target and Windows view, inspect the task output, then cancel the receipt. If a terminal output line does not match the declared contract, fix the pack/operation contract rather than treating loader completion as success.

Related pages: [Multi-Step Operations](../operations.md), [Runtime Adapters](../runtime.md), [Runtime Receipts](../evidence.md), and [Troubleshooting](../troubleshooting.md).
