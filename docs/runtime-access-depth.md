# Runtime Access and Configuration Depth

This tranche adds four read-only public packs and seven operator-controlled private packs. Each uses typed runtime arguments, builds for x64 and x86, emits structured output, and exports as a raw object, Sliver extension, or Cobalt Strike package.

## Inspect access and local state

Check what the current Windows security context can open on a selected process:

```bash
bofbench new access-check --pack process-access-check
bofbench run bofs/access-check --via lab --lab devbox \
  --arg target_pid=1234 --arg access_mask=0
```

`access_mask=0` tests BOFBench's named standard rights. A nonzero mask tests exactly that operator-supplied Windows access mask.

Enumerate exports from one selected process module:

```bash
bofbench new exports --pack module-export-inventory
bofbench run bofs/exports --via lab --lab devbox \
  --arg target_pid=1234 --arg module_filter=kernel32.dll --arg result_limit=40
```

Inventory local account policy and neighbor-cache state:

```bash
bofbench new host-policy --pack local-account-policy-inventory,network-neighbor-inventory
bofbench run bofs/host-policy --via lab --lab devbox \
  --arg family=0 --arg state_filter=0 --arg result_limit=64
```

## Duplicate and close selected handles

The private handle pair accepts exact source and target process contexts:

```bash
bofbench new handle-op --pack internal/process-handle-duplicate
bofbench run bofs/handle-op --via lab --lab devbox \
  --arg source_pid=1234 --arg source_handle=0x88 \
  --arg target_pid=5678 --arg desired_access=0 --arg options=2
```

Capture `duplicated_handle` from structured output and close that exact handle when wanted:

```bash
bofbench new handle-close --pack internal/process-handle-close
bofbench run bofs/handle-close --via lab --lab devbox \
  --arg target_pid=5678 --arg target_handle=0x9c
```

## Change and restore a process command line

The action accepts an arbitrary PID and replacement. `guard_mode=identity` and `backup_path` are optional controls, not runtime requirements.

```bash
bofbench new cmdline-set --pack internal/process-command-line-set
bofbench run bofs/cmdline-set --via lab --lab devbox \
  --arg target_pid=1234 --arg command_line='worker.exe --mode alternate' \
  --arg guard_mode=none --arg backup_path='C:\bofbench\cmdline.bak'

bofbench new cmdline-restore --pack internal/process-command-line-restore
bofbench run bofs/cmdline-restore --via lab --lab devbox \
  --arg target_pid=1234 --arg backup_path='C:\bofbench\cmdline.bak' \
  --arg remove_backup=1
```

## Execute through a threadpool wait callback

This pack executes operator-supplied bytes in the current BOF host process, which means the native loader, Sliver session process, or Beacon process selected by the runtime:

```bash
bofbench new tpwait --pack internal/threadpool-wait-execute
bofbench run bofs/tpwait --via sliver --lab devbox \
  --arg target_pid=0 --arg payload=@file:callback.bin \
  --arg timeout_ms=5000 --arg free_after=1
```

## Change and restore service configuration

Select the exact service and fields to change. Omitted fields remain unchanged. An identity guard and backup are optional.

```bash
bofbench new service-set --pack internal/service-config-set
bofbench run bofs/service-set --via lab --lab devbox \
  --arg service_name=ExampleSvc \
  --arg binary_path='C:\Tools\service.exe --worker' \
  --arg start_type=3 --arg guard_mode=none \
  --arg backup_path='C:\bofbench\service-config.bak'

bofbench new service-restore --pack internal/service-config-restore
bofbench run bofs/service-restore --via lab --lab devbox \
  --arg service_name=ExampleSvc \
  --arg backup_path='C:\bofbench\service-config.bak' \
  --arg remove_backup=1
```

Passwords can use `@prompt`, `@env:NAME`, or `@file:path`; receipts record the argument name but not its value.

## Prove and resume

Proofs use BOFBench's disposable target and independent state checks while the packs themselves remain operator-controlled:

```bash
bofbench pack prove internal/process-handle-duplicate --via lab --lab devbox
bofbench pack prove internal/process-command-line-set --via lab --lab devbox
bofbench pack prove internal/threadpool-wait-execute --via lab --lab devbox
bofbench pack prove internal/service-config-set --via lab --lab devbox
```

For a large Sliver lane, inspect and resume incomplete work with the runtime commands documented in [Run a BOF](runtime.md).
