# Live Capability Proof

This walkthrough proves the complete operator loop with direct BOFBench commands. It uses one unchanged project across x64 lab execution, x86 lab execution, and a Sliver session associated with the same named Windows profile.

Use only Windows systems and C2 sessions you own or are authorized to test.

## Public-safe lane

### Register and inspect the target

```bash
bofbench lab add dedicated \
  --provider existing \
  --transport ssh \
  --host windows-lab \
  --user operator \
  --build-mode auto

bofbench lab bootstrap --lab dedicated
bofbench lab status --lab dedicated
```

The profile may point to a VM, a physical host, an SSH alias, or an IP address. For WinRM and Vagrant variants, see [Portable Lab Profiles](lab-profiles.md).

### Build and explain one parameterized BOF

```bash
bofbench new portable-survey --pack deep-survey
bofbench build bofs/portable-survey --arch x64
bofbench build bofs/portable-survey --arch x86
bofbench analyze bofs/portable-survey
```

The analysis should name discovery capabilities, read-only effects, `process_filter` and `result_limit` argument types, runtime requirements, and supported targets.

### Run different queries without rebuilding

```bash
bofbench run bofs/portable-survey --via lab --lab dedicated --arch x64 \
  --arg process_filter=lsass --arg result_limit=5

bofbench run bofs/portable-survey --via lab --lab dedicated --arch x64 \
  --arg process_filter=svchost --arg result_limit=10

bofbench run bofs/portable-survey --via lab --lab dedicated --arch x86 \
  --arg process_filter=explorer --arg result_limit=5
```

This proves runtime parameter changes and x64/x86 dispatch while leaving the project source unchanged.

### Run the same x64 project through Sliver

Set a session selector once if the profile does not already have one:

```bash
bofbench lab add dedicated-sliver \
  --from dedicated \
  --sliver-session DEDICATED-BOF

bofbench sliver setup --lab dedicated-sliver
bofbench sliver sessions --lab dedicated-sliver
bofbench run bofs/portable-survey --via sliver --lab dedicated-sliver \
  --arg process_filter=lsass --arg result_limit=5
```

The Sliver receipt should contain the same object hash and typed values as the analyzed x64 object, plus its selected session and captured output.

### Explain an external open-source BOF

```bash
bofbench arsenal acquire https://github.com/trustedsec/CS-Situational-Awareness-BOF \
  --name trustedsec-sa
bofbench arsenal inventory arsenal/trustedsec-sa
bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
bofbench analyze bofs/portable-survey \
  --compare arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
```

The report should distinguish identity/token discovery in `whoami` from the broader parameterized survey rather than stopping at raw imports.

## Privileged internal lane

The internal lane is deliberately constrained to a disposable target process and uniquely named artifacts. Do not substitute a critical Windows process or real credential material. Run state-changing packs only on a snapshot-backed or otherwise disposable authorized host.

### Register the private catalog

```bash
bofbench catalog add ~/bofbench-packs-internal --name internal
bofbench pack list
bofbench pack show internal/token-impersonation
```

Pack versions and source hashes are captured in each generated project's `bofbench.lock.json`; private pack source remains outside the public repository.

### Deploy the sacrificial LocalSystem target

```bash
bofbench lab target deploy --lab dedicated
bofbench lab target status --lab dedicated
```

The status output provides the `BOFBenchTarget` PID, alertable thread ID, user, and canary path. Use those exact values for `<TARGET_PID>`, `<TARGET_TID>`, and `<CANARY_PATH>` below.

### Token and execution proof

```bash
bofbench new token-proof --pack internal/token-impersonation
bofbench build bofs/token-proof
bofbench analyze bofs/token-proof
bofbench run bofs/token-proof --via lab --lab dedicated \
  --arg source_pid=<TARGET_PID> \
  --arg command='C:\Windows\System32\whoami.exe'
```

Before execution, analysis should identify token open, duplication, impersonation, and alternate-context process launch as one behavior chain.

### Remote-thread and APC proofs

Use a one-byte `RET` (`0xC3`) or another harmless operator-supplied test payload. Both commands target only `BOFBenchTarget`:

```bash
bofbench new remote-thread-proof --pack internal/process-inject
bofbench analyze bofs/remote-thread-proof
bofbench run bofs/remote-thread-proof --via lab --lab dedicated \
  --arg target_pid=<TARGET_PID> \
  --arg payload=/path/to/authorized-ret-payload.bin

bofbench new apc-proof --pack internal/apc-inject
bofbench analyze bofs/apc-proof
bofbench run bofs/apc-proof --via lab --lab dedicated \
  --arg target_pid=<TARGET_PID> \
  --arg target_tid=<TARGET_TID> \
  --arg payload=ww==
```

The analyzer should predict remote allocation/write/thread-start and allocation/write/APC-queue chains respectively. Receipts provide the exact object hash and observed output.

### Bounded dump and collection proofs

```bash
bofbench new dump-proof --pack internal/process-minidump
bofbench run bofs/dump-proof --via lab --lab dedicated \
  --arg target_pid=<TARGET_PID> \
  --arg output_path='C:\bofbench\proofs\BOFBenchTarget.dmp'

bofbench new collection-proof --pack internal/file-collect
bofbench run bofs/collection-proof --via lab --lab dedicated \
  --arg path=<CANARY_PATH> \
  --arg max_bytes=4096
```

The file pack reads only the exact path and enforces the supplied byte limit.

### Named persistence and cleanup

Every artifact uses a unique `BOFBench-*` name and its declared cleanup companion:

```bash
bofbench new run-key-proof --pack internal/run-key
bofbench run bofs/run-key-proof --via lab --lab dedicated \
  --arg value_name=BOFBench-LiveProof \
  --arg command='C:\Windows\System32\cmd.exe /d /c exit 0'
bofbench pack show internal/run-key --cleanup
bofbench run bofs/run-key-proof --via lab --lab dedicated --cleanup \
  --arg value_name=BOFBench-LiveProof

bofbench new task-proof --pack internal/scheduled-task
bofbench run bofs/task-proof --via lab --lab dedicated \
  --arg task_name=BOFBench-LiveProof \
  --arg command='C:\Windows\System32\cmd.exe /d /c exit 0'
bofbench run bofs/task-proof --via lab --lab dedicated --cleanup \
  --arg task_name=BOFBench-LiveProof
```

After each cleanup, verify from an independent Windows administrative shell that the exact Run value or task no longer exists.

### Service and explicit remote-service proof

```bash
bofbench new service-proof --pack internal/service-execution
bofbench run bofs/service-proof --via lab --lab dedicated \
  --arg service_name=BOFBench-LiveProof \
  --arg binary_path='C:\bofbench\target\bofbench-target.exe'
bofbench run bofs/service-proof --via lab --lab dedicated --cleanup \
  --arg service_name=BOFBench-LiveProof

bofbench new remote-service-proof --pack internal/remote-service
bofbench run bofs/remote-service-proof --via lab --lab dedicated \
  --arg target_host=<AUTHORIZED_LAB_COMPUTER> \
  --arg service_name=BOFBench-RemoteProof \
  --arg command='C:\bofbench\target\bofbench-target.exe'
bofbench run bofs/remote-service-proof --via lab --lab dedicated --cleanup \
  --arg target_host=<AUTHORIZED_LAB_COMPUTER> \
  --arg service_name=BOFBench-RemoteProof
```

The remote-service target is always explicit; BOFBench does not scan for hosts or propagate between them.

### Remove the disposable target

```bash
bofbench lab target remove --lab dedicated
```

Confirm `BOFBenchTarget`, every `BOFBench-*` service/task/value, generated dump, and test file are absent before retaining or reusing the host.

## What counts as proof

For each capability, retain three linked facts:

1. **Predicted**: `analyze` identifies the behavior chain, arguments, effects, and needs.
2. **Executed**: `run` captures structured output and a successful runtime receipt.
3. **Matched**: the receipt object SHA-256 is identical to the analyzed object SHA-256.

State-changing proof adds a fourth fact: an independent check confirms the named artifact exists after the action and is absent after cleanup.
