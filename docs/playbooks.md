# Operator Playbooks

## Build and run a parameterized survey

```bash
bofbench new survey --pack host-discovery,system-discovery,domain-discovery
bofbench build bofs/survey
bofbench analyze bofs/survey
bofbench run bofs/survey --via lab \
  --arg process_filter=lsass \
  --arg result_limit=25
```

Change `process_filter` to another image or an empty string and rerun the same object.

## Analyze a third-party token BOF

```bash
bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
bofbench arsenal search arsenal/trustedsec-sa --can token
```

Confirm whether the result is token discovery, impersonation, or alternate-token process launch. The stronger names require function-local chains, not a single token API.

## Internal token operation

```bash
bofbench catalog add ~/bofbench-packs-internal --name internal
bofbench new token-op --pack internal/token-impersonation
bofbench analyze bofs/token-op
bofbench run bofs/token-op --via sliver \
  --arg source_pid=1234 \
  --arg command=whoami
```

Analysis should identify both token duplication/impersonation and process creation with another token before execution.

## Compare injection techniques

```bash
bofbench new remote-thread --pack internal/process-inject
bofbench new queued-apc --pack internal/apc-inject
bofbench build bofs/remote-thread
bofbench build bofs/queued-apc
bofbench analyze dist/remote-thread.x64.o \
  --compare dist/queued-apc.x64.o --format md
```

The diff should separate remote-thread creation from APC queueing while retaining the shared process-open, allocation, and memory-write effects.

## Persistence and exact cleanup

```bash
bofbench new lab-task --pack internal/scheduled-task
bofbench analyze bofs/lab-task
bofbench run bofs/lab-task --via lab \
  --arg task_name=BOFBenchLab \
  --arg command='cmd.exe /c whoami > %TEMP%\bofbench-task.txt'

bofbench run bofs/lab-task --via lab --cleanup \
  --arg task_name=BOFBenchLab
```

Observe the named task independently before cleanup, then confirm that exact task is gone.

## Explicit-target remote service

```bash
bofbench new remote-service --pack internal/remote-service
bofbench analyze bofs/remote-service
bofbench run bofs/remote-service --via sliver \
  --arg target_host=LAB-WKS01 \
  --arg service_name=BOFBenchLab \
  --arg command='C:\Windows\System32\cmd.exe /c whoami'

bofbench run bofs/remote-service --via sliver --cleanup \
  --arg target_host=LAB-WKS01 \
  --arg service_name=BOFBenchLab
```

The pack operates only on the supplied host and service name.

## Export for another operator

```bash
bofbench export bofs/token-op --for sliver \
  --args i:1234 Z:whoami
bofbench export verify export/token-op-sliver.zip
```

The package carries the named argument contract, object hash, analysis, target metadata, and cleanup information.
