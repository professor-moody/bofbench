# Native Process Depth

BOFBench exposes process, image, thread, memory, job, and object-namespace capabilities against operator-selected targets. The lab proof helper publishes x64 and x86 processes, alertable threads, known modules, writable regions, and exact hashes for repeatable automated acceptance.

## Inspect a disposable process

```bash
bofbench new process-map --pack process-mitigation-inventory,process-memory-map,thread-start-inventory,process-image-inventory,thread-state-inventory,process-job-inventory
bofbench build bofs/process-map
bofbench analyze bofs/process-map
bofbench run bofs/process-map --via lab --lab devbox \
  --arg target_pid=<fixture-pid> \
  --arg result_limit=32
```

Analysis explains the process-query, memory-map, mitigation-policy, and thread-start abilities before execution.

## Choose unguarded or guarded memory mutation

Normal runtime operation does not require a fixture hash or backup:

```bash
bofbench new memory-write --pack internal/process-memory-write
bofbench run bofs/memory-write --via lab --lab devbox \
  --arg target_pid=1234 --arg address=0x7ff600001000 \
  --arg content=@file:/absolute/path/payload.bin \
  --arg guard_mode=none
```

The declared proof selects `guard_mode=hash`, creates a backup, verifies the result independently, then restores it:

```bash
bofbench pack prove internal/process-memory-write \
  --via lab --lab devbox

bofbench pack prove internal/process-memory-protect \
  --via lab --lab devbox
```

The proof—not the normal pack contract—does the following:

1. validates the original bytes by SHA-256;
2. validates the supplied bytes by SHA-256;
3. creates a new exact backup path;
4. writes and reads back the bounded range;
5. independently checks the target memory;
6. restores the backup only when the current bytes still match;
7. confirms the original hash and backup removal.

The protection proof follows the same pattern for one exact page: verify current protection, change it, query it independently, restore it, and query it again.

## In-memory execution transformations

```bash
bofbench pack prove internal/suspended-process-spawn --via lab --lab devbox
bofbench pack prove internal/early-bird-apc --via lab --lab devbox
bofbench pack prove internal/local-section-execute --via lab --lab devbox
bofbench pack prove internal/thread-hijack-execute --via lab --lab devbox
bofbench pack prove internal/module-stomp-execute --via lab --lab devbox
bofbench pack prove internal/process-hollow-spawn --via lab --lab devbox
bofbench pack prove internal/process-library-load --via lab --lab devbox
```

The declared proofs use a one-byte `RET` payload and disposable children. Operator runs accept arbitrary supplied payload files, PIDs, TIDs, addresses, host images, parent PIDs, and DLL paths. See [Operator-Controlled Execution](operator-execution-depth.md) for direct commands.

## Use the same contract through Sliver

```bash
bofbench runtime status --lab devbox
bofbench runtime sessions --via sliver --lab devbox
bofbench pack prove internal/local-section-execute --via sliver --lab devbox
```

Sliver proof requires a live session that matches the selected profile. Unavailable session context remains unavailable coverage; it is never presented as a successful C2 proof.
