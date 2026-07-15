# Native Process Depth

BOFBench can inspect and exercise disposable process, thread, and memory fixtures without using a critical Windows process. The target helper publishes an alertable thread, bounded readable and writable regions, an independently queryable protection-test page, and exact hashes.

## Inspect a disposable process

```bash
bofbench new process-map --pack process-mitigation-inventory,process-memory-map,thread-start-inventory
bofbench build bofs/process-map
bofbench analyze bofs/process-map
bofbench run bofs/process-map --via lab --lab devbox \
  --arg target_pid=<fixture-pid> \
  --arg result_limit=32
```

Analysis explains the process-query, memory-map, mitigation-policy, and thread-start abilities before execution.

## Prove guarded memory mutation

Use the private catalog only on an authorized disposable target:

```bash
bofbench pack prove internal/process-memory-write \
  --via lab --lab devbox

bofbench pack prove internal/process-memory-protect \
  --via lab --lab devbox
```

The write proof:

1. validates the original bytes by SHA-256;
2. validates the supplied bytes by SHA-256;
3. creates a new exact backup path;
4. writes and reads back the bounded range;
5. independently checks the target memory;
6. restores the backup only when the current bytes still match;
7. confirms the original hash and backup removal.

The protection proof follows the same pattern for one exact page: verify current protection, change it, query it independently, restore it, and query it again.

## Prove controlled in-memory execution

```bash
bofbench pack prove internal/suspended-process-spawn --via lab --lab devbox
bofbench pack prove internal/early-bird-apc --via lab --lab devbox
bofbench pack prove internal/local-section-execute --via lab --lab devbox
```

The declared proofs use a one-byte `RET` payload and marked disposable children. Spawned PIDs are captured from structured BOF output, passed to cleanup, and terminated only when both image and unique run marker match. Local section execution runs only inside the isolated loader child.

## Use the same contract through Sliver

```bash
bofbench runtime status --lab devbox
bofbench runtime sessions --via sliver --lab devbox
bofbench pack prove internal/local-section-execute --via sliver --lab devbox
```

Sliver proof requires a live session that matches the selected profile. Unavailable session context remains unavailable coverage; it is never presented as a successful C2 proof.
