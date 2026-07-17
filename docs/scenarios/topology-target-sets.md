# Run Across an Explicit Target Set

## Objective

Apply one operation to a finite, ordered set of registered Windows profiles without converting discovery into autonomous targeting.

## Prerequisites

- A topology with an execution profile and two or more target profiles.
- Each target resolves to a distinct observed computer identity.
- Required authentication supplied outside the topology definition.
- The private catalog configured or passed with `--catalog`.

## Define the set

```bash
bofbench lab topology target add proxmox-standalone \
  --set windows-targets --lab proxmox-target-a
bofbench lab topology target add proxmox-standalone \
  --set windows-targets --lab proxmox-target-b
bofbench lab topology target list proxmox-standalone
```

The stored set contains profile names only. Order is stable, duplicates are rejected, and no credential enters the topology file.

## Run the operation

```bash
bofbench operation graph internal/cross-host-operation-matrix --expand
bofbench operation run internal/cross-host-operation-matrix \
  --catalog ~/bofbench-packs-internal \
  --via lab --topology proxmox-standalone \
  --targets windows-targets --parallelism 4 \
  --arg auth_mode=new_credentials \
  --arg domain=. \
  --arg username=@env:BOFBENCH_TARGET_USER \
  --arg password=@prompt
```

Operation schema v11 expands one pinned branch per target. Each branch records the requested profile, observed computer identity, exact object hash, structured result, captures, effect state, and cleanup mapping.

## Interpret and resume

```bash
bofbench operation watch runs/<run-id>/operation.json --follow
bofbench operation resume runs/<run-id>/operation.json --parallelism 4
```

A failed or incomplete branch stops new dependent scheduling, but already running independent branches finish. Resume refreshes incomplete runtime receipts and skips completed targets. If a profile now resolves to a different computer identity, inspect the replacement rather than accepting stale captures.

## Cleanup

```bash
bofbench operation cleanup runs/<run-id>/operation.json --parallelism 4
bofbench lab verify clean --lab proxmox-target-a
bofbench lab verify clean --lab proxmox-target-b
```

Cleanup reverses completed stateful work per target. It does not execute cleanup for branches that never ran.

## Variations

- Use the public `remote-host-posture` operation for read-only posture collection.
- Use `multi-target-event-collection` to export exact bounded Event Log selections.
- Use a domain topology and member profiles while keeping state-changing actions away from the DC.

## Common failures

- **Unknown set/profile:** list the topology and add only registered profiles.
- **Computer identity mismatch:** verify the guest/IP mapping and host key before resuming.
- **Authentication failure:** confirm the supplied context and remote management surface; secrets are not stored for automatic replay.
- **Partial cleanup:** inspect each per-target cleanup receipt and verify state independently on the owning role.
