# BOFBench roadmap

Status: active, reviewed 2026-08-23.

BOFBench exists to compose, analyze, execute, compare, and export BOFs from
typed capability contracts. Its next phase is stabilization and proof of the
large surface already built, not another rapid capability tranche.

## Offensive output

**What an operator gets:** a BOF that is proven to compile and execute on real
Windows, with its emitted output captured — plus the same BOF's behaviour across
runtimes, so a pack that works under one loader and not another is a known fact
rather than a surprise on an engagement.

**Why it is offensive:** the artifact itself is the deliverable. Everything else
in this repository exists so that shipping one is not a guess about whether it
runs, what it prints, or whether it leaves the host dirty.

**How to get it:**

```
bofbench lab bootstrap --lab <profile>
bofbench run bofs/<project> --via lab --lab <profile>
```

The run reports `PASS`, the observed output lines, and an evidence set including
the compiled object and build log. Bootstrap proves the guest can compile,
which is the difference between "the BOF is broken" and "the lab is".

**Feeding EDR Lab:** a bundle exported from a project can be scored by
`edrlab artifact` for per-product visibility. That answers the second question
an operator has after "does it run" — namely "who notices" — and no BOF has
been through that path yet.

## Next action

Export one stable benign x64 MinGW BOF as an EDR Lab target-v2 bundle and score
it across the available Defender and Elastic targets. Preserve BOFBench
build/runtime evidence separately from product detection evidence so the suite
has its first reproducible producer-to-detection result.

## Current state

- Build, analysis v3, native/lab/Sliver/Cobalt Strike adapters, operation schema
  v11, runtime receipts v6, topology target sets, cleanup, export, and release
  packaging are implemented; all Go packages currently pass.
- The private catalog now has a full static receipt against `c38791e`: all 192
  packs and 67 operations pass MinGW x64/x86 build and expected-signature
  analysis, with raw/Sliver/Cobalt Strike exports generated. MSVC remains
  unavailable, and the static gate does not qualify live, cleanup, or comparison
  cells by itself.
- The first two private live cells are qualified at harness commit `b567497`:
  `memory-allocation-roundtrip#secret-roundtrip` passed separate x64 and x86 lab
  executions, both independent state checks in each cell, receipt-bound cleanup,
  target removal, clean-lab verification, and provider shutdown. All eight BOF
  object hashes match their `c38791e` static cells exactly.
- The first x64 cell exposed and fixed two proof-harness defects: PowerShell
  pointer and hashing incompatibilities, plus the unsafe early return that
  skipped operation cleanup after a failed post-run assertion. Full Go tests
  and vet pass at `b567497`.
- Sliver control now runs the pinned Linux amd64 client (`1.7.3`, SHA-256
  `b0e328a131e4d679e9b268552db99ca2d46051b9205a67f9b7f7c1628983daae`)
  inside VM 4120. SSH host trust is pinned, the operator credential remains on
  Linux, verified extensions stage remotely, and generated implants copy
  directly VM-to-VM. The Mac receives session/task output and receipts without
  storing or executing Sliver material.
- The frozen x64 user-context Sliver cell remains an executed non-qualification:
  `OpenProcess` returned access denied against the LocalSystem target. A separate
  SYSTEM-context cell is qualified at controller `36795d1`. Session `4a968e17`
  completed allocate, remote-file write, read, both independent state checks,
  exact cleanup, session removal, clean-lab verification, and shutdown of VMs
  4110 and 4120. All four object hashes match the frozen static boundary.
- The first SYSTEM attempt exposed a missing cross-host file-argument path after
  allocation succeeded. `36795d1` stages only `file`-typed arguments in an
  owner-only control-VM directory and also fixes release builds so embedded
  commit metadata no longer reports `unknown`.
- The distinct x86 SYSTEM-context Sliver cell is also qualified. Session
  `dad9be0b` completed the unchanged 18-byte allocate/write/read/cleanup proof
  against the x86 LocalSystem target, passed both independent state checks, and
  matched all four frozen x86 object hashes. Session cleanup, clean-lab
  verification, and shutdown of VMs 4110 and 4120 all passed.
- Release gate `catalog-2026.08.23.5` now qualifies the declared compatibility
  floor at canonical BOFBench commit `c922a23`. Fresh reports cover all 297
  packs and 80 operations and partition exactly into 105/13 public and 192/67
  private results. The private static matrix is identical to the `c38791e`
  compatibility floor after removing only volatile run provenance. Seven
  operation cells plus one pack cell and all eight cleanup cells validate by
  exact receipt digest.
- The gate remains honestly `pass_with_unavailable`: MSVC x64/x86, remaining
  pack proof and cleanup cells, comparison contracts, other operation proof
  cases, and live Cobalt Strike execution are not qualified.
- `main` is the active canonical line established from `3f6506f`; the obsolete
  `fix/live-proxmox-path` ref contains no work absent from `main`. Historical
  slice branches and tags remain available.
- Operator Lab has selected direct Proxmox as the sole production control plane.
  EDR Lab's target-v2 artifact receipt proves the replacement end to end, so
  the unused brokered `operator-lab` provider is now removal debt rather than a
  supported compatibility path.
- The release gate is deterministic and part of the private catalog's strict
  documentation check; source-report, manifest, compatibility, inventory, or
  accepted-live-receipt drift makes it fail.
- The first non-memory cell is qualified. X64 native-lab
  `service-transition-observe#fixture-service-transition` passed its two-wave
  watcher/trigger DAG, service Running check, service/process/task cleanup,
  target removal, zero-artifact verification, and VM 4110 shutdown on the first
  run.
- The matching SYSTEM-context Sliver operation was measured and did not
  qualify. Session `dd9f0ad1` accepted the exact watcher BOF, but Sliver 1.7.3
  buffers session-extension output until the BOF returns. BOFBench could not
  observe `status=ready` while the watcher remained active; the implant request
  expired after 32 seconds and the service trigger correctly stayed blocked.
  Cleanup found no service, fixture process, or loader task; target/session
  removal, zero-artifact verification, and shutdown of VMs 4110/4120 passed.
- Task submission is not accepted as a substitute for the declared readiness
  output. The next Sliver service lane uses the existing sequential
  `service-execution#fixture-service` pack proof instead, so no catalog surface
  or weaker async contract is introduced.
- The sequential pack lane is now qualified at `4829b51`. After preserving an
  exact-cleanup retry that failed only the restarted VM's worker-provenance
  boundary, a final run deployed the versioned worker and used SYSTEM session
  `a0febdcd`. Service creation, two independent state checks, both frozen BOF
  hashes, exact cleanup, session removal, zero-artifact verification, and
  shutdown of VMs 4110/4120 all passed.
- X64 SYSTEM-context Sliver cancellation is now qualified at `c922a23` through
  session `886cd1c5`. The accepted timer lifecycle completed create, set, wait,
  query, terminal cancel, independent signaled/absent checks, and exact
  handle-close cleanup with all frozen object hashes. Five rejected attempts
  preserve the import, UTF-16, and SYSTEM DACL defects that were fixed; target
  and session removal, zero-artifact verification, and both VM shutdowns passed.
- X86 SYSTEM-context Sliver cancellation is independently qualified through
  session `bc0ed4bf`. The exact x86 create, control, and cleanup objects passed
  the five-step timer path and both state checks on the first attempt. The
  session and BOF objects are x86 while the operation intentionally retains its
  handle in the main LocalSystem target service; that identity boundary is
  explicit in the receipt. Teardown again returned VMs 4110/4120 to stopped.
- Historical live receipts remain tied to the commits that produced them. The
  release gate now accepts an older controller/catalog boundary only when it is
  a verified ancestor and current static rebuilding produces identical object
  hashes, avoiding both evidence rewriting and accidental stale-proof reuse.
- Local release `0.1.0` is built and independently verified from clean commit
  `e77a897`. Darwin amd64/arm64, Linux amd64, Windows amd64, and docs-site
  archives pass `SHA256SUMS`; every CLI embeds the same version, commit, and
  build time. Archive inspection found and fixed a `.DS_Store` leak before the
  accepted rebuild. The receipt is `docs/evidence/release-0.1.0-local.json`;
  no tag, push, or publication has occurred.

## Now: connect execution evidence to detection evidence

1. Select a benign, deterministic, no-persistence x64 pack with no unstable
   target identity requirements; freeze its source, object, packed arguments,
   loader, and BOFBench commit.
2. Export exactly that object in EDR Lab bundle format, validate the bundle
   locally, and execute it through the target-v2 artifact path on disposable
   Defender and Elastic targets.
3. Join the build, runtime, cleanup, and per-product detection receipts by
   immutable digests. A product negative is a valid measured result; missing or
   incomplete telemetry is not.
4. Return every disposable target to its declared clean/stopped state and add
   the accepted cross-tool receipt to Operator Lab's aggregate view.

## Next: improve confidence, not surface area

- Measure the adjacent named-event lifecycle through x64 SYSTEM Sliver before
  selecting another kernel-object family.
- Build a labeled third-party-object evaluation corpus for analyzer precision,
  unsupported cases, architecture differences, and cross-function explanations.
- Add compatibility tests for every supported prior schema and publish removal
  criteria for the legacy `feature`, `recipe`, `dev`, `preflight`, and `stage`
  commands.
- Make runtime comparison reports easy to aggregate without weakening exact
  object-hash and terminal-output requirements.
- Qualify the BOFBench-to-EDR-Lab bundle lane with a stable, benign fixture and
  preserve analysis, runtime, and product evidence as separate layers.
- Define a bounded proof case for the existing cross-host operation matrix only
  after both host identities, credentials, reversible effects, and cleanup
  checks are frozen; the current matrix declaration alone is not executable
  qualification evidence.
- Remove the retired Operator Lab provider, mTLS configuration, and neutral-lab
  live-gate scripts after the target-v2 artifact path has a passing receipt.

## Later

- Add packs or operation schemas only in response to measured catalog gaps.
- Improve the TUI after the CLI/release baseline is stable; it remains a view of
  the same commands, not a second workflow engine.

## Not now

Do not add another operation-schema version or broad capability tranche before
the selected proof matrix and first publication decision are complete.

## Update rule

Keep **Next action** to one outcome. Review this file at every schema change,
catalog-total change, runtime-adapter change, or release cut.
