# BOFBench roadmap

Status: active, reviewed 2026-08-30.

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

**Feeding EDR Lab:** a bundle exported from a project can be classified by
`edrlab artifact` against each product. That answers the second question an
operator has after "does it run" — namely "who notices". The first qualified BOF
result now preserves BOFBench source/build/analysis evidence separately from EDR
Lab's product evidence; numeric scoring is withheld on target v2.

## Next action

Freeze a version 3 corpus layer that carries the independently audited
`sc_enum` correction without modifying versions 1 or 2, and add a second
loader-blocked family plus a second positive interprocedural family from a third
upstream repository before measuring it.

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
- Release gate `catalog-2026.08.23.6` now qualifies the declared compatibility
  floor at canonical BOFBench commit `c922a23`. Fresh reports cover all 297
  packs and 80 operations and partition exactly into 105/13 public and 192/67
  private results. The private static matrix is identical to the `c38791e`
  compatibility floor after removing only volatile run provenance. Eight
  operation cells plus one pack cell and all nine cleanup cells validate by
  exact receipt digest.
- The gate remains honestly `pass_with_unavailable`: MSVC x64/x86, remaining
  pack proof and cleanup cells, comparison contracts, other operation proof
  cases, and live Cobalt Strike execution are not qualified.
- `main` is the active canonical line established from `3f6506f`; the obsolete
  `fix/live-proxmox-path` ref contains no work absent from `main`. Historical
  slice branches and tags remain available.
- Operator Lab has selected direct Proxmox as the sole production control plane.
  EDR Lab's target-v2 artifact receipt proves the replacement end to end, and
  BOFBench's unused brokered provider and `labapi` dependency have been removed.
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
- X64 SYSTEM-context Sliver named-event lifecycle is qualified through session
  `ff280a98`. Static preflight fixed the event imports, bounded UTF-16 handling,
  and narrow SYSTEM/Administrators descriptor before the first live attempt.
  The exact create, control, and cleanup objects passed query, signal, wait,
  reset, independent final nonsignaled/absent checks, and retained-handle close;
  target/session removal, zero-artifact verification, and shutdown of VMs
  4110/4120 also passed.
- X86 SYSTEM-context Sliver named-event parity is qualified through session
  `676d46e0` on the first live attempt. The published 0.1.0 controller reproduced
  the frozen x86 create, control, and handle-close objects, then completed query,
  signal, wait, reset, independent nonsignaled/absent checks, exact cleanup,
  session removal, zero-artifact verification, and shutdown of VMs 4110/4120.
  This post-release cell advances internal catalog gate
  `catalog-2026.08.25.7`; it does not rewrite the immutable 0.1.0 manifest.
- The first BOFBench-to-EDR-Lab lane is qualified. The argument-free x64 MinGW
  `bofs/demo` object is reproducible, has no arguments or persistence, and was
  exported with exact object, loader, wrapper, effect, and cleanup digests.
  Defender completed it with its effect observed and no product action in 3/3
  runs; Elastic prevented the same bytes before effect in 3/3. Collector
  liveness, all six cleanups, and all six clone destructions passed.
- The live lane exposed three boundary defects before qualification: EDR Lab
  did not translate producer `{{run_dir}}`, the BOFBench wrapper did not isolate
  the loader's final result, and cleanup did not bind the exact effect path.
  The rejected attempts and fixes remain preserved rather than overwritten.
- `qualification/receipts/20260824-demo-edrlab-producer/consumer.json` joins the
  immutable producer selection to EDR Lab receipt `72018730...` without moving
  product semantics into BOFBench. Numeric visibility and stealth scores remain
  withheld because target v2 lacks the required LitterBox evidence.
- Historical live receipts remain tied to the commits that produced them. The
  release gate now accepts an older controller/catalog boundary only when it is
  a verified ancestor and current static rebuilding produces identical object
  hashes, avoiding both evidence rewriting and accidental stale-proof reuse.
- Local release `0.1.0` is built and independently verified from clean commit
  `e77a897`. Darwin amd64/arm64, Linux amd64, Windows amd64, and docs-site
  archives pass `SHA256SUMS`; every CLI embeds the same version, commit, and
  build time. Archive inspection found and fixed a `.DS_Store` leak before the
  accepted rebuild. The immutable pre-publication receipt is
  `docs/evidence/release-0.1.0-local.json`.
- `qualification/release-manifest-0.1.0.json` now binds that release receipt,
  catalog gate `.6`, all nine selected live/cleanup receipts, and the qualified
  3+3 EDR consumer result by path, historical commit, and SHA-256. Its strict
  verifier rejects receipt drift, expanded coverage, unknown status values,
  path traversal, missing cleanup/destruction proof, and any mismatch between
  the declared cells and their source gates. Six broader cells remain withheld
  and four MSVC static cells remain unavailable.
- **Published 2026-08-25:** public repository
  `https://github.com/professor-moody/bofbench` and release `v0.1.0` are live.
  The annotated tag peels to qualified source commit `e77a897`; all five
  downloaded archives reproduce `SHA256SUMS`, and the attached manifest matches
  digest `3d16b8e4...728d35a`. Publication receipt
  `qualification/receipts/bofbench-0.1.0-published-20260825.json` preserves the
  remote tag, release, asset, and qualification identities without changing
  any withheld or unavailable cell.
- **Corpus frozen 2026-08-30:** `testdata/analyzer-corpus-v1.json` binds one
  TrustedSec source commit and object lock to 16 reviewed behaviors, 32 paired
  x64/x86 objects, per-architecture loader-support classes, and exact capability
  and behavior-chain label sets. The freeze declares its two material coverage
  limits before evaluation: there is no loader-blocked object and no positive
  interprocedural chain.
- **Corpus measured 2026-08-30:** the labels frozen at `9dd0eab` were evaluated
  unchanged against analyzer commit `afb0a20` and signature-set digest
  `abdb6714...fdb0cd73`. All 32 loader-support classifications were correct;
  capability labels scored 44 TP, 0 FP, and 0 FN; behavior chains scored 18 TP,
  0 FP, and 0 FN; and all 16 x64/x86 pairs agreed. The digest-bound receipt is
  `qualification/receipts/bofbench-analyzer-corpus-evaluation-20260830.json`.
  Blocked-object and interprocedural recall remain withheld exactly as declared
  before measurement.
- **Version 2 frozen and measured 2026-08-30:** commit `7e19c7b` adds, without
  editing version 1, two source-reviewed TrustedSec Remote Ops families and four
  exact objects. The combined 18-family/36-object corpus includes two
  `unsupported_beacon_api` objects and two reviewed interprocedural
  `process_memory_read` positives. Evaluator commit `b7c5b33` classified all 36
  loader outcomes correctly, including 2/2 blocked objects, and retained
  perfect capability labels. It measured behavior recall at 20/22 and
  interprocedural recall at 0/2, localizing both false negatives to the x64/x86
  `lastpass` pair. Receipt:
  `qualification/receipts/bofbench-analyzer-corpus-v2-evaluation-20260830.json`.
- **Direct-call recovery measured 2026-08-30:** analyzer commit `5a9fd2a`
  decodes x86/x64 instructions only inside known executable function ranges,
  ignores relocated call bytes, accepts targets only at exact known function
  symbols, and retains the shortest call path as static evidence. The unchanged
  version 2 corpus then measured 22/22 behavior recall and 2/2 interprocedural
  recall; loader support remained 36/36, blocked-object recall 2/2, capabilities
  46 TP / 0 FP / 0 FN, and all 18 architecture pairs agreed. Two reported
  `remote_service_inventory` positives remain a formal mismatch because the
  inherited frozen `sc_enum` labels are empty.
- **Frozen-label audit 2026-08-30:** pinned `sc_enum` source independently
  confirms that `go` opens the supplied host's service manager and calls
  `enumerate_services`, which consumes that handle with
  `EnumServicesStatusExA`. The audit therefore classifies the two post-fix
  positives as a version 1 label omission, not analyzer false positives. Neither
  frozen corpus was edited. The post-fix measurement and audit are
  `qualification/receipts/bofbench-analyzer-corpus-v2-postfix-20260830.json`
  and
  `qualification/receipts/bofbench-analyzer-corpus-v2-label-audit-20260830.json`.

## Completed: publish the release boundary

1. **Complete:** strict manifest verification passed from clean sibling
   checkouts before publication.
2. **Complete:** `v0.1.0` points to the exact archive source commit, while
   `main` retains the later evidence and manifest history.
3. **Complete:** the public release contains all five archives, `SHA256SUMS`,
   and the exact qualification manifest; an independent download readback
   reproduced every digest.

## Next: improve confidence, not surface area

- Define a version 3 correction layer that cites the independent `sc_enum`
  audit, preserves both earlier corpora and measurements byte-for-byte, and
  cannot silently override an inherited case.
- Before freezing version 3, add a second blocked family and a second positive
  interprocedural family from a third upstream repository so corrected labels
  are not the only reason its metrics change.
- Add compatibility tests for every supported prior schema and publish removal
  criteria for the legacy `feature`, `recipe`, `dev`, `preflight`, and `stage`
  commands.
- Make runtime comparison reports easy to aggregate without weakening exact
  object-hash and terminal-output requirements.
- Define a bounded proof case for the existing cross-host operation matrix only
  after both host identities, credentials, reversible effects, and cleanup
  checks are frozen; the current matrix declaration alone is not executable
  qualification evidence.
- Remove the retired Operator Lab provider, mTLS configuration, and neutral-lab
  live-gate scripts in the suite's retirement phase; target v2 now has the
  passing receipt that permits that cleanup.

## Later

- Add packs or operation schemas only in response to measured catalog gaps.
- Improve the TUI after the CLI/release baseline is stable; it remains a view of
  the same commands, not a second workflow engine.

## Not now

Do not present the version 2 post-fix result as a perfect corpus pass: it closes
the reviewed `lastpass` false negatives but deliberately retains the audited
`sc_enum` frozen-label mismatch. Do not revise version 1 or version 2 in place.

## Update rule

Keep **Next action** to one outcome. Review this file at every schema change,
catalog-total change, runtime-adapter change, or release cut.
