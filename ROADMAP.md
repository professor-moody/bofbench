# BOFBench roadmap

Status: active, reviewed 2026-08-16.

BOFBench exists to compose, analyze, execute, compare, and export BOFs from
typed capability contracts. Its next phase is stabilization and proof of the
large surface already built, not another rapid capability tranche.

## Next action

Create a canonical `main` line and release candidate from the current
105-public-pack, 192-private-pack, 80-operation workbench, then publish one
static and live coverage report for its supported compiler and runtime matrix.

## Current state

- Build, analysis v3, native/lab/Sliver/Cobalt Strike adapters, operation schema
  v11, runtime receipts v6, topology target sets, cleanup, export, and release
  packaging are implemented; all Go packages currently pass.
- The repository has no `main` branch. Work is accumulated on
  `fix/live-proxmox-path` among many historical slice branches.
- Documentation contains both the earlier brokered Operator Lab provider and the
  current direct Proxmox/persistent-profile path. July broker live-gate receipts
  remain unavailable while newer direct-lab work is documented elsewhere.
- The public/private catalog sizes and generated references are precise, but no
  current release receipt summarizes which of the 297 packs and 80 operations
  are static-tested, lab-proven, or C2-proven.

## Now: stabilize a releasable baseline

1. Establish `main`, preserve useful branch/tag history, and define the branch
   and release policy. Reconcile the supported lab paths and mark each as
   canonical, compatibility, experimental, or retired.
2. Freeze schema versions and totals, run generated-code checks, all Go tests,
   docs checks, full public/private pack tests, operation tests, and release
   packaging from one commit.
3. Produce a coverage artifact keyed by pack/operation, architecture, compiler,
   runtime, proof status, object hash, and cleanup result. `unavailable` remains
   coverage debt and never becomes a pass.
4. Prove a representative risk-weighted lane on Windows: x64 and x86 native/lab,
   state-changing cleanup, async/cancellation, cross-host/domain operations, and
   complete Sliver tasks. Licensed Cobalt Strike is a separate optional live
   gate; package verification is not live proof.
5. Cut a versioned release with checksums and embedded commit only after the
   coverage report and private-catalog compatibility check pass.

## Next: improve confidence, not surface area

- Build a labeled third-party-object evaluation corpus for analyzer precision,
  unsupported cases, architecture differences, and cross-function explanations.
- Add compatibility tests for every supported prior schema and publish removal
  criteria for the legacy `feature`, `recipe`, `dev`, `preflight`, and `stage`
  commands.
- Make runtime comparison reports easy to aggregate without weakening exact
  object-hash and terminal-output requirements.
- Qualify the BOFBench-to-EDR-Lab bundle lane with a stable, benign fixture and
  preserve analysis, runtime, and product evidence as separate layers.

## Later

- Add packs or operation schemas only in response to measured catalog gaps.
- Improve the TUI after the CLI/release baseline is stable; it remains a view of
  the same commands, not a second workflow engine.

## Not now

Do not add another operation-schema version or broad capability tranche before
the current proof matrix, branch policy, and first release are complete.

## Update rule

Keep **Next action** to one outcome. Review this file at every schema change,
catalog-total change, runtime-adapter change, or release cut.
