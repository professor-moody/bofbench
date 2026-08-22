# BOFBench roadmap

Status: active, reviewed 2026-08-22.

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

Publish one combined `b567497` coverage manifest by running the public/private
static and release gates at that commit and joining the qualified x64 Windows
lane through its unchanged exact object hashes.

## Current state

- Build, analysis v3, native/lab/Sliver/Cobalt Strike adapters, operation schema
  v11, runtime receipts v6, topology target sets, cleanup, export, and release
  packaging are implemented; all Go packages currently pass.
- The private catalog now has a full static receipt against `c38791e`: all 192
  packs and 67 operations pass MinGW x64/x86 build and expected-signature
  analysis, with raw/Sliver/Cobalt Strike exports generated. MSVC and all live,
  proof, cleanup, and comparison cells remain explicitly unqualified.
- The first private live cell is qualified at harness commit `b567497`:
  `memory-allocation-roundtrip#secret-roundtrip` passed x64 lab execution, both
  independent state checks, receipt-bound cleanup, target removal, clean-lab
  verification, and provider shutdown. All four BOF object hashes match the
  `c38791e` static report exactly; x86 and C2 cells remain unqualified.
- That live run exposed and fixed two proof-harness defects: PowerShell pointer
  and hashing incompatibilities, plus the unsafe early return that skipped
  operation cleanup after a failed post-run assertion. Full Go tests and vet pass
  at `b567497`.
- `main` is the active canonical line established from `3f6506f`; the obsolete
  `fix/live-proxmox-path` ref contains no work absent from `main`. Historical
  slice branches and tags remain available.
- Operator Lab has selected direct Proxmox as the sole production control plane.
  EDR Lab's target-v2 artifact receipt proves the replacement end to end, so
  the unused brokered `operator-lab` provider is now removal debt rather than a
  supported compatibility path.
- The public/private catalog sizes and generated references are precise, but no
  combined release receipt yet summarizes which of the 297 packs and 80
  operations are static-tested, lab-proven, or C2-proven.

## Now: stabilize a releasable baseline

1. Freeze schema versions and totals, then rerun public/private pack and
   operation matrices plus release packaging at `b567497` so the release gate
   includes the qualified proof-harness fixes.
2. Produce a coverage artifact keyed by pack/operation, architecture, compiler,
   runtime, proof status, object hash, and cleanup result. `unavailable` remains
   coverage debt and never becomes a pass.
3. Prove a representative risk-weighted lane on Windows: x64 and x86 native/lab,
   state-changing cleanup, async/cancellation, cross-host/domain operations, and
   complete Sliver tasks. Licensed Cobalt Strike is a separate optional live
   gate; package verification is not live proof.
4. Cut a versioned release with checksums and embedded commit only after the
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
- Remove the retired Operator Lab provider, mTLS configuration, and neutral-lab
  live-gate scripts after the target-v2 artifact path has a passing receipt.

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
