# Operational Development Program

BOFBench is a lab-proven functional alpha. The complete workflow exists, but operational confidence is still concentrated in a small first-party fixture set and one pinned public arsenal.

The program objective is:

> For any pinned BOF source, BOFBench can safely acquire it, record its provenance, build or ingest it, explain whether the current loader supports it, execute it in a disposable Windows lab, validate its behavioral contract, and produce a verified operator package with versioned evidence and no unexplained failure states.

## Program Invariants

- Keep the CLI convention-first; do not add approval gates or a required project manifest.
- Treat static findings as review evidence, not vulnerability verdicts.
- Keep native execution confined to authorized local and disposable lab environments.
- Derive analyzer compatibility from the loader's real capability set.
- Expand loader support only with a minimal fixture and a pinned real-object proof.
- Preserve source, build, analysis, run, lab, and stage provenance through handoff.
- Require measurable evidence before marking a slice complete.

## Milestones

### A. Credible Handoff

Freeze the recovered baseline, secure arsenal acquisition, verify staged packages, add loader-aware preflight, fingerprint Windows evidence, run a bounded corpus matrix, and produce a self-verifying release.

### B. Team Pilot

Add reproducible builds, VM lifecycle automation, loader hardening, arsenal recipes, offensive scenario metadata, result correlation, and environment-gated C2 validation.

### C. Operational Release

Add native Windows execution CI, provenance-bearing releases, team validation, stable schemas, and operator/developer runbooks.

## Phase A: Foundation and Trust

| Slice | Status | Outcome | Acceptance gate |
| --- | --- | --- | --- |
| 0. Baseline freeze | Complete | Establish the recovered tree, source-control boundary, baseline commit, and tag. | A clean checkout reproduces tests, builds, loader, docs, and releases. |
| 1. Input and package safety | Complete | Transactional acquisition, safe ZIP handling, bounded downloads, versioned stage manifests, and directory/ZIP verification. | Adversarial archives are rejected without replacing an existing arsenal; all target packages verify in directory/ZIP form locally and Windows lab smoke passes. |
| 2. Evidence contracts | Complete | Shared schema/tool/host/run headers, lineage, collision-safe run IDs, build persistence, and object/loader/config/source/lab fingerprints are implemented. | Contract/legacy tests, release metadata inspection, and fingerprinted Windows lab smoke pass. |
| 3. Capability registry | Complete | A versioned JSON catalog generates the native C header and drives Go analysis/runtime decisions for machine, relocation, Beacon shim, import-prefix, dynamic-import, and fallback-library behavior. | Catalog validation, generated-file freshness, compiled C-helper parity, native loader build, and Windows smoke pass. |

## Phase B: Predictive Analysis and Builds

| Slice | Status | Outcome | Acceptance gate |
| --- | --- | --- | --- |
| 4. Loader compatibility preflight | Complete | `inspect`, `analyze`, `preflight`, `run`, and `test` report or enforce compatible, runtime-lookup, architecture, entrypoint, relocation, Beacon API, and dynamic-import states with structured evidence. | All 64 pinned TrustedSec x64 objects classify before execution: 57 compatible, 7 runtime-lookup warnings, 0 blocked, and 0 analysis failures; Windows preflight and native smoke pass. |
| 5. BOF analyzer depth | Complete | Bounded COFF parsing emits structured layout diagnostics; analysis records toolchain, resolved/decorated entrypoint, section alignment/storage, numeric relocations, and non-destructive finding suppressions; baselines track entry/section/finding-state changes. Catalog v2 and `bss_reloc` add correct zero-fill handling. | MinGW and MSVC analyzer goldens, 13 malformed-layout cases, stripped and long/unusual-section cases, suppression/baseline tests, the 64-object pinned corpus, and Windows native BSS smoke pass. |
| 6. Arsenal-wide analysis | Complete | `preflight <arsenal> --arch x64|x86|all` produces selected or full JSON/Markdown/text matrices with source-tree, object, and sidecar fingerprints plus architecture, status, blocker, toolchain, entrypoint, and argument-need dimensions; `--report-only` separates inventory from gating. | One command classifies all 128 pinned variants: 57 compatible x64, 7 x64 runtime-lookup warnings, 64 expected x86 architecture blockers, 94 BeaconData argument-required rows, and zero analysis failures; Windows report-only matrix passes. |
| 7. Reproducible builds | Pending | Strict configuration parsing, compiler profiles, structured diagnostics, toolchain metadata, and artifact comparison. | Every build success or failure records enough evidence to reproduce or explain it. |

## Phase C: Runtime and Loader Hardening

| Slice | Outcome | Acceptance gate |
| --- | --- | --- |
| 8. Loader input hardening | Validate all COFF ranges before pointer arithmetic; classify crash and timeout behavior. | Malformed and fuzz corpora never crash BOFBench or produce an unknown loader exit. |
| 9. Loader memory model | Apply staged write/relocate/protect behavior and record mapped-section evidence. | Existing fixtures pass without blanket unexplained RWX behavior. |
| 10. Capability expansion | Add only corpus-observed shims, imports, and relocations with fixtures. | Every capability has positive, negative, and real-object evidence. |
| 11. Compiler/runtime matrix | Exercise supported MinGW/MSVC variants and optimization/object patterns. | Matrix failures are classified; x86 execution remains explicit until separately proven. |

## Phase D: Windows VM and Lab

| Slice | Outcome | Acceptance gate |
| --- | --- | --- |
| 12. Windows bootstrap | Idempotent Go, Git, compiler, SSH, loader, workspace, and optional debugger setup. | A clean snapshot reaches `doctor` pass through one documented bootstrap path. |
| 13. Lab lifecycle | Add `status`, `bootstrap`, `sync`, `smoke`, `collect`, and `reset`, initially over SSH to an existing VM. | A host-side workflow moves from clean snapshot to collected report. |
| 14. Environment fingerprinting | Record Windows build, compiler, loader hash, BOFBench version, VM identity, and selection. | Runs can be compared without guessing what changed. |
| 15. Crash evidence | Collect exit/exception state, streams, loader JSON, and optional dump/debugger artifacts. | A crash yields an actionable evidence bundle. |

## Phase E: Arsenal and Offensive Workflows

| Slice | Outcome | Acceptance gate |
| --- | --- | --- |
| 16. Arsenal v2 | Resolved revisions, lockfiles, hashes, adapters, update/diff, deduplication, and offline cache behavior. | A lock reproduces inventory and source changes are visible. |
| 17. Test recipes | External sidecars for arguments, entry, timeout, output, exit, platform, and unsupported reasons. | Each selected BOF is runnable or explicitly environment/operator-dependent. |
| 18. Offensive scenarios | Describe privilege, domain/network/host prerequisites, state changes, artifacts, and cleanup without adding approval gates. | Representative host, process, network, registry, and directory scenarios repeat in the lab. |
| 19. Corpus conformance | Track pass, expected unsupported, environment-dependent, and regression across versions. | The pinned release corpus has zero unexplained failures. |

## Phase F: Operator and C2 Handoff

| Slice | Outcome | Acceptance gate |
| --- | --- | --- |
| 20. Stage manifest v2 | Carry full provenance and hashes for object, analysis, run evidence, compatibility, and target metadata. | Tampering with any referenced package file fails verification. |
| 21. Cobalt Strike fidelity | Validate Aggressor syntax, alias, object, entrypoint, and argument contracts. | Contract tests and an authorized environment-gated import/execution smoke pass. |
| 22. Sliver fidelity | Validate supported extension metadata, paths, and argument mapping. | Contract tests and an environment-gated operator smoke pass. |
| 23. Raw handoff | Ship exact commands, hashes, prerequisites, compatibility, reports, and notes. | Another operator can verify and exercise the artifact without the source workspace. |

## Phase G: Team Operations and Release

| Slice | Outcome | Acceptance gate |
| --- | --- | --- |
| 24. Run registry | Rebuildable `runs list/show/diff` correlation from source through stage. | Any package traces back to its source, build, analysis, loader, and lab run. |
| 25. TUI actions | Clipboard support, then service-backed build/analyze/test/stage actions. | TUI and CLI produce identical commands and evidence. |
| 26. Windows execution CI | Controlled native-loader integration runner separate from fast unit CI. | Every release candidate runs first-party fixtures and the safe public smoke set on Windows. |
| 27. Release provenance | Embedded version/commit, pinned dependencies, SBOM, checksums, and optional signatures. | A clean-host installation passes doctor, stage verification, and supported smoke. |
| 28. Team pilot | Teammate exercises, friction closure, and operator/developer runbooks. | A new user completes acquisition through verified handoff using shipped documentation. |

## Global Slice Gate

Every implementation slice must pass, as applicable:

1. `go test ./...`
2. `go vet ./...`
3. `go run ./cmd/capgen -check -out native/loader/capabilities.generated.h`
4. host and Windows CLI builds
5. `mkdocs build --strict`
6. native loader build
7. Windows lab smoke
8. staged-directory and ZIP verification
9. release archive checksum and content inspection

## Deliberate Deferrals

These are outside the critical path until Windows x64 is operationally reliable:

- Wine COFF execution
- x86 native execution
- hypervisor-specific VM provisioning
- direct C2 session APIs
- multi-user service/dashboard architecture
- automated BOF or exploit generation
