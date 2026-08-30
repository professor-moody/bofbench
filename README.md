# BOFBench

BOFBench is a capability-first workbench for building, analyzing, running, and exporting Beacon Object Files.

Current stabilization, proof, and release priorities are in [ROADMAP.md](ROADMAP.md).

## Release

[BOFBench 0.1.0](https://github.com/professor-moody/bofbench/releases/tag/v0.1.0)
provides verified archives for macOS amd64/arm64, Linux amd64, Windows amd64,
and the documentation site. Verify downloads with the attached `SHA256SUMS`.
The attached qualification manifest records the exact selected, withheld, and
unavailable evidence boundary; publication does not turn an unqualified cell
into a pass.

```text
new → add packs → build → analyze → run → export
```

## Start

```bash
go build -o work/bin/bofbench ./cmd/bofbench

work/bin/bofbench new portable-survey --pack deep-survey
work/bin/bofbench build bofs/portable-survey
work/bin/bofbench analyze bofs/portable-survey
```

Register any Windows system reachable over SSH or WinRM, then run with runtime arguments:

```bash
work/bin/bofbench lab add dedicated \
  --provider existing \
  --transport ssh \
  --host windows-lab \
  --user operator
work/bin/bofbench lab bootstrap --lab dedicated
work/bin/bofbench run bofs/portable-survey --via lab --lab dedicated \
  --arg process_filter=lsass \
  --arg result_limit=25
```

Moving the same project to another machine does not change its source or lock file:

```bash
work/bin/bofbench lab add replacement --from dedicated --host 10.0.0.50
work/bin/bofbench lab bootstrap --lab replacement
work/bin/bofbench lab use replacement
```

See [Portable Lab Profiles](docs/lab-profiles.md) for SSH, WinRM, Vagrant, build modes, selection rules, and fresh-host setup.

Export the same BOF:

```bash
work/bin/bofbench export bofs/portable-survey --for raw
work/bin/bofbench export bofs/portable-survey --for sliver
work/bin/bofbench export bofs/portable-survey --for cobaltstrike
work/bin/bofbench export bofs/portable-survey --for edrlab
```

Use a direct Proxmox profile for the shared lab:

```bash
work/bin/bofbench lab status --lab proxmox-dev
work/bin/bofbench run bofs/portable-survey \
  --via lab --lab proxmox-dev --observe full
```

The run receipt binds BOFBench's direct target and runtime evidence. The EDR
export is a repository-neutral `windows.artifact-bundle/v1`; EDR Lab owns its
fresh target-v2 lifecycle and product classification.

## Capability packs

A pack owns source fragments, typed runtime arguments, expected capabilities, effects, operating requirements, output fields, supported runtimes, and optional cleanup.

```bash
work/bin/bofbench pack list
work/bin/bofbench pack search process
work/bin/bofbench pack show system-discovery
```

Add a private/local or Git-backed catalog without rebuilding BOFBench:

```bash
work/bin/bofbench catalog add ~/bofbench-packs-internal --name internal
work/bin/bofbench pack show internal/token-impersonation
work/bin/bofbench add bofs/portable-survey internal/token-impersonation
```

Resolved versions, source hashes, argument contracts, external catalog roots, and cleanup companions are stored in `bofbench.lock.json`.

## Analyze BOFBench and third-party objects

```bash
work/bin/bofbench analyze bofs/portable-survey
work/bin/bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
work/bin/bofbench analyze first.x64.o --compare second.x64.o
```

Default output leads with:

- **Can do** — confirmed primitives, strong function-local behavior chains, and possible pack-declared abilities;
- **Effects** — reads, writes, execution, persistence, credential access, or remote reach;
- **Needs** — privilege, arguments, network, domain, and host conditions;
- **Arguments** — inferred or pack-defined BOF types;
- **Works with** — native, lab, Sliver, and Cobalt Strike support.

The analyzer recognizes chains including remote-thread/APC injection, token duplication and impersonation, alternate-token process launch, service creation/start, Run-key persistence, credential-process access, and minidump collection. Isolated imports remain primitives; they are not inflated into multi-step capabilities.

## Runtime adapters

```bash
work/bin/bofbench run bofs/portable-survey --via native
work/bin/bofbench run bofs/portable-survey --via lab --lab dedicated
work/bin/bofbench run bofs/portable-survey --via sliver --lab dedicated
work/bin/bofbench run bofs/portable-survey --via cobaltstrike
```

- Native execution uses child-process Windows COFF loaders with timeouts, exception reporting, output limits, and per-section memory protection.
- AMD64 objects use `native/loader/bofbench-loader.exe`.
- I386 objects use `native/loader/bofbench-loader-x86.exe` under WoW64.
- Lab runs sync the project to an existing or provider-backed Windows VM and collect reports.
- Sliver packages use `extension.json`, named typed arguments, and `coff-loader`.
- Live Cobalt Strike execution uses an ephemeral Aggressor script and environment-only credentials.

## Cleanup

Stateful packs declare exact cleanup companions:

```bash
work/bin/bofbench pack show internal/run-key --cleanup
work/bin/bofbench run bofs/persist --via lab --lab disposable --cleanup \
  --arg value_name=BOFBenchLab
```

Cleanup is built in an isolated temporary project so the action BOF is never modified.

## Arsenal intelligence

```bash
work/bin/bofbench arsenal inventory arsenal/trustedsec-sa
work/bin/bofbench arsenal search arsenal/trustedsec-sa --can token
work/bin/bofbench arsenal search arsenal/trustedsec-sa \
  --effect credential-access --works-with sliver
work/bin/bofbench arsenal search arsenal/trustedsec-sa \
  --arch x64 --confidence 'strong chain' --has-args
```

Indexes include capabilities, behavior chains, arguments, effects, requirements, architecture, loader support, source/version, runtime targets, and duplicate object groups. Exact object analyses are cached and refreshed only when the object, source identity, or analyzer signature set changes.

Scale pack validation and live proof from the same manifests:

```bash
work/bin/bofbench pack test --all --catalog builtin
work/bin/bofbench pack test --all --catalog internal
work/bin/bofbench pack prove internal/section-map-inject --via lab --lab devbox
```

## Operator TUI

```bash
work/bin/bofbench tui
```

The Build, Analyze, Arsenal, Run, Lab, and Results workspaces execute the same CLI commands with Enter and show real output—no wrapper scripts or parallel business logic.

## Test and docs

```bash
go test ./...
make docs
make docs-check
make docs-media   # optional: regenerate the six checked-in VHS clips
```

The operator handbook starts at [`docs/index.md`](docs/index.md); task-oriented walkthroughs are indexed in the [Scenario Library](docs/scenarios/index.md). `make docs-check` validates both available handbook layers, generated pack references, links, anchors, media, direct command examples, and the host-only build/analyze/arsenal/export smoke lane.

Compatibility commands (`feature`, `recipe`, `dev`, `preflight`, and `stage`) remain supported through `0.x` and cannot be removed before `1.0.0`. Their exact replacements, known parity gaps, and testable removal gates live in the [generated compatibility reference](docs/legacy-commands.md) and its [versioned JSON contract](docs/evidence/command-compatibility-v1.json).
