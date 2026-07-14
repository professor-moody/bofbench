# BOFBench

BOFBench is a capability-first workbench for building, analyzing, running, and exporting Beacon Object Files.

```text
new → add packs → build → analyze → run → export
```

## Start

```bash
go build -o work/bin/bofbench ./cmd/bofbench

work/bin/bofbench new fieldcheck \
  --pack host-discovery,system-discovery
work/bin/bofbench add bofs/fieldcheck domain-discovery
work/bin/bofbench build bofs/fieldcheck
work/bin/bofbench analyze bofs/fieldcheck
```

Run it on an existing Windows lab with runtime arguments:

```bash
work/bin/bofbench lab init --provider existing --host bofbench-winvm
work/bin/bofbench lab bootstrap
work/bin/bofbench run bofs/fieldcheck --via lab \
  --arg process_filter=lsass \
  --arg result_limit=25
```

Export the same BOF:

```bash
work/bin/bofbench export bofs/fieldcheck --for raw
work/bin/bofbench export bofs/fieldcheck --for sliver
work/bin/bofbench export bofs/fieldcheck --for cobaltstrike
```

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
work/bin/bofbench add bofs/fieldcheck internal/token-impersonation
```

Resolved versions, source hashes, argument contracts, external catalog roots, and cleanup companions are stored in `bofbench.lock.json`.

## Analyze BOFBench and third-party objects

```bash
work/bin/bofbench analyze bofs/fieldcheck
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
work/bin/bofbench run bofs/fieldcheck --via native
work/bin/bofbench run bofs/fieldcheck --via lab
work/bin/bofbench run bofs/fieldcheck --via sliver
work/bin/bofbench run bofs/fieldcheck --via cobaltstrike
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
work/bin/bofbench run bofs/persist --via lab --cleanup \
  --arg value_name=BOFBenchLab
```

Cleanup is built in an isolated temporary project so the action BOF is never modified.

## Arsenal intelligence

```bash
work/bin/bofbench arsenal inventory arsenal/trustedsec-sa
work/bin/bofbench arsenal search arsenal/trustedsec-sa --can token
work/bin/bofbench arsenal search arsenal/trustedsec-sa \
  --effect credential-access --works-with sliver
```

Indexes include capabilities, behavior chains, arguments, effects, requirements, architecture, loader support, source/version, runtime targets, and duplicate object groups.

## Operator TUI

```bash
work/bin/bofbench tui
```

The Build, Analyze, Arsenal, Run, Lab, and Results workspaces execute the same CLI commands with Enter and show real output—no wrapper scripts or parallel business logic.

## Test and docs

```bash
go test ./...
mkdocs build --strict
mkdocs serve
```

Documentation starts at [`docs/index.md`](docs/index.md). Compatibility commands (`feature`, `recipe`, `dev`, `preflight`, and `stage`) remain readable for one major release while the primary surface uses packs, `analyze`, `run --via`, and `export --for`.
