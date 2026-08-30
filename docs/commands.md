# Command Reference

## Primary workflow

| Command | Purpose |
| --- | --- |
| `catalog` | Add, list, update, or remove pack catalogs. |
| `pack` | List, search, show, validate, and document capability packs. |
| `new` | Create a BOF project and resolve initial packs. |
| `add` | Add more packs to an existing project. |
| `build` | Compile a project to a COFF object. |
| `analyze` | Explain capabilities, chains, effects, arguments, requirements, and runtime support. |
| `run --via` | Execute through `native`, `lab`, `sliver`, or `cobaltstrike`. |
| `export --for` | Produce raw, Sliver, Cobalt Strike, or EDR Lab packages. |
| `arsenal` | Acquire, index, search, compare, and operate on external BOFs. |
| `operation` | Run, resume, inspect, and reverse-clean multi-step pack workflows. |
| `lab` | Configure, bootstrap, run, snapshot, restore, and inspect Windows labs. |
| `tui` | Run the action-oriented terminal workbench. |

## Catalog and packs

```bash
bofbench catalog add ~/bofbench-packs-internal --name internal
bofbench catalog list
bofbench catalog update internal
bofbench catalog remove internal

bofbench pack list
bofbench pack search token
bofbench pack show internal/token-impersonation
bofbench pack show internal/run-key --cleanup
bofbench pack validate path/to/pack.json
bofbench pack test process-tree
bofbench pack test --all --catalog internal
bofbench pack prove internal/section-map-inject --via lab --lab devbox --arch x64
bofbench pack docs --catalog builtin --output docs/pack-reference.md
```

## Create and compose

```bash
bofbench new portable-survey --pack deep-survey
bofbench add bofs/portable-survey internal/token-impersonation
```

Use `--catalog path` for a one-command external catalog. The resolved root is retained in the lockfile for later commands.

## Operations

```bash
bofbench operation list
bofbench operation search process
bofbench operation show internal/section-map-start-unmap
bofbench operation graph internal/adaptive-memory-execute
bofbench operation graph internal/adaptive-memory-execute --format mermaid
bofbench operation graph internal/adaptive-memory-execute --format json
bofbench operation show internal/coordination-matrix --expand
bofbench operation graph internal/coordination-matrix --expand
bofbench operation validate operations/example/operation.json
bofbench operation test internal/virtual-memory-execute
bofbench operation test --all --catalog ~/bofbench-packs-internal \
  --compiler mingw --compiler msvc
bofbench operation prove internal/virtual-memory-execute \
  --catalog ~/bofbench-packs-internal --via lab --lab devbox --arch x64 \
  --parallelism 4
bofbench operation run internal/section-map-start-unmap \
  --via lab --lab devbox --parallelism 4 \
  --arg target_pid=1234 --arg payload=@file:/tmp/payload.bin
bofbench operation run internal/ipc-coordination-matrix \
  --via lab --lab devbox --parallelism 3 <typed arguments>
bofbench operation graph internal/ipc-dependency-matrix --expand
bofbench operation run internal/ipc-dependency-matrix \
  --via lab --lab devbox --parallelism 4 <typed arguments>
bofbench operation run internal/registry-change-observe \
  --via lab --lab devbox --parallelism 4 <typed arguments>
bofbench operation watch runs/<run-id>/operation.json --follow
bofbench operation cancel runs/<run-id>/operation.json
bofbench operation cancel runs/<run-id>/operation.json --cleanup
bofbench operation resume runs/<run-id>/operation.json --parallelism 4
bofbench operation cleanup runs/<run-id>/operation.json --parallelism 4
bofbench operation docs --output docs/operation-reference.md
```

See [multi-step operations](operations.md) for result routing, parallel groups, dependency-aware DAGs, background readiness, live watching, cancellation, contracts, captures, sensitive inputs, proof, resume, and reverse-topological cleanup. `--parallelism` accepts `1–16` and defaults to `4`.

## Build

```bash
bofbench build bofs/portable-survey
bofbench build bofs/portable-survey --compiler mingw --arch x64
bofbench build bofs/portable-survey --compiler msvc --verify-reproducible
```

## Analyze

```bash
bofbench analyze bofs/portable-survey
bofbench analyze object.x64.o --format text
bofbench analyze object.x64.o --format json
bofbench analyze object.x64.o --format md
bofbench analyze current.x64.o --compare previous.x64.o
bofbench analyze third-party.x64.o --explain token-impersonation
```

Default output leads with `Can do`, `Effects`, `Needs`, `Arguments`, and `Works with`.

## Run

```bash
bofbench run bofs/portable-survey --via native \
  --arg process_filter=lsass --arg result_limit=25
bofbench run bofs/portable-survey --via lab --lab dedicated \
  --arg process_filter=lsass --arg result_limit=25
bofbench run bofs/portable-survey --via sliver --lab dedicated \
  --arg process_filter=lsass --arg result_limit=25
bofbench run bofs/portable-survey --via cobaltstrike \
  --arg process_filter=lsass --arg result_limit=25
```

Run a stateful pack's isolated cleanup companion:

```bash
bofbench run bofs/persist --via lab --lab disposable --cleanup --arg value_name=BOFBenchLab
```

For an external object without named metadata, use compatibility tokens:

```bash
bofbench run object.x64.o --via native --args z:target i:25
```

## Export

```bash
bofbench export bofs/portable-survey --for raw
bofbench export bofs/portable-survey --for sliver --arch x64
bofbench export bofs/portable-survey --for sliver --arch x86
bofbench export bofs/portable-survey --for cobaltstrike
bofbench export bofs/portable-survey --for edrlab
bofbench export verify export/portable-survey-sliver.zip
```

`feature`, `recipe`, `dev`, and `preflight` remain compatibility commands, while `stage` is an exact alias of `export`. All remain supported through `0.x` and cannot be removed before `1.0.0`. See [Legacy Command Compatibility](legacy-commands.md) for exact replacements and open parity gates, or run `bofbench compatibility` (`--format json` for automation).

## Lab

```bash
bofbench lab add development \
  --provider existing \
  --transport ssh \
  --host windows-development \
  --user operator

bofbench lab add dedicated \
  --from development \
  --host 10.0.0.50 \
  --identity ~/.ssh/bofbench-dedicated

bofbench lab list
bofbench lab show dedicated
bofbench lab use dedicated
bofbench lab bootstrap --lab dedicated
bofbench lab status --lab dedicated
bofbench run bofs/portable-survey --via lab --lab dedicated
```

Profile selection follows `--lab`, `BOFBENCH_LAB`, project default, active global profile, and the only configured profile. A project default contains only the profile name:

```bash
bofbench lab use dedicated --project bofs/portable-survey
```

Prepare a fresh Windows transport or register a Vagrant environment:

```bash
bofbench lab setup-script --transport ssh
bofbench lab setup-script --transport winrm

bofbench lab add disposable \
  --provider vagrant \
  --vagrantfile lab/Vagrantfile \
  --machine workstation \
  --topology standalone
bofbench lab up --lab disposable
bofbench lab snapshot clean --lab disposable
bofbench lab restore clean --lab disposable
```

Inspect provider media, build exact templates, provision a domain, and manage ordered target sets:

```bash
bofbench lab media list --provider proxmox \
  --proxmox-prep ~/.config/bofbench/proxmox-lab.json
bofbench lab template status --lab proxmox-domain-dc
bofbench lab template build --lab proxmox-domain-dc \
  --vmid 4102 --iso local:iso/windows-server.iso
bofbench lab topology provision proxmox-domain \
  --domain bofbench.test --netbios BOFBENCH --credential @prompt
bofbench lab topology verify proxmox-domain
bofbench lab topology target add proxmox-standalone \
  --set windows-targets --lab proxmox-target
```

Manage the disposable LocalSystem process used for privileged capability proof:

```bash
bofbench lab target deploy --lab disposable
bofbench lab target status --lab disposable
bofbench lab target remove --lab disposable
```

Check Sliver for the same named target:

```bash
bofbench sliver setup --lab dedicated
bofbench sliver sessions --lab dedicated
```

## Arsenal

```bash
bofbench arsenal acquire <path-or-url> --name team
bofbench arsenal inventory arsenal/team
bofbench arsenal search arsenal/team --can token
bofbench arsenal search arsenal/team --effect writes-state --works-with sliver
bofbench arsenal search arsenal/team --arch x64 --confidence 'strong chain' --has-args
bofbench arsenal search arsenal/team --api RpcBinding --chain remote_registry --loader compatible
bofbench arsenal matrix arsenal/team
bofbench arsenal matrix arsenal/team --format json
bofbench arsenal matrix arsenal/team --analysis-version 3
bofbench arsenal graph arsenal/team --capability remote-execution
bofbench arsenal graph arsenal/team --capability token --format mermaid
bofbench arsenal compare old.x64.o new.x64.o
```

## Runtime control and comparison

```bash
bofbench runtime control add sliver-lab \
  --runtime sliver --provider proxmox \
  --proxmox-prep ~/.config/bofbench/proxmox-lab.json \
  --vmid 4120 --template-vmid 4104
bofbench runtime control up sliver-lab
bofbench runtime control status sliver-lab
bofbench sliver lab-session start \
  --control sliver-lab --lab proxmox-dev --arch x64 --context user

bofbench runtime compare bofs/portable-survey \
  --via lab,sliver --lab proxmox-dev
bofbench runtime compare operation internal/domain-remote-operation-matrix \
  --via lab,sliver --topology proxmox-domain \
  --catalog ~/bofbench-packs-internal
```

## Inspect, list, and fetch compatibility surfaces

Use the capability-first commands for new workflows. These direct object/arsenal commands remain available:

```bash
bofbench inspect object.x64.o
bofbench list /absolute/path/to/objects
bofbench fetch <PATH_OR_URL> --name external-source
```

`inspect` prints human-readable object analysis. `list` inventories an arsenal-like directory. `fetch` acquires a known alias, Git repository, ZIP, or raw object; `arsenal acquire` is preferred when the result will be locked, indexed, searched, or compared.

## Documentation

```bash
bofbench docs serve
bofbench docs build --strict
```

Repository maintainers should use `make docs-check` because it also verifies generated pack references, links, media, command coverage, and executable host scenarios.

## Runtime task visibility

```bash
bofbench runtime status --lab devbox
bofbench runtime sessions --via sliver --lab devbox
bofbench runtime wait --via sliver --lab devbox --timeout 10m
bofbench runtime tasks --via sliver --lab devbox
bofbench runtime tasks --via lab
bofbench runtime task <TASK_ID> --refresh
bofbench runtime task <TASK_ID> --refresh --wait --timeout 10m
bofbench runtime task <TASK_ID> --cancel
bofbench runtime watch --via sliver --lab devbox --refresh --timeout 10m
```
