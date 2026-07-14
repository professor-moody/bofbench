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
| `export --for` | Produce raw, Sliver, or Cobalt Strike packages. |
| `arsenal` | Acquire, index, search, compare, and operate on external BOFs. |
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
bofbench pack docs --output docs/pack-reference.md
```

## Create and compose

```bash
bofbench new fieldcheck --pack host-discovery,system-discovery
bofbench add bofs/fieldcheck domain-discovery
bofbench add bofs/fieldcheck internal/token-impersonation
```

Use `--catalog path` for a one-command external catalog. The resolved root is retained in the lockfile for later commands.

## Build

```bash
bofbench build bofs/fieldcheck
bofbench build bofs/fieldcheck --compiler mingw --arch x64
bofbench build bofs/fieldcheck --compiler msvc --verify-reproducible
```

## Analyze

```bash
bofbench analyze bofs/fieldcheck
bofbench analyze object.x64.o --format text
bofbench analyze object.x64.o --format json
bofbench analyze object.x64.o --format md
bofbench analyze current.x64.o --compare previous.x64.o
```

Default output leads with `Can do`, `Effects`, `Needs`, `Arguments`, and `Works with`.

## Run

```bash
bofbench run bofs/fieldcheck --via native \
  --arg process_filter=lsass --arg result_limit=25
bofbench run bofs/fieldcheck --via lab \
  --arg process_filter=lsass --arg result_limit=25
bofbench run bofs/fieldcheck --via sliver \
  --arg process_filter=lsass --arg result_limit=25
bofbench run bofs/fieldcheck --via cobaltstrike \
  --arg process_filter=lsass --arg result_limit=25
```

Run a stateful pack's isolated cleanup companion:

```bash
bofbench run bofs/persist --via lab --cleanup --arg value_name=BOFBenchLab
```

For an external object without named metadata, use compatibility tokens:

```bash
bofbench run object.x64.o --via native --args z:target i:25
```

## Export

```bash
bofbench export bofs/fieldcheck --for raw
bofbench export bofs/fieldcheck --for sliver
bofbench export bofs/fieldcheck --for cobaltstrike
bofbench export verify export/fieldcheck-sliver.zip
```

`stage`, `feature`, `recipe`, `dev`, and `preflight` remain compatibility aliases for one major release and print or document the capability-first equivalent.

## Lab

```bash
bofbench lab init --provider existing --host bofbench-winvm
bofbench lab bootstrap
bofbench lab status
bofbench lab run bofs/fieldcheck

bofbench lab init --provider vagrant --topology standalone
bofbench lab up
bofbench lab snapshot clean
bofbench lab restore clean
```

## Arsenal

```bash
bofbench arsenal acquire <path-or-url> --name team
bofbench arsenal inventory arsenal/team
bofbench arsenal search arsenal/team --can token
bofbench arsenal search arsenal/team --effect writes-state --works-with sliver
bofbench arsenal compare old.x64.o new.x64.o
```
