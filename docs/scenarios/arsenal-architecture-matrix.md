# Compare an Arsenal Across Architectures

## Objective

Analyze every x64 and x86 object independently, identify real behavioral differences, and reuse cached results on later searches.

## Prerequisites

- A local arsenal containing objects or source.
- Optional `.cna`, `extension.json`, manifests, and source files near their objects.

```bash
bofbench arsenal acquire \
  https://github.com/trustedsec/CS-Situational-Awareness-BOF.git \
  --name trustedsec-sa
bofbench arsenal lock arsenal/trustedsec-sa
```

## Build the matrix

```bash
bofbench arsenal matrix arsenal/trustedsec-sa
bofbench arsenal matrix arsenal/trustedsec-sa --format json \
  > /tmp/trustedsec-matrix.json
```

Arsenal-index version 2 records a separate analysis for each object architecture. The matrix compares normalized capabilities, behavior chains, arguments, loader support, imports, effects, and runtime support. It also reports x64-only/x86-only entries, cache state, metadata associations, and concrete loader blockers.

Expected summary:

```text
ARSENAL ARCHITECTURE MATRIX
summary   entries=<N> pairs=<N> equivalent=<N> different=<N> ...
```

A different SHA-256 is normal across architectures and does not by itself mean behavioral drift.

## Search the architecture-aware index

```bash
bofbench arsenal search arsenal/trustedsec-sa \
  --arch x86 --loader compatible

bofbench arsenal search arsenal/trustedsec-sa \
  --api RpcBinding --chain remote_registry --loader compatible

bofbench arsenal search arsenal/trustedsec-sa \
  --can token --confidence 'confirmed primitive' --has-args
```

All populated filters are ANDed. `--api` searches normalized imports, `--chain` searches function-local behavioral chains, and `--loader` searches the per-architecture loader result.

## Inspect one difference

```bash
jq '.entries[] | select(.equivalent == false) |
  {name, differences, x64, x86, corpus_blockers}' \
  /tmp/trustedsec-matrix.json | less
```

Then compare the exact pair:

```bash
bofbench analyze arsenal/trustedsec-sa/SA/<name>/<name>.x64.o
bofbench analyze arsenal/trustedsec-sa/SA/<name>/<name>.x86.o
bofbench analyze arsenal/trustedsec-sa/SA/<name>/<name>.x64.o \
  --compare arsenal/trustedsec-sa/SA/<name>/<name>.x86.o
```

## Cache behavior

The first matrix refreshes uncached object/architecture analyses. Repeating it should move unchanged cells to `cache_hits`. A version-1 cache is ignored and rebuilt safely; source arsenals and lock files are not rewritten.

Cache invalidation occurs when the object hash, source identity, architecture, or analyzer-signature-set hash changes.

## Common failures

- `analysis_error`: preserve the object and inspect it directly with `bofbench analyze`.
- `unsupported_relocation` or another blocker: the matrix records the concrete architecture and loader result.
- unexpected source association: keep `.cna`, `extension.json`, or source close to the corresponding object directory.
- unexpected hash drift: run `bofbench arsenal verify` and `bofbench arsenal diff` before updating the lock.

## Next commands

```bash
bofbench arsenal verify arsenal/trustedsec-sa
bofbench arsenal inventory arsenal/trustedsec-sa
bofbench arsenal regression <baseline.json> <current.json>
```

