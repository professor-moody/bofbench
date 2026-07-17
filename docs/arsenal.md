# Arsenal Intelligence

An arsenal is a rebuildable capability index over public or private BOFs. It accepts local directories, Git repositories, ZIPs, source trees, `.cna` files, Sliver extensions, and existing objects.

## Acquire and index

```bash
bofbench arsenal acquire https://github.com/trustedsec/CS-Situational-Awareness-BOF.git \
  --name trustedsec-sa
bofbench arsenal inventory arsenal/trustedsec-sa
```

The inventory records capabilities, behavior chains, effects, arguments, architecture, loader support, source/version, target compatibility, and duplicate object groups. Arsenal index version 2 stores a separate analysis for every object and architecture. Analysis is cached outside the arsenal by object hash, source identity, architecture, analyzer-signature-set hash, and analysis schema version. Repeating a search reuses unchanged objects and reports `cached` versus `refreshed` counts. Old or older-analysis caches are ignored and rebuilt without touching the source arsenal.

## Search in operator language

```bash
bofbench arsenal search arsenal/trustedsec-sa --can token
bofbench arsenal search arsenal/trustedsec-sa \
  --effect credential-access --works-with sliver
bofbench arsenal search arsenal/trustedsec-sa --requires admin
bofbench arsenal search arsenal/trustedsec-sa --arch x64 \
  --confidence 'strong chain' --has-args
bofbench arsenal search arsenal/trustedsec-sa \
  --api RpcBinding --chain remote_registry --loader compatible
```

Search filters are ANDed. Results are grouped by operator capability and show confidence, arguments, effects, requirements, and runtimes before object structure. Nearby `.cna`, Sliver `extension.json`, source, and manifest metadata is associated with the correct object pair.

## Architecture matrix

```bash
bofbench arsenal matrix arsenal/trustedsec-sa
bofbench arsenal matrix arsenal/trustedsec-sa --format json
bofbench arsenal matrix arsenal/trustedsec-sa --analysis-version 3
```

The matrix analyzes x64 and x86 independently, then reports:

- capability and behavior-chain equivalence;
- argument, loader-support, import, effect, and runtime differences;
- x64-only or x86-only entries;
- associated source, `.cna`, and Sliver extension files;
- cache reuse and concrete loader blockers.

A hash difference is expected between architectures and does not itself make behavior different. The equivalence decision compares normalized operator behavior and runtime contracts.

## Capability graph

Graph objects to one focused capability using analysis v3 evidence:

```bash
bofbench arsenal graph arsenal/trustedsec-sa \
  --capability remote-execution
bofbench arsenal graph arsenal/trustedsec-sa \
  --capability token --format mermaid
bofbench arsenal graph arsenal/trustedsec-sa \
  --capability process --format json
```

The graph is capability-focused, not an import dump. Object nodes connect to inferred capabilities, with architecture, confidence, interprocedural evidence, and loader state retained in the machine-readable form.

## Analyze and compare

```bash
bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
bofbench arsenal compare first.x64.o second.x64.o
```

Comparison emphasizes capability, argument, behavior-chain, and loader changes. Duplicate or changed hashes remain visible but do not imply changed behavior by themselves.

## x64 and x86 coverage

The loader matrix supports AMD64 and I386 COFF objects. x64 runs through `bofbench-loader.exe`; x86 runs through the separate `bofbench-loader-x86.exe` helper under WoW64 on Windows x64.

```bash
bofbench preflight arsenal/trustedsec-sa --arch all --report-only
```

The matrix reports compatibility by corpus coverage, relocation family, Beacon shim, toolchain, and argument need.

## Existing object workflow

```bash
bofbench analyze path/to/public-bof.x64.o
bofbench run path/to/public-bof.x64.o --via native --args z:target i:25
bofbench export path/to/public-bof.x64.o --for sliver --args z:target i:25
```

Use compatibility `--args` tokens when no pack or extension metadata supplies names. Project-based BOFs should use `--arg name=value`.

## Acquisition limits

HTTP and ZIP acquisition is bounded. Extraction rejects absolute paths, traversal, Windows drive/backslash escapes, symlinks, special files, duplicates, and case-colliding destinations. Updates are prepared beside the target and replace it only after validation succeeds.
