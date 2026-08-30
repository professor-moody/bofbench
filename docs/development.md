# Build and Extend a BOF

Create a project from one or more packs:

```bash
bofbench new fieldcheck --pack host-discovery,system-discovery
bofbench add bofs/fieldcheck domain-discovery
bofbench build bofs/fieldcheck
```

The generated project contains normal C source, `beacon.h`, `bofbench.toml`, and `bofbench.lock.json`. Source fragments remain visible and editable. Pack calls are inserted in dependency order and duplicate fragments are suppressed.

## Add an external pack

```bash
bofbench catalog add ~/bofbench-packs-internal --name internal
bofbench add bofs/fieldcheck internal/token-impersonation
bofbench build bofs/fieldcheck
```

Parameterized pack calls share one Beacon data parser. Argument order comes from the lockfile, and named values are converted to the correct BOF packing type at runtime.

## Build matrix

```bash
bofbench build bofs/fieldcheck --compiler mingw --arch x64
bofbench build bofs/fieldcheck --compiler msvc --arch x64
bofbench matrix bofs/fieldcheck --compiler mingw --arch all --execute never
```

MinGW and MSVC builds record the exact compiler, flags, object hash, source/config fingerprints, and compiler log. x86 objects are dispatched through the separate x86 loader helper on Windows.

## Analyze after every build

```bash
bofbench analyze bofs/fieldcheck
```

Project analysis adds pack-declared arguments and capabilities to the object-derived primitives and behavior chains. Declared metadata is marked `possible`; function-local API evidence can raise a known chain to `strong chain`.

## Backward-compatible projects

Projects containing `bofbench.recipe.json` migrate on first pack use. The original sidecar remains in place, and the resolved equivalent is written to `bofbench.lock.json`. `feature`, `recipe`, and `dev` remain compatibility commands through `0.x`; the [compatibility contract](legacy-commands.md) records which workflows have complete replacements and which still have evidence gaps.
