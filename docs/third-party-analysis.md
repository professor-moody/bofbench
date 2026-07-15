# Analyze Third-Party BOFs

BOFBench can analyze an existing `.o` without a project, source tree, or pack manifest. Metadata improves argument and source attribution, but it is not required for structural and behavioral analysis.

## Analyze one object

```bash
bofbench analyze /absolute/path/to/object.x64.o
```

Start with `Can do`, `Needs`, `Effects`, and `Works with`. Then inspect imports, relocations, strings, and loader details if the capability conclusion needs explanation.

## Analyze an object with adjacent metadata

Keep the object beside its public source, `.cna`, or Sliver `extension.json`:

```text
external-bof/
├── extension.json
├── source.c
└── object.x64.o
```

BOFBench uses adjacent contracts to name typed arguments and target support while retaining object-derived behavior evidence.

## Compare architectures

```bash
bofbench analyze object.x64.o --compare object.x86.o --format md
```

Equivalent x64/x86 variants should normally produce the same operator capability even when section layout, relocation counts, sizes, and compiler artifacts differ.

## Compare versions

```bash
bofbench analyze old/object.x64.o \
  --compare new/object.x64.o --format md
```

Review changes in this order:

1. Added or removed capabilities.
2. Changed effects and requirements.
3. Changed typed arguments.
4. Changed runtime/loader support.
5. Structural changes such as imports, sections, relocations, and size.

## Index a repository

```bash
bofbench arsenal acquire https://github.com/<owner>/<repo> --name public-bofs
bofbench arsenal inventory arsenal/public-bofs
bofbench arsenal lock arsenal/public-bofs
bofbench arsenal search arsenal/public-bofs --can token --arch x64
```

The index is keyed by object hash, source version, architecture, and analyzer-signature-set hash. Repeated searches reuse unchanged analysis.

## Search in operator language

```bash
bofbench arsenal search arsenal/public-bofs --can token
bofbench arsenal search arsenal/public-bofs --effect starts-execution
bofbench arsenal search arsenal/public-bofs --works-with sliver --has-args
bofbench arsenal search arsenal/public-bofs --requires admin --confidence strong-chain
```

Search results lead with capability, confidence, arguments, effects, and runtime support. Structural fields remain available for drill-down.

## Verify acquisition state

```bash
bofbench arsenal verify arsenal/public-bofs
bofbench arsenal diff arsenal/public-bofs
bofbench arsenal regression <before-report> <after-report>
```

The lock pins source revision and discovered object hashes. Regression distinguishes a changed hash from changed behavior or loader compatibility.

## When analysis is uncertain

- Check whether the object contains an entrypoint and supported architecture.
- Look for its `.cna` or `extension.json` argument contract.
- Compare source imports with object relocations.
- Run `--loader-details` to separate unsupported loader behavior from offensive capability.
- Treat isolated APIs as primitives, not complete execution chains.
- Use a named lab profile for runtime confirmation and retain the exact-hash receipt.
