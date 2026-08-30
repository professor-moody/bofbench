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

## Frozen analyzer evaluation corpus

`testdata/analyzer-corpus-v1.json` is the first review boundary for measuring the
analyzer against third-party objects. It binds one TrustedSec source commit and
the digest of `testdata/corpus-lock.json` to 16 reviewed behaviors and paired
x64/x86 objects. Each case declares its expected loader-support class and exact
capability, behavior-chain, and interprocedural-chain label sets.

The labels are frozen before evaluation. A measurement may report disagreements
but must not rewrite labels to match analyzer output. Version 1 contains no
loader-blocked object and no positive interprocedural chain, so it can measure
false positives in those areas but cannot support a recall claim for either.
Static labels also do not claim that an object executed successfully.

Run the evaluation only from a clean checkout so the report can bind the exact
analyzer source and binary:

```bash
make analyzer-corpus
```

The first measurement evaluated the labels frozen at commit `9dd0eab` against
analyzer commit `afb0a20` and signature-set digest
`abdb67143e4386bedca8e2b277bd8c4032e1f4bc8bed1f986e9a40e3fdb0cd73`.
All 32 support classifications matched, capability labels scored 44 TP / 0 FP /
0 FN, behavior-chain labels scored 18 TP / 0 FP / 0 FN, and all 16 architecture
pairs agreed. The full per-object result and provenance are preserved in
`qualification/receipts/bofbench-analyzer-corpus-evaluation-20260830.json`.
Blocked-object and interprocedural recall remain withheld; the passing result
does not erase the coverage limits declared before evaluation.

### Version 2: missing-class measurement

`testdata/analyzer-corpus-v2.json` layers two reviewed TrustedSec Remote Ops
families over the immutable version 1 corpus. Its separate extension lock binds
the upstream commit, four x64/x86 objects, and the two source files used for
review. The combined boundary contains 18 families and 36 objects, including
two loader-blocked objects and two positive interprocedural objects.

Run a current measurement into the ignored `work/` directory:

```bash
make analyzer-corpus-v2
```

The pre-fix measurement against `b7c5b33` classified all 36 loader outcomes
correctly, measured blocked-object recall at 2/2, and retained 46 TP / 0 FP / 0
FN capability labels. It found 20/22 behavior labels and 0/2 interprocedural
labels; both misses were the reviewed `lastpass` process-memory chain. The
immutable receipt is
`qualification/receipts/bofbench-analyzer-corpus-v2-evaluation-20260830.json`.

Commit `5a9fd2a` recovers resolved local x86/x64 calls only within known
executable function ranges. The same frozen corpus then found all 22 reviewed
behavior labels and both interprocedural labels. Its remaining two reported
positives are the x64/x86 `sc_enum` service-inventory chain. Independent review
of the pinned source confirms that `go` opens the supplied host's service
manager and calls the helper that enumerates services with that handle. Because
the inherited version 1 labels are immutable and empty for this case, the
post-fix report remains `mismatch` instead of rewriting history.

The remeasurement and the digest-bound label audit are preserved at
`qualification/receipts/bofbench-analyzer-corpus-v2-postfix-20260830.json` and
`qualification/receipts/bofbench-analyzer-corpus-v2-label-audit-20260830.json`.
A successor corpus must cite that audit explicitly; versions 1 and 2 must not be
edited to turn either historical result green.

## When analysis is uncertain

- Check whether the object contains an entrypoint and supported architecture.
- Look for its `.cna` or `extension.json` argument contract.
- Compare source imports with object relocations.
- Run `--loader-details` to separate unsupported loader behavior from offensive capability.
- Treat isolated APIs as primitives, not complete execution chains.
- Use a named lab profile for runtime confirmation and retain the exact-hash receipt.
