# Compare Arbitrary Objects

## Objective

Explain two unknown COFF objects without assuming their filenames describe their behavior.

## Inspect the inputs

```bash
file /absolute/path/first.o /absolute/path/second.o
bofbench analyze /absolute/path/first.o --format json
bofbench analyze /absolute/path/second.o --format json
```

Confirm architecture, entrypoint, sections, imports, relocations, and loader support before comparing capability.

## Produce a behavioral comparison

```bash
bofbench analyze /absolute/path/first.o \
  --compare /absolute/path/second.o \
  --format md
```

Read the result in this order:

1. Capability additions and removals.
2. Strong-chain versus primitive confidence.
3. Effect changes, especially new writes, execution, or remote reach.
4. Required arguments and privilege.
5. Runtime compatibility.
6. Structural changes.

## Recover argument metadata

Place known metadata adjacent to each object:

```text
candidate/
├── extension.json
├── command.cna
├── source.c
└── object.x64.o
```

Rerun analysis. BOFBench correlates `.cna`, Sliver extension, source, and pack metadata without replacing object-derived behavioral evidence.

## Distinguish common outcomes

- Same capabilities, different hash: likely rebuild or toolchain variation.
- Same imports, different required string: potentially different operator action using shared APIs.
- Added isolated API: a new primitive, not automatically a full chain.
- Added complete function-local chain: a meaningful behavioral change.
- Loader regression only: execution compatibility changed even if capability did not.

## Preserve the result

```bash
bofbench arsenal lock /absolute/path/to/corpus
bofbench arsenal inventory /absolute/path/to/corpus
bofbench arsenal diff /absolute/path/to/corpus
```

The lock lets a later operator distinguish source revision, object hash, and analyzer-signature changes.
