# Author and Prove an External Pack

## Objective

Create a reusable pack outside BOFBench, consume it from a normal project, and verify its static and live contracts.

## Prerequisites

- A writable external catalog directory.
- MinGW-w64 for x64/x86 tests.
- Optional Windows profile for live proof.

## Create the pack

Follow the complete manifest and source contract in [Author an External Pack](../pack-authoring.md). The minimum useful pack includes:

- Stable `id`, semantic version, title, and summary.
- Capabilities, effects, requirements, platforms, and architectures.
- Typed arguments.
- Header fragments and generated call.
- Structured output fields.
- Function-local analyzer signature.
- Target support and at least one proof case where practical.

## Register and validate

```bash
bofbench catalog add "$PWD/my-bof-packs" --name local
bofbench pack validate local/environment-value
bofbench pack show local/environment-value
```

Validation catches schema mistakes, path traversal, missing fragments, duplicate IDs, invalid cleanup mapping, unsupported placeholders, and incomplete analysis signatures.

## Test every declared target

```bash
bofbench pack test local/environment-value
```

Require x64/x86 builds when both are declared, passing analyzer expectations, and verified raw/Sliver/Cobalt Strike exports. Record MSVC as unavailable until a Windows compiler profile exists.

## Consume the pack

```bash
bofbench new env-reader --pack local/environment-value
bofbench build bofs/env-reader
bofbench analyze bofs/env-reader
bofbench run bofs/env-reader --via lab --lab devbox \
  --arg name=SystemRoot --arg max_chars=256
```

Inspect `bofbench.lock.json` to confirm catalog, version, source hash, arguments, and analyzer expectations are frozen for the project.

## Prove behavior

```bash
bofbench pack prove local/environment-value --via lab --lab devbox
```

The proof should match the structured tag and fields. For state-changing packs, add independent `after_run` and `after_cleanup` checks and capture dynamic values needed by cleanup.

## Release the catalog revision

Commit the manifest, fragments, generated reference, and tests together. Bump the pack version when arguments, output fields, effects, cleanup, or operational behavior changes.
