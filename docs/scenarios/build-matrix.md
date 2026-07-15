# Build Across Architectures and Toolchains

## Objective

Produce and compare x64/x86 objects and exercise both MinGW and MSVC where available.

## Prerequisites

- MinGW-w64 x64 and x86 compilers on the operator host.
- Optional Windows lab with MSVC for Windows-native compiler coverage.

## Build explicit cells

```bash
bofbench new matrix-survey --pack process-tree,thread-inventory
bofbench build bofs/matrix-survey --arch x64 --compiler mingw
bofbench build bofs/matrix-survey --arch x86 --compiler mingw
```

Use the matrix command for repeatable combinations:

```bash
bofbench matrix bofs/matrix-survey \
  --arch x64,x86 \
  --compiler mingw \
  --optimization debug,size,speed
```

The report separates each compiler/architecture/optimization cell. One unavailable cell does not erase passing coverage.

## Use Windows MSVC

```bash
bofbench lab status --lab devbox
bofbench run bofs/matrix-survey --via lab --lab devbox \
  --bootstrap auto --build-mode remote --arch x64 \
  --arg target_pid=0 --arg result_limit=16
```

`build_mode=remote` requires the Windows compiler. `auto` prefers remote compilation when available and otherwise uploads a local object. `local` always builds on the operator workstation.

## Compare behavioral equivalence

```bash
bofbench analyze dist/matrix-survey.x64.o \
  --compare dist/matrix-survey.x86.o --format md
```

Architecture-specific sizes, relocations, and section layouts may differ. The operator capabilities, effects, arguments, and runtime intent should remain equivalent.

## Expected evidence

- One build report per cell with compiler, architecture, object hash, and source hash.
- Analyzer expectations passing for both objects.
- Separate loader support for x64 and x86 helpers.
- Remote receipt identifying the compiler and exact executed object.

## Common failures

- `compiler_missing`: install the named toolchain or choose `build_mode=local`.
- x86 unsupported by selected compiler profile: use the MinGW x86 cell.
- analyzer difference: inspect imports and generated source before assuming architecture alone caused it.
- loader mismatch: ensure x86 objects dispatch through the x86 helper rather than the x64 loader.
