# Native Windows COFF Loaders

BOFBench uses separate child-process helpers:

| Object | Helper | Host |
| --- | --- | --- |
| AMD64 COFF | `bofbench-loader.exe` | Windows x64 |
| I386 COFF | `bofbench-loader-x86.exe` | Windows x64 through WoW64 |

The child process enforces timeouts and output limits, reports exceptions, and maps each section with the final protection implied by its COFF flags. Objects with malformed tables, missing entrypoints, unsupported relocations, or unsupported Beacon APIs stop before entrypoint execution.

## Relocations

AMD64 support includes `ADDR64`, `ADDR32`, `ADDR32NB`, `REL32` variants, `SECTION`, and `SECREL`. I386 support includes `DIR32`, `DIR32NB`, `REL32`, `SECTION`, and `SECREL`.

## Beacon shims

The loader provides argument parsing, output, token helpers, and the Beacon formatting family (`BeaconFormatAlloc`, reset, free, append, printf, string conversion, and integer append) where semantics can be reproduced accurately.

## Dynamic imports

`LIBRARY$API` imports resolve through the named library. Unqualified imports use the compatibility catalog's exact mapping first and bounded fallback lookup only when required. Runtime receipts record the loader and object hashes plus resolution/exception details.

## Build helpers

```bash
make -C native/loader clean all
file native/loader/bofbench-loader.exe
file native/loader/bofbench-loader-x86.exe
```

Override discovery with `BOFBENCH_LOADER` for x64 or `BOFBENCH_LOADER_X86` for x86.

## Loader support output

```bash
bofbench analyze object.x64.o --format text
bofbench preflight object.x64.o
```

For one object, capability-first analysis includes loader support after `Can do`, `Needs`, and `Works with`. `preflight` remains a compatibility command because its multi-object selection, strict exit behavior, and persisted matrix evidence are not yet fully replaced. See the [compatibility contract](legacy-commands.md#preflight).
