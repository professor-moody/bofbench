# Native Loader

The native loader is a Windows x64 executable built from `native/loader/loader.c`.

It implements the first real execution path:

- parse COFF file headers,
- map sections into executable memory,
- zero-fill COFF uninitialized-data sections such as `.bss`,
- apply AMD64 relocations,
- resolve Beacon compatibility symbols,
- resolve common WinAPI imports,
- allocate near-image trampolines/import slots for external references,
- call the requested BOF entrypoint as `go(char *args, int len)`,
- emit JSON with output, errors, and exit state.

## Validation Boundary

The native loader does not rely on Go preflight for memory safety. It creates one validated COFF view before mapping anything:

- section, raw-data, relocation, symbol, auxiliary-symbol, and string-table ranges are checked with subtraction-based bounds tests before pointer arithmetic;
- long symbol names must point inside the declared string table and terminate within it;
- section-image sizing and page alignment are overflow-checked;
- relocation symbol indexes, auxiliary-record references, write offsets, write widths, and 32/64-bit displacement overflows are rejected before a write;
- initialized data must have bounded file storage, while uninitialized sections are zero-filled;
- the requested entrypoint must resolve once to an in-range defined symbol.

Hard limits bound resource use: 256 MiB object files, 512 MiB mapped images, 16 MiB packed arguments, 4,096 sections, 1,048,576 symbols/relocations, 1,024-byte symbol names, and 512 cached external symbols. A rejected object emits `exit_state: "validation_error"` and a stable `error_code` such as `section_table_range`, `symbol_name_termination`, or `relocation_offset_range`.

The Go parent retains the last 4 MiB of each loader process stream, parses the final JSON protocol line, records the process exit code, and distinguishes a timeout from a Windows exception such as `0xc0000005`. A malformed-object or process-protocol failure therefore cannot silently collapse into an unknown terminal state.

Section memory is still allocated RWX during map/relocate/execute. Staged write/relocate/protect behavior is the next memory-model slice.

Build with MinGW-w64:

```sh
make -C native/loader
```

Build with MSVC:

```powershell
cl /O2 /W4 /Fe:bofbench-loader.exe native\loader\loader.c
```

Runtime lookup order:

1. `BOFBENCH_LOADER`
2. `bofbench-loader.exe` next to the `bofbench` binary
3. `native/loader/bofbench-loader.exe`

Non-Windows hosts return `requires_windows` for `run`, while `build`, `inspect`, `analyze`, `test`, and `stage` still work.

The Go CLI owns orchestration and reporting. The loader boundary is intentionally narrow so future Linux ELF and macOS Mach-O runners can be implemented as native shims without changing operator commands.

## Why Trampolines Exist

AMD64 COFF frequently uses `REL32` relocations for calls. A mapped BOF section may be more than +/-2GB away from the loader executable, Beacon shims, or WinAPI functions. Directly writing those addresses into `REL32` call sites can truncate the displacement and crash with `0xc0000005`.

The loader reserves a small executable stub area next to the mapped sections. External function calls resolve to local jump stubs, and `__imp_` symbols resolve to local import pointer slots. That keeps the relocation target close to the BOF code while the stub safely jumps to the real 64-bit address.

## Fixture Coverage

The Windows lab smoke exercises the loader with small benign BOFs under `testdata/bofs`:

| Fixture | Loader behavior |
| --- | --- |
| `hello` | entrypoint call and Beacon output |
| `arg_echo` | packed string and integer parsing |
| `winapi_call` | WinAPI import lookup |
| `data_reloc` | static/global data and pointer relocations |
| `bss_reloc` | zero-filled uninitialized-data section mapping |
| `callback_ptr` | function pointer relocation and call-through |
| `parser_all` | short parsing, binary extraction, length tracking, and `BeaconOutput` |
| `unresolved` | unresolved external failure report |
| `crash` | isolated access violation and exception-code evidence |
| `timeout` | timeout report |

The Windows-only hardening corpus also invokes the native executable directly with 29 targeted malformed layouts and 180 deterministic metadata mutations. It requires valid JSON and a known error code for every case. `FuzzInspectCOFFNeverPanics` provides the matching Go analyzer fuzz target.
