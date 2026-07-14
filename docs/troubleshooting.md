# Troubleshooting

## `run` says Windows is required

Windows COFF execution requires Windows. On macOS/Linux, use:

```sh
bofbench analyze dist/payload.x64.o
bofbench export dist/payload.x64.o --for raw
```

`analyze` still reports compiled capabilities and loader support. Continue with `bofbench run <project> --via lab` or move the object to Windows. x64 uses `bofbench-loader.exe`; x86 uses `bofbench-loader-x86.exe` under WoW64.

For other artifact types, `run --runtime auto` reports `requires_linux`, `requires_darwin`, or the matching setup state instead of pretending execution happened. On Linux and macOS, ELF and Mach-O execution also requires `cc` because the runner links the object into a small local harness before execution.

## Compiler missing

Install MinGW-w64, use a Windows x64 shell with MSVC `cl.exe` on PATH, or provide a `build` override in `bofbench.toml`. For Linux ELF and macOS Mach-O `run`, install the platform C compiler exposed as `cc`.

Default compiler for x64:

```text
x86_64-w64-mingw32-gcc
```

Windows x64 fallback:

```text
cl /nologo /c payload.c /Fo:dist\payload.x64.o /I payload-dir /DBOF /Brepro /experimental:deterministic /pathmap:workspace=.
```

Use `--compiler mingw` or `--compiler msvc` to stop auto-selection and receive an explicit `compiler_unavailable` diagnostic when that profile cannot be used. The persisted `build.json` records the requested profile even when selection fails.

## Configuration rejected

`bofbench.toml` is parsed strictly. The error and `build.json` diagnostics identify every malformed line in one pass. Quote string values and each array element, use only `[profile.<name>]` sections, remove duplicate aliases such as setting both `entry` and `entrypoint`, and keep `timeout_ms` positive.

## Reproducibility check failed

`--verify-reproducible` compares two object files byte-for-byte by size and SHA-256. On failure, inspect `reproducibility.first`, `reproducibility.second`, the compiler identity, environment, full command, diagnostics, and `build.log`. Timestamp macros, generated source, nondeterministic custom build steps, and flags that embed absolute paths are common causes. Set `deterministic = false` only when nondeterminism is intentional; doing so disables BOFBench's deterministic flags but does not bypass an explicitly requested reproducibility check.

## Unsupported relocation

The loader reports the unsupported AMD64 or I386 relocation type. Use `analyze --format text` to see relocation records and rebuild with a compatible toolchain if needed.

## Loader exits with `0xc0000005`

The parent now records this as `exit_state: "crash"`, `loader_error_code: "windows_exception"`, and `loader_process.exception_code: "0xc0000005"`. Review the event timeline to see whether preflight, load, and `entry_call` were reached. Structurally malformed objects should stop earlier with `validation_error`; an exception after `entry_call` usually belongs to module behavior, argument assumptions, or an unmodeled loader/runtime interaction.

## Native validation error

Inspect `loader_error_code` and the first error line. Codes identify the failed boundary directly, for example `section_data_range`, `string_table_range`, `aux_symbol_range`, `relocation_symbol_range`, or `relocation_offset_range`. The Go analysis/preflight report should normally expose the corresponding structural blocker before the native process is started; disagreement is a loader/analyzer parity bug worth preserving with the object and both reports.

## Unresolved symbol

The loader resolves Beacon shims and common WinAPI imports. Unsupported symbols fail loudly with the object path and symbol index/name context.

## Output contract failed

`bofbench test` marks a run as `output_contract_failed` when configured `expect` strings are missing or configured `forbid` strings appear in captured output.

For the full command sequence, return to the [Quickstart](quickstart.md). Loader-specific failures are detailed in [Native Loader](native-loader.md).
