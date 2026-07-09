# Troubleshooting

## `run` says Windows is required

Windows COFF execution is Windows x64 only. On macOS/Linux, use:

```sh
bofbench inspect dist/payload.x64.o
bofbench analyze dist/payload.x64.o
bofbench stage dist/payload.x64.o --target raw
```

For other artifact types, `run --runtime auto` reports `requires_linux`, `requires_darwin`, or the matching setup state instead of pretending execution happened. On Linux and macOS, ELF and Mach-O execution also requires `cc` because the runner links the object into a small local harness before execution.

## Compiler missing

Install MinGW-w64, use a Windows x64 shell with MSVC `cl.exe` on PATH, or provide a `build` override in `bofbench.toml`. For Linux ELF and macOS Mach-O `run`, install the platform C compiler exposed as `cc`.

Default compiler for x64:

```text
x86_64-w64-mingw32-gcc
```

Windows x64 fallback:

```text
cl /nologo /c payload.c /Fo:dist\payload.x64.o /I payload-dir /DBOF
```

## Unsupported relocation

The loader reports the unsupported AMD64 relocation type. Use `inspect` to see relocation records and rebuild with a simpler toolchain if needed.

## Loader exits with `0xc0000005`

This usually means the native loader crashed before it could emit a structured module failure. Check whether the object uses relocations or import patterns outside the current loader support. The loader includes near-image external call trampolines for standard AMD64 `REL32` calls, so a simple Beacon shim call should not crash.

## Unresolved symbol

The loader resolves Beacon shims and common WinAPI imports. Unsupported symbols fail loudly with the object path and symbol index/name context.

## Output contract failed

`bofbench test` marks a run as `output_contract_failed` when configured `expect` strings are missing or configured `forbid` strings appear in captured output.
