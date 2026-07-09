# bofbench

`bofbench` is an offensive object-module workbench for building, analyzing, running, testing, and staging BOFs and BOF-like payload artifacts.

This version is convention-first and operator-shaped:

- No required JSON manifest.
- No approval/review gates.
- Optional `bofbench.toml` only stores repeatable test args and build defaults.
- Cobra command surface with direct verbs: `new`, `fetch`, `list`, `build`, `inspect`, `analyze`, `run`, `test`, `stage`, `lab`, `doctor`, `tui`, and `docs`.
- Bubble Tea/Lip Gloss TUI for arsenal details, command previews, run-history filters, event snippets, and analyzer navigation.
- Static artifact analysis for Windows COFF, Linux ELF, and macOS Mach-O relocatable objects.
- Analysis reports include runtime compatibility, host requirements, and next run/test commands.
- Real Windows x64 native execution is handled by `native/loader/bofbench-loader.exe`.
- Run and test reports include normalized runtime event timelines for load, args, entry calls, output/errors, and terminal state.
- Stage manifests are versioned and carry SHA-256/size records for every packaged file; directories and ZIPs can be verified after handoff.
- BOF source builds prefer MinGW-w64 and fall back to MSVC `cl.exe` on Windows x64.
- Non-matching hosts can still fetch, build, inspect, analyze, test statically, stage, and build docs.

## Quickstart

```sh
go build -o work/bin/bofbench ./cmd/bofbench
work/bin/bofbench new smoke
work/bin/bofbench new pidcheck --template winapi
work/bin/bofbench doctor
work/bin/bofbench build bofs/smoke
work/bin/bofbench inspect dist/smoke.x64.o
work/bin/bofbench analyze dist/smoke.x64.o --format md
work/bin/bofbench analyze dist/smoke.x64.o --baseline runs/<old-analysis>/analysis.json --format md
work/bin/bofbench stage dist/smoke.x64.o --target cobaltstrike --args z:hello i:3
work/bin/bofbench stage verify stage/smoke-cobaltstrike.zip
```

On Windows x64, build or copy the native loader, then run:

```sh
work/bin/bofbench run dist/smoke.x64.o --args z:hello i:3
```

For a remote Windows lab, the recommended shape is a GUI-capable VM with SSH enabled. Use SSH for normal `go test`, `build`, and `run` automation, and keep RDP/console access for WinDbg, ProcMon, Process Explorer, and loader crash debugging.

```sh
bofbench lab smoke --print --repo-root C:\bofbench --skip-fetch
bofbench lab summary
```

## Public BOF Arsenal

```sh
bofbench fetch trustedsec-sa
bofbench fetch https://github.com/org/repo --name foo --ref main --type git
bofbench fetch https://example.test/payloads.zip --name payloads --type zip
bofbench fetch https://example.test/payload.x64.o --name single-object --type raw
bofbench list arsenal/trustedsec-sa
bofbench test arsenal/trustedsec-sa --select whoami,ipconfig,netuser
```

`fetch trustedsec-sa` pins [TrustedSec CS-Situational-Awareness-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) at `ee9459cc4f42c6b025797bad22ffe8d9f1cf6487`.

Each fetched arsenal gets a `source.json` with URL, ref, type, adapter, fetch time, and local path.

HTTP downloads are bounded and ZIP acquisition is transactional. Unsafe paths, symlinks, special files, duplicate/case-colliding entries, excessive entry counts, and oversized expansion are rejected before an existing arsenal is replaced.

`inspect` and `analyze` include imports, relocation detail, visible strings, review findings, and optional baseline diffs so operators can see likely loader/runtime issues before running or staging.

`bofbench.toml` supports named test profiles and expected exits for repeatable positive and negative fixture checks.

## Runtime Model

`run --runtime auto` selects the runtime from the artifact type:

| Artifact | Runtime | Current execution status |
| --- | --- | --- |
| Windows COFF | `windows-coff` | implemented on Windows x64 |
| Windows COFF through Wine | `wine-coff` | planned |
| Linux ELF relocatable | `linux-elf` | implemented on Linux with `cc` |
| macOS Mach-O object | `darwin-macho` | implemented on macOS with `cc` |

This keeps the Go CLI portable while platform-native loader internals can stay in C or Rust when that becomes the better engineering trade.

The ELF and Mach-O runners link the relocatable object into a tiny native harness and call `entry(argc, argv)`. They are useful for platform-native payload fixtures and CI coverage; Windows BOF-compatible argument packing and Beacon shims remain the `windows-coff` loader's job.

## Native Loader

Build from a host with MinGW-w64:

```sh
make -C native/loader
```

Or on Windows:

```powershell
cl /O2 /W4 /Fe:bofbench-loader.exe native\loader\loader.c
```

Copy `bofbench-loader.exe` next to `bofbench.exe` or set `BOFBENCH_LOADER`.

## Docs

```sh
bofbench docs serve
bofbench docs build
```

The MkDocs site lives under `docs/`.

## Release

```sh
make release
```

Release packages are written under `dist/release/` for macOS, Linux, Windows, and the built docs site. Windows packages include `bofbench-loader.exe` when it is available.
