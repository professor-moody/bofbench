# Quickstart

Build the CLI:

```sh
go build -o work/bin/bofbench ./cmd/bofbench
```

Create a payload:

```sh
work/bin/bofbench new smoke
```

Starter templates are available:

```sh
work/bin/bofbench new pidcheck --template winapi
work/bin/bofbench new badlink --template unresolved
work/bin/bofbench new slow --template timeout
```

Build it:

```text
created BOF payload workspace bofs/smoke
```

```sh
work/bin/bofbench build bofs/smoke --verify-reproducible
```

The default `auto` profile prefers MinGW-w64. On Windows x64, `bofbench` falls back to MSVC `cl.exe` when MinGW is not installed. Use `--compiler mingw` or `--compiler msvc` when toolchain identity must be explicit.

Example build output:

```json
{
  "name": "smoke",
  "arch": "x64",
  "object": "dist/smoke.x64.o",
  "compiler": {
    "requested": "auto",
    "profile": "mingw",
    "path": "/opt/homebrew/bin/x86_64-w64-mingw32-gcc",
    "version": "x86_64-w64-mingw32-gcc (GCC) 16.1.0",
    "sha256": "..."
  },
  "reproducibility": {
    "checked": true,
    "reproducible": true,
    "method": "double_compile",
    "first": {"sha256": "..."},
    "second": {"sha256": "..."}
  },
  "status": "built"
}
```

The complete build record and combined compiler log are persisted together under `runs/<timestamp>-build-smoke/`. A compiler or configuration failure produces the same JSON contract with `status: "error"`, diagnostics, and an evidence path.

Inspect:

```sh
work/bin/bofbench inspect dist/smoke.x64.o
```

Example inspect output:

```text
object: dist/smoke.x64.o
kind: coff
arch: x64
toolchain: mingw-gcc confidence=reported compiler=GCC: (GNU) ...
entry "go": yes
  symbol=go section=.text offset=0x0
sections:
  .text              size=48       relocs=2    align=16    storage=file      flags=R-X
unresolved externals:
  BeaconPrintf
```

Write analysis reports:

```sh
work/bin/bofbench analyze dist/smoke.x64.o --format md
```

Reports are written under `runs/<timestamp>-analysis-*/analysis.json` and `analysis.md`.
The report includes bounded COFF diagnostics, toolchain/entrypoint/section evidence, loader compatibility, import classification, visible strings, and review findings. Use repeatable `--suppress category` or `--suppress 'category=evidence-glob'` rules to mark acknowledged findings without deleting them.

Run a named profile from `bofbench.toml`:

```sh
work/bin/bofbench test bofs/smoke --profile alt
```

Stage for Cobalt Strike:

```sh
work/bin/bofbench stage dist/smoke.x64.o --target cobaltstrike --args z:hello i:3
```

Open the terminal UI:

```sh
work/bin/bofbench tui
```
