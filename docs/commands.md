# Commands

## `new`

Create a BOF payload workspace:

```sh
bofbench new whoami
bofbench new echoer --template args
bofbench new pidcheck --template winapi
bofbench new badlink --template unresolved
```

Creates `bofs/whoami/` with a BOF source file, `beacon.h`, `bofbench.toml`, and README.
Templates are `args`, `hello`, `winapi`, `unresolved`, and `timeout`.

## `fetch`

Fetch a public BOF arsenal or direct artifact source:

```sh
bofbench fetch trustedsec-sa
bofbench fetch https://github.com/org/repo --name foo --ref main --type git
bofbench fetch https://example.test/payloads.zip --name payloads --type zip
bofbench fetch https://example.test/payload.x64.o --name payload --type raw
```

Flags:

| Flag | Meaning |
| --- | --- |
| `--name` | local directory name under `arsenal/` |
| `--ref` | Git ref, branch, tag, or SHA |
| `--type` | `auto`, `git`, `zip`, or `raw` |
| `--adapter` | `auto`, `trustedsec-sa`, or `generic` |

Every fetch writes `arsenal/<name>/source.json`.

## `list`

List BOFs in an arsenal-like layout:

```sh
bofbench list arsenal/trustedsec-sa
```

## `build`

Build a BOF from a directory, source file, or existing object:

```sh
bofbench build ./bofs/whoami --arch x64
```

## `inspect`

Inspect an artifact in human-readable form:

```sh
bofbench inspect ./dist/whoami.x64.o
```

`inspect` supports COFF, ELF, Mach-O, and unknown artifact detection.
It includes runtime compatibility, sections, imports, findings, unresolved symbols, and a short visible-string preview.

## `analyze`

Write structured analysis reports:

```sh
bofbench analyze ./dist/whoami.x64.o --format json
bofbench analyze ./dist/whoami.x64.o --format md
bofbench analyze ./dist/whoami.x64.o --baseline runs/<old-analysis>/analysis.json --format md
```

Outputs land in `runs/<timestamp>-analysis-*/analysis.json` and `analysis.md`.
Reports include runtime compatibility, import classification, relocation details, visible strings, review findings, and optional baseline diffs. See [Analysis Reports](analysis.md).

## `run`

Run an artifact through a platform runtime:

```sh
bofbench run ./dist/whoami.x64.o --entry go --args z:hello i:3
bofbench run ./dist/whoami.x64.o --runtime windows-coff --timeout 5000
bofbench run ./fixtures/native.o --runtime auto --args z:hello
```

`--runtime auto` maps COFF to `windows-coff`, ELF to `linux-elf`, and Mach-O to `darwin-macho`.

For ELF and Mach-O objects on matching hosts, `run` links a tiny native harness with `cc` and calls `entry(argc, argv)`. Token values after `--args` become argv values. For Windows COFF BOFs, tokens are packed into Beacon-compatible args and passed to `go(char *args, int len)`.

`result.json` and `result.md` include a normalized event timeline with `artifact`, `arg_pack`, `load`, `entry_call`, output/error, and terminal events. The same event schema is used by `test`, including output-contract failures.

## `test`

Run configured payload or arsenal tests. Without a matching native runtime, this still analyzes and writes a report:

```sh
bofbench test ./testdata/bofs --select hello,arg_echo
bofbench test arsenal/trustedsec-sa --select whoami,ipconfig,env --timeout 5000
bofbench test arsenal/trustedsec-sa --select whoami --runtime windows-coff
bofbench test bofs/echoer --profile alt
```

When `bofbench.toml` is present, `test` honors `args`, `expect`, `forbid`, `entry`, `timeout_ms`, `expect_exit`, `expect_status`, and named `[profile.<name>]` sections.

Arsenal tests write `result.json` and `result.md` under `runs/<timestamp>-test-arsenal-*/`.

Report statuses:

| Status | Meaning |
| --- | --- |
| `pass` | selected entries ran and passed |
| `analyze_pass` | selected entries analyzed successfully but were not runnable on this host |
| `mixed_pass` | some entries ran and some were analyze-only |
| `fail` | at least one selected entry failed build, analysis, run, or output contract |

## `stage`

Package a BOF for a C2 target:

```sh
bofbench stage ./dist/whoami.x64.o --target cobaltstrike --args z:target i:1
bofbench stage ./dist/whoami.x64.o --target sliver
bofbench stage ./dist/whoami.x64.o --target raw
```

Stage packages include `manifest.json`, `objects/`, `reports/analysis.json`, `reports/analysis.md`, and the latest matching run/test report when available.

## `lab`

Run or summarize the Windows lab smoke workflow:

```sh
bofbench lab smoke --print --repo-root C:\bofbench --skip-fetch
bofbench lab smoke --repo-root C:\bofbench --select whoami,ipconfig,env --skip-fetch
bofbench lab summary
bofbench lab summary runs/<timestamp>-lab-smoke/lab-smoke.json --format json
```

`lab smoke` wraps `scripts/windows-lab-smoke.ps1`. On non-Windows hosts, use `--print` to generate the PowerShell command to run over SSH/RDP/console on the Windows lab host. `lab summary` reads the latest `runs/*-lab-smoke/lab-smoke.json` unless a path is supplied.

## `doctor`

Check the local operator environment:

```sh
bofbench doctor
bofbench doctor --format json
bofbench doctor --strict
```

`doctor` checks host OS/arch, Go, Git, BOF compilers, the Windows COFF loader, native runtime availability, MkDocs, and the standard workspace directories. Default mode is report-only for warnings; `--strict` exits nonzero on warnings too.

## `tui`

Open the terminal UI:

```sh
bofbench tui
```

Views include arsenal browser, analyzer help, run history, staging wizard, and command help.

## `docs`

Serve or build the MkDocs site:

```sh
bofbench docs serve
bofbench docs build
```
