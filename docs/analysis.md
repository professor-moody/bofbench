# Analysis Reports

`inspect` is the fast human view. `analyze` writes the same evidence as JSON and Markdown under `runs/`.

```sh
bofbench inspect dist/hello.x64.o
bofbench analyze dist/hello.x64.o --format md
```

The analyzer currently reports:

- artifact kind, architecture, size, hash, and entrypoint presence,
- runtime compatibility for the current host and the selected runtime,
- sections, flags, and relocation counts,
- relocation details when the object format exposes them,
- unresolved symbols and imported API conventions,
- visible strings after filtering common object-format noise,
- review findings for missing entrypoints, writable/executable sections, memory/process/network/registry/dynamic-linking imports, and notable strings.

## Import Classification

BOF-style imports such as `KERNEL32$VirtualAlloc` are split into library and API fields. Beacon shims such as `BeaconPrintf` are categorized separately so operator reports do not confuse expected Beacon imports with missing WinAPI support.

Generic unresolved symbols remain visible as external symbols. That is intentional: unsupported runtime dependencies should be obvious before a BOF reaches staging.

## Runtime Compatibility

Analysis reports include a structured `runtime_compatibility` object and a Markdown table:

```json
{
  "runtime": "windows-coff",
  "status": "requires_windows_amd64",
  "can_run": false,
  "required_os": "windows",
  "required_arch": "amd64",
  "host_os": "darwin",
  "host_arch": "arm64",
  "run_command": "bofbench run dist/hello.x64.o --runtime windows-coff"
}
```

This makes `inspect` and `analyze` more actionable before execution: a COFF object on macOS will say it needs the Windows x64 lab, while ELF and Mach-O objects point to their matching host runners.

## Relocation Detail

COFF relocation records include section, offset, relocation type, and symbol name when available. ELF and Mach-O records use the same schema with best-effort symbol resolution.

Markdown reports cap relocation rows for readability. JSON reports retain the structured `relocation_details` array.

## Findings

Findings are review cues, not verdicts. A finding means "look here before running or staging."

| Severity | Meaning |
| --- | --- |
| `high` | likely to block execution or deserves immediate review |
| `review` | API or section behavior that should be understood before use |
| `info` | contextual evidence such as notable strings |

## String Output

The string table is capped and filtered. It keeps operator-relevant values such as source filenames, toolchain markers, URLs, commands, paths, IP literals, and secret-like labels while dropping common section names and COFF table artifacts.

Use JSON output when another system needs to diff or ingest the result:

```sh
bofbench analyze dist/hello.x64.o --format json
```

## Baseline Diffs

Compare a current object against a previous `analysis.json`:

```sh
bofbench analyze dist/hello.x64.o --baseline runs/20260709-120000-analysis-hello-x64/analysis.json --format md
```

The command writes `diff.json` and `diff.md` next to the new analysis report. The diff tracks hash changes, size delta, relocation delta, entrypoint changes, section changes, added/removed imports, added/removed findings, and unresolved-symbol changes.
