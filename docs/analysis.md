# Analysis Reports

`inspect` is the fast human view. `analyze` writes the same evidence as JSON and Markdown under `runs/`.

```sh
bofbench inspect dist/hello.x64.o
bofbench analyze dist/hello.x64.o --format md
bofbench preflight dist/hello.x64.o
```

The analyzer currently reports:

- artifact kind, architecture, size, hash, and entrypoint presence,
- resolved entrypoint symbol, section, and offset, including x86 C/stdcall decoration normalization,
- reported or inferred COFF toolchain family and evidence,
- runtime compatibility for the current host and the selected runtime,
- Windows COFF loader compatibility from the authoritative capability catalog,
- sections, flags, alignment, file-backed versus zero-fill storage, and relocation counts,
- relocation details when the object format exposes them,
- unresolved symbols and imported API conventions,
- visible strings after filtering common object-format noise,
- review findings for missing entrypoints, writable/executable sections, memory/process/network/registry/dynamic-linking imports, and notable strings.

## COFF Structural Diagnostics

COFF parsing is bounded before any table or payload range is read. `coff_diagnostics` explains invalid section/symbol/string/relocation ranges, bad auxiliary-symbol references, invalid symbol sections or values, malformed long names, duplicate sections or relocations, reserved alignment encodings, stripped symbol tables, and entrypoint location/type problems.

Diagnostics remain part of the analysis even when they block execution. Error-severity layout diagnostics become structured `malformed_object` preflight blockers, so `run` and `test` refuse the artifact before launching the native loader. Warning diagnostics remain review evidence.

Uninitialized-data sections such as `.bss` are recorded as `zero-fill`. Capability catalog v2 teaches the generated native loader to leave these mapped ranges zeroed instead of copying bytes from file offset zero.

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

COFF relocation records include section, offset, numeric relocation code, relocation type, and symbol name when available. ELF and Mach-O records use the same schema with best-effort symbol resolution.

Markdown reports cap relocation rows for readability. JSON reports retain the structured `relocation_details` array.

## Loader Compatibility

Windows COFF analysis includes `loader_compatibility` with a catalog version, overall status, and structured `blockers` and `warnings`. Hard blockers include unsupported architecture, missing entrypoint, unsupported or unknown relocation codes, unsupported Beacon APIs, and malformed `LIBRARY$API` imports. Plain externals that the loader can only search for across its fallback DLL set are reported as `fallback_lookup` warnings.

The analyzer, runtime gate, and native loader all consume `internal/capability/windows_coff.json`; the native loader consumes its generated C header. Import-pointer prefixes are evaluated longest-first, so `__imp__BeaconPrintf` is normalized to `BeaconPrintf` consistently in Go and C.

Use `preflight` for an execution-free gate or an arsenal-wide matrix. A hard blocker exits nonzero; `--strict` also fails runtime-lookup warnings.

## Findings

Findings are review cues, not verdicts. A finding means "look here before running or staging."

| Severity | Meaning |
| --- | --- |
| `high` | likely to block execution or deserves immediate review |
| `review` | API or section behavior that should be understood before use |
| `info` | contextual evidence such as notable strings |

Findings can be acknowledged without deleting their raw evidence:

```sh
bofbench inspect payload.x64.o --suppress memory_api
bofbench analyze payload.x64.o --suppress 'external_symbol=Missing*' --format md
```

A rule is either an exact category or `category=evidence-glob`; `*` can select every category. Suppressed findings remain in JSON and Markdown with `suppressed: true`, the matching rule, original severity, detail, and evidence. Finding summaries separate active, suppressed, and total counts. Invalid rules fail analysis rather than silently matching nothing.

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

The command writes `diff.json` and `diff.md` next to the new analysis report. The diff tracks hash changes, size delta, relocation delta, resolved entrypoint location, section size/flags/alignment/storage changes, added/removed imports and findings, active/suppressed finding deltas, and unresolved-symbol changes.
