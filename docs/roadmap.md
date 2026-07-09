# Roadmap

The near-term goal is to make `bofbench` boringly reliable for local offensive module development: fetch, build, analyze, run, test, stage, and explain failures.

## Slice 1: Analyzer Depth

- Add import classification, visible string filtering, and review findings.
- Expand relocation details in JSON and Markdown. Implemented for COFF, with best-effort ELF/Mach-O detail.
- Add runtime compatibility notes for each artifact. Implemented as structured `runtime_compatibility` output in JSON, Markdown, and `inspect`.
- Add diff-friendly analysis output for before/after build changes.

## Slice 2: Windows Lab Proof

- Use `scripts/windows-lab-smoke.ps1` as the default VM proof command. Implemented.
- Add fixture rebuilds for hello, arg parsing, WinAPI call, unresolved symbol, and timeout. Implemented.
- Add relocation and parser fixture coverage for static data, function pointers, short args, binary extraction, and `BeaconOutput`. Implemented.
- Keep a small TrustedSec Situational Awareness smoke selection for every lab run.
- Capture summary JSON under `runs/` for repeatable evidence.
- Add `bofbench lab smoke` and `bofbench lab summary` so lab execution and evidence review are available from the main CLI. Implemented.

## Slice 3: Developer Loop

- Improve `new` with selectable templates: no-arg, arg parser, WinAPI import, and failure fixtures. Implemented for `hello`, `args`, `winapi`, `unresolved`, and `timeout`.
- Add `test --profile` so common argument/output contracts are easy to rerun. Implemented.
- Add `analyze --baseline` to compare current object output against a previous run. Implemented.
- Add clearer build logs and compiler diagnostics.

## Slice 4: TUI Operator UX

- Add a findings browser for recent analysis reports. Implemented as recent findings in the Analyze view.
- Add run-history filtering by status, runtime, and artifact. Implemented for status, runtime, and selected-artifact filters with selected report detail.
- Add an arsenal detail view with build/run/stage command previews. Implemented.
- Add a staging flow that writes the same packages as the CLI.

## Slice 5: Runtime Coverage

- Broaden Windows COFF relocation and import support with fixtures first. Expanded with `data_reloc`, `callback_ptr`, and `parser_all`.
- Normalize runtime events across Windows COFF, Linux ELF, and macOS Mach-O reports. Implemented for load, arg packing, entry calls, output/error, contract, timeout, crash, and exit events.
- Keep Linux ELF and macOS Mach-O runners focused on native object fixtures.
- Evaluate Wine COFF only after Windows loader behavior is stable enough to compare against.

## Slice 6: Release Hardening

- Keep release packages self-contained.
- Include generated docs and the Windows loader where available.
- Publish checksums.
- Keep GitHub Pages docs tied to `mkdocs build --strict`.

## Demo Path

```sh
bofbench fetch trustedsec-sa
bofbench list arsenal/trustedsec-sa
bofbench inspect arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o --format md
bofbench test arsenal/trustedsec-sa --select whoami,ipconfig,env --runtime windows-coff
bofbench lab summary
bofbench stage arsenal/trustedsec-sa/SA/whoami/whoami.x64.o --target raw
```
