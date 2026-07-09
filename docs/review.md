# Engineering Review

This page captures the current design review so future work starts from evidence, not vibes.

## Current Strengths

- The command surface is direct: `new`, `fetch`, `list`, `build`, `inspect`, `analyze`, `run`, `test`, `stage`, `lab`, `doctor`, `tui`, and `docs`.
- Fetching supports aliases, Git, zip, and raw artifact URLs under `arsenal/`.
- Windows x64 COFF execution uses a native loader with Beacon argument/output shims.
- Linux ELF and macOS Mach-O have matching-host linked native runners for platform object fixtures.
- Analysis reports include structured runtime compatibility with host requirements and next commands.
- Run and test reports now include a normalized event timeline across runtime types.
- Persisted evidence uses shared schema/tool/host/run headers with lineage and relevant object, loader, configuration, and lab fingerprints.
- Builds use strict typed configuration, explicit MinGW/MSVC profiles, deterministic defaults, structured diagnostics, compiler provenance, and optional byte-for-byte rebuild gates; failures persist the same evidence contract.
- The Windows loader independently validates bounded COFF views and relocation writes; malformed/mutation corpora, bounded process streams, and exception/timeout classification keep terminal states explicit.
- Windows lab smoke and summary evidence are available through the main CLI.
- Stage packages include objects, manifests, analysis reports, and latest run/test reports when available.
- Stage manifests are versioned, hash every packaged file, and can be verified in directory or ZIP form.
- ZIP/raw arsenal acquisition is bounded and transactional; unsafe archive entries are rejected before replacement.
- CI covers Go tests on Linux/macOS/Windows, docs build, native loader build, and release smoke.

## Main Gaps

- The Windows loader has useful fixture coverage now, but still needs broader real-world import and relocation validation against larger BOF sets.
- Loader input handling is bounded; the next native reliability gap is replacing blanket RWX mapping with staged write/relocate/protect behavior and mapped-section evidence.
- The TUI is now a triage surface; next improvement is optional command execution or clipboard integration.
- Windows lab setup has repeatable smoke and summary commands; next improvement is richer bootstrap for toolchain installation and optional debugger setup.
- Staging integrity is now machine-verifiable; real Cobalt Strike and Sliver import/execution validation remains environment-gated work.

## Review Rules

Before calling a slice done:

1. Run `go test ./...`.
2. Run `mkdocs build --strict`.
3. Build the CLI for the local host and Windows.
4. On Windows x64, run `scripts/windows-lab-smoke.ps1`.
5. Run `bofbench stage verify` against both a staged directory and ZIP.

## Current Decisions

- Keep Go as the main CLI/TUI/analyzer/staging language.
- Keep native loader internals isolated behind runtime adapters.
- Use `arsenal` for fetched public or internal module sets.
- Treat findings as review cues rather than block gates.
- Keep execution scoped to authorized local/lab environments.
