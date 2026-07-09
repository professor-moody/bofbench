# Evidence Contracts

Persisted BOFBench JSON uses a shared versioned header so reports can be correlated and interpreted after they leave the original workspace.

```json
{
  "schema": "bofbench.run",
  "schema_version": 1,
  "run_id": "20260709-190212-run-hello",
  "parent_run_id": "20260709-190212-test-arsenal-trustedsec-sa",
  "tool": {
    "name": "bofbench",
    "version": "0.1.0",
    "commit": "b17f228",
    "build_time": "2026-07-09T19:02:00Z"
  },
  "host": {
    "os": "windows",
    "arch": "amd64",
    "go_version": "go1.24.0"
  }
}
```

Development builds report `version=dev` and `commit=unknown`. Release builds inject the release label, Git commit, and UTC build time through linker metadata. Inspect the current binary with:

```sh
bofbench version
bofbench version --format json
```

## Schema Names

| Schema | Artifact |
| --- | --- |
| `bofbench.analysis` | static artifact analysis |
| `bofbench.analysis-diff` | baseline/current analysis comparison |
| `bofbench.build` | build command, log, configuration, and output evidence |
| `bofbench.run` | run or single-payload test result |
| `bofbench.arsenal-test` | aggregate arsenal test report |
| `bofbench.arsenal-source` | fetched source metadata |
| `bofbench.lab-smoke` | Windows lab summary and environment fingerprint |
| `bofbench.preflight` | per-artifact or arsenal-wide loader compatibility matrix |
| `bofbench.doctor` | environment readiness report |
| `bofbench.stage` | staged-package manifest |
| `bofbench.stage-verification` | stage integrity verification result |
| `bofbench.version` | binary build and host identity |

## Lineage

Top-level operations receive a unique `run_id`. Child evidence uses `parent_run_id`:

- aggregate arsenal test → per-entry analysis/run,
- aggregate loader preflight → per-entry analysis identity,
- staged manifest → embedded analysis,
- analysis → analysis diff.

Run directory allocation is collision-safe even when identical operations start within one second.

## Fingerprints

- Analysis records object size and SHA-256.
- Builds persist `build.json` beside `build.log` for success and failure. Records include source tree/file, configuration, compiler binary, and output fingerprints; build mode, working directory, relevant environment, exact command, exit code, typed diagnostics, and failure text.
- Reproducibility-gated builds retain the first and second object size/SHA-256 plus the comparison method and verdict. `non_reproducible` is a failing build state, not a warning.
- Arsenal `source.json` records a deterministic content-tree fingerprint in addition to URL/ref metadata.
- Runtime reports record object, loader, and test-configuration fingerprints. Windows results also carry the native loader error code plus bounded process exit/exception/stdout/stderr evidence, including stream-truncation flags.
- Loader preflight reports record the capability-catalog version, artifact hashes, root tree fingerprint, structured blockers/warnings, architecture/status/toolchain/argument dimensions, and configuration fingerprints when sidecar arguments are present.
- Stage manifests record every packaged file's size and SHA-256.
- Windows lab summaries record BOFBench and loader SHA-256 plus Windows, architecture, PowerShell, Go, compiler, and machine identity.

Source-tree fingerprints ignore `.git`, `source.json`, Finder `.DS_Store`, and AppleDouble `._*` transport metadata. This keeps the same source tree stable across macOS-to-Windows lab synchronization without hiding normal source files.

## Compatibility

Readers continue to accept legacy analysis and lab reports that predate the shared header. Missing headers remain distinguishable as schema version zero rather than being silently presented as current evidence. Stage v1 packages without the optional shared provenance fields verify with warnings; newly generated packages carry complete run/tool/host lineage.
