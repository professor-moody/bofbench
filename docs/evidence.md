# Reports and Runtime Receipts

BOFBench writes detailed JSON and Markdown automatically while keeping terminal output short.

| Operation | Primary files |
| --- | --- |
| Build | `build.json`, compiler log, object fingerprint |
| Analyze | `analysis.json`, `analysis.md`, optional `diff.json`/`diff.md` |
| Native run | `result.json`, `result.md` |
| Lab | local transport/run receipt plus collected remote reports |
| Cobalt Strike | redacted `cobaltstrike.json` receipt |
| Operation | `operation.json` with execution mode, completion/readiness dependencies, waves, background task state, route, child, capture, attempts, retry reason/backoff, cancellation, and cleanup state |
| Operation proof | `operation-proof.json` with contracts, expected paths/waves/steps/attempts/reasons, state checks, and coverage |
| Export | manifest, analysis, argument contract, target metadata, checksums |

## Correlation

Object SHA-256 is the stable join between build, analysis, runtime, and export. Pack projects also record resolved version and content hash in `bofbench.lock.json`.

Static capabilities and observed runtime evidence are intentionally separate:

- `capabilities` and `behavior_chains` explain what the object contains;
- `observed` records matching runtime output or state evidence when available;
- `source_and_version` records repository/ref/commit/object hash context.

Operation receipt version 8 retains the complete version-7 asynchronous DAG record and adds per-step attempt number and limit, exact per-attempt runtime receipts, matched retry reason, deterministic delay, next eligible time, attempt captures, exhaustion, and optional attempt-cleanup state. A completion dependency is not scheduled until the normal terminal contract passes. Retry is possible only for complete terminal output matching a declared finite retry contract.

Operation receipt version 9 preserves all version-8 fields and records the pinned definition used to resolve safe argument templates. Template source remains in the operation definition; receipts store only resolved non-sensitive arguments and the names of redacted sensitive values. Resolution supports typed operation inputs, topology fields, and completed ancestor captures—never shell expansion, expressions, or forward references.

Operation receipt version 10 adds the bounded fan-out source contract, resolved item count, branch-to-item association, observed concurrency, per-branch contract/runtime state, and reverse cleanup results. It retains the complete v9 definition and transitive hash pinning. Sensitive inputs cannot be fan-out sources and are never copied into branch metadata.

Runtime receipt version 6 adds asynchronous worker identity, progress timestamps, cancellation support/request/completion state, and terminal cancellation reasons to version-5 refresh and chunk metadata. Version-4 and version-5 runtime receipts remain readable and are normalized in memory.

## Quiet automation

Report creation, hashes, compiler identity, cleanup recommendations, and target metadata are automatic. They do not become approval steps. Execution stops only when compilation fails, the object cannot be loaded safely, or the requested runtime is unavailable.

## Export verification

```bash
bofbench export verify export/fieldcheck-sliver
bofbench export verify export/fieldcheck-sliver.zip --format json
```

Verification checks schema, object identity, packed arguments, target metadata, internal report references, inventory completeness, and each recorded file hash.
