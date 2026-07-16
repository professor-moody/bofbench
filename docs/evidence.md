# Reports and Runtime Receipts

BOFBench writes detailed JSON and Markdown automatically while keeping terminal output short.

| Operation | Primary files |
| --- | --- |
| Build | `build.json`, compiler log, object fingerprint |
| Analyze | `analysis.json`, `analysis.md`, optional `diff.json`/`diff.md` |
| Native run | `result.json`, `result.md` |
| Lab | local transport/run receipt plus collected remote reports |
| Cobalt Strike | redacted `cobaltstrike.json` receipt |
| Operation | `operation.json` with execution mode, completion/readiness dependencies, waves, background task state, route, child, capture, cancellation, and cleanup state |
| Operation proof | `operation-proof.json` with contracts, expected paths/waves/steps, state checks, and coverage |
| Export | manifest, analysis, argument contract, target metadata, checksums |

## Correlation

Object SHA-256 is the stable join between build, analysis, runtime, and export. Pack projects also record resolved version and content hash in `bofbench.lock.json`.

Static capabilities and observed runtime evidence are intentionally separate:

- `capabilities` and `behavior_chains` explain what the object contains;
- `observed` records matching runtime output or state evidence when available;
- `source_and_version` records repository/ref/commit/object hash context.

Operation receipt version 7 retains the complete version-6 DAG record and adds background mode, readiness contracts and captures, `depends_on_ready`, bounded step timeouts, ready/progress timestamps, active task identity, cancellation state, and terminal cancellation reasons. A completion dependency is not scheduled until its producer finishes and matches; a readiness dependency may start while its producer remains active, but only after the exact readiness contract matches.

Runtime receipt version 6 adds asynchronous worker identity, progress timestamps, cancellation support/request/completion state, and terminal cancellation reasons to version-5 refresh and chunk metadata. Version-4 and version-5 runtime receipts remain readable and are normalized in memory.

## Quiet automation

Report creation, hashes, compiler identity, cleanup recommendations, and target metadata are automatic. They do not become approval steps. Execution stops only when compilation fails, the object cannot be loaded safely, or the requested runtime is unavailable.

## Export verification

```bash
bofbench export verify export/fieldcheck-sliver
bofbench export verify export/fieldcheck-sliver.zip --format json
```

Verification checks schema, object identity, packed arguments, target metadata, internal report references, inventory completeness, and each recorded file hash.
