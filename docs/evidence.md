# Reports and Runtime Receipts

BOFBench writes detailed JSON and Markdown automatically while keeping terminal output short.

| Operation | Primary files |
| --- | --- |
| Build | `build.json`, compiler log, object fingerprint |
| Analyze | `analysis.json`, `analysis.md`, optional `diff.json`/`diff.md` |
| Native run | `result.json`, `result.md` |
| Lab | local transport/run receipt plus collected remote reports |
| Cobalt Strike | redacted `cobaltstrike.json` receipt |
| Operation | `operation.json` with execution mode, dependencies, waves, step, route, child, parallel branch, capture, blocked-step, and cleanup state |
| Operation proof | `operation-proof.json` with contracts, expected paths/waves/steps, state checks, and coverage |
| Export | manifest, analysis, argument contract, target metadata, checksums |

## Correlation

Object SHA-256 is the stable join between build, analysis, runtime, and export. Pack projects also record resolved version and content hash in `bofbench.lock.json`.

Static capabilities and observed runtime evidence are intentionally separate:

- `capabilities` and `behavior_chains` explain what the object contains;
- `observed` records matching runtime output or state evidence when available;
- `source_and_version` records repository/ref/commit/object hash context.

Operation receipt version 6 additionally records execution mode, stable topological order, dependency lists, ready/start/completion timestamps, execution waves, blocked descendants, selected `parallelism`, maximum observed concurrency, explicit parallel-group state, nested child receipt paths, deterministic expanded paths, and reverse-topological cleanup state. A submitted or running C2 task remains incomplete. A DAG dependent is not scheduled until every dependency has complete output and a matching contract.

Runtime receipt version 5 adds refresh metadata, completion source, numbered output chunks, final-chunk state, remote task errors, terminal reason, and complete-versus-partial output classification. Version-4 runtime receipts remain readable and are normalized in memory.

## Quiet automation

Report creation, hashes, compiler identity, cleanup recommendations, and target metadata are automatic. They do not become approval steps. Execution stops only when compilation fails, the object cannot be loaded safely, or the requested runtime is unavailable.

## Export verification

```bash
bofbench export verify export/fieldcheck-sliver
bofbench export verify export/fieldcheck-sliver.zip --format json
```

Verification checks schema, object identity, packed arguments, target metadata, internal report references, inventory completeness, and each recorded file hash.
