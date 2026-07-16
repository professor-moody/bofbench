# Reports and Runtime Receipts

BOFBench writes detailed JSON and Markdown automatically while keeping terminal output short.

| Operation | Primary files |
| --- | --- |
| Build | `build.json`, compiler log, object fingerprint |
| Analyze | `analysis.json`, `analysis.md`, optional `diff.json`/`diff.md` |
| Native run | `result.json`, `result.md` |
| Lab | local transport/run receipt plus collected remote reports |
| Cobalt Strike | redacted `cobaltstrike.json` receipt |
| Operation | `operation.json` with step, route, child, parallel branch, capture, and cleanup state |
| Operation proof | `operation-proof.json` with contracts, expected paths/branches, state checks, and coverage |
| Export | manifest, analysis, argument contract, target metadata, checksums |

## Correlation

Object SHA-256 is the stable join between build, analysis, runtime, and export. Pack projects also record resolved version and content hash in `bofbench.lock.json`.

Static capabilities and observed runtime evidence are intentionally separate:

- `capabilities` and `behavior_chains` explain what the object contains;
- `observed` records matching runtime output or state evidence when available;
- `source_and_version` records repository/ref/commit/object hash context.

Operation receipt version 5 additionally records the selected `parallelism`, maximum observed concurrency, per-group and per-branch timestamps, branch runtime/contract states, explicit exports, nested child receipt paths, deterministic expanded paths, and reverse cleanup state. A branch that is submitted or still running remains incomplete. A group is not complete until every `join=all` branch has complete output and a matching contract.

## Quiet automation

Report creation, hashes, compiler identity, cleanup recommendations, and target metadata are automatic. They do not become approval steps. Execution stops only when compilation fails, the object cannot be loaded safely, or the requested runtime is unavailable.

## Export verification

```bash
bofbench export verify export/fieldcheck-sliver
bofbench export verify export/fieldcheck-sliver.zip --format json
```

Verification checks schema, object identity, packed arguments, target metadata, internal report references, inventory completeness, and each recorded file hash.
