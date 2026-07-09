# Staging

`stage` packages an object for operator use.

Every stage target includes:

- object file under `objects/`,
- `manifest.json`,
- `reports/analysis.json`,
- `reports/analysis.md`,
- latest matching `run` or `test` result as `reports/latest-result.json` and `reports/latest-result.md` when available,
- README,
- zip package.

The `bofbench.stage` version 1 manifest records target, object path, staged object path, entrypoint, arguments, generated time, analysis report paths, any included latest run/test report, and a size/SHA-256 record for every packaged file except the manifest itself.

## Verify a Package

Verify either the directory or the ZIP after generation, copying, or operator handoff:

```sh
bofbench stage verify stage/whoami-cobaltstrike
bofbench stage verify stage/whoami-cobaltstrike.zip
bofbench stage verify stage/whoami-cobaltstrike.zip --format json
```

Verification checks:

- safe, duplicate-free regular-file inventory,
- manifest schema and metadata,
- every recorded file's size and SHA-256,
- exact inventory with no unrecorded files,
- staged object integrity and correspondence with `analysis.json`,
- analysis/latest-report references and JSON validity,
- Cobalt Strike, Sliver, or raw target-specific metadata,
- README, entrypoint, arguments, and object-path consistency.

Statuses are `pass`, `pass_with_warnings`, and `fail`. An analysis-error package can be structurally valid with a warning when its error evidence matches the manifest. Verification proves package integrity and internal consistency, not publisher authenticity; signed release provenance is a later operational-program slice.

## Cobalt Strike

```sh
bofbench stage dist/whoami.x64.o --target cobaltstrike --args z:target
```

Outputs:

- generated `.cna`,
- shared stage files listed above.

The generated Aggressor script uses `bof_pack` and `beacon_inline_execute`.

## Sliver

```sh
bofbench stage dist/whoami.x64.o --target sliver
```

Outputs Sliver-style extension metadata and object layout.

## Raw

```sh
bofbench stage dist/whoami.x64.o --target raw
```

Outputs the object plus operator notes and shared stage files.
