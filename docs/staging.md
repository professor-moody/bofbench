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

The manifest records target, object path, staged object path, entrypoint, arguments, generated time, analysis report paths, and any included latest run/test report.

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
