# Run Through Sliver

BOFBench follows Sliver's BOF extension contract: COFF `.o` files, `extension.json`, typed arguments, and the `coff-loader` dependency.

## Prepare Sliver

Use your authorized Sliver client/configuration and ensure the selected Windows session is alive. BOFBench can inspect sessions directly:

```bash
bofbench sliver sessions --session DEVBOX
```

## Run a project directly

```bash
bofbench run bofs/fieldcheck --via sliver \
  --session DEVBOX \
  --arg process_filter=lsass \
  --arg result_limit=25
```

This command:

1. builds and analyzes the project;
2. generates and verifies a Sliver extension;
3. preserves pack argument names and BOF types;
4. selects the exact live session;
5. loads and executes the extension;
6. prints structured BOF output.

## Export for another operator

```bash
bofbench export bofs/fieldcheck --for sliver \
  --args z:lsass i:25
bofbench export verify export/fieldcheck-sliver.zip
```

`extension.json` names `process_filter` and `result_limit`, declares their Sliver types, points to the object, and declares `coff-loader`.

## Run an existing exported extension

```bash
bofbench sliver run export/fieldcheck-sliver lsass 25 \
  --session DEVBOX
```

The package is verified before it is loaded. Newlines and unsafe command names are rejected before a Sliver console command is generated.

## Cleanup

```bash
bofbench run bofs/persist --via sliver --cleanup \
  --session DEVBOX \
  --arg service_name=BOFBenchLab
```

The isolated cleanup project is packaged and executed through the same adapter.
