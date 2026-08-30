# Export BOFs

`export` produces a self-verifying raw, Sliver, or Cobalt Strike package from a project or existing object.

```bash
bofbench export bofs/fieldcheck --for raw
bofbench export bofs/fieldcheck --for sliver --arch x64
bofbench export bofs/fieldcheck --for sliver --arch x86
bofbench export bofs/fieldcheck --for cobaltstrike
bofbench export bofs/fieldcheck --for edrlab
```

Every package includes:

- the exact object and SHA-256;
- entrypoint and packed BOF arguments;
- real pack argument names when available;
- capability analysis and loader support;
- target install/run instructions;
- source/project/version context;
- a file inventory with sizes and hashes;
- cleanup information when a companion exists.

For project input, `--arch x64|x86` selects the compiled object and the matching target metadata. A Sliver x86 export advertises `windows/386`; it is never mislabeled as an amd64 extension.

Verify the directory or ZIP independently:

```bash
bofbench export verify export/fieldcheck-sliver
bofbench export verify export/fieldcheck-sliver.zip --format json
```

For a third-party object without named metadata, provide compatibility argument tokens:

```bash
bofbench export external.x64.o --for sliver --args z:target i:25
```

`stage` and `stage verify` are exact aliases of `export` and `export verify`. They remain supported through `0.x` and cannot be removed before `1.0.0`; see the [compatibility contract](legacy-commands.md#stage).
