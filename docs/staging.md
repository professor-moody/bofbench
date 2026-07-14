# Export BOFs

`export` produces a self-verifying raw, Sliver, or Cobalt Strike package from a project or existing object.

```bash
bofbench export bofs/fieldcheck --for raw
bofbench export bofs/fieldcheck --for sliver
bofbench export bofs/fieldcheck --for cobaltstrike
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

Verify the directory or ZIP independently:

```bash
bofbench export verify export/fieldcheck-sliver
bofbench export verify export/fieldcheck-sliver.zip --format json
```

For a third-party object without named metadata, provide compatibility argument tokens:

```bash
bofbench export external.x64.o --for sliver --args z:target i:25
```

`stage` and `stage verify` remain aliases for one major release.
