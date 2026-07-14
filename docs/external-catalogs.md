# External Pack Catalogs

A catalog is a directory or Git repository containing one or more `pack.json` files and their source fragments.

```text
bofbench-packs-internal/
├── token-impersonation/
│   ├── pack.json
│   └── token_impersonation.h
└── run-key/
    ├── pack.json
    └── run_key.h
```

## Add and update

```bash
bofbench catalog add ~/bofbench-packs-internal --name internal
bofbench catalog add ssh://git.example/packs.git --name team
bofbench catalog update team
bofbench catalog remove team
```

Catalog search order is embedded public packs, project-local `.bofbench/packs`, configured user catalogs, then explicit `--catalog` paths. If two catalogs contain the same ID, use the qualified name:

```bash
bofbench pack show internal/token-impersonation
bofbench pack show team/token-impersonation
```

## Composition rules

- Dependencies are added before the requesting pack.
- Duplicate packs and duplicate arguments are suppressed.
- Conflicting argument types fail with a specific error.
- Source paths are relative and cannot leave the pack directory.
- Resolved versions and content hashes are written to `bofbench.lock.json`.
- Existing recipe projects migrate on first pack use while retaining the original sidecar.
- Schema-v2 analyzer signatures are deduplicated by ID and definition. Conflicting definitions are qualified by catalog rather than blocking unrelated analysis.
- Schema-v2 proof cases use typed pack arguments and bounded fixture placeholders; cleanup can be declared without becoming an approval step.

Run the complete catalog contract without creating projects by hand:

```bash
bofbench pack test --all --catalog internal
bofbench pack prove --all --catalog internal --via lab --lab disposable
```

Use a project-local catalog when a BOF should carry unpublished source alongside the project:

```text
bofs/fieldcheck/.bofbench/packs/custom-check/pack.json
bofs/fieldcheck/.bofbench/packs/custom-check/custom_check.h
```
