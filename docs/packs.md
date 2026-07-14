# Capability Packs

A **pack** is the only operator-facing composition concept. It combines implementation source, typed runtime arguments, capability expectations, effects, requirements, target support, output fields, and an optional cleanup companion.

```bash
bofbench pack list
bofbench pack search process
bofbench pack show system-discovery
bofbench new survey --pack host-discovery,system-discovery
bofbench add bofs/survey domain-discovery
```

## Parameterized behavior

Pack arguments are runtime values. This changes the target without recompiling the object:

```bash
bofbench run bofs/survey --via lab \
  --arg process_filter=lsass \
  --arg result_limit=25
```

Supported BOF types are `string`, `wstring`, `int`, `short`, `bytes`, and `file`. A bytes value accepts base64 or `@path`; a file value reads the selected file for native BOF packing while preserving the path for C2 clients.

## Public and private catalogs

The embedded catalog ships with public discovery capabilities. Add a local or Git-backed catalog for internal packs:

```bash
bofbench catalog add ~/bofbench-packs-internal --name internal
bofbench catalog list
bofbench pack show internal/token-impersonation
```

Project locks remember the external catalog root used to resolve a pack, so a later `build`, `analyze`, or `export` can reopen the project without repeating `--catalog`.

## Cleanup companions

Stateful packs name an exact cleanup pack:

```bash
bofbench pack show internal/scheduled-task --cleanup
bofbench run bofs/task-access --via lab --cleanup \
  --arg task_name=BOFBenchLab
```

Cleanup runs from an isolated generated project. BOFBench never injects the cleanup call into the action BOF.

## Pack manifest

Every external pack uses strict `pack.json` metadata and source files that cannot escape the catalog directory:

```json
{
  "schema": "bofbench.pack",
  "schema_version": 1,
  "id": "example",
  "version": "1.0.0",
  "title": "Example",
  "summary": "One explicit capability",
  "tier": "internal",
  "capabilities": ["selected operation"],
  "effects": ["starts execution"],
  "platforms": ["windows"],
  "architecture": ["x64", "x86"],
  "privilege": "operator rights",
  "network": "none",
  "arguments": [{"name": "target_pid", "type": "int", "required": true}],
  "source": {"header_fragments": ["example.h"], "calls": ["example($PARSER)"]},
  "expected_analysis": ["process access"],
  "output_fields": ["target_pid", "status"],
  "target_support": ["native", "lab", "sliver", "cobaltstrike"]
}
```

Validate and generate reference documentation directly from the contracts:

```bash
bofbench pack validate path/to/pack.json
bofbench pack docs --output docs/pack-reference.md
```

See [External Catalogs](external-catalogs.md) for layout and collision rules.
