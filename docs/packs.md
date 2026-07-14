# Capability Packs

A **pack** is the only operator-facing composition concept. It combines implementation source, typed runtime arguments, capability expectations, effects, requirements, target support, output fields, and an optional cleanup companion.

```bash
bofbench pack list
bofbench pack search process
bofbench pack show deep-survey
bofbench new portable-survey --pack deep-survey
```

## Test and prove packs at scale

`pack test` is the fast contract loop. It validates the manifest, builds every declared architecture, checks analyzer expectations, and verifies raw, Sliver, and Cobalt Strike exports:

```bash
bofbench pack test process-tree
bofbench pack test --all --catalog builtin
bofbench pack test --all --catalog internal
```

Missing compilers are shown as unavailable coverage. They do not turn a valid pack into a failed approval gate.

`pack prove` executes manifest-declared cases with typed fixture values and retains the exact runtime receipt and object hash:

```bash
bofbench pack prove thread-inventory --via lab --lab devbox
bofbench pack prove internal/section-map-inject --via lab --lab devbox
bofbench pack prove --all --catalog internal --via sliver --lab dedicated
```

Proof cases that declare cleanup run the cleanup companion. BOFBench independently verifies the named Startup-folder artifact is absent after that proof.

## Parameterized behavior

Pack arguments are runtime values. This changes the target without recompiling the object:

```bash
bofbench run bofs/portable-survey --via lab --lab dedicated \
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
bofbench run bofs/task-access --via lab --lab disposable --cleanup \
  --arg task_name=BOFBenchLab
```

Cleanup runs from an isolated generated project. BOFBench never injects the cleanup call into the action BOF.

## Pack manifest

Every external pack uses strict `pack.json` metadata and source files that cannot escape the catalog directory:

```json
{
  "schema": "bofbench.pack",
  "schema_version": 2,
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
  "expected_analysis": ["selected_process_access"],
  "analysis_signatures": [{
    "id": "selected_process_access",
    "name": "Selected process access",
    "summary": "Open one selected process for bounded inspection.",
    "steps": [{"action": "open selected process", "apis": ["OpenProcess"]}],
    "effects": ["accesses another process"],
    "requirements": ["an exact target PID"]
  }],
  "proof_cases": [{
    "id": "disposable-target",
    "via": ["lab", "sliver"],
    "arguments": {"target_pid": "$TARGET_PID"},
    "expect": {"tag": "example", "fields": {"status": "complete"}}
  }],
  "output_fields": ["target_pid", "status"],
  "target_support": ["native", "lab", "sliver", "cobaltstrike"]
}
```

Schema version 1 remains readable. Version 2 adds optional `analysis_signatures` and `proof_cases`; manifests are not silently rewritten. Supported proof placeholders include target PID/thread, memory canary, exact canary/DPAPI paths, lab host, temporary run root, and run ID.

Validate and generate reference documentation directly from the contracts:

```bash
bofbench pack validate path/to/pack.json
bofbench pack docs --catalog builtin --output docs/pack-reference.md
```

See [External Catalogs](external-catalogs.md) for layout and collision rules.
