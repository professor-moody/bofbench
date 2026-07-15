# Author an External Capability Pack

An external pack lets a team add reusable BOF behavior without rebuilding BOFBench. The manifest is the single contract for source composition, typed arguments, analysis, runtime packaging, output, proof, and cleanup.

## Start a catalog

```text
my-bof-packs/
└── environment-value/
    ├── pack.json
    └── environment_value.h
```

Register the catalog while developing it:

```bash
bofbench catalog add "$PWD/my-bof-packs" --name local
bofbench pack validate local/environment-value
bofbench pack show local/environment-value
```

Catalog source paths are resolved beneath the catalog root. Pack paths must not escape that root.

## Define the operator contract

Use a strict `bofbench.pack` manifest. The example below accepts one runtime string and an output limit:

```json
{
  "schema": "bofbench.pack",
  "schema_version": 4,
  "id": "environment-value",
  "version": "1.0.0",
  "title": "Environment Value",
  "summary": "Read one explicitly selected environment variable",
  "tier": "public",
  "capabilities": ["selected environment-variable lookup"],
  "effects": ["reads process environment data"],
  "platforms": ["windows"],
  "architecture": ["x64", "x86"],
  "privilege": "current process context",
  "network": "none",
  "arguments": [
    {"name": "name", "type": "string", "required": true},
    {"name": "max_chars", "type": "int", "default": "256"}
  ],
  "source": {
    "header_fragments": ["environment_value.h"],
    "calls": ["bofbench_pack_environment_value($PARSER)"]
  },
  "expected_analysis": ["environment_value"],
  "output_fields": ["status", "name", "value", "chars", "error"],
  "target_support": ["native", "lab", "sliver", "cobaltstrike"]
}
```

Argument types are `string`, `wstring`, `int`, `short`, `bytes`, and `file`. Mark a secret input with `"sensitive": true`; BOFBench accepts `@prompt`, `@env:NAME`, and `@file:path` without persisting the resolved value.

## Emit structured output

Every operator-relevant line starts with the pack tag and stable key/value fields:

```c
BOFBENCH_PRINTF(
    CALLBACK_OUTPUT,
    "[environment-value] status=complete name=%s value=%s chars=%lu",
    name,
    value,
    chars
);
```

Keep field names stable across architectures and runtime adapters. Report Windows errors on a tagged error line. Human prose can accompany structured fields, but proof expectations and receipt redaction depend on the stable contract.

## Describe analyzer evidence

Add a function-local signature:

```json
"analysis_signatures": [{
  "id": "environment_value",
  "name": "Selected environment-variable lookup",
  "summary": "Read one named environment value from the current process",
  "effects": ["reads process environment data"],
  "requirements": ["an environment variable name"],
  "required_strings": ["[environment-value]"],
  "steps": [{
    "action": "read selected value",
    "apis": ["GetEnvironmentVariableA", "GetEnvironmentVariableW"]
  }]
}]
```

APIs within one step are alternatives. Every step must be evidenced in the same function before a multi-step chain becomes `strong chain`. Use required strings to distinguish two packs that share APIs but perform different operator actions.

## Add a proof case

```json
"proof_cases": [{
  "id": "read-system-root",
  "via": ["lab", "sliver"],
  "arguments": {"name": "SystemRoot", "max_chars": "256"},
  "expect": {
    "tag": "environment-value",
    "fields": {"status": "complete", "value": "*"}
  }
}]
```

Proof cases can use target placeholders, capture structured output, run cleanup steps, compare payload hashes, and perform independent state checks. See [Test and Prove Packs](pack-testing.md) for the full loop.

## Add cleanup for state-changing behavior

A state-changing action names a cleanup companion and maps action arguments into cleanup arguments:

```json
"cleanup_pack": "artifact-remove",
"cleanup_arguments": {
  "path": "$arg.output_path",
  "guard_mode": "$arg.cleanup_guard_mode"
}
```

The action remains independently runnable. Cleanup is a discoverable operator operation, not an approval step.

## Build a consuming project

```bash
bofbench new env-reader --pack local/environment-value
bofbench build bofs/env-reader --arch x64
bofbench analyze bofs/env-reader
bofbench run bofs/env-reader --via lab --lab devbox \
  --arg name=SystemRoot --arg max_chars=256
```

The lock records the external catalog, pack version, source hash, argument contract, and analyzer expectation so another operator can reproduce the exact project.
