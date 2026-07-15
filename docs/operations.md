# Multi-Step Operations

Operations connect existing capability packs into a linear workflow. A step can capture a structured output field—such as a PID, address, hash, path, or task identifier—and pass it to a later step. The packs remain independently buildable and runnable; the operation adds sequencing, checkpointing, resume, and reverse cleanup.

<video controls preload="metadata" poster="assets/images/operation-lifecycle.png" width="100%">
  <source src="assets/media/operation-lifecycle.webm" type="video/webm">
</video>

## Operator workflow

```bash
bofbench operation list
bofbench operation search process
bofbench operation show internal/section-map-start-unmap
bofbench operation run internal/section-map-start-unmap \
  --via lab --lab devbox \
  --arg target_pid=1234 \
  --arg payload=@file:/absolute/path/payload.bin
```

The run creates `runs/<run-id>/operation.json`. The receipt pins the operation definition, every pack hash, each object hash, step state, complete runtime receipt, non-sensitive captures, and cleanup results. Sensitive inputs are named under `redacted_inputs` but their values are never stored.

```mermaid
flowchart LR
  A["Typed operation inputs"] --> B["Build and analyze step 1"]
  B --> C["Execute and wait for complete output"]
  C --> D["Capture tagged fields"]
  D --> E["Resolve step 2 arguments"]
  E --> F["Checkpoint operation receipt"]
  F --> G["Reverse cleanup when requested"]
```

## Reference forms

Operation arguments accept four reference forms:

| Form | Meaning |
|---|---|
| `$input.target_pid` | typed operator input |
| `$capture.remote_base` | named capture from an earlier step |
| `$step.map.remote_base` | the same capture with its producing step made explicit |
| `$topology.target.computer_name` | a resolved topology role value |

Forward references are rejected. A capture names an output tag and field, for example:

```json
{
  "id": "map",
  "pack": "process-section-map",
  "arguments": {
    "target_pid": "$input.target_pid",
    "payload": "$input.payload"
  },
  "captures": {
    "remote_base": {
      "tag": "process-section-map",
      "field": "remote_base"
    }
  }
}
```

The next step can use `"start_address": "$capture.remote_base"`. Capture fields declared sensitive by the pack cannot be persisted.

## Complete schema example

```json
{
  "schema": "bofbench.operation",
  "schema_version": 1,
  "id": "map-start-unmap",
  "version": "1.0.0",
  "title": "Map, start, and unmap",
  "summary": "Pass a remote section base into thread start and cleanup",
  "tier": "internal",
  "inputs": [
    {"name": "target_pid", "type": "int", "required": true},
    {"name": "payload", "type": "file", "required": true, "sensitive": true}
  ],
  "steps": [
    {
      "id": "map",
      "pack": "process-section-map",
      "arguments": {"target_pid": "$input.target_pid", "payload": "$input.payload"},
      "captures": {"remote_base": {"tag": "process-section-map", "field": "remote_base"}},
      "cleanup": {
        "pack": "process-section-unmap",
        "arguments": {"target_pid": "$input.target_pid", "remote_base": "$capture.remote_base"}
      }
    },
    {
      "id": "start",
      "pack": "process-thread-start",
      "arguments": {"target_pid": "$input.target_pid", "start_address": "$capture.remote_base"}
    }
  ]
}
```

Validate a file before adding it to a catalog:

```bash
bofbench operation validate operations/map-start-unmap/operation.json
```

Catalog operations live at `operations/<id>/operation.json`. BOFBench searches embedded definitions, project-local `.bofbench/operations`, configured catalogs, and explicit `--catalog` roots. Collisions require the qualified catalog name.

## Incomplete tasks and resume

BOFBench advances only after a runtime says output is complete. A submitted or still-running C2 task leaves the operation `incomplete`; it is not represented as success.

```bash
bofbench operation resume runs/<run-id>/operation.json
```

Completed steps are skipped and their non-sensitive captures are reused. Resupply a sensitive input when an unfinished step still needs it:

```bash
bofbench operation resume runs/<run-id>/operation.json \
  --arg password=@prompt
```

Resume refuses a changed operation or changed pack definition because the stored captures belong to the pinned code. Start a new run after intentionally updating a definition.

## Cleanup

Cleanup is optional and executes completed stateful steps in reverse order:

```bash
bofbench operation cleanup runs/<run-id>/operation.json
```

Use `--cleanup` to clean after a successful run or `--cleanup-on-failure` to clean already-completed steps when a later step fails. Cleanup state and its runtime receipts are checkpointed, so a repeated cleanup skips completed cleanup work.

## Runtime and topology selection

All steps use the same `--via`, `--lab`, `--topology`, `--arch`, and `--compiler` selection. This keeps arguments and captured addresses within one runtime context.

```bash
bofbench operation run internal/remote-service-lifecycle \
  --via lab --topology dedicated-standalone \
  --arg service_name=OperatorService \
  --arg command='C:\Tools\service.exe'
```

Credentials still use `@prompt`, `@env:NAME`, or `@file:/path`. Topology files contain profile names only.

## TUI

Open `bofbench tui`, select **operations**, choose a definition, cycle the runtime and lab, and press `e` to enter typed inputs. The workspace exposes the exact direct command plus receipt, resume, and cleanup paths.

## Common failures

- **Missing capture:** the producing output did not contain the declared tag and field. Inspect the step runtime output and correct the capture contract.
- **Incomplete output:** follow the runtime task, then resume the receipt.
- **Changed definition:** start a new operation so code and captures remain correlated.
- **Unavailable runtime:** use `bofbench runtime status --lab <name>` and select an available adapter.
- **Cleanup input was sensitive:** resupply it with `operation cleanup --arg name=@prompt`.

See the [generated operation reference](operation-reference.md) and the [operation lifecycle scenario](scenarios/operation-lifecycle.md).
