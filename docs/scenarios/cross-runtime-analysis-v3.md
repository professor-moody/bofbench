# Compare Runtimes and Explain Analysis v3

## Objective

Run one exact object through lab and Sliver, compare its declared structured fields, and explain a third-party behavior chain using interprocedural evidence.

## Prerequisites

- A completed lab runtime and a matching live Sliver session.
- The same architecture and exact object for both lanes.
- A pack with schema-v6 comparison contracts.
- Third-party x64/x86 objects for architecture-matrix analysis.

## Compare one project

```bash
bofbench build bofs/survey --arch x64
bofbench runtime compare bofs/survey \
  --via lab,sliver --lab proxmox-dev \
  --arg result_limit=10
```

The comparison receipt contains:

- the exact shared object SHA-256;
- each terminal runtime receipt and task/session identity;
- complete/partial/unavailable classification;
- exact, presence, normalized, payload-hash, and ignored-field decisions;
- an overall match only after all required fields pass.

Submitted or partial Sliver work does not compare as successful. Refresh the task and rerun or resume after its final chunk arrives.

## Explain a capability

```bash
bofbench analyze third-party.x64.o --explain token-impersonation
```

Analysis v3 normalizes thunks/wrappers, follows the statically connected function graph, correlates API-return resources, and reports every evidence function. A strong interprocedural chain requires the complete ordered behavior through connected functions; global imports from unrelated functions are insufficient.

## Graph and compare architectures

```bash
bofbench arsenal matrix arsenal/trustedsec-sa --analysis-version 3
bofbench arsenal graph arsenal/trustedsec-sa \
  --capability remote-execution --format mermaid
```

The matrix analyzes each x64 and x86 object independently. It compares capabilities, chains, effects, arguments, loader support, and evidence functions rather than treating x64 as representative of both.

## Compare an operation

```bash
bofbench runtime compare operation internal/domain-remote-operation-matrix \
  --catalog ~/bofbench-packs-internal \
  --via lab,sliver --topology proxmox-domain
```

Operation comparison pins the complete object-set digest and compares only terminal completed steps. It never repeats a stateful action or cleanup implicitly; the operator decides when each runtime lane runs.

## Common failures

- **Object hash differs:** rebuild once, then use that exact object in both lanes.
- **Missing comparison contract:** add schema-v6 field behavior to the pack or inspect receipts manually.
- **Capability not found:** use the analysis summary or JSON to find the normalized chain ID.
- **Unexpected interprocedural chain:** inspect `evidence_functions`, call connectivity, resource flow, and positive/negative fixtures.
