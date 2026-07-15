# Operation Reference

Generated from resolved `bofbench.operation` manifests.

## `builtin/network-posture`

Inventory local adapters, forwarding routes, and proxy configuration

- Schema version: `2`
- Tier: `public`
- Steps: `3`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `family` | `string` | false | false | `` |
| `result_limit` | `int` | false | false | `` |

### Steps

1. `adapters` → `network-adapter-inventory`
2. `routes` → `network-route-inventory`
3. `proxy` → `proxy-configuration-inventory`

### Proof cases

- `local-network`: via `lab,sliver`, architectures `x64,x86`

## `builtin/process-triage`

Inspect a selected process, its loaded images, thread state, and security context

- Schema version: `2`
- Tier: `public`
- Steps: `3`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `target_pid` | `int` | true | false | `` |
| `result_limit` | `int` | false | false | `` |

### Steps

1. `images` → `process-image-inventory`
2. `threads` → `thread-state-inventory`
3. `security` → `process-security-inventory`

### Proof cases

- `target-process`: via `lab,sliver`, architectures `x64,x86`

## `builtin/wait-chain-triage`

Correlate process images, thread state, handle types, and Windows wait chains for an exact process

- Schema version: `3`
- Tier: `public`
- Steps: `4`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `target_pid` | `int` | true | false | `` |
| `target_tid` | `int` | false | false | `` |
| `result_limit` | `int` | false | false | `` |

### Steps

1. `process` → `process-image-inventory`
2. `threads` → `thread-state-inventory`
3. `handles` → `process-handle-type-summary`
4. `waits` → `thread-wait-chain-inventory`

### Proof cases

- `target-waits`: via `lab,sliver`, architectures `x64,x86`, expected path `process → threads → handles → waits`

