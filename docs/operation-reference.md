# Operation Reference

Generated from resolved `bofbench.operation` manifests.

## `builtin/network-posture`

Inventory local adapters, forwarding routes, and proxy configuration

### Inputs

| Name | Type | Required | Sensitive |
|---|---|---:|---:|
| `family` | `string` | false | false |
| `result_limit` | `int` | false | false |

### Steps

1. `adapters` → `network-adapter-inventory`
2. `routes` → `network-route-inventory`
3. `proxy` → `proxy-configuration-inventory`

## `builtin/process-triage`

Inspect a selected process, its loaded images, thread state, and security context

### Inputs

| Name | Type | Required | Sensitive |
|---|---|---:|---:|
| `target_pid` | `int` | true | false |
| `result_limit` | `int` | false | false |

### Steps

1. `images` → `process-image-inventory`
2. `threads` → `thread-state-inventory`
3. `security` → `process-security-inventory`

