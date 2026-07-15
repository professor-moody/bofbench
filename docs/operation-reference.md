# Operation Reference

Generated from resolved `bofbench.operation` manifests.

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

