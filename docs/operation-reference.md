# Operation Reference

Generated from resolved `bofbench.operation` manifests.

## `builtin/coordination-surface-triage`

Correlate detailed process handles, exact synchronization state, and the local mailslot namespace

- Schema version: `4`
- Execution: `linear`
- Tier: `public`
- Steps: `3`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `target_pid` | `int` | true | false | `` |
| `handle_type` | `string` | false | false | `` |
| `object_type` | `string` | true | false | `` |
| `object_name` | `wstring` | true | false | `` |
| `mailslot_prefix` | `wstring` | false | false | `` |
| `result_limit` | `int` | false | false | `` |

### Steps

1. `handles` → `process-handle-detail-inventory`
2. `state` → `synchronization-object-state`
3. `mailslots` → `mailslot-inventory`

### Proof cases

- `target-coordination`: via `lab,sliver`, architectures `x64,x86`, expected path `handles → state → mailslots`, expanded path `handles → state → mailslots`

## `builtin/filesystem-and-smb-posture`

Inspect NTFS streams, reparse metadata, and active SMB connections as one concurrent ready wave

- Schema version: `10`
- Execution: `dag`
- Tier: `public`
- Steps: `3`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `path` | `wstring` | true | false | `` |
| `stream_filter` | `wstring` | false | false | `` |
| `remote_filter` | `wstring` | false | false | `` |
| `result_limit` | `int` | false | false | `` |

### Steps

1. `streams` → `file-stream-inventory`
2. `reparse` → `file-reparse-point-inventory`
3. `smb` → `smb-connection-inventory`

### Proof cases

- `canary-filesystem`: via `lab,sliver`, architectures `x64,x86`, waves `streams+reparse+smb`

## `builtin/ipc-activation-triage`

Inventory RPC, COM registration, active COM monikers, ALPC ports, and windows as one dependency-aware ready wave

- Schema version: `6`
- Execution: `dag`
- Tier: `public`
- Steps: `5`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `result_limit` | `int` | false | false | `` |
| `rpc_interface_filter` | `string` | false | false | `` |
| `rpc_protocol_filter` | `string` | false | false | `` |
| `rpc_annotation_filter` | `string` | false | false | `` |
| `com_scope` | `string` | false | false | `` |
| `registry_view` | `string` | false | false | `` |
| `clsid_filter` | `wstring` | false | false | `` |
| `rot_filter` | `string` | false | false | `` |
| `alpc_directory` | `wstring` | false | false | `` |
| `alpc_prefix` | `wstring` | false | false | `` |
| `window_scope` | `string` | false | false | `` |
| `window_class_filter` | `wstring` | false | false | `` |
| `window_title_filter` | `wstring` | false | false | `` |

### Steps

1. `rpc` → `rpc-endpoint-inventory`
2. `com-registration` → `com-registration-inventory`
3. `rot` → `com-running-object-inventory`
4. `alpc` → `alpc-port-inventory`
5. `windows` → `window-inventory`

### Proof cases

- `target-ipc`: via `lab,sliver`, architectures `x64,x86`, waves `rpc+com-registration+rot+alpc+windows`

## `builtin/ipc-surface-triage`

Inventory RPC endpoints, COM registrations, and ALPC ports concurrently

- Schema version: `5`
- Execution: `linear`
- Tier: `public`
- Steps: `1`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `result_limit` | `int` | false | false | `` |
| `com_scope` | `string` | false | false | `` |
| `registry_view` | `string` | false | false | `` |
| `clsid_filter` | `wstring` | false | false | `` |
| `alpc_directory` | `wstring` | false | false | `` |
| `alpc_prefix` | `wstring` | false | false | `` |

### Steps

1. `surfaces` → `parallel:all (3 branches)`
    - branch `rpc` → `rpc-endpoint-inventory`
    - branch `com` → `com-registration-inventory`
    - branch `alpc` → `alpc-port-inventory`

### Proof cases

- `local-ipc`: via `lab,sliver`, architectures `x64,x86`, expected path `surfaces`, expanded path `surfaces → surfaces/rpc → surfaces/com → surfaces/alpc → surfaces/$join`

## `builtin/network-connectivity-triage`

Inventory local network profiles, socket endpoints, and DNS cache state as one concurrent ready wave

- Schema version: `8`
- Execution: `dag`
- Tier: `public`
- Steps: `3`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `protocol` | `string` | false | false | `` |
| `family` | `string` | false | false | `` |
| `result_limit` | `int` | false | false | `` |

### Steps

1. `profiles` → `network-profile-inventory`
2. `sockets` → `socket-endpoint-inventory`
3. `dns-cache` → `dns-cache-inventory`

### Proof cases

- `local-connectivity`: via `lab,sliver`, architectures `x64,x86`, waves `profiles+sockets+dns-cache`

## `builtin/network-posture`

Inventory local adapters, forwarding routes, and proxy configuration

- Schema version: `2`
- Execution: `linear`
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
- Execution: `linear`
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

## `builtin/secure-network-posture`

Inspect one HTTPS endpoint certificate and response metadata while inventorying current-user BITS jobs

- Schema version: `9`
- Execution: `dag`
- Tier: `public`
- Steps: `3`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `https_url` | `wstring` | true | false | `` |
| `allow_invalid` | `int` | false | false | `` |
| `bits_filter` | `wstring` | false | false | `` |
| `result_limit` | `int` | false | false | `` |

### Steps

1. `certificate` → `tls-certificate-inventory`
2. `response` → `http-response-metadata`
3. `bits` → `bits-job-inventory`

### Proof cases

- `fixture-https`: via `lab,sliver`, architectures `x64,x86`, waves `certificate+response+bits`

## `builtin/wait-chain-triage`

Correlate process images, thread state, handle types, and Windows wait chains for an exact process

- Schema version: `3`
- Execution: `linear`
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

## `builtin/windows-eventing-posture`

Inventory Event Log channels, query bounded events, and enumerate ETW providers as concurrent roots

- Schema version: `7`
- Execution: `dag`
- Tier: `public`
- Steps: `3`
- Proof cases: `1`

### Inputs

| Name | Type | Required | Sensitive | Topology value |
|---|---|---:|---:|---|
| `channel_filter` | `wstring` | false | false | `` |
| `channel` | `wstring` | false | false | `` |
| `xpath` | `wstring` | false | false | `` |
| `provider_filter` | `wstring` | false | false | `` |
| `result_limit` | `int` | false | false | `` |

### Steps

1. `channels` → `event-log-channel-inventory`
2. `events` → `event-log-query`
3. `providers` → `etw-provider-inventory`

### Proof cases

- `local-eventing`: via `lab,sliver`, architectures `x64,x86`, waves `channels+events+providers`

