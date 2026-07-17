# Resilient Network Transport and Bounded Retry

## Objective

Use this workflow to inspect Windows network state, exercise exact operator-selected TCP, UDP, HTTP, WebSocket, DNS, WinHTTP-download, and BITS capabilities, and retry only a response your operation explicitly recognizes as transient.

The public operation is read-only. The private operations exchange or write operator-supplied data. Automated proof uses BOFBenchTarget's loopback endpoints; ordinary runs accept other authorized endpoints, URLs, paths, headers, bodies, and BITS names.

## Prerequisites

- A configured Windows lab profile with native x64/x86 loaders.
- The private catalog configured as `internal` for transport operations.
- BOFBenchTarget schema v10 for the exact proof commands.
- Network access permitted by the selected Windows token and host policy.

```bash
bofbench catalog add ~/bofbench-packs-internal --name internal
bofbench lab status --lab devbox
bofbench lab target deploy --lab devbox
bofbench lab target status --lab devbox
```

Target status prints the disposable TCP/UDP ports, HTTP echo/blob/transient URLs, WebSocket URL, DNS fixture name, and known blob SHA-256. These are proof inputs, not compiled restrictions.

## Inventory the local connectivity surface

```bash
bofbench operation run network-connectivity-triage \
  --via lab --lab devbox --arch x64 --parallelism 3 \
  --arg protocol=all --arg family=all --arg result_limit=32
```

The operation runs three independent roots in one ready wave:

```text
[network-profile-inventory] status=complete shown=...
[socket-endpoint-inventory] status=complete shown=...
[dns-cache-inventory] status=complete shown=...
```

`socket-endpoint-inventory` reports bounded TCP/UDP rows with family, state, PID, address, and port. `dns-cache-inventory` returns name/type/TTL metadata. `network-profile-inventory` correlates Network List Manager connectivity, profile category, identifiers, and join context.

## Prove the complete transport matrix

The matrix composes child operations for TCP, UDP, HTTP, WebSocket, DNS, and transfers:

```bash
bofbench operation graph internal/network-transport-matrix --expand
bofbench operation test internal/network-transport-matrix \
  --catalog ~/bofbench-packs-internal --compiler mingw
bofbench operation prove internal/network-transport-matrix \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox --arch x64 --parallelism 4
```

The proof engine resolves run-specific paths and payloads, verifies response and file hashes, and uses exact captured BITS job identifiers for optional cleanup. Repeat with `--arch x86` to exercise the separate WoW64 loader.

## Observe a declared 503 → 200 retry

```bash
bofbench operation run internal/http-transaction-roundtrip \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox --arch x64 \
  --arg url=<TARGET_HTTP_TRANSIENT_URL> \
  --arg method=POST \
  --arg headers='X-BOFBench: operator' \
  --arg body=@file:/absolute/path/request.bin \
  --arg expected_sha256=<REQUEST_SHA256> \
  --arg proxy_mode=direct \
  --arg timeout_ms=10000
```

The fixture returns a complete HTTP 503 once, then a complete 200. The step's normal contract accepts only 200. Its retry contract names 503 as `transient-http`, so the receipt records two attempts and one retry reason.

```bash
bofbench operation watch runs/<run-id>/operation.json --follow
jq '.steps[] | {id, state, attempt, max_attempts, retry_state, retry_reason, attempts}' \
  runs/<run-id>/operation.json
```

Interpret the result carefully:

- `runtime_receipt.execution_state=completed` means the loader task finished.
- `contract_state=completed` means the normal `http_status=200` result matched.
- `attempts[0].retry_reason=transient-http` explains why attempt one did not advance dependencies.
- A timeout, runtime failure, partial output, or HTTP status not listed under `retry.when` stops the operation without retry.

## Run the primitive packs directly

Operations are optional. Direct pack projects expose the same typed controls:

```bash
bofbench new exact-http --pack internal/winhttp-request
bofbench run bofs/exact-http --via lab --lab devbox \
  --arg url=https://authorized.example/api \
  --arg method=POST \
  --arg headers=@file:/secure/headers.txt \
  --arg body=@file:/secure/request.bin \
  --arg proxy_mode=system \
  --arg follow_redirects=0 \
  --arg timeout_ms=15000 \
  --arg max_response=131072
```

Request and response bytes are shown live when requested but redacted from stored receipts. Sizes, statuses, hashes, task identity, and object hash remain available for correlation.

## Transfer and cleanup

```bash
bofbench operation run internal/transfer-lifecycle \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox --cleanup \
  --arg url=<EXACT_URL> \
  --arg expected_sha256=<SHA256> \
  --arg winhttp_path='C:\Windows\Temp\operator-winhttp.bin' \
  --arg bits_path='C:\Windows\Temp\operator-bits.bin' \
  --arg job_name='Operator-Exact-Transfer'
```

The WinHTTP and BITS roots run concurrently. Both file hashes must match before the operation completes. Reverse cleanup removes the exact files and cancels or completes only the captured BITS GUID. Cleanup is convenient, not mandatory for ordinary operator commands.

## Variations

- Use `dns-query` with an exact resolver through `dns_server`.
- Bind TCP or UDP to an operator-selected interface and port instead of port zero.
- Select direct, system, or named proxy behavior for WinHTTP.
- Use WebSocket text or binary frames with independent size limits.
- Use `fixed` backoff for a stable polling interval or `exponential` with `max_delay_ms`.
- Set `max_attempts` from 2–16; the first execution is attempt one.

## Failures and recovery

- `connection-refused`: confirm the exact endpoint and firewall policy; do not add retry unless a complete result contract can identify the transient state.
- `hash-mismatch`: preserve the receipt, compare the exact request/response or file source, and do not clean evidence until understood.
- `retry exhausted`: inspect every attempt receipt and its terminal HTTP status.
- `retry_wait`: `operation cancel` interrupts backoff; `operation resume` preserves elapsed attempts.
- BITS job absent during cleanup: cleanup is idempotent and still removes the exact supplied output path.
- C2 task incomplete: refresh the exact runtime task; incomplete output is never retry evidence.

```bash
bofbench operation cancel runs/<run-id>/operation.json --cleanup
bofbench operation resume runs/<run-id>/operation.json
bofbench runtime task runs/<runtime-run>/result.json --refresh --wait --timeout 10m
```

## Evidence and next commands

Operation state is in `runs/<run-id>/operation.json`; each attempt embeds its normalized runtime receipt. Pack proof is in `runs/<run-id>/pack-proof.json`, and operation proof is in `runs/<run-id>/operation-proof.json`.

Continue with [Composable Operations](../operations.md), [Runtime Receipts](../evidence.md), [Arsenal Architecture Matrix](arsenal-architecture-matrix.md), or [Troubleshooting](../troubleshooting.md).
