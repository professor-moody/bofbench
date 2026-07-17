# Operate Secure HTTP and BITS

## Objective

Use this workflow when you need to inspect an HTTPS endpoint, send an explicitly authenticated request, expose a one-shot HTTP listener, or configure a BITS job before transfer begins. It demonstrates operation-schema v9 by passing a listener's captured ephemeral port into a later WinHTTP URL.

## Resulting capability

The public lane reports the exact TLS certificate SHA-256, subject, issuer, validity, HTTP response metadata, and bounded current-user BITS jobs. With the private catalog, the same interface can:

- bind an operator-selected HTTP address and port;
- send Basic, Digest, or NTLM credentials from typed sensitive arguments;
- create a BITS job without immediately resuming it;
- query, prioritize, resume, suspend, complete, or cancel that exact job;
- set or clear an exact BITS notification command.

## Prerequisites

- A Windows x64 or x86 lab profile with BOFBench bootstrapped.
- Network access to the selected endpoints.
- The private catalog for listener, authentication, and BITS mutation packs.
- BITS service availability for BITS operations.

The disposable target supplies loopback HTTP/HTTPS endpoints and a self-signed certificate only for proof. Normal packs accept operator-selected URLs, credentials, commands, paths, and job identifiers.

## Inspect HTTPS and BITS posture

```bash
bofbench operation show secure-network-posture
bofbench operation run secure-network-posture \
  --via lab --lab devbox --arch x64 \
  --arg https_url=https://127.0.0.1:<PORT>/blob \
  --arg allow_invalid=1 \
  --arg bits_filter=BOFBench \
  --arg result_limit=16
```

Expected result tags:

```text
[tls-certificate-inventory] status=complete ... sha256=<CERTIFICATE_SHA256>
[http-response-metadata] status=complete http_status=200 ...
[bits-job-inventory] status=complete shown=<COUNT> limit=16
```

`allow_invalid=1` permits the request to complete against a lab certificate; it does not suppress certificate reporting. Leave it at `0` for ordinary validation.

## Capture an ephemeral listener port

```bash
bofbench operation graph internal/http-listener-roundtrip --format mermaid
bofbench operation run internal/http-listener-roundtrip \
  --via lab --lab devbox --arch x64 \
  --arg bind_address=127.0.0.1 \
  --arg request=@file:/absolute/path/request.bin \
  --arg request_sha256=<REQUEST_SHA256> \
  --arg response=@file:/absolute/path/response.bin \
  --arg response_sha256=<RESPONSE_SHA256> \
  --arg timeout_ms=120000
```

The listener first emits:

```text
[http-listener-exchange] status=ready bind=127.0.0.1 port=<EPHEMERAL_PORT>
```

BOFBench captures `port` and resolves the client argument from this definition:

```json
{"url":"http://${input.bind_address}:${capture.port}/echo"}
```

No wrapper script discovers or rewrites the port. The client starts only after the readiness contract matches. The receipt stores the non-sensitive port, exact pack/object hashes, step state, and output contract; request and response material remains redacted.

## Send an authenticated request

```bash
bofbench operation run internal/authenticated-http-roundtrip \
  --via lab --lab devbox --arch x64 \
  --arg url=https://server.example/api \
  --arg username=@env:BOFBENCH_HTTP_USER \
  --arg password=@prompt \
  --arg body=@file:/absolute/path/request.bin \
  --arg body_sha256=<REQUEST_SHA256> \
  --arg allow_invalid=0
```

The live terminal shows status and response hash. The operation receipt records `username` and `password` as redacted input names and never stores their values. A response advances only when the declared `status=complete` and HTTP status contract match.

## Configure a paused BITS job

```bash
bofbench operation run internal/bits-control-lifecycle \
  --via lab --lab devbox --arch x64 --cleanup \
  --arg url=https://server.example/payload.bin \
  --arg output_path='C:\\bofbench\\work\\payload.bin' \
  --arg job_name=OperatorTransfer \
  --arg priority=high
```

The operation performs `create(resume=0) → priority → query → resume → query`. It captures the exact job GUID from `bits-transfer-start`, reuses that GUID for every later step, and cancels only that job during optional cleanup.

For direct control:

```bash
bofbench new bits-control --pack internal/bits-transfer-control
bofbench run bofs/bits-control --via lab --lab devbox \
  --arg job_id='<GUID>' --arg action=suspend
```

Supported actions are `resume`, `suspend`, `complete`, and `cancel`.

## Inspect evidence

```bash
jq '{schema_version,status,execution_waves,captures,redacted_inputs,steps}' \
  runs/<run-id>/operation.json
```

Interpret these fields:

- `schema_version=9` identifies template-aware receipts.
- `ready_state=matched` shows that the listener was active before the client ran.
- `captures.port` is the exact resolved listener port.
- `pack_sha256` and `object_sha256` bind each result to the executed capability.
- `redacted_inputs` lists sensitive names without their values.

## Variations

- Use `port=<FIXED_PORT>` in a direct listener run when another system must connect.
- Set `auth_scheme=ntlm` or `digest` on `winhttp-auth-request` when the endpoint requires it.
- Create a BITS job with `resume=0`, configure notification and priority packs independently, then resume it later.
- Run x86 by selecting `--arch x86`; the same typed contracts apply.

## Common failures

- `certificate failed`: verify the URL is HTTPS and decide explicitly whether the lab certificate requires `allow_invalid=1`.
- `listener exited before ready`: the selected address/port could not be bound.
- `authentication 401`: verify scheme, username, password, and endpoint challenge.
- `BITS job not found`: use the captured GUID from the same user context; BITS jobs are user-scoped.
- `template missing capture`: ensure the consuming DAG step depends on the listener's readiness or completion.

## Cleanup and next commands

BITS and downloaded-file cleanup is optional for normal operation. Proof cases use exact GUID/path cleanup and independently verify absence. HTTP listeners are one-shot and close after their exchange or timeout.

Continue with [Resilient Network Transport](network-transport-retry.md), [Runtime Receipts](receipts.md), or [Multi-Step Operations](../operations.md).
