# Parallel Native IPC and RPC

## Objective

Use schema-version-5 operations to run independent native Windows work concurrently while preserving exact result contracts, deterministic receipts, resumable C2 state, and reverse cleanup.

This scenario covers three layers:

1. public RPC endpoint, COM registration, and ALPC namespace inventory;
2. a full-duplex named-pipe server/client exchange;
3. a nested matrix that runs named-pipe, redirected-process, RPC, and COM workflows concurrently.

## Resulting capability

At the end, you can:

- identify local RPC bindings, COM activation registrations, and ALPC/LPC port names;
- create and retain an exact named-pipe server, exchange bounded sensitive bytes in both directions, and close its retained handle;
- launch an operator-selected command with redirected standard handles, exchange input/output concurrently, capture its PID, and clean it up;
- probe an exact RPC string binding and invoke an exact typed COM automation member;
- inspect a version-5 receipt showing fork/join state, child receipts, exported captures, actual concurrency, and deterministic cleanup.

## Prerequisites

- BOFBench built on the operator workstation.
- The private catalog configured as `internal`.
- A reachable Windows lab profile such as `devbox`.
- MinGW for local x64/x86 builds; MSVC is optional unless explicitly selected.
- Authorization for the selected Windows host, process holder, pipe name, command, RPC endpoint, and COM class.

Check the runtime and catalog:

```bash
bofbench lab status --lab devbox
bofbench operation show ipc-surface-triage
bofbench operation show internal/ipc-coordination-matrix --expand
```

## Public IPC surface triage

The public operation executes three read-only discovery packs concurrently:

```bash
bofbench operation graph ipc-surface-triage --expand
bofbench operation run ipc-surface-triage \
  --via lab --lab devbox --arch x64 --parallelism 3 \
  --arg result_limit=24 \
  --arg com_scope=all \
  --arg registry_view=native \
  --arg clsid_filter= \
  --arg alpc_directory='\RPC Control' \
  --arg alpc_prefix=
```

Expected shape:

```text
step 1/1  surfaces → parallel join=all branches=3
  branch rpc          [rpc-endpoint-inventory] status=complete shown=24
  branch com          [com-registration-inventory] status=complete shown=24
  branch alpc         [alpc-port-inventory] status=complete shown=24
operation  completed
receipt    runs/<run-id>/operation.json
```

The terminal prints branches in definition order even if they finish in another order. Open the receipt and confirm:

```text
parallelism: 3
max_concurrency: 3
steps[0].parallel.join: all
steps[0].parallel.state: completed
steps[0].parallel.observed_concurrency: 3
```

Useful variations:

- use `--parallelism 1` to serialize the same graph for debugging;
- use `--arg clsid_filter=<substring>` to narrow COM results;
- change `alpc_directory` and `alpc_prefix` to inspect another exact Object Manager directory;
- repeat with `--arch x86` to exercise the x86 loader and registry-view behavior.

## Build and analyze the direct packs

The three discovery packs and ten private operational packs remain usable independently:

```bash
bofbench pack show rpc-endpoint-inventory
bofbench pack show com-registration-inventory
bofbench pack show alpc-port-inventory
bofbench pack show internal/named-pipe-server-create
bofbench pack show internal/process-pipe-spawn
bofbench pack show internal/rpc-binding-probe
bofbench pack show internal/com-dispatch-invoke

bofbench pack test rpc-endpoint-inventory
bofbench pack test internal/named-pipe-server-create
bofbench pack test internal/com-dispatch-invoke
```

Analysis distinguishes endpoint enumeration, registry-backed COM discovery, Object Manager namespace reads, retained pipe operations, redirected process I/O, exact RPC binding probes, and typed `IDispatch` invocation. An isolated support API does not become a multi-step chain unless the complete function-local signature is present.

## Named-pipe duplex roundtrip

Prepare bounded request and response files and calculate their hashes with the operator workstation's normal file-hashing tool. Then run the server child operation and client pack concurrently:

```bash
bofbench operation run internal/named-pipe-duplex-roundtrip \
  --via lab --lab devbox --arch x64 --parallelism 2 \
  --arg holder_pid=<HOLDER_PID> \
  --arg pipe_name='\\.\pipe\OperatorDuplex' \
  --arg request=@file:/secure/request.bin \
  --arg request_sha256=<REQUEST_SHA256> \
  --arg response=@file:/secure/response.bin \
  --arg response_sha256=<RESPONSE_SHA256> \
  --arg timeout_ms=60000
```

The create step captures `server_handle`. The `exchange` group then starts:

- `server`: connect, read and hash-verify the request, write the response, disconnect;
- `client`: connect by exact pipe name, send the request, receive and hash-verify the response.

The request and response are available live to the packs. Persisted receipts retain sensitive field names, byte counts, and hashes—not payload bytes.

Clean the retained server handle when wanted:

```bash
bofbench operation cleanup runs/<run-id>/operation.json --parallelism 2
```

## Redirected process command session

This operation captures a child PID plus retained stdin/stdout handles. It writes and reads concurrently, then inventories the exact child:

```bash
bofbench operation run internal/process-pipe-command-session \
  --via lab --lab devbox --arch x64 --parallelism 2 \
  --arg holder_pid=<HOLDER_PID> \
  --arg command='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "$line=[Console]::In.ReadLine(); [Console]::Out.Write($line); Start-Sleep -Seconds 600"' \
  --arg request=@file:/secure/request.bin \
  --arg request_sha256=<REQUEST_SHA256> \
  --arg response_sha256=<REQUEST_SHA256> \
  --arg max_bytes=65536 \
  --arg timeout_ms=5000
```

Inspect `child_pid`, `stdin_handle`, and `stdout_handle` under the operation captures. Cleanup closes the retained handles and terminates the captured PID in reverse order:

```bash
bofbench operation cleanup runs/<run-id>/operation.json --parallelism 2
```

## RPC and COM probe matrix

Probe an exact RPC endpoint while invoking a typed COM automation member:

```bash
bofbench operation run internal/rpc-com-probe-matrix \
  --via lab --lab devbox --arch x64 --parallelism 2 \
  --arg string_binding='ncacn_ip_tcp:127.0.0.1[135]' \
  --arg auth_level=0 \
  --arg timeout_ms=5000 \
  --arg class_kind=progid \
  --arg class_name='Scripting.Dictionary' \
  --arg member=Count \
  --arg invoke_kind=get \
  --arg argument_type=none
```

`com-dispatch-invoke` also accepts one `string`, `int`, `bool`, or `bytes` argument. Supply byte arguments through `@file:` so the receipt records redaction without storing the bytes.

## Nested IPC coordination matrix

The top-level operation runs three child operations concurrently:

```bash
bofbench operation graph internal/ipc-coordination-matrix --expand

bofbench operation run internal/ipc-coordination-matrix \
  --via lab --lab devbox --arch x64 --parallelism 3 \
  --arg holder_pid=<HOLDER_PID> \
  --arg pipe_name='\\.\pipe\OperatorMatrix' \
  --arg message=@file:/secure/request.bin \
  --arg message_sha256=<REQUEST_SHA256> \
  --arg command='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "$line=[Console]::In.ReadLine(); [Console]::Out.Write($line); Start-Sleep -Seconds 600"' \
  --arg string_binding='ncacn_ip_tcp:127.0.0.1[135]' \
  --arg timeout_ms=60000
```

The parent explicitly exports:

- `server_handle` from the named-pipe branch;
- `child_pid` from the redirected-process branch.

The expanded path records every nested child and branch:

```text
matrix
matrix/named_pipe
matrix/named_pipe/create
matrix/named_pipe/exchange/server
matrix/named_pipe/exchange/client
matrix/named_pipe/exchange/$join
matrix/process_pipe
matrix/process_pipe/exchange/stdin
matrix/process_pipe/exchange/stdout
matrix/process_pipe/exchange/$join
matrix/rpc_com
matrix/rpc_com/probe/rpc
matrix/rpc_com/probe/com
matrix/rpc_com/probe/$join
matrix/$join
```

## Resume and cleanup

If a Sliver branch is submitted or running, the parent remains incomplete:

```bash
bofbench operation resume runs/<run-id>/operation.json --parallelism 3
```

Resume enters the incomplete child receipt before advancing the parent. It does not rerun completed siblings. Runtime failure does not select a fallback because branch effects may be unknown.

Cleanup is deterministic even though execution was concurrent:

```bash
bofbench operation cleanup runs/<run-id>/operation.json --parallelism 3
```

BOFBench visits completed top-level branches in reverse declaration order, then recursively visits each child operation and its completed branches in reverse order.

## Common failures and recovery

- **Preparation failed before the fork:** fix the named compiler, analyzer, typed argument, runtime, or package error. No branch was launched.
- **Pipe connect timed out:** confirm the exact pipe name, holder PID, server handle, and timeout. The duplex workflow normally needs a longer operation timeout than a single read.
- **Payload hash mismatch:** verify the file path and expected SHA-256. Receipts intentionally do not contain sensitive bytes.
- **RPC status is nonzero:** the binding was parsed, but the exact endpoint or authentication choice did not complete as expected.
- **COM member not found:** confirm class kind, class name, member spelling, invocation kind, and argument type.
- **Process output incomplete:** confirm the command reads the same bounded request length and remains alive long enough for inspection.
- **Parallel group incomplete:** inspect `steps[].parallel.branches`, complete the named runtime task, then resume.
- **Cleanup stopped:** keep the receipt, correct access/runtime availability, and rerun cleanup; completed cleanup work is skipped.

## Related commands

```bash
bofbench operation test --all --catalog internal
bofbench operation prove internal/ipc-coordination-matrix \
  --via lab --lab devbox --arch x64 --parallelism 3
bofbench runtime status --lab devbox
bofbench lab verify clean --lab devbox
```

Continue with [Multi-Step Operations](../operations.md), [Runtime Receipts](../evidence.md), [Operator TUI](../tui.md), and the private IPC/RPC runbooks.
