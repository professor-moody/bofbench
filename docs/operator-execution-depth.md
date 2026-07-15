# Operator-Controlled Execution

Private BOFBench packs accept operator-selected processes, threads, addresses, paths, commands, credentials, payloads, and remote hosts. Proof fixtures make automated testing repeatable; they are not runtime restrictions in the compiled BOFs.

## Guard modes are optional

Mutation and cleanup packs use one consistent control:

```text
guard_mode=none      perform the requested operation directly
guard_mode=hash      require the supplied content or current-state hash
guard_mode=identity  require the supplied process, module, file, task, service, or value identity
```

Backups, restoration, cleanup, overwrite, and expected hashes are separate typed arguments. A pack only requires them when the selected operation needs them—for example, restoration requires a backup to restore.

## Write process memory directly

```bash
bofbench new memory-op --pack internal/process-memory-write
bofbench run bofs/memory-op --via lab --lab devbox \
  --arg target_pid=1234 \
  --arg address=0x7ff600001000 \
  --arg content=@file:/absolute/path/payload.bin \
  --arg guard_mode=none
```

Add optional verification and recovery when desired:

```bash
bofbench run bofs/memory-op --via lab --lab devbox \
  --arg target_pid=1234 \
  --arg address=0x7ff600001000 \
  --arg content=@file:/absolute/path/payload.bin \
  --arg guard_mode=hash \
  --arg expected_before_sha256=<CURRENT_SHA256> \
  --arg content_sha256=<PAYLOAD_SHA256> \
  --arg backup_path='C:\Temp\region.bak'
```

## Redirect a thread

```bash
bofbench new hijack --pack internal/thread-hijack-execute
bofbench run bofs/hijack --via lab --lab devbox \
  --arg target_pid=1234 \
  --arg target_tid=5678 \
  --arg payload=@file:/absolute/path/payload.bin \
  --arg resume=1 \
  --arg restore=0
```

`restore=1` captures the original context, resumes the redirected thread, then restores that context. `restore=0` leaves the operator-requested transformation in place.

## Replace a module-backed range

```bash
bofbench new stomp --pack internal/module-stomp-execute
bofbench run bofs/stomp --via lab --lab devbox \
  --arg target_pid=1234 \
  --arg target_address=0x7ffb12341000 \
  --arg module_identity='example.dll+.text' \
  --arg payload=@file:/absolute/path/payload.bin \
  --arg execution_method=thread \
  --arg backup_path='C:\Temp\example-text.bak' \
  --arg restore=0
```

The module identity is operator metadata unless `guard_mode=identity` is selected. Backup and immediate restoration are optional.

## Create a suspended replacement process

```bash
bofbench new hollow --pack internal/process-hollow-spawn
bofbench run bofs/hollow --via lab --lab devbox \
  --arg host_image='C:\Windows\System32\notepad.exe' \
  --arg command_line='notepad.exe' \
  --arg payload=@file:/absolute/path/payload.bin \
  --arg parent_pid=1234 \
  --arg creation_flags=0 \
  --arg resume=1
```

The pack creates the selected image suspended, optionally applies the selected parent, writes the supplied execution bytes, redirects the primary thread, and resumes when requested. Its structured output includes the child PID for later cleanup.

## Load and unload a DLL

```bash
bofbench new library-op --pack internal/process-library-load
bofbench run bofs/library-op --via lab --lab devbox \
  --arg target_pid=1234 \
  --arg dll_path='C:\Tools\operator.dll'
```

Use the returned `module_base` directly:

```bash
bofbench new library-unload --pack internal/process-library-unload
bofbench run bofs/library-unload --via lab --lab devbox \
  --arg target_pid=1234 \
  --arg module_base=0x7ffb20000000 \
  --arg guard_mode=none
```

## Automated proof remains strict

```bash
bofbench pack prove internal/thread-hijack-execute --via lab --lab devbox
bofbench pack prove internal/module-stomp-execute --via lab --lab devbox
bofbench pack prove internal/process-hollow-spawn --via lab --lab devbox
bofbench pack prove internal/process-library-load --via lab --lab devbox
```

These proof cases use disposable x64/x86 helpers, an alertable thread, known memory regions, benign `RET` bytes, backup paths, captured PIDs/module bases, and independent cleanup checks. Those choices belong to the proof harness, not the operator interface.
