# Runtime Model

`bofbench` uses one command language across artifact formats, then selects the runtime from the object type.

| Artifact | Analyzer | Runtime | Execution status |
| --- | --- | --- | --- |
| Windows COFF | implemented | `windows-coff` | implemented on Windows x64 |
| Windows COFF through Wine | implemented | `wine-coff` | planned |
| Linux ELF relocatable | implemented | `linux-elf` | linked native runner on Linux |
| macOS Mach-O object | implemented | `darwin-macho` | linked native runner on macOS |

```sh
bofbench run dist/whoami.x64.o --runtime auto
bofbench run dist/whoami.x64.o --runtime windows-coff
```

`auto` maps:

- COFF to `windows-coff`
- ELF to `linux-elf`
- Mach-O to `darwin-macho`

If the host cannot execute the runtime, the result is explicit:

```json
{
  "runtime": "windows-coff",
  "status": "setup_error",
  "exit_state": "requires_windows"
}
```

This is the main Go advantage for the tool: the same CLI, fetcher, analyzer, test report, stage command, docs, and TUI can work on macOS, Linux, and Windows, while each native runner stays honest about its host requirements.

`inspect` and `analyze` now write the selected runtime and host requirement into `runtime_compatibility`, so reports can say `runnable`, `requires_windows_amd64`, `requires_linux`, or `requires_darwin` before an operator attempts execution.

## Normalized Run Events

Every runtime report includes an `events` timeline in `result.json`, and `result.md` renders the same events as a table.

```json
{
  "type": "beacon_output",
  "time_ms": 6,
  "status": "line",
  "message": "hello from native loader fixture"
}
```

The first implemented event vocabulary is intentionally small:

| Event | Meaning |
| --- | --- |
| `artifact` | object type and path were detected |
| `arg_pack` | CLI tokens were packed or normalized for the runtime |
| `load` | loader, linker, or harness setup reached a terminal state |
| `entry_call` | configured entrypoint was invoked or attempted |
| `beacon_output` | captured output line from Beacon-compatible output or native stdout |
| `beacon_error` | captured error line from loader, linker, stderr, or setup failure |
| `api_event` | bofbench-side contract event such as expected-output failure |
| `exit` | normal terminal state |
| `timeout` | timeout terminal state |
| `crash` | crash terminal state when a runner can report it |

This gives Windows COFF, Linux ELF, and macOS Mach-O reports one review language even though their execution mechanics differ.

## Windows Loader Process Evidence

Windows COFF results preserve native-loader failure evidence separately from Beacon output:

```json
{
  "status": "fail",
  "exit_state": "crash",
  "loader_error_code": "windows_exception",
  "loader_process": {
    "exit_code": 3221225477,
    "exception_code": "0xc0000005"
  }
}
```

`loader_process.stdout` and `stderr` contain non-protocol process lines when present. Each stream is tail-bounded to 4 MiB and reports a truncation flag. Invalid or incomplete loader JSON, process-start failures, exit-status mismatches, output-limit failures, validation failures, crashes, and timeouts have separate exit/error codes. `result.md` renders the same process evidence.

## Linked Native Object Runners

The Linux ELF and macOS Mach-O runners are intentionally simple and real: on matching hosts they use `cc` to link the relocatable object into a small harness, execute the harness with the requested timeout, and capture stdout, stderr, exit state, and duration in the normal run report.

The harness calls:

```c
entry(argc, argv);
```

CLI tokens passed after `--args` become argv values. For example, `--args z:hello i:3` is passed as `hello` and `3`.

This runner is for platform-native object modules and fixtures. Windows BOF-compatible packed args, Beacon output capture, and Beacon API shims are handled by the `windows-coff` runtime.
