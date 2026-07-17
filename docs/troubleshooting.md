# Troubleshooting

## `run` says Windows is required

Windows COFF execution requires Windows. On macOS/Linux, use:

```sh
bofbench analyze dist/payload.x64.o
bofbench export dist/payload.x64.o --for raw
```

`analyze` still reports compiled capabilities and loader support. Continue with `bofbench run <project> --via lab --lab <name>` or move the object to Windows. x64 uses `bofbench-loader.exe`; x86 uses `bofbench-loader-x86.exe` under WoW64.

For other artifact types, `run --runtime auto` reports `requires_linux`, `requires_darwin`, or the matching setup state instead of pretending execution happened. On Linux and macOS, ELF and Mach-O execution also requires `cc` because the runner links the object into a small local harness before execution.

## Compiler missing

Install MinGW-w64, use a Windows x64 shell with MSVC `cl.exe` on PATH, or provide a `build` override in `bofbench.toml`. For Linux ELF and macOS Mach-O `run`, install the platform C compiler exposed as `cc`.

Default compiler for x64:

```text
x86_64-w64-mingw32-gcc
```

Windows x64 fallback:

```text
cl /nologo /c payload.c /Fo:dist\payload.x64.o /I payload-dir /DBOF /Brepro /experimental:deterministic /pathmap:workspace=.
```

Use `--compiler mingw` or `--compiler msvc` to stop auto-selection and receive an explicit `compiler_unavailable` diagnostic when that profile cannot be used. The persisted `build.json` records the requested profile even when selection fails.

For a remote Windows machine without a compiler, clone or add the profile with `--build-mode local`. BOFBench builds on the operator host and uploads the object:

```sh
bofbench lab add compiler-free --from dedicated --build-mode local
bofbench run bofs/portable-survey --via lab --lab compiler-free
```

## Lab profile is ambiguous

When more than one profile exists and none is selected, BOFBench prints the available names instead of guessing. Select one for the command, environment, project, or global configuration:

```sh
bofbench lab list
bofbench lab use dedicated
bofbench lab use dedicated --project bofs/portable-survey
BOFBENCH_LAB=dedicated bofbench lab status
```

Selection order is `--lab`, `BOFBENCH_LAB`, project default, active global profile, and the only configured profile.

## SSH host key changed

BOFBench keeps SSH host-key verification enabled. Confirm that the host was intentionally rebuilt or replaced, then update the correct user or profile-specific `known_hosts` file using your normal SSH tooling. Do not bypass verification in a lab profile.

## WinRM authentication failed

Existing-machine WinRM passwords are not stored. Set the sanitized profile-specific environment variable printed by `lab show`, or run from an interactive terminal to receive a no-echo prompt. For example, a profile named `clean-winrm` uses:

```sh
export BOFBENCH_LAB_CLEAN_WINRM_WINRM_PASSWORD='...'
bofbench lab status --lab clean-winrm
```

For a Vagrant profile, use `bofbench lab up --lab <name>` first. BOFBench retrieves the current WinRM connection from Vagrant and does not use the existing-machine password variable.

## Bootstrap is partial or timed out

Run status to see which capabilities are already usable, then repeat the idempotent bootstrap with a longer timeout:

```sh
bofbench lab status --lab dedicated
bofbench lab bootstrap --lab dedicated --timeout 10m
```

Ordinary `run --via lab` uses `--bootstrap auto`. Use `--bootstrap always` to recheck hashes or `--bootstrap never` to prevent deployment on a controlled target.

## Configuration rejected

`bofbench.toml` is parsed strictly. The error and `build.json` diagnostics identify every malformed line in one pass. Quote string values and each array element, use only `[profile.<name>]` sections, remove duplicate aliases such as setting both `entry` and `entrypoint`, and keep `timeout_ms` positive.

## Reproducibility check failed

`--verify-reproducible` compares two object files byte-for-byte by size and SHA-256. On failure, inspect `reproducibility.first`, `reproducibility.second`, the compiler identity, environment, full command, diagnostics, and `build.log`. Timestamp macros, generated source, nondeterministic custom build steps, and flags that embed absolute paths are common causes. Set `deterministic = false` only when nondeterminism is intentional; doing so disables BOFBench's deterministic flags but does not bypass an explicitly requested reproducibility check.

## Unsupported relocation

The loader reports the unsupported AMD64 or I386 relocation type. Use `analyze --format text` to see relocation records and rebuild with a compatible toolchain if needed.

## Loader exits with `0xc0000005`

The parent now records this as `exit_state: "crash"`, `loader_error_code: "windows_exception"`, and `loader_process.exception_code: "0xc0000005"`. Review the event timeline to see whether preflight, load, and `entry_call` were reached. Structurally malformed objects should stop earlier with `validation_error`; an exception after `entry_call` usually belongs to module behavior, argument assumptions, or an unmodeled loader/runtime interaction.

## Native validation error

Inspect `loader_error_code` and the first error line. Codes identify the failed boundary directly, for example `section_data_range`, `string_table_range`, `aux_symbol_range`, `relocation_symbol_range`, or `relocation_offset_range`. The Go analysis/preflight report should normally expose the corresponding structural blocker before the native process is started; disagreement is a loader/analyzer parity bug worth preserving with the object and both reports.

## Unresolved symbol

The loader resolves Beacon shims and common WinAPI imports. Unsupported symbols fail loudly with the object path and symbol index/name context.

## Output contract failed

`bofbench test` marks a run as `output_contract_failed` when configured `expect` strings are missing or configured `forbid` strings appear in captured output.

## DAG step is blocked

Inspect the operation receipt's `dependencies`, `execution_waves`, and `blocked_steps`. A blocked step was not executed because an ancestor failed or remained incomplete. Refresh C2 work before resuming:

```sh
bofbench runtime task runs/<runtime-run>/result.json --refresh --wait --timeout 10m
bofbench operation resume runs/<operation-run>/operation.json --parallelism 4
```

BOFBench does not schedule a fallback after a runtime crash or partial output because the remote effect is unknown.

## Background step never becomes ready

Inspect the operation and task receipts together:

```sh
bofbench operation watch runs/<operation-run>/operation.json --follow
bofbench runtime task runs/<task-run>/result.json --refresh
```

The watcher must emit the exact tag and fields declared under `ready`. A terminal result before readiness is a failure, even if the loader itself exited normally. Confirm that the watched key, directory, service, process, channel, ETW session, or event exists in the selected Windows view and user context. For 32-bit registry work, select the intended `view=32|64|native`.

## Retry did not happen or is exhausted

Inspect the step and its `attempts` array:

```bash
bofbench operation watch runs/<operation-run>/operation.json --follow
jq '.steps[] | select(.max_attempts > 1) | {id,state,attempt,max_attempts,retry_state,retry_reason,next_attempt_at,attempts}' \
  runs/<operation-run>/operation.json
```

BOFBench retries only complete terminal output that matches one named `retry.when` contract. A runtime failure, timeout, partial output, incomplete C2 task, or undeclared application result cannot consume the retry path. `exhausted` means the most recent complete transient result matched but the finite attempt limit was reached. `retry_wait` may be resumed or canceled; cancellation interrupts the deterministic backoff immediately. A background watcher cannot retry after it has emitted readiness.

## Cancel an active operation

```sh
bofbench operation cancel runs/<operation-run>/operation.json
bofbench operation cancel runs/<operation-run>/operation.json --cleanup
```

Cancellation stops new scheduling and asks each active runtime task to stop. Native and lab receipts show `cancel_supported`, request/completion timestamps, and the terminal reason. If a detected C2 runtime cannot cancel an exact task, BOFBench records `unsupported` instead of claiming success. `--cleanup` visits only already-completed stateful steps.

## C2 receipt remains partial

Confirm the recorded runtime, session, and task ID still exist:

```sh
bofbench runtime tasks --via sliver --lab devbox
bofbench runtime task <TASK_ID> --refresh
bofbench runtime watch --via sliver --lab devbox --refresh --timeout 10m
```

`output_classification=partial` or `final_chunk=false` cannot satisfy an operation result contract. Sliver refresh uses retained task output. Cobalt Strike completion requires the licensed callback path and a terminal callback; package verification is not live completion.

## Arsenal matrix shows an architecture difference

Use JSON output to see the exact category:

```sh
bofbench arsenal matrix arsenal/trustedsec-sa --format json
```

Loader support, imports, arguments, effects, capabilities, and behavior chains are compared independently. A different object hash is normal and is not itself a behavioral difference. Reacquire or relock the corpus only when the recorded source revision or object hash is unexpected.

For the full command sequence, return to the [Quickstart](quickstart.md). Loader-specific failures are detailed in [Native Loader](native-loader.md).
