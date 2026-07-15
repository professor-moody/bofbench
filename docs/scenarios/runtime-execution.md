# Execute Through Native and Lab Runtimes

Use this scenario after static analysis answers what an object can do and you are ready to observe it on Windows. The same project is executed through the Windows-native adapter and a named remote lab profile; BOFBench records both runs as normalized receipts.

## Resulting capability

The project reports bounded host and process context. Static analysis predicts those behaviors, while each completed receipt records the exact object hash, typed arguments, target computer, output, and terminal execution state.

## Prerequisites

- A built x64 object.
- A Windows system registered as a named lab profile.
- A bootstrapped BOFBench runtime on that profile.
- Any privileges required by the selected packs. The packs below need ordinary process-enumeration access.

Set the profile once for this shell or pass `--lab` to each command:

```bash
export BOFBENCH_LAB=devbox
bofbench lab status
```

## Build and inspect the project

```bash
bofbench new runtime-survey --pack host-discovery,process-tree
bofbench build bofs/runtime-survey --arch x64
bofbench analyze bofs/runtime-survey
```

Confirm that `Can do` includes host identity and a process-tree inventory. `Needs` explains the access context, and `Arguments` should include the bounded filter and result limit.

## Run through the named lab

```bash
bofbench run bofs/runtime-survey --via lab \
  --arg process_filter=explorer \
  --arg result_limit=12
```

Expected output is concise and structured:

```text
[host] computer=DEVBOX
[process-tree] pid=4120 ppid=1080 session=1 arch=x64 image=explorer.exe
runtime  lab
state    completed
receipt  runs/<run-id>/result.json
```

Hostnames and process identifiers vary. Treat the output tag and completed receipt as the stable contract.

## Run with the Windows-native adapter

On the Windows system, or through an interactive shell on that system:

```powershell
bofbench run bofs/runtime-survey --via native `
  --arg process_filter=explorer `
  --arg result_limit=12
```

The native and lab adapters prepare the same object and typed argument buffer. Their transport and target metadata differ, but their pack output contract does not.

## Interpret the receipt

Open the receipt named by the command:

```bash
bofbench inspect runs/<run-id>/result.json
```

Check these fields before using the run as evidence:

| Receipt field | Interpretation |
| --- | --- |
| `state=completed` | Execution reached a terminal successful state |
| `output_complete=true` | The adapter collected the complete task output |
| `object_sha256` | The exact object that ran |
| `argument_types` | The values were packed with the expected BOF types |
| `profile` and `target_computer` | Where execution occurred |
| `redacted_fields` | Sensitive values intentionally omitted from storage |

Observed behavior is attached to analysis only when the receipt and analysis object hashes match. A successful receipt for an older object is not evidence for a newly rebuilt one.

## Useful variations

```bash
# Choose a different profile without changing the project.
bofbench run bofs/runtime-survey --via lab --lab dedicated \
  --arg process_filter=svchost --arg result_limit=20

# Inspect adapter readiness before another run.
bofbench runtime status --lab dedicated

# Use the project-local profile reference for a shared workflow.
bofbench lab use dedicated
```

## Common failures and recovery

- **No profile selected:** run `bofbench lab list`, then pass `--lab` or use `bofbench lab use`.
- **Runtime is missing or outdated:** run `bofbench lab bootstrap --lab <name>`. The default `--bootstrap auto` also repairs missing runtime components during normal runs.
- **Object architecture mismatch:** rebuild with `--arch x64` or `--arch x86` to match the loader.
- **Argument rejected:** compare the value with `bofbench pack show process-tree`; integer and string arguments are not interchangeable.
- **Receipt is incomplete:** do not treat submission as execution proof. Inspect runtime tasks and resume collection.

## Cleanup and next commands

This read-only survey creates no Windows state to remove. Delete the local project only when its receipts and object are no longer needed.

- [Inspect Receipts and Observed Behavior](receipts.md)
- [Move an Unchanged Project to Another VM](portable-vm.md)
- [Operate Sliver Sessions and Tasks](c2-tasks.md)
