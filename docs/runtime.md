# Run a BOF

Use one command for every execution target:

```bash
bofbench run <project-or-object> --via native|lab|sliver|cobaltstrike
```

## Native

On Windows, `native` launches the selected COFF loader in a child process with timeout, output limits, exception reporting, and per-section memory protections. x64 and x86 objects dispatch to separate helpers.

```bash
bofbench run bofs/fieldcheck --via native \
  --arg process_filter=lsass --arg result_limit=25
```

Malformed or unsupported objects stop before the entrypoint. Loader compatibility, process exit, exceptions, memory protections, Beacon output, errors, and duration are written to `runs/<id>/result.json` and `result.md`.

## Remote lab

```bash
bofbench run bofs/fieldcheck --via lab \
  --arg process_filter=lsass --arg result_limit=25
```

The adapter syncs project source and lock data, builds and runs on the Windows host, and collects the object and reports back to the local `runs/` directory.

## Sliver

```bash
bofbench run bofs/fieldcheck --via sliver \
  --session DEVBOX \
  --arg process_filter=lsass --arg result_limit=25
```

BOFBench prepares a verified extension, selects the live session, converts all typed arguments, executes the extension command, and prints compact BOF output.

## Cobalt Strike

```bash
bofbench run bofs/fieldcheck --via cobaltstrike \
  --arg process_filter=lsass --arg result_limit=25
```

The licensed adapter generates an ephemeral Aggressor script, uses `agscript`, packs values with `bof_pack`, invokes `beacon_inline_execute`, and records a redacted receipt. Connection secrets are read only from environment or an interactive credential source, never the project.

## Cleanup

```bash
bofbench run bofs/persist --via lab --cleanup --arg value_name=BOFBenchLab
```

Cleanup companions run from an isolated temporary project. They are convenient runtime actions, not approval gates.
