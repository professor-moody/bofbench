# Run a BOF

Use one command for every execution target:

```bash
bofbench run <project-or-object> --via native|lab|sliver|cobaltstrike
```

All four paths implement the same runtime-adapter contract: detect, prepare, execute, optional cleanup, and receipt generation.

Before running, get a concise readiness view instead of a long diagnostic report:

```bash
bofbench runtime status --lab devbox
bofbench runtime sessions --via sliver --lab devbox
```

The first command shows the native loader, remote lab, Sliver configuration/session match, and licensed Cobalt Strike availability. The second lists selectable Sliver sessions for the named profile.

## Native Windows

On Windows, `native` launches the selected COFF loader in a child process with timeout, output limits, exception reporting, and per-section memory protections. x64 and x86 objects dispatch to separate helpers.

```bash
bofbench run bofs/portable-survey --via native --arch x64 \
  --arg process_filter=lsass --arg result_limit=5
```

Malformed or unsupported objects stop before the entrypoint.

## Remote Windows lab

```bash
bofbench run bofs/portable-survey --via lab --lab dedicated \
  --arg process_filter=lsass --arg result_limit=5
```

The adapter resolves the named profile, automatically bootstraps missing or changed runtime components, chooses local or remote compilation from `build_mode`, executes through the matching loader, and collects output.

Use [Portable Lab Profiles](lab-profiles.md) to register and switch machines without editing the project.

## Sliver

```bash
bofbench sliver setup --lab dedicated
bofbench run bofs/portable-survey --via sliver --lab dedicated \
  --arg process_filter=lsass --arg result_limit=5
```

BOFBench discovers the client and configuration, prepares a verified extension, selects the profile's live session, converts the project argument contract into Sliver arguments, executes the extension, and captures the task/session output. Installing `coff-loader` is always explicit:

```bash
bofbench sliver setup --lab dedicated --install
```

## Cobalt Strike

```bash
bofbench run bofs/portable-survey --via cobaltstrike \
  --arg process_filter=lsass --arg result_limit=5
```

The licensed adapter generates an ephemeral Aggressor script, uses `agscript`, packs values with `bof_pack`, invokes `beacon_inline_execute`, and records a redacted receipt. Connection secrets come only from environment variables, the operating-system credential source, or interactive input.

## One receipt schema

Every adapter writes `runs/<id>/result.json` using `bofbench.runtime-receipt` version 4. Receipts include:

- selected profile and remote computer identity;
- runtime, session, and task identifier when present;
- exact object SHA-256;
- named values and BOF argument types;
- captured output, timeout, exit state, duration, and error;
- cleanup invocation and result when requested.

Version 4 distinguishes `submitted`, `running`, `completed`, `failed`, and `timeout`, and records whether task output is complete. A C2 task is never reported as passed merely because it was submitted.

Sensitive receipts record the names of protected arguments and redacted output fields, never their values. Remote-lab runs apply that policy to the remote developer report, collected lab report, event stream, final receipt, and proof report. Credential Manager packs automatically use the existing interactive Windows session because the SSH transport has a different logon-session credential context.

Runtime output becomes **Observed** analysis evidence only when the receipt object hash exactly matches the analyzed object.

## Cleanup

```bash
bofbench run bofs/persist --via lab --lab disposable --cleanup \
  --arg value_name=BOFBench-Lab
```

Cleanup companions run from an isolated temporary project. They are convenient runtime actions, not approval gates.
