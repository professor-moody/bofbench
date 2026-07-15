# Documentation Conventions

This handbook is written around direct BOFBench operation.

## Command notation

- `bofbench` means the CLI is on `PATH`.
- `work/bin/bofbench` is used only during installation before that path is configured.
- Replace values in angle brackets, such as `<PID>` or `<WINDOWS_HOST>`.
- Windows paths use single quotes in POSIX shells to preserve backslashes.
- Every terminal recording types direct `bofbench` commands.

## Output notation

Output labeled **Representative output** is sanitized but retains real field names and status semantics. Dynamic PIDs, addresses, hashes, timestamps, hostnames, session IDs, and run IDs use descriptive placeholders.

Output labeled **Live proof** comes from a checked and sanitized evidence fixture. The original runtime report remains outside the public repository.

## Runtime claims

- `package-tested` means export structure and argument packing were verified.
- `adapter-tested` means adapter behavior passed deterministic tests.
- `live-proven` means execution completed through the named runtime with complete output.
- `unavailable` is reported when the runtime, session, compiler, role, or user context was not present.
- Submission without completed output is not a live pass.

## Operational controls

Private packs accept operator-selected targets and payloads. Hash, identity, backup, restore, overwrite, and cleanup arguments are optional controls unless a Windows API intrinsically requires a value. Automated proof cases may choose stricter values to make repeatable verification possible.

## Scenario prerequisites

Each scenario names its required host, Windows role, privilege, runtime, and catalog. Do not assume a domain, live C2 session, snapshot provider, compiler, or licensed client when the prerequisites do not list one.

## Paths and evidence

BOFBench writes run material beneath `runs/<id>/`. Projects live beneath `bofs/`, compiled objects beneath `dist/`, and packages beneath `export/` unless a command says otherwise. These directories are local working state and are not required to be committed.
