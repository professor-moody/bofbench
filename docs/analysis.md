# Behavioral Capability Analysis

`analyze` accepts a BOF project or any compiled `.o`/`.obj`:

```bash
bofbench analyze bofs/fieldcheck
bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
bofbench analyze first.x64.o --compare second.x64.o
```

Project input is source-checked, built, and enriched with its locked pack arguments and expectations. Third-party objects are analyzed directly from COFF structure, relocations, function symbols, imported APIs, and useful strings.

## Read the default result

```text
Can do
  - Token duplication and impersonation — strong chain in token_operation
  - Process creation with another token — strong chain in token_operation
Effects
  - accesses a security token
  - changes security context
  - starts execution
Needs
  - source process access and token duplication rights
Arguments
  - source_pid (int, required)
  - command (wstring, required)
Works with
  - cobaltstrike, lab, native, sliver
Object      dist/token-check.x64.o
Loader      compatible; blockers=0
```

The operator summary comes first. Section layouts, raw imports, relocations, findings, and report paths remain under `--format text`, `--format md`, or `--format json`.

## Confidence levels

| Confidence | Meaning |
| --- | --- |
| `confirmed primitive` | The object has a concrete API primitive such as process open, registry write, or token query. |
| `strong chain` | Required steps occur in the same function and form a recognized behavior sequence. |
| `possible` | A resolved pack declares the capability, or object evidence is suggestive but not a complete chain. |

An isolated `OpenProcess` import does not become injection. BOFBench reports remote-thread injection only when process open, remote allocation, memory write, and remote thread start correlate inside one function. APC injection requires the corresponding queue step. Token impersonation requires token open, duplicate, and apply.

## Current behavior chains

- remote-thread process injection;
- APC process injection;
- token duplication and impersonation;
- process creation with another token;
- service creation and start;
- registry Run-key persistence;
- credential-process memory access;
- process minidump collection.

Each chain lists its ordered steps, API evidence, function, effects, and operating requirements in the Markdown and JSON reports.

## Argument inference

Arguments are resolved from, in order:

- the project pack lock;
- adjacent Sliver `extension.json`;
- Aggressor `.cna` argument packing;
- BOF configuration and known Beacon data reads.

The analyzer distinguishes an absent argument contract from an object that appears to take no arguments.

## Source and version

When known, reports include repository, Git ref, commit, and object SHA-256. The terminal calls this **Source and version**. It is descriptive context, not an approval step.

## Observed behavior

Static capability and runtime observation are separate fields. A strong chain says the object contains the sequence; an observed result says a matching object hash produced output or state in a recorded run. Keep both when comparing predicted and actual behavior.

## Compare objects

```bash
bofbench analyze old.x64.o --compare new.x64.o --format md
```

The diff includes added and removed capabilities, behavior chains, imports, findings, sections, entrypoint changes, size, relocations, and hashes. A hash change alone is not described as a behavioral change.

## Analyze TrustedSec `whoami`

```bash
bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
```

The object’s identity, SID, group, privilege, and token-query APIs support current identity and token discovery. They do not form token duplication, impersonation, process injection, persistence, or service-execution chains. That distinction is the point of capability analysis v2.

## Loader support

Hard blockers are limited to conditions that prevent a safe load: malformed objects, unsupported relocations or Beacon shims, missing entrypoints, incompatible architecture/helper availability, and unresolved imports that the loader cannot service. `preflight` remains a compatibility alias for `analyze --loader-details` during the migration window.

Continue with [Arsenal Intelligence](arsenal.md) for batch search or [Run a BOF](runtime.md) for execution receipts.
