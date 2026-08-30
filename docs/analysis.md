# Behavioral Capability Analysis

`analyze` accepts a BOF project or any compiled `.o`/`.obj`:

```bash
bofbench analyze bofs/fieldcheck
bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
bofbench analyze first.x64.o --compare second.x64.o
```

Project input is source-checked, built, and enriched with its locked pack arguments and expectations. Third-party objects are analyzed directly from COFF structure, relocations, function symbols, imported APIs, useful strings, and cross-function call/resource flow.

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
| `strong chain` | Required steps form a recognized same-function or call-connected interprocedural sequence with correlated resources. |
| `possible` | A resolved pack declares the capability, or object evidence is suggestive but not a complete chain. |

An isolated `OpenProcess` import does not become injection. BOFBench reports remote-thread injection only when process open, remote allocation, memory write, and remote thread start correlate inside one function or a statically connected wrapper/callee flow. APC injection requires the corresponding queue step. Token impersonation requires token open, duplicate, and apply. Unconnected functions never become a chain merely because the global import set contains every API.

## Analysis schema v3

Schema v3 retains every v1/v2 structural and capability field and adds:

- normalized compiler thunks and wrapper functions;
- API-return correlation across a call-connected function graph;
- resource flows for handles, tokens, processes, threads, memory, registry keys, services, and network objects;
- `evidence_functions` and an `interprocedural` marker on behavior chains;
- architecture-aware evidence for x64/x86 matrix comparison.

Focus on one capability without losing the full JSON/Markdown evidence:

```bash
bofbench analyze third-party.x64.o --explain token-impersonation
```

The explanation names the matched chain, confidence, evidence functions, ordered APIs, effects, requirements, and unresolved gaps. Capability names normalize hyphens and underscores for operator convenience.

## Current behavior chains

- remote-thread process injection;
- APC process injection;
- token duplication and impersonation;
- process creation with another token;
- service creation and start;
- registry Run-key persistence;
- credential-process memory access;
- process minidump collection.
- handle duplication and object query;
- process-token inventory and current-token privilege adjustment;
- bounded process-memory read;
- DPAPI file recovery;
- Credential Manager inventory and targeted reads;
- module, driver, session, and logged-on-user inventory;
- WMI query and explicit-target process creation;
- scheduled-task creation and cleanup.

Each chain lists its ordered steps, API evidence, function, effects, and operating requirements in the Markdown and JSON reports.

## Argument inference

Arguments are resolved from, in order:

- adjacent Sliver `extension.json`;
- Aggressor `.cna` argument packing;
- the project pack lock associated with `dist/<project>.<arch>.o`;
- BOF configuration and known Beacon data reads.

The analyzer distinguishes an absent argument contract from an object that appears to take no arguments.

## Source and version

When known, reports include repository, Git ref, commit, and object SHA-256. The terminal calls this **Source and version**. It is descriptive context, not an approval step.

## Observed behavior

Static capability and runtime observation are separate fields. A strong chain says the object contains the sequence; an observed result says a matching object hash produced output or state in a recorded run. BOFBench accepts both legacy receipt hashes and version-2 `object_sha256`, but correlates neither unless the object hash matches exactly.

## Compare objects

```bash
bofbench analyze old.x64.o --compare new.x64.o --format md
```

The diff includes added and removed capabilities, behavior chains, imports, findings, sections, entrypoint changes, size, relocations, and hashes. A hash change alone is not described as a behavioral change.

## Analyze TrustedSec `whoami`

```bash
bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
```

The object’s identity, SID, group, privilege, and token-query APIs support current identity and token discovery. They do not form token duplication, impersonation, process injection, persistence, or service-execution chains. That distinction remains central in capability analysis v3; wrapper normalization improves evidence without relaxing the required sequence.

## Loader support

Hard blockers are limited to conditions that prevent a safe load: malformed objects, unsupported relocations or Beacon shims, missing entrypoints, incompatible architecture/helper availability, and unresolved imports that the loader cannot service. `analyze --format text` includes loader details for one object. The compatibility `preflight` command remains distinct for corpus selection, strict exit behavior, and persisted matrix evidence; its [replacement gaps are tracked explicitly](legacy-commands.md#preflight).

Continue with [Arsenal Intelligence](arsenal.md) for batch search or [Run a BOF](runtime.md) for execution receipts.
