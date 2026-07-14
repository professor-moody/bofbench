# Quickstart

This path creates a parameterized Windows discovery BOF, explains its capabilities, and prepares it for a runtime.

## 1. Build BOFBench

```bash
go build -o work/bin/bofbench ./cmd/bofbench
work/bin/bofbench doctor
```

MinGW-w64 is used for portable COFF builds. On Windows, MSVC is also supported. Native COFF execution uses the separate x64 and x86 loader helpers.

## 2. Create a project from packs

```bash
work/bin/bofbench new fieldcheck \
  --pack host-discovery,system-discovery
work/bin/bofbench add bofs/fieldcheck domain-discovery
```

The project now contains generated C source plus `bofbench.lock.json`. The lock records pack versions, source hashes, runtime arguments, and cleanup relationships.

Inspect the operator contract:

```bash
work/bin/bofbench pack show system-discovery
```

## 3. Build

```bash
work/bin/bofbench build bofs/fieldcheck
```

The concise result names the object, architecture, compiler, size, hash, and report directory. Use `--compiler mingw` or `--compiler msvc` when compiler selection must be explicit.

## 4. Analyze

```bash
work/bin/bofbench analyze bofs/fieldcheck
```

Read the result from top to bottom:

- **Can do**: inferred primitives and function-local behavior chains.
- **Effects**: reads, writes, execution, persistence, credential access, or remote reach.
- **Needs**: privilege, target, domain, network, and host conditions.
- **Arguments**: runtime values from the pack contract.
- **Works with**: native, lab, Sliver, and Cobalt Strike support.

Use `--format text` for loader/object details, `--format md` for the complete report, or `--format json` for automation.

## 5. Connect an existing Windows VM

```bash
work/bin/bofbench lab init --provider existing --host bofbench-winvm
work/bin/bofbench lab bootstrap
work/bin/bofbench lab status
```

Bootstrap deploys the Windows CLI and both loader helpers, then reports usable capabilities such as compile, x64/x86 native run, Sliver, debugging, and snapshot support.

## 6. Run with named arguments

```bash
work/bin/bofbench run bofs/fieldcheck --via lab \
  --arg process_filter=lsass \
  --arg result_limit=25
```

Change the filter or limit without rebuilding. The same argument names flow into Sliver and Cobalt Strike packages.

Other runtimes use the same command:

```bash
work/bin/bofbench run bofs/fieldcheck --via native \
  --arg process_filter=lsass --arg result_limit=25
work/bin/bofbench run bofs/fieldcheck --via sliver \
  --arg process_filter=lsass --arg result_limit=25
work/bin/bofbench run bofs/fieldcheck --via cobaltstrike \
  --arg process_filter=lsass --arg result_limit=25
```

## 7. Export

```bash
work/bin/bofbench export bofs/fieldcheck --for raw
work/bin/bofbench export bofs/fieldcheck --for sliver
work/bin/bofbench export bofs/fieldcheck --for cobaltstrike
```

Each directory and ZIP self-verifies its object, argument packing, target metadata, reports, and file hashes. `stage` remains an alias for one major release.

## Analyze an existing public object

No project or pack metadata is required:

```bash
work/bin/bofbench analyze \
  arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
```

Continue with [Behavioral Analysis](analysis.md), [Windows Lab](windows-lab.md), or [Sliver](sliver.md).
