# Quickstart

This path creates a parameterized Windows survey BOF, explains what it can do, and runs the same project on a named Windows target.

## 1. Build BOFBench

```bash
go build -o work/bin/bofbench ./cmd/bofbench
work/bin/bofbench doctor
```

MinGW-w64 produces portable COFF builds. Windows systems may also use MSVC. Native execution uses separate x64 and x86 loader helpers.

## 2. Create a project from a capability pack

```bash
work/bin/bofbench new portable-survey --pack deep-survey
work/bin/bofbench pack show deep-survey
```

The generated project contains C source and `bofbench.lock.json`. The lock records pack versions, source hashes, typed runtime arguments, and any cleanup relationship.

## 3. Build x64 and x86 objects

```bash
work/bin/bofbench build bofs/portable-survey --arch x64
work/bin/bofbench build bofs/portable-survey --arch x86
```

The result names the object, architecture, compiler, size, hash, and report directory. Use `--compiler mingw` or `--compiler msvc` when compiler selection must be explicit.

## 4. Analyze capabilities

```bash
work/bin/bofbench analyze bofs/portable-survey
```

Read the result from top to bottom:

- **Can do** describes inferred primitives and function-local behavior chains.
- **Effects** identifies reads, writes, execution, persistence, credential access, and remote reach.
- **Needs** identifies privilege, target, domain, network, and host conditions.
- **Arguments** names the runtime values and BOF types.
- **Works with** identifies native, lab, Sliver, and Cobalt Strike support.

Use `--format text` for loader details, `--format md` for the complete report, or `--format json` for automation.

## 5. Register any Windows host

An SSH alias, DNS name, or IP address can become a named profile:

```bash
work/bin/bofbench lab add dedicated \
  --provider existing \
  --transport ssh \
  --host windows-lab \
  --user operator \
  --remote-root 'C:\bofbench'

work/bin/bofbench lab bootstrap --lab dedicated
work/bin/bofbench lab status --lab dedicated
```

Bootstrap deploys the Windows CLI and both loaders only when their hashes differ. A compiler on Windows is optional: `build_mode=auto` falls back to a local build and uploads the object.

See [Portable Lab Profiles](lab-profiles.md) for WinRM, fresh-host setup, Vagrant, cloning a profile, and target-selection rules.

## 6. Run with named arguments

```bash
work/bin/bofbench run bofs/portable-survey \
  --via lab \
  --lab dedicated \
  --arch x64 \
  --arg process_filter=lsass \
  --arg result_limit=5
```

Change the filter or result limit without rebuilding the project. Run the x86 object by changing only `--arch x86`.

To use the profile's Sliver session:

```bash
work/bin/bofbench sliver setup --lab dedicated
work/bin/bofbench run bofs/portable-survey \
  --via sliver \
  --lab dedicated \
  --arg process_filter=lsass \
  --arg result_limit=5
```

Both runtimes write a normalized `runs/<id>/result.json` receipt with the profile, remote computer, runtime/session, object hash, typed arguments, output, timeout, and exit state.

## 7. Export

```bash
work/bin/bofbench export bofs/portable-survey --for raw
work/bin/bofbench export bofs/portable-survey --for sliver
work/bin/bofbench export bofs/portable-survey --for cobaltstrike
```

Each directory and ZIP verifies the object, argument packing, target metadata, reports, and file hashes. `stage` remains a compatibility alias for one major release.

## Analyze an existing public object

No project or pack metadata is required:

```bash
work/bin/bofbench analyze \
  arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
```

Continue with [Behavioral Analysis](analysis.md), [Live Capability Proof](live-proof.md), or [Run Through Sliver](sliver.md).
