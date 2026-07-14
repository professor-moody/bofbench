# Windows Lab

BOFBench supports an existing Windows VM first, then provider-backed standalone or domain topologies.

## Existing VM

Create an SSH alias or WinRM route to the VM, then save the non-secret lab configuration:

```bash
bofbench lab init --provider existing --host bofbench-winvm
bofbench lab bootstrap
bofbench lab status
```

Bootstrap builds or deploys:

- the BOFBench Windows executable;
- `bofbench-loader.exe` for x64;
- `bofbench-loader-x86.exe` for WoW64 x86 execution;
- the remote project workspace;
- compiler, native execution, Sliver, debugging, and snapshot probes.

`lab status` reports usable capabilities rather than a checklist.

## Run a project

```bash
bofbench lab run bofs/fieldcheck
bofbench run bofs/fieldcheck --via lab \
  --arg process_filter=lsass --arg result_limit=25
```

The local project and lock are synced, the Windows host builds/runs the object, and linked reports are collected locally.

## Vagrant provider

Use an operator-supplied licensed Windows box and Vagrantfile:

```bash
bofbench lab init --provider vagrant --topology standalone
bofbench lab up
bofbench lab snapshot clean
bofbench lab restore clean
```

The `domain` topology is intended for an operator-supplied Windows Server domain controller plus workstation. BOFBench does not include Windows images, licenses, C2 passwords, or VM credentials.

## State-changing pack cycle

```bash
bofbench run bofs/persist --via lab --arg value_name=BOFBenchLab
# independently inspect the named artifact
bofbench run bofs/persist --via lab --cleanup --arg value_name=BOFBenchLab
# independently confirm the exact artifact is gone
```

Stateful packs declare their cleanup companions, but cleanup is never a prerequisite for building or running.
