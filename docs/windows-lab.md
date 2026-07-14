# Windows Lab

BOFBench treats every Windows VM or physical host as a named lab profile. Projects contain capabilities and arguments; global profiles contain machine-specific connection details.

## Existing Windows machine

Create an SSH alias or use a direct DNS name/IP, then save a non-secret profile:

```bash
bofbench lab add development \
  --provider existing \
  --transport ssh \
  --host windows-development \
  --user operator \
  --remote-root 'C:\bofbench'

bofbench lab bootstrap --lab development
bofbench lab status --lab development
```

Bootstrap probes the host and deploys only missing or changed components:

- the BOFBench Windows executable;
- `bofbench-loader.exe` for x64;
- `bofbench-loader-x86.exe` for WoW64 x86 execution;
- the managed remote workspace;
- compiler, native execution, Sliver, debugging, disk, elevation, and snapshot capabilities.

`lab status` reports what the machine can do. It does not require a compiler when the profile uses local-build fallback.

## Move to another machine

Clone the reusable settings and replace the connection fields:

```bash
bofbench lab add dedicated \
  --from development \
  --host 10.0.0.50 \
  --user operator \
  --identity ~/.ssh/bofbench-dedicated

bofbench lab bootstrap --lab dedicated
bofbench lab use dedicated
```

An unchanged project now runs on the dedicated system:

```bash
bofbench run bofs/portable-survey --via lab --lab dedicated \
  --arg process_filter=lsass --arg result_limit=5
```

Use [Portable Lab Profiles](lab-profiles.md) for selection precedence, WinRM, fresh-host setup, profile migration, and build modes.

## Vagrant provider

Use an operator-supplied licensed Windows box and Vagrantfile:

```bash
bofbench lab add disposable \
  --provider vagrant \
  --vagrantfile lab/Vagrantfile \
  --machine workstation \
  --topology standalone

bofbench lab up --lab disposable
bofbench lab snapshot clean --lab disposable
bofbench lab restore clean --lab disposable
```

BOFBench reads the current WinRM host, forwarded port, username, and generated password from Vagrant at run time. The profile does not become stale when a forwarded port changes.

The `domain` topology is intended for an operator-supplied Windows Server domain controller and workstation. BOFBench includes no Windows image, license, C2 password, or VM credential.

## Stateful pack cycle

```bash
bofbench run bofs/persist --via lab --lab disposable \
  --arg value_name=BOFBench-Lab --arg command='cmd.exe /c exit 0'

# Inspect the exact named artifact from an independent shell or lab verifier.

bofbench run bofs/persist --via lab --lab disposable --cleanup \
  --arg value_name=BOFBench-Lab
```

Stateful packs declare cleanup companions, but cleanup is never a prerequisite for building, analyzing, or running. Snapshot restore remains the strongest whole-machine reset.
