# Bootstrap a Compiler-Free Windows Host

## Objective

Use a new Windows system that has only SSH or WinRM. Build the BOF locally, upload the object, and run it with the remote native loader.

<video class="bb-video-clip" controls preload="metadata" poster="../../assets/images/lab-run.png">
  <source src="../../assets/media/lab-run.webm" type="video/webm">
</video>

## Prepare Windows transport

Generate the one-time elevated PowerShell for the chosen transport:

```bash
bofbench lab setup-script --transport ssh
# or
bofbench lab setup-script --transport winrm
```

Run the printed commands in an elevated Windows PowerShell, then register the profile:

```bash
bofbench lab add cleanhost \
  --provider existing --transport ssh \
  --host <WINDOWS_HOST> --user operator \
  --remote-root 'C:\bofbench' \
  --build-mode local
```

## Bootstrap runtime components

```bash
bofbench lab bootstrap --lab cleanhost
bofbench lab status --lab cleanhost
```

Expected capabilities:

```text
build     remote=false local=true
run       x64=true x86=true
```

Remote compilation is not required. Bootstrap deploys BOFBench's Windows CLI and separate x64/x86 loader helpers only when hashes differ.

## Build locally and execute remotely

```bash
bofbench new portable-host --pack host-discovery,process-tree
bofbench run bofs/portable-host --via lab --lab cleanhost \
  --bootstrap auto --build-mode local --arch x64 \
  --arg result_limit=10
```

Data flow:

```mermaid
flowchart LR
    S[Project source on operator host] --> C[Local MinGW build]
    C --> O[COFF object]
    O --> U[Verified upload]
    U --> L[Remote native loader]
    L --> R[Remote output and receipt]
    R --> B[Collected local run directory]
```

## Upgrade later

If MSVC is installed later, change the global profile to `build_mode=auto` or `remote`. The project does not change.

## Common failures

- `local=false`: install MinGW-w64 on the operator host.
- loader unavailable: rerun bootstrap and inspect remote disk space/architecture.
- x86 failure only: confirm the x86 helper was deployed and the OS supports WoW64.
- transport timeout: increase transport timeout only after confirming Windows firewall and service state.
