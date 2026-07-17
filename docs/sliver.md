# Run Through Sliver

BOFBench uses Sliver's BOF extension model: COFF `.o` artifacts, `extension.json`, typed arguments, and the `coff-loader` dependency.

Use this adapter only with an authorized Sliver server and Windows session.

## Proxmox control and disposable lab sessions

BOFBench can manage the lifecycle of an isolated, BOFBench-owned Sliver control VM without storing Sliver credentials in a lab profile:

```bash
bofbench runtime control add sliver-lab \
  --runtime sliver --provider proxmox \
  --proxmox-prep ~/.config/bofbench/proxmox-lab.json \
  --vmid 4120 --template-vmid 4104
bofbench runtime control up sliver-lab

bofbench sliver lab-session start \
  --control sliver-lab --lab proxmox-dev --arch x64 --context user
```

Repeat session creation sequentially for `x64 user`, `x64 system`, and `x86 user` proof coverage. Do not place an implant in a Windows template or clean snapshot. Stop and remove the disposable session when its lane completes:

```bash
bofbench sliver lab-session stop --lab proxmox-dev --cleanup
bofbench runtime control down sliver-lab
```

`lab-session start` waits for a profile-matching live session and writes a secret-free receipt. It does not manufacture success when no session checks in.

## Bind a session to a lab profile

Store a session selector while registering or cloning the Windows target:

```bash
bofbench lab add dedicated \
  --from development \
  --host 10.0.0.50 \
  --sliver-session DEDICATED-BOF
```

This stores only the selector. Sliver client configuration and authentication stay in Sliver's own configuration.

## Check the runtime

```bash
bofbench sliver setup --lab dedicated
bofbench runtime status --lab dedicated
bofbench runtime sessions --via sliver --lab dedicated
```

Setup discovers the client and configuration, checks connectivity, and verifies `coff-loader`. It never installs a dependency implicitly. Use `--install` only when you explicitly want setup to install it:

```bash
bofbench sliver setup --lab dedicated --install
```

## Run a project directly

```bash
bofbench run bofs/portable-survey --via sliver --lab dedicated \
  --arg process_filter=lsass \
  --arg result_limit=5
```

The adapter:

1. builds and analyzes the x64 project;
2. generates and verifies its extension;
3. preserves pack argument names and BOF types;
4. selects the exact live session;
5. loads and executes the extension with typed values;
6. captures full output, task/session identifiers, timeout, and exit state in `runs/<id>/result.json`.

The receipt is complete only after Sliver reports task completion and BOFBench captures the task output. A submitted task with no completed output remains `submitted`; it is not converted into a pass.

Compare a completed Sliver result with native lab execution only when both lanes use the exact same object:

```bash
bofbench runtime compare bofs/portable-survey \
  --via lab,sliver --lab dedicated
```

The comparison uses the manifest's field contracts and retains separate runtime receipts. Volatile PIDs or timestamps may be ignored or normalized only when the pack declares that behavior.

Use `--session <id-or-name>` for a one-command override. Otherwise `--lab`, `BOFBENCH_LAB`, project default, and active-profile selection apply in that order.

## Export for another operator

```bash
bofbench export bofs/portable-survey --for sliver \
  --args z:lsass i:5
bofbench export verify export/portable-survey-sliver.zip
```

`extension.json` names `process_filter` and `result_limit`, declares their Sliver types, points to the object, and declares `coff-loader`.

## Run an existing exported extension

```bash
bofbench sliver run export/portable-survey-sliver lsass 5 \
  --lab dedicated
```

The package is verified before loading. Newlines and unsafe command names are rejected before a Sliver console command is generated.

## Cleanup

```bash
bofbench run bofs/persist --via sliver --lab dedicated --cleanup \
  --arg service_name=BOFBench-Lab
```

The isolated cleanup project is packaged and executed through the same adapter.
