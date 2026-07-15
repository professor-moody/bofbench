# Move an Unchanged Project to Another VM

## Objective

Register Windows systems as named profiles and move the same BOF project between them without editing source, paths, credentials, or compiler configuration inside the project.

## Register the first system

```bash
bofbench lab add devbox \
  --provider existing \
  --transport ssh \
  --host bofbench-winvm \
  --user operator \
  --remote-root 'C:\bofbench'

bofbench lab bootstrap --lab devbox
bofbench lab status --lab devbox
```

## Clone connection-independent settings

```bash
bofbench lab add dedicated \
  --from devbox \
  --host 10.0.0.50 \
  --user operator \
  --identity ~/.ssh/bofbench-dedicated
```

The new profile inherits provider, transport, remote root, and build preferences. Authentication remains in the SSH agent, identity path, environment, or interactive prompt—not in the BOF project.

## Bootstrap and switch

```bash
bofbench lab bootstrap --lab dedicated
bofbench lab use dedicated
bofbench lab list
bofbench lab show dedicated
```

Run an existing project unchanged:

```bash
bofbench run bofs/first-survey --via lab --lab dedicated \
  --arg result_limit=10
```

## Selection precedence

BOFBench resolves the profile in this order:

1. `--lab <name>`.
2. `BOFBENCH_LAB`.
3. Project-local profile-name reference.
4. Active global profile.
5. The only configured profile.

If several profiles exist and none is selected, the command stops and names them rather than choosing a host silently.

## Use WinRM

```bash
bofbench lab setup-script --transport winrm
bofbench lab add winrm-host \
  --provider existing --transport winrm \
  --host 10.0.0.60 --user operator \
  --remote-root 'C:\bofbench'
```

Supply the password through the profile-specific environment variable or interactive input. Do not place it in `.bofbench/lab.json`.

## Recovery

- Changed host key: confirm the host was rebuilt, then update the profile-specific known-hosts record deliberately.
- Authentication failure: test SSH/WinRM outside BOFBench using the same user and credential source.
- Partial bootstrap: rerun `bootstrap`; deployment is hash-aware and idempotent.
- Wrong active host: use explicit `--lab` and inspect `lab show` before execution.
