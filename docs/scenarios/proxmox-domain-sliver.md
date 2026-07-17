# Provision a Domain and Prove a Sliver Session

## Objective

Build the missing live-environment lane without changing a BOF project: inspect licensed media, prepare exact Proxmox-owned resources, provision a DC-plus-member topology, start a disposable Sliver session, and preserve honest receipts.

## Prerequisites

- A secret-free Proxmox preparation file whose resource plan reserves the `bofbench` pool and VMIDs `4100-4199`.
- A licensed Windows Server ISO on the configured ISO storage.
- Registered `proxmox-domain-dc`, `proxmox-domain-member`, and `proxmox-domain-ops` lab profiles.
- Linux template VMID `4104` and Sliver control VMID `4120` on the isolated bridge.
- Domain and DSRM password supplied through `@prompt`, `@env:NAME`, or `@file:path`; never a project file.

## Inspect before changing anything

```bash
bofbench lab media list --provider proxmox \
  --proxmox-prep ~/.config/bofbench/proxmox-lab.json
bofbench lab template status --lab proxmox-domain-dc
bofbench runtime control list
bofbench lab topology show proxmox-domain
```

If the Server ISO is absent, stop here. The domain lane is unavailable—not passed and not simulated. Existing standalone snapshots remain untouched.

## Build and provision

```bash
bofbench lab template build --lab proxmox-domain-dc \
  --vmid 4102 --name bofbench-windows-server-template \
  --iso local:iso/windows-server.iso --memory-mb 4096 --cores 4

bofbench lab topology up proxmox-domain
bofbench lab topology provision proxmox-domain \
  --domain bofbench.test --netbios BOFBENCH --credential @prompt
bofbench lab topology verify proxmox-domain
```

Provisioning is idempotent. It follows DC promotion and reboots, joins the member roles, creates the disposable BOFBench OU, and records role-specific receipts without the password.

## Start a live Sliver lane

```bash
bofbench runtime control add sliver-lab \
  --runtime sliver --provider proxmox \
  --proxmox-prep ~/.config/bofbench/proxmox-lab.json \
  --vmid 4120 --template-vmid 4104
bofbench runtime control up sliver-lab
bofbench sliver lab-session start \
  --control sliver-lab --lab proxmox-domain-ops \
  --arch x64 --context user
bofbench runtime status --lab proxmox-domain-ops
```

Expected readiness includes a selected live Windows session, `coff-loader`, the session architecture/context, and a terminal control-plane state. A configured client without a matching session remains unavailable.

## Prove and compare

```bash
bofbench pack prove builtin/domain-controller-inventory \
  --via lab --topology proxmox-domain
bofbench pack prove internal/ldap-acl-read \
  --catalog ~/bofbench-packs-internal \
  --via sliver --topology proxmox-domain
bofbench runtime compare bofs/domain-survey \
  --via lab,sliver --lab proxmox-domain-ops
```

Read the underlying runtime receipts before the comparison. Both lanes must be terminal, complete, and tied to the exact same object hash. Volatile fields are normalized or ignored only when declared by the pack.

## Teardown

```bash
bofbench sliver lab-session stop --lab proxmox-domain-ops --cleanup
bofbench runtime control down sliver-lab
bofbench lab topology verify proxmox-domain
bofbench lab topology down proxmox-domain
```

Confirm that session material, proof objects, services, tasks, files, registry values, and directory changes are absent before restoring or taking a clean snapshot.

## Common failures

- **No Server media:** supply the licensed ISO and rerun the read-only media command.
- **Promotion reboot timeout:** inspect the domain-provision receipt and the DC role before rerunning; successful prior steps are verified rather than repeated.
- **No matching Sliver session:** inspect architecture, Windows profile identity, selector, and control-plane service state.
- **Comparison incomplete:** refresh the persisted task, confirm final output, then rerun or resume comparison.

Continue with [Cross-Host Target Sets](topology-target-sets.md) or [Cross-Runtime Analysis v3](cross-runtime-analysis-v3.md).
