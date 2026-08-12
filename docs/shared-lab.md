# The shared lab on gr9

`docs/proxmox-labs.md` describes how BOFBench treats any Proxmox VM as a lab
profile. This page is the concrete instance the suite actually runs on, and the
two things about it that are specific to BOFBench.

The lab itself — host, networks, templates, credentials, console — is documented
in the Operator Lab manual. It is shared: EDR Lab, LoaderParity and ReverseLab
run on the same host.

## What BOFBench uses

| | |
| --- | --- |
| Host | `gr9` at `10.0.0.63`, single node |
| Profiles | `~/Library/Application Support/bofbench/labs.json` |
| Machines | `proxmox:gr9/4110`, `/4111`, `/4112` |
| Templates | `4100` clean, `4101` development |
| Slice | `6140-6179`, when it clones rather than driving a persistent VM |
| Config | `~/.config/bofbench/proxmox-gr9.json`, CA pinned |

```sh
bofbench lab status --lab proxmox-dev
bofbench lab bootstrap --lab proxmox-dev
bofbench run bofs/<project> --via lab --lab proxmox-dev
```

!!! warning "Guests are not routable from a workstation"
    The experiment bridge has outbound NAT and no inbound route, and the
    hypervisor is the only machine on both networks. `--host` takes an SSH alias
    with a `ProxyJump` through it, or `--proxmox-ssh-proxy gr9` for the API leg.

    A guest that answers `ping` but refuses SSH is usually a missing host key
    rather than a routing problem; the lab recycles DHCP addresses, so stale
    `known_hosts` entries are normal.

## Why the client here is not the shared one

The suite has a shared Proxmox client, `labpve`, because four repositories each
carried their own copy and the copies drifted into the same defects.

BOFBench keeps its own deliberately. This provider is a different design — an
SSH tunnel and a provider interface, with no guest-agent exec path at all — so
porting it would be a real refactor to inherit fixes for problems it mostly does
not have.

It shared exactly one of them: a linked clone must not send a `storage`
parameter, because it has no disks of its own to place and Proxmox rejects the
parameter rather than ignoring it. That is fixed here and pinned by a test
covering both clone modes. The configured profiles use full clones today, so
nothing was broken in practice; it was fixed before it was met a third time.

## Slices instead of a coordinator

Each tool clones into its own band of VMIDs, so two tools cannot pick the same
id regardless of what order they run in and nothing has to agree at runtime.

A machine inside the lab band but inside nobody's slice is reported as a stray
by the lab console — not a policy violation, an orphan that no tool believes it
owns and therefore nothing will clean up. Keep BOFBench clones inside
`6140-6179` so they are never read as one.
