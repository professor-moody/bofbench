# BOFBench Proxmox infrastructure

These files define only the BOFBench-owned `vmbr290` network. They do not
modify `vmbr0`, other isolated bridges, or VMs outside the `bofbench` pool.
The bridge itself is created through the Proxmox node-network API; the checked-
in systemd units own its scoped NAT and DHCP/DNS services.

- subnet: `10.12.90.0/24`
- gateway/DNS: `10.12.90.1`
- DHCP pool: `10.12.90.100-199`
- outbound NAT: `vmbr290` to `vmbr0`
- planned VMIDs: `4100-4199`

The provider API authenticates with a privilege-separated token resolved from
the environment or OS credential store. Token secrets, Windows passwords, and
private key contents must never be written into profiles, receipts, or this
directory.

## Checked-in assets

- `network/` and `systemd/` define DHCP/DNS and NAT only for the BOFBench bridge.
- `windows/Autounattend.xml.tmpl` is the Windows 11 installation answer template.
- `tools/autounattend` creates and uploads transient answer media from an external one-time password and SSH public key.
- `windows/provision.ps1` installs the QEMU agent, OpenSSH, WinRM, and the portable template marker.
- `windows/dev-tools.ps1` installs MSVC/SDK, Go, WinDbg tooling, and MinGW x64/x86 into a development clone.
- `windows/domain-controller.ps1` and `windows/domain-member.ps1` prepare the two domain roles after licensed Server/workstation media and credentials are supplied.

## Shared-cluster invariant

Every VM created by this program must remain inside the `bofbench` pool and
VMID range 4100-4199. Do not change, clone, snapshot, stop, or destroy a VM
outside that boundary. The bridge-use ACL is scoped to `vmbr290`; no SDN or
network permission is granted globally.

The intended template plan is:

| VMID | Template |
| ---: | --- |
| 4100 | Windows 11 clean, QEMU agent + transports, compiler-free |
| 4101 | Windows 11 development, MSVC + MinGW x64/x86 + Go + debugger |
| 4102 | Windows Server base, created only when licensed Server media exists |
| 4103 | Windows member base, created only when the workstation image and domain bootstrap are ready |

Operational clones use the remaining reserved VMIDs. Profiles—not project
files—select those clones.
