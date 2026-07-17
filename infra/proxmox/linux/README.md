# Sliver control template

The Linux template at VMID `4104` is a small Ubuntu or Debian cloud image on
`vmbr290`. It is owned by the `bofbench` pool and contains no listener,
operator configuration, or implant. The runtime VM at `4120` is cloned from
that template.

Template preparation:

1. Create a 2-vCPU, 2-GB, 24-GB cloud-image VM in the BOFBench VMID range.
2. Attach only `vmbr290`, enable the QEMU guest agent, and provision SSH key
   authentication for the lab administrator.
3. Copy this directory to `/opt/bofbench`.
4. Run `sudo /opt/bofbench/sliver-control-install.sh`.
5. Verify `/var/lib/sliver/receipts/install.json`, shut down, and convert VMID
   `4104` to a template.

After cloning VMID `4120`, create `/etc/bofbench/sliver.env` with the isolated
guest address only:

```text
SLIVER_LHOST=10.12.90.40
SLIVER_LPORT=31337
```

Then start the service. Proxmox and host firewalls must reject access to that
port from every interface except `vmbr290` and the explicit operator path.
Operator configuration is generated into an external, mode-0600 location and
referenced by BOFBench; it is never stored in a project or runtime-control
profile.

The pinned release is Sliver `1.7.3`. The server SHA-256 is checked before
installation and recorded again in the local install receipt. Updating it is a
deliberate source change followed by a fresh template and acceptance run.
