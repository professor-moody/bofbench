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
5. Verify `/var/lib/sliver/receipts/install.json`, including both pinned binary
   hashes, shut down, and convert VMID
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

```bash
sudo systemctl start sliver-server.service
sudo bofbench-sliver-operator-configure
```

The operator setup is idempotent: it preserves an existing non-empty profile,
rejects multiple profiles, and writes only a secret-free receipt under
`/var/lib/sliver/receipts/operator.json`.

The runtime client uses the dedicated `bofbench` account and exactly one
operator profile at
`/home/bofbench/.sliver-client/configs/bofbench.cfg`. BOFBench reaches that
client over SSH, stages each verified extension beneath a fresh owner-only
`/tmp/bofbench-sliver-*` directory, captures the complete console result, and
removes the staging directory. The Mac never stores or executes a Sliver
binary or operator credential.

The pinned release is Sliver `1.7.3`. The server SHA-256 is
`e3216ecd12f6e7e97cb4588bb6d85c70eca3bdfad8b0818ffd53ccb2e357ccc8` and
the Linux amd64 client SHA-256 is
`b0e328a131e4d679e9b268552db99ca2d46051b9205a67f9b7f7c1628983daae`.
Both are checked before installation and recorded again in the local install
receipt. Updating either is a deliberate source change followed by a fresh
template and acceptance run.
