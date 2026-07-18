# Neutral Operator Lab

The `operator-lab` provider leases a fresh Windows x64 clone from `labd`. It
does not grant BOFBench a Proxmox token and does not replace existing direct
Proxmox profiles.

Configure the mTLS API and guest SSH material through the environment:

```text
OPERATOR_LAB_URL=https://operator-lab.example:8443
OPERATOR_LAB_CA=/private/operator-lab-ca.pem
OPERATOR_LAB_CLIENT_CERT=/private/bofbench-client.pem
OPERATOR_LAB_CLIENT_KEY=/private/bofbench-client-key.pem
BOFBENCH_OPERATOR_LAB_SSH_IDENTITY=/private/id_bofbench_operator_lab
```

Then register a portable profile:

```text
bofbench lab add shared-x64 \
  --provider operator-lab --profile bofbench-dev-x64
```

The profile stores only the neutral profile name and optional paths. At run
time BOFBench acquires one short-lived lease, writes a run-owned `known_hosts`
file from the QEMU-guest-agent-authenticated host key, uses the exact leased
address, and heartbeats while the BOF runs.

```text
bofbench run bofs/portable-survey \
  --via lab --lab shared-x64 --observe full
```

`--observe full` writes ordered start/completion markers. The runtime receipt
records the lease ID, neutral profile identity, VMID, sensor session, deadline,
clone task, destroy task, and destruction proof. It records neither mTLS key nor
guest private key. Clone-destruction failure fails the operation and leaves the
neutral lab quarantined.

Only `labd` owns machine lifecycle. BOFBench still owns its build, typed
arguments, runtime result, and cleanup semantics; it does not classify EDR
alerts or loader parity.
