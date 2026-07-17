# Fan-Out SMB and NTFS Operations

## Objective

Use BOFBench to inspect filesystem/SMB posture, manipulate explicitly selected SMB and NTFS artifacts through private packs, and apply one operation to several exact paths or hosts without scanning.

## Resulting capability

The public lane can report:

- NTFS alternate streams for an exact file or directory;
- reparse-point tags, targets, and attributes for an exact path;
- current SMB client connections and their local/remote identity;
- the broader filesystem and SMB posture through one public operation.

The private lane adds exact connection, directory, file copy/move, alternate-stream, and reparse-point actions. Version-10 operations can expand a bounded operator input into independent branches while retaining per-branch receipts and cleanup.

## Prerequisites

- BOFBench and the embedded public catalog.
- A configured Windows profile for live execution.
- The private catalog for state-changing runbooks.
- An exact UNC host/share/path or local NTFS path supplied by the operator.
- Rights required by Windows for the requested path and object.

For cross-host work, define an execution/target topology:

```bash
bofbench lab topology add dedicated-standalone \
  --execution devbox \
  --target dedicated
bofbench lab topology status dedicated-standalone
```

The target must expose only the Windows services required by the selected packs. For the walkthrough below that means File and Printer Sharing plus WMI/DCOM on the isolated lab network. If a disposable standalone target uses a local administrator through `new_credentials`, Windows may also require `LocalAccountTokenFilterPolicy=1`; make that change only inside a snapshot-backed lab and restore the snapshot after the run. A domain or managed-service-account topology normally uses its existing authentication policy instead.

## Public posture

Inspect the three packs before composing them:

```bash
bofbench pack show file-stream-inventory
bofbench pack show file-reparse-point-inventory
bofbench pack show smb-connection-inventory
bofbench operation show filesystem-and-smb-posture
```

Build and analyze the public operation's packs through its static test:

```bash
bofbench operation test filesystem-and-smb-posture \
  --compiler mingw --arch x64
```

Run the public operation with an exact path and bounded result limit:

```bash
bofbench operation run filesystem-and-smb-posture \
  --via lab --lab dedicated --arch x64 \
  --arg path='C:\Windows\System32\notepad.exe' \
  --arg result_limit=32
```

Expected structured lines lead with capability results rather than loader detail:

```text
[file-stream-inventory] status=complete path=C:\Windows\System32\notepad.exe streams=1
[file-reparse-point-inventory] status=complete path=C:\Windows\System32\notepad.exe is_reparse=0
[smb-connection-inventory] status=complete connections=0
```

A zero SMB-connection count is a successful bounded observation, not a failed capability.

## Open and close one SMB connection

```bash
bofbench operation run internal/smb-connection-lifecycle \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox \
  --arg remote='\\DEDICATED\C$'
```

The action and cleanup packs are separate:

- `smb-connection-open` connects to the exact supplied remote name.
- `smb-connection-close` cancels only the exact supplied connection.

SMB network-use mappings are scoped to a Windows logon session. Open and close therefore share state only when the runtime preserves that session, such as one native or C2 session. Remote lab tasks normally use separate SSH/WinRM logons: their proof validates the exact open result but cannot claim that a later task observed or closed the same mapping. Restore the disposable snapshot or end the originating session for deterministic lab teardown.

## Exact file lifecycle

```bash
bofbench operation run internal/smb-file-lifecycle \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox \
  --arg source_path='C:\Temp\payload.bin' \
  --arg directory_path='\\DEDICATED\C$\BOFBench\run-001' \
  --arg copy_path='\\DEDICATED\C$\BOFBench\run-001\payload.bin' \
  --arg move_path='\\DEDICATED\C$\BOFBench\run-001\payload-moved.bin' \
  --cleanup
```

Interpret the receipt in execution order:

1. the SMB connection is established;
2. the exact destination directory is created if requested;
3. the source is copied to the exact destination;
4. the destination is moved to the supplied final path;
5. cleanup removes only the paths and connection represented by completed steps.

Each step retains its pack hash, object hash, typed arguments, structured output contract, runtime receipt, and cleanup result.

## Alternate stream lifecycle

```bash
bofbench operation run internal/alternate-stream-lifecycle \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab dedicated \
  --arg path='C:\Temp\carrier.txt' \
  --arg stream='bofbench-data' \
  --arg content=@file:/absolute/path/request.bin \
  --arg expected_sha256=<REQUEST_SHA256> \
  --cleanup
```

The write step reports the exact base path, stream, size, and SHA-256. The public inventory step independently sees the stream. Cleanup removes the named stream without deleting the base file.

## Reparse-point lifecycle

```bash
bofbench operation run internal/reparse-point-lifecycle \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab dedicated \
  --arg path='C:\Temp\bofbench-link' \
  --arg tag=66 \
  --arg data=@file:/absolute/path/reparse-data.bin \
  --arg guid=ABEiM0RVZneImaq7zN3u/w== \
  --cleanup
```

Use a tag, payload, and—when the selected non-Microsoft tag requires it—16-byte GUID accepted by the selected Windows filesystem and API. The operation records the tag and exact path; the inventory step confirms the resulting metadata. Cleanup targets the same path/tag/GUID relationship.

## Collect several exact paths

`multi-path-file-collection` is a schema-v10 fan-out operation. It does not enumerate a directory. It splits only the declared `paths` input:

```bash
bofbench operation show internal/multi-path-file-collection --expand
bofbench operation run internal/multi-path-file-collection \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab dedicated --parallelism 4 \
  --arg paths='C:\Temp\one.txt;C:\Temp\two.txt;C:\Temp\three.txt' \
  --arg max_bytes=1048576
```

The operation:

1. removes empty entries;
2. deduplicates exact strings while preserving first-seen order;
3. refuses a list larger than the declared maximum;
4. expands one pinned branch per path;
5. executes at most `--parallelism` branches concurrently;
6. records every successful, failed, incomplete, and cleaned branch.

Inspect the receipt:

```bash
bofbench operation watch runs/<RUN_ID>/operation.json
bofbench operation cleanup runs/<RUN_ID>/operation.json
```

## Triage several explicit hosts

`multi-target-remote-triage` invokes the remote read-only child workflow once for each exact host supplied:

```bash
bofbench operation run internal/multi-target-remote-triage \
  --catalog ~/bofbench-packs-internal \
  --via lab --lab devbox --parallelism 4 \
  --arg targets='member-a,member-b' \
  --arg auth_mode=new_credentials \
  --arg domain=. \
  --arg username=@env:BOFBENCH_TARGET_USER \
  --arg password=@prompt \
  --arg namespace='ROOT\CIMV2' \
  --arg query='SELECT Caption FROM Win32_OperatingSystem' \
  --arg property=Caption \
  --arg result_limit=4
```

Each unique target becomes one exact remote WMI query. Duplicate inputs are collapsed before scheduling. This is bounded fan-out, not discovery: BOFBench does not add hosts, expand CIDRs, follow trusts, or retry undeclared targets. Sensitive credentials are passed through the existing prompt/environment contract and are redacted from operation and runtime receipts.

## Evidence and interpretation

The version-10 operation receipt records:

- the exact fan-out source input name and separator;
- the declared and resolved item counts;
- each branch item, step or child-operation path, object/definition hashes, runtime state, contract state, and cleanup state;
- observed maximum concurrency;
- aggregate completed, failed, incomplete, and unavailable counts.

Runtime observation correlates with analysis only when the object SHA-256 matches exactly. Sensitive file contents remain available to the live command only when the pack contract permits and are redacted from stored receipts.

## Common failures and recovery

- **List exceeds maximum:** split the operator-selected list or raise the operation's declared limit within 1–64.
- **Access denied:** confirm the exact local/remote path and current or explicit credential context.
- **UNC path not found:** verify name resolution, share name, SMB service, and firewall on the supplied host.
- **Local administrator is denied remotely:** confirm the disposable target's account and Windows token-filtering policy; prefer domain credentials outside standalone proof labs.
- **Connection inventory does not show a successful open:** the open and inventory ran in different Windows logon sessions. Inspect the open result itself, then close in the originating native/C2 session or restore the lab snapshot.
- **Alternate stream unsupported:** verify the destination is NTFS and that the path resolves to a filesystem supporting named streams.
- **Reparse payload rejected:** use a tag/payload format accepted by the Windows reparse API and target filesystem.
- **One fan-out branch fails:** inspect that branch receipt. Completed branches are not rerun by resume; cleanup visits only completed stateful branches.
- **Incomplete C2 branch:** refresh or resume its exact runtime task. Submission alone never satisfies the operation contract.

Related: [Composable Operations](../operations.md), [Standalone and Domain Topologies](topologies.md), [Proxmox-Native Labs](../proxmox-labs.md), [Runtime Receipts](../evidence.md), and [Private Catalog Setup](../external-catalogs.md).
