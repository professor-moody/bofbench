# Deep Capability Workflows

BOFBench uses the same `new → build → analyze → run` workflow for discovery, token work, bounded collection, WMI, and C2 execution. Deep pack source can stay in a local catalog while projects retain only resolved versions, argument contracts, and hashes.

Use only Windows systems and C2 sessions you own or are explicitly authorized to test. The examples below use BOFBench-created fixtures rather than critical processes or real credential material.

## Prepare the disposable target

```bash
bofbench catalog add ~/bofbench-packs-internal --name internal
bofbench lab target deploy --lab devbox
bofbench lab target status --lab devbox
```

Status prints the exact values used by later commands:

- LocalSystem target PID and alertable thread ID;
- unique named-pipe fixture;
- resident memory-canary address, size, and SHA-256;
- exact file-canary path and SHA-256;
- Credential Manager target name, owner, size, and expected SHA-256;
- user- and machine-scoped DPAPI blob paths and expected plaintext hashes;
- exact Windows Vault GUID, resource, identity, secret size, and expected SHA-256;
- generated exportable certificate store, subject, and thumbprint;
- a unique WMI marker path.

The generated manifest contains identifiers, paths, limits, and hashes—not plaintext fixture values.

## Continuous capability tranche

The current public tranche adds direct, bounded inventory packs:

```bash
bofbench pack test process-tree
bofbench pack test thread-inventory
bofbench pack test named-pipe-inventory
bofbench new process-map --pack process-tree
bofbench build bofs/process-map
bofbench analyze bofs/process-map
bofbench run bofs/process-map --via lab --lab devbox \
  --arg process_filter=BOFBench --arg result_limit=16
```

`ldap-query` accepts an explicit server, base DN, filter, comma-separated property list, and result limit. Its static build, analyzer, and export contracts work without a domain; live proof remains unavailable until a domain profile exists.

The private tranche adds `token-details`, `process-environment-read`, `parent-process-spawn`, `section-map-inject`, and paired `startup-folder`/`startup-folder-cleanup` packs. All accept exact targets and bounded values:

```bash
bofbench pack test internal/token-details
bofbench pack prove internal/token-details --via lab --lab devbox
bofbench pack prove internal/section-map-inject --via lab --lab devbox
bofbench pack prove internal/startup-folder --via lab --lab devbox
```

The section-map proof uses a one-byte `RET` fixture against `BOFBenchTarget`. The Startup-folder proof uses a unique `BOFBench-<run-id>.cmd`, invokes its declared cleanup companion, and verifies the exact leaf is absent through the lab transport.

## Authentication inventory and exact recovery

The public catalog exposes bounded authentication metadata without returning secrets:

```bash
bofbench new auth-survey \
  --pack security-package-inventory,certificate-store-inventory
bofbench build bofs/auth-survey
bofbench analyze bofs/auth-survey
bofbench run bofs/auth-survey --via lab --lab devbox \
  --arg name_filter=Negotiate --arg result_limit=16 \
  --arg scope=current_user --arg store=MY \
  --arg subject_filter=BOFBench --arg result_limit=16
```

For focused use, compose the two packs into separate projects when their shared argument names need different values. `security-package-inventory` reports SSPI package names, flags, comments, and maximum token sizes. `certificate-store-inventory` reports the selected store's subjects, issuers, validity, thumbprints, and private-key availability.

The private catalog separates metadata from exact recovery:

```bash
bofbench pack prove internal/logon-session-details --via lab --lab devbox
bofbench pack prove internal/kerberos-cache-inventory --via lab --lab devbox
bofbench pack prove internal/vault-inventory --via lab --lab devbox
bofbench pack prove internal/vault-read --via lab --lab devbox
```

A standalone machine may return zero Kerberos tickets; that is a successful bounded query. `vault-read` requires the exact GUID, resource, identity, and byte limit. BOFBench verifies recovered chunks in memory against the fixture SHA-256, then redacts the `hex` field from every stored report.

Direct Vault usage remains the ordinary workflow:

```bash
bofbench new vault-read --pack internal/vault-read
bofbench analyze bofs/vault-read
bofbench run bofs/vault-read --via lab --lab devbox \
  --arg vault_guid='<VAULT_GUID>' \
  --arg resource='<VAULT_RESOURCE>' \
  --arg identity='<VAULT_IDENTITY>' \
  --arg max_bytes=128
```

The recovered bytes are visible during the command and absent from the resulting receipt.

## Re-protect DPAPI material and export one PFX

Both stateful authentication packs name `internal/file-remove` as their cleanup companion. Their action arguments map `output_path` to the cleanup pack's `path` automatically:

```bash
bofbench new dpapi-reprotect --pack internal/dpapi-reprotect-file
bofbench run bofs/dpapi-reprotect --via lab --lab devbox \
  --arg input_path='<DPAPI_USER_PATH>' \
  --arg output_path='C:\bofbench\proof\reprotected.bin' \
  --arg scope=current_user
bofbench run bofs/dpapi-reprotect --via lab --lab devbox --cleanup \
  --arg output_path='C:\bofbench\proof\reprotected.bin'

bofbench new pfx-export --pack internal/certificate-pfx-export
bofbench run bofs/pfx-export --via lab --lab devbox \
  --arg scope=current_user --arg store=MY \
  --arg thumbprint='<CERT_THUMBPRINT>' \
  --arg output_path='C:\bofbench\proof\fixture.pfx' \
  --arg password=@prompt --arg include_chain=0
bofbench run bofs/pfx-export --via lab --lab devbox --cleanup \
  --arg output_path='C:\bofbench\proof\fixture.pfx'
```

`pack prove` independently decrypts the generated DPAPI blob and compares its plaintext hash, or opens the PFX and confirms the expected certificate and private key, before invoking exact-file cleanup and checking absence.

## Read an exact memory canary

```bash
bofbench new memory-proof --pack internal/process-memory-read
bofbench build bofs/memory-proof
bofbench analyze bofs/memory-proof
bofbench run bofs/memory-proof --via lab --lab devbox \
  --arg target_pid=<TARGET_PID> \
  --arg address=<MEMORY_CANARY_ADDRESS> \
  --arg size=<MEMORY_CANARY_SIZE>
```

Analysis should lead with **Bounded process-memory read**, followed by the PID, hexadecimal address, and integer size contract. Runtime output is emitted in short hexadecimal chunks and never exceeds 4 KiB.

## Inspect handles and tokens

```bash
bofbench new handle-proof --pack internal/handle-inventory
bofbench run bofs/handle-proof --via lab --lab devbox \
  --arg target_pid=<TARGET_PID> --arg result_limit=32

bofbench new token-proof --pack internal/token-inventory
bofbench run bofs/token-proof --via lab --lab devbox \
  --arg process_filter=BOFBench --arg result_limit=20
```

`handle-query` accepts one PID and one hexadecimal handle value when a specific object type needs inspection. It duplicates only that handle and does not operate on the resulting object.

Privilege adjustment is similarly explicit:

```bash
bofbench new privilege-proof --pack internal/privilege-adjust
bofbench analyze bofs/privilege-proof
bofbench run bofs/privilege-proof --via lab --lab devbox \
  --arg privilege_name=SeDebugPrivilege
```

The change applies only to the loader process token and disappears with that process.

## Credential Manager: list, then read

Metadata discovery and material recovery are separate packs:

```bash
bofbench new credential-list --pack internal/credential-list
bofbench run bofs/credential-list --via lab --lab devbox \
  --arg 'filter=*' --arg result_limit=10

bofbench new credential-read --pack internal/credential-read
bofbench analyze bofs/credential-read
bofbench run bofs/credential-read --via lab --lab devbox \
  --arg target_name=BOFBench-LiveProof --arg max_bytes=128
```

The first operation returns names, usernames, types, persistence, and sizes. The second requires one exact name and a byte limit. On SSH labs BOFBench quietly dispatches these two packs through the existing interactive Windows session so Credential Manager uses the correct logon context. Compare recovered bytes with the hash from `lab target status`; do not substitute a real credential entry.

## Recover a DPAPI fixture

```bash
bofbench new dpapi-proof --pack internal/dpapi-unprotect-file
bofbench analyze bofs/dpapi-proof
bofbench run bofs/dpapi-proof --via lab --lab devbox \
  --arg blob_path='<DPAPI_USER_PATH>' --arg max_bytes=128
```

Use the machine-scoped fixture when the runtime session differs from the user that deployed the target. Analysis explains the file-read → DPAPI-unprotect chain before execution.

## Run bounded WMI operations

```bash
bofbench new wmi-query --pack internal/wmi-query
bofbench analyze bofs/wmi-query
bofbench run bofs/wmi-query --via lab --lab devbox \
  --arg namespace='ROOT\CIMV2' \
  --arg query='SELECT Name,ProcessId FROM Win32_Process' \
  --arg property=Name --arg result_limit=20
```

WMI process creation takes exactly one target and command:

```bash
bofbench new wmi-create --pack internal/wmi-process-create
bofbench analyze bofs/wmi-create
bofbench run bofs/wmi-create --via lab --lab devbox \
  --arg target_host=. \
  --arg command='cmd.exe /d /c echo BOFBench-WMI-Proof> <WMI_MARKER_PATH>'

bofbench new marker-cleanup --pack internal/file-remove
bofbench run bofs/marker-cleanup --via lab --lab devbox \
  --arg path='<WMI_MARKER_PATH>'
```

There is no host discovery or propagation in the execution pack. The operator supplies one host and one command.

## Use the same object through Sliver

```bash
bofbench sliver setup --lab devbox
bofbench sliver sessions --lab devbox
bofbench run bofs/wmi-query --via sliver --lab devbox \
  --arg namespace='ROOT\CIMV2' \
  --arg query='SELECT Caption FROM Win32_OperatingSystem' \
  --arg property=Caption --arg result_limit=5
```

The runtime receipt records the selected session, task identifier, typed arguments, output, and exact object SHA-256. Running `analyze` again shows structured output under **Observed** only when that hash matches.

## Remove every fixture

```bash
bofbench lab target remove --lab devbox
bofbench lab target status --lab devbox
```

Removal deletes the exact Credential Manager entry, DPAPI blobs, WMI marker, files, service, state, and target directory. The expected final status is unavailable because `BOFBenchTarget` no longer exists.
