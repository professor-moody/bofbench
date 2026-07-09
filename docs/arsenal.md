# Public BOF Arsenal

The first arsenal adapter targets TrustedSec Situational Awareness BOFs.

```sh
bofbench fetch trustedsec-sa
bofbench list arsenal/trustedsec-sa
```

Example layout discovered by the adapter:

```text
SA/ipconfig/ipconfig.x64.o
SA/netuser/netuser.x64.o
SA/whoami/whoami.x64.o
```

Run selected smoke coverage:

```sh
bofbench preflight arsenal/trustedsec-sa --select whoami,ipconfig,netuser
bofbench test arsenal/trustedsec-sa --select whoami,ipconfig,netuser
```

Arsenal tests write JSON and Markdown reports under `runs/<timestamp>-test-arsenal-*/`.

Arsenal preflight writes a corpus compatibility matrix under `runs/<timestamp>-preflight-*/`. Each x64 object is classified as `compatible`, `compatible_runtime_lookup`, or a concrete blocker such as `unsupported_relocation` or `unsupported_beacon_api`. The JSON retains every structured issue and the Markdown report is the review-oriented matrix. Use `--strict` when runtime fallback lookup warnings must fail the gate.

On non-Windows, arsenal tests inspect compatible objects and report that execution requires Windows x64. Loader-incompatible objects fail during the preflight phase on every host.

Current macOS transcript:

```text
ipconfig: analyze pass kind=coff arch=x64 relocs=239 (run requires windows-coff)
netuser: analyze pass kind=coff arch=x64 relocs=118 (run requires windows-coff)
whoami: analyze pass kind=coff arch=x64 relocs=131 (run requires windows-coff)
reports: runs/20260709-165525-test-arsenal-trustedsec-sa/result.json runs/20260709-165525-test-arsenal-trustedsec-sa/result.md
```

Current Windows VM transcript:

```text
arp: run pass
env: run pass
ipconfig: run pass
locale: run pass
netstat: run pass
routeprint: run pass
tasklist: run pass
uptime: run pass
whoami: run pass
reports: runs\20260709-165703-test-arsenal-trustedsec-sa\result.json runs\20260709-165703-test-arsenal-trustedsec-sa\result.md
```

Windows report summary:

```json
{
  "total": 9,
  "passed": 9,
  "analyze_only": 0,
  "failed": 0
}
```

## URL Fetch

`fetch` also accepts Git, zip, and raw URLs:

```sh
bofbench fetch https://github.com/org/repo --name foo --ref main --type git --adapter generic
bofbench fetch https://example.test/payloads.zip --name payloads --type zip
bofbench fetch https://example.test/whoami.x64.o --name whoami-raw --type raw
```

Each fetch writes `arsenal/<name>/source.json`:

```json
{
  "name": "trustedsec-sa",
  "url": "https://github.com/trustedsec/CS-Situational-Awareness-BOF.git",
  "ref": "ee9459cc4f42c6b025797bad22ffe8d9f1cf6487",
  "type": "git",
  "adapter": "trustedsec-sa",
  "fetched_at": "2026-07-09T21:15:00Z",
  "path": "arsenal/trustedsec-sa"
}
```

Current source metadata also includes the shared schema/tool/host/run header and a deterministic `content_fingerprint` over fetched content, excluding `.git` internals and `source.json` itself.

## Acquisition Safety

ZIP and raw HTTP acquisition use a 256 MiB compressed/download limit. ZIP archives are limited to 100,000 entries and 512 MiB expanded content. Extraction rejects traversal and absolute paths, Windows drive/backslash paths, symlinks, special files, and duplicate or case-colliding destinations.

ZIP and raw updates are staged beside the destination and replace an existing arsenal only after download and validation succeed. A failed or malicious update therefore leaves the prior arsenal intact and removes temporary staging content.
