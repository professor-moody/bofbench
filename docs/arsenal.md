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
bofbench test arsenal/trustedsec-sa --select whoami,ipconfig,netuser
```

Arsenal tests write JSON and Markdown reports under `runs/<timestamp>-test-arsenal-*/`.

On non-Windows, arsenal tests inspect objects and report that execution requires Windows x64.

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
