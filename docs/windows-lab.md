# Windows Lab

For day-to-day work, use a GUI-capable Windows x64 VM with SSH enabled.

Recommended access model:

| Path | Use |
| --- | --- |
| SSH | automated build, test, run, and staging commands |
| RDP or VM console | debugger, ProcMon, Process Explorer, and crash triage |

Useful smoke commands:

```powershell
cd C:\bofbench
go test ./...
go build -o work\bin\bofbench.exe .\cmd\bofbench
.\work\bin\bofbench.exe doctor
.\work\bin\bofbench.exe run .\dist\hello.x64.o --args z:hello i:3
.\work\bin\bofbench.exe run .\dist\arg_echo.x64.o --args z:test-message i:42
.\work\bin\bofbench.exe run .\dist\winapi_call.x64.o
.\work\bin\bofbench.exe test .\testdata\bofs\data_reloc --runtime windows-coff
.\work\bin\bofbench.exe test .\testdata\bofs\bss_reloc --runtime windows-coff
.\work\bin\bofbench.exe test .\testdata\bofs\callback_ptr --runtime windows-coff
.\work\bin\bofbench.exe test .\testdata\bofs\parser_all --runtime windows-coff
.\work\bin\bofbench.exe stage .\dist\hello.x64.o --target raw
.\work\bin\bofbench.exe stage verify .\stage\hello-raw.zip --format json
.\work\bin\bofbench.exe fetch trustedsec-sa
.\work\bin\bofbench.exe preflight .\arsenal\trustedsec-sa --select whoami,ipconfig,env,arp,netstat,routeprint,tasklist,uptime,locale
.\work\bin\bofbench.exe test .\arsenal\trustedsec-sa --select whoami,ipconfig,env,arp,netstat,routeprint,tasklist,uptime,locale --timeout 7000
```

The repeatable version is:

```powershell
.\work\bin\bofbench.exe lab smoke --repo-root C:\bofbench --select whoami,ipconfig,env --skip-fetch
.\work\bin\bofbench.exe lab summary
```

The CLI wrapper calls the lab script and then `lab summary` renders the latest JSON evidence in a compact table. To print the exact PowerShell command without running it:

```powershell
.\work\bin\bofbench.exe lab smoke --print --repo-root C:\bofbench --select whoami,ipconfig,env --skip-fetch
```

When launched through `bofbench lab smoke`, the script builds and uses `work\bin\bofbench-lab.exe` so it does not overwrite the currently running `bofbench.exe`.

The underlying script can still be run directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows-lab-smoke.ps1 -RepoRoot C:\bofbench -Select 'whoami,ipconfig,env'
```

The script writes `runs\<timestamp>-lab-smoke\lab-smoke.json` with each step, status, duration, and error text. It verifies the generated loader-capability contract, covers positive fixtures and expected negative fixtures (`unresolved`, `timeout`), preflights the selected TrustedSec objects, and then runs the arsenal smoke.

The summary also carries the shared evidence header and fingerprints the lab environment: Windows version/architecture, PowerShell, Go, compiler path, machine identity, and SHA-256 for the BOFBench and loader binaries.

Fixture coverage:

| Fixture | Purpose |
| --- | --- |
| `hello` | entrypoint call and `BeaconPrintf` |
| `arg_echo` | `BeaconDataParse`, `BeaconDataExtract`, and `BeaconDataInt` |
| `winapi_call` | common WinAPI import resolution |
| `data_reloc` | global data and pointer relocations |
| `bss_reloc` | zero-filled uninitialized `.bss` section handling |
| `callback_ptr` | relocated function pointer invocation |
| `parser_all` | `BeaconDataShort`, `BeaconDataLength`, `BeaconOutput`, and binary arg extraction |
| `unresolved` | expected unresolved-symbol failure |
| `timeout` | expected timeout handling |

Expected successful output states:

```json
{
  "runtime": "windows-coff",
  "status": "pass",
  "exit_state": "success"
}
```

The current VM arsenal smoke uses a small TrustedSec Situational Awareness selection by default and can be expanded with `-Select` when you want broader coverage.

Compiler setup:

- MinGW-w64 is preferred for BOF parity with common public BOF build flows.
- MSVC `cl.exe` is accepted on Windows x64 for local source fixtures and simple payloads.
- The native loader can be copied from `native/loader/bofbench-loader.exe`, built with MinGW-w64, or built with MSVC.
