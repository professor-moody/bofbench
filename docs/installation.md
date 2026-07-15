# Install and Verify BOFBench

This guide prepares an operator workstation for building, analyzing, testing, and exporting BOFs. A Windows system is needed only when you want native Windows execution; build and static analysis work from macOS, Linux, or Windows.

## What you need

| Component | Required for | How BOFBench uses it |
| --- | --- | --- |
| Go 1.24 or newer | CLI build and tests | Builds `bofbench`, target helpers, and release binaries |
| MinGW-w64 | Portable x64/x86 BOFs | Compiles Windows COFF objects without a Windows build host |
| Git | Catalogs and arsenals | Resolves Git-backed packs and public BOF repositories |
| MkDocs Material | Documentation | Builds this handbook with strict link and navigation checks |
| OpenSSH or WinRM | Remote Windows lab | Bootstraps and runs objects on named Windows profiles |
| VHS, Freeze, FFmpeg | Documentation media | Optional; regenerates terminal clips and poster frames |

Sliver and Cobalt Strike are optional runtime integrations. Their absence does not prevent building, analyzing, testing, or exporting compatible packages.

## Build from source

```bash
git clone <BOFBENCH_REPOSITORY_URL> bofbench
cd bofbench
go build -o work/bin/bofbench ./cmd/bofbench
work/bin/bofbench version
```

Keep `work/bin/bofbench` inside the repository while following this handbook. Add it to `PATH` when you want the shorter `bofbench` form:

```bash
export PATH="$PWD/work/bin:$PATH"
bofbench version
```

## Run the environment check

```bash
bofbench doctor
```

Read the result by capability. A missing Windows loader affects native Windows execution, while a missing C2 client affects only that adapter. Optional tools should not be confused with a broken core installation.

Typical operator workstation:

```text
BOFBench doctor
go             ready
mingw x64      ready
mingw x86      ready
mkdocs         ready
windows lab    configured or unavailable
sliver         configured or unavailable
cobaltstrike   unavailable unless licensed client is supplied
```

## Install MinGW-w64

=== "macOS"

    ```bash
    brew install mingw-w64
    x86_64-w64-mingw32-gcc --version
    i686-w64-mingw32-gcc --version
    ```

=== "Debian or Ubuntu"

    ```bash
    sudo apt-get update
    sudo apt-get install -y gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
    x86_64-w64-mingw32-gcc --version
    i686-w64-mingw32-gcc --version
    ```

=== "Windows"

    Use an MSYS2 MinGW environment or register a Windows lab profile with MSVC. Verify compiler discovery with:

    ```powershell
    bofbench doctor
    bofbench lab status --lab <profile>
    ```

## Confirm the complete host workflow

```bash
bofbench new install-check --pack host-discovery
bofbench build bofs/install-check --arch x64
bofbench build bofs/install-check --arch x86
bofbench analyze bofs/install-check
bofbench export bofs/install-check --for raw
bofbench export verify export/install-check-raw
```

Success means the project was resolved from the embedded catalog, both COFF objects compiled, the analyzer explained the object, and the export manifest verified. Windows execution is deliberately not part of this host-only check.

## Install documentation tools

```bash
python3 -m pip install mkdocs-material
brew install vhs freeze ffmpeg   # optional media toolchain on macOS
make docs-check
```

`make docs-check` builds the CLI, confirms generated references have not drifted, executes the host documentation smoke lane, checks links and media, and builds both available MkDocs sites in strict mode.

## Next steps

- Follow [Build and Run Your First BOF](scenarios/first-bof.md).
- Read [How BOFBench Fits Together](concepts.md).
- Register Windows with [Portable Lab Profiles](lab-profiles.md).
- Diagnose setup problems in [Troubleshooting](troubleshooting.md).
