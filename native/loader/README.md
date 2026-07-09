# bofbench native loader

This directory contains the Windows x64 native COFF runner used by `bofbench run`.

Build from a Windows developer shell:

```powershell
cl /O2 /W4 /Fe:bofbench-loader.exe loader.c
```

Or from a host with MinGW-w64:

```sh
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -o bofbench-loader.exe loader.c
```

Copy `bofbench-loader.exe` next to the `bofbench` binary or set `BOFBENCH_LOADER` to its path.
