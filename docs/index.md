# bofbench

`bofbench` is an offensive object-module workbench for teams that need a fast local loop:

1. create or fetch BOFs,
2. build Windows COFF objects first,
3. analyze COFF, ELF, and Mach-O relocatable artifacts,
4. run through the native runtime when host and artifact match,
5. test payload behavior,
6. stage for Cobalt Strike, Sliver, or raw operator handoff.

The CLI is intentionally direct. There is no required manifest and no workflow gate in the hot path. A tiny optional `bofbench.toml` can store repeatable args and output checks.

```sh
bofbench build ./bofs/whoami
bofbench inspect ./dist/whoami.x64.o
bofbench analyze ./dist/whoami.x64.o --format md
bofbench run ./dist/whoami.x64.o --args z:hello i:3
bofbench stage ./dist/whoami.x64.o --target cobaltstrike
bofbench tui
```

The first BOF-compatible execution target is Windows x64 COFF. Linux ELF and macOS Mach-O analysis and linked native runners are available on matching hosts, so the same workbench can test platform-native object modules without reshaping the command language.
