# Arsenal Intelligence

An arsenal is a rebuildable capability index over public or private BOFs. It accepts local directories, Git repositories, ZIPs, source trees, `.cna` files, Sliver extensions, and existing objects.

## Acquire and index

```bash
bofbench arsenal acquire https://github.com/trustedsec/CS-Situational-Awareness-BOF.git \
  --name trustedsec-sa
bofbench arsenal inventory arsenal/trustedsec-sa
```

The inventory records capabilities, behavior chains, effects, arguments, architecture, loader support, source/version, target compatibility, and duplicate object groups.

## Search in operator language

```bash
bofbench arsenal search arsenal/trustedsec-sa --can token
bofbench arsenal search arsenal/trustedsec-sa \
  --effect credential-access --works-with sliver
bofbench arsenal search arsenal/trustedsec-sa --requires admin
```

Search filters are ANDed. The terminal prints compact matches; the persisted JSON and Markdown retain full analysis for drill-down.

## Analyze and compare

```bash
bofbench analyze arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
bofbench arsenal compare first.x64.o second.x64.o
```

Comparison emphasizes capability, argument, behavior-chain, and loader changes. Duplicate or changed hashes remain visible but do not imply changed behavior by themselves.

## x64 and x86 coverage

The loader matrix supports AMD64 and I386 COFF objects. x64 runs through `bofbench-loader.exe`; x86 runs through the separate `bofbench-loader-x86.exe` helper under WoW64 on Windows x64.

```bash
bofbench preflight arsenal/trustedsec-sa --arch all --report-only
```

The matrix reports compatibility by corpus coverage, relocation family, Beacon shim, toolchain, and argument need.

## Existing object workflow

```bash
bofbench analyze path/to/public-bof.x64.o
bofbench run path/to/public-bof.x64.o --via native --args z:target i:25
bofbench export path/to/public-bof.x64.o --for sliver --args z:target i:25
```

Use compatibility `--args` tokens when no pack or extension metadata supplies names. Project-based BOFs should use `--arg name=value`.

## Acquisition limits

HTTP and ZIP acquisition is bounded. Extraction rejects absolute paths, traversal, Windows drive/backslash escapes, symlinks, special files, duplicates, and case-colliding destinations. Updates are prepared beside the target and replace it only after validation succeeds.
