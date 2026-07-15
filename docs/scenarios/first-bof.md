# Build and Run Your First BOF

## Objective

Create a parameterized Windows survey, understand its predicted capability, run the same object on a named Windows lab, and export it for another runtime.

<video class="bb-video-clip" controls preload="metadata" poster="../../assets/images/build-analyze.png">
  <source src="../../assets/media/build-analyze.webm" type="video/webm">
</video>

## Prerequisites

- BOFBench and MinGW-w64 pass the checks in [Install and Verify](../installation.md).
- A Windows profile named `devbox`, or replace that name throughout.
- No private catalog is required.

## Create and inspect the project

```bash
bofbench new first-survey --pack host-discovery,process-tree
bofbench add bofs/first-survey network-neighbor-inventory
bofbench pack show process-tree
```

The project lock should list all three resolved packs, their versions and hashes, typed arguments, effects, and target support. `add` changes project composition; runtime filters remain arguments.

## Build both objects

```bash
bofbench build bofs/first-survey --arch x64
bofbench build bofs/first-survey --arch x86
```

Representative output:

```text
BOF BUILD PASS
object  dist/first-survey.x64.o
arch    x64
compiler mingw
sha256  <OBJECT_SHA256>
```

If x86 fails while x64 succeeds, confirm `i686-w64-mingw32-gcc` is installed. Do not treat one successful architecture as proof of the other.

## Analyze before execution

```bash
bofbench analyze bofs/first-survey
```

Confirm that `Can do` describes host, process-tree, and network-neighbor discovery; `Effects` should remain read-only. Review typed filters and limits under `Arguments`.

## Run with named values

```bash
bofbench lab status --lab devbox
bofbench run bofs/first-survey --via lab --lab devbox --arch x64 \
  --arg root_pid=0 \
  --arg family=0 \
  --arg result_limit=20
```

Change `result_limit` or network family and rerun without rebuilding. The receipt under `runs/<id>/result.json` records the exact object hash and argument types.

## Export and verify

```bash
bofbench export bofs/first-survey --for raw
bofbench export bofs/first-survey --for sliver
bofbench export verify export/first-survey-raw
bofbench export verify export/first-survey-sliver.zip
```

The raw package is suitable for a loader operator. The Sliver package includes `extension.json`, typed arguments, object artifacts, source/version metadata, analysis, and hashes.

## Recovery and next steps

- Compiler unavailable: follow [Build Across Architectures](build-matrix.md).
- Lab unavailable: follow [Move to Another VM](portable-vm.md).
- Analysis unclear: read [Capability Reports](../report-interpretation.md).
- Continue with [Inspect Receipts](receipts.md) or [Export Packages](export-packages.md).
