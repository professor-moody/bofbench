# Export for Native and C2 Runtimes

## Objective

Produce verifiable raw, Sliver, and Cobalt Strike packages from one project and understand what each recipient receives.

<video class="bb-video-clip" controls preload="metadata" poster="../../assets/images/export-verify.png">
  <source src="../../assets/media/export-verify.webm" type="video/webm">
</video>

## Build and analyze once

```bash
bofbench new handoff-survey --pack host-discovery,process-tree
bofbench build bofs/handoff-survey --arch x64
bofbench analyze bofs/handoff-survey
```

## Export all targets

```bash
bofbench export bofs/handoff-survey --for raw
bofbench export bofs/handoff-survey --for sliver
bofbench export bofs/handoff-survey --for cobaltstrike
```

Each package carries the exact object, target metadata, argument contract, source/version record, analysis, manifest, and hashes. C2 packages also contain their runtime-specific metadata or script.

## Verify directory and ZIP

```bash
bofbench export verify export/handoff-survey-raw
bofbench export verify export/handoff-survey-raw.zip --format json
bofbench export verify export/handoff-survey-sliver.zip
bofbench export verify export/handoff-survey-cobaltstrike.zip
```

Verification detects missing files, modified objects, hash drift, unsafe archive entries, and inconsistent report links.

## Typed arguments

Named project arguments are the preferred interface. Raw typed forms remain available for handoff cases:

```bash
bofbench export bofs/handoff-survey --for sliver \
  --args i:0 i:10
```

Document the argument names and order in the package notes. Never place resolved sensitive values in export arguments or project files.

## Runtime claims

- Raw export: object and manifest verified.
- Sliver export: extension contract and typed packing verified; live execution is a separate claim.
- Cobalt Strike export: Aggressor package and `bof_pack` contract verified; licensed `agscript` execution is separate.

## Handoff checklist

- Verify the ZIP immediately before transfer.
- Provide the object SHA-256 and package checksum out of band when appropriate.
- Name architecture and required runtime.
- Include example named arguments without secrets.
- Explain expected structured output.
- Name cleanup companion for state-changing packs.
