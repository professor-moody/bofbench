# Package a Reproducible Handoff

## Objective

Deliver a project, verified runtime package, documentation, and evidence that another operator can inspect before execution.

## Freeze project inputs

```bash
bofbench build bofs/handoff-survey --arch x64
bofbench analyze bofs/handoff-survey --format md
git status --short
```

Retain project source and `bofbench.lock.json`. The lock records exact pack versions and source hashes; the object and analysis record the compiled result.

## Export and verify

```bash
bofbench export bofs/handoff-survey --for sliver
bofbench export verify export/handoff-survey-sliver
bofbench export verify export/handoff-survey-sliver.zip --format json
```

## Include operator notes

Document:

- Resulting capability and effects.
- Architecture and runtime.
- Required privileges, target conditions, and typed arguments.
- Expected structured output tags.
- Package and object SHA-256 values.
- Cleanup companion and optional guard/backup choices.
- Whether execution is static-tested, package-tested, adapter-tested, or live-proven.

Do not include passwords, recovered output, private-key material, live session identifiers, or host-specific credentials.

## Build product releases

```bash
VERSION=<VERSION> scripts/release.sh
cd dist/release
shasum -a 256 -c SHA256SUMS
```

The release produces macOS, Linux, Windows, and documentation archives. The embedded commit should match the committed source used for the build.

## Recipient verification

The receiving operator should:

```bash
shasum -a 256 -c SHA256SUMS
bofbench export verify handoff-survey-sliver.zip
bofbench analyze <OBJECT_FROM_PACKAGE>
```

Compare the independently observed object hash and capability report with the handoff notes before running.

## Final acceptance

- Project lock resolves without source edits.
- Export verification passes after transfer.
- Expected arguments and output are documented.
- Runtime claims are precise.
- Sensitive values are absent.
- Cleanup behavior is understood before state-changing execution.
