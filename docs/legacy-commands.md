# Legacy command compatibility

This is the generated human-readable view of `bofbench.command-compatibility` schema version 1, reviewed 2026-08-30. Compatibility commands are supported through `0.x`; none may be removed before `1.0.0`.

| Command | Replacement coverage | Removal ready |
| --- | --- | --- |
| `feature` | complete | false |
| `recipe` | partial | false |
| `dev` | partial | false |
| `preflight` | partial | false |
| `stage` | complete | false |

## `feature`

Individual features and curated feature packs are versioned built-in packs.

| Legacy workflow | Primary replacement | Notes |
| --- | --- | --- |
| `bofbench feature list` | `bofbench pack list` | Use pack search and pack show to narrow or inspect results. |
| `bofbench feature add <project> <feature...>` | `bofbench add <project> <pack...>` | Every supported feature ID resolves as a built-in pack. |
| `bofbench feature pack list` | `bofbench pack list` |  |
| `bofbench feature pack add <project> <pack>` | `bofbench add <project> <pack>` |  |
| `bofbench new <project> --feature <feature>` | `bofbench new <project> --pack <pack>` |  |

Command-specific removal criteria:

- keep a registry test proving every supported feature and curated feature pack resolves as a built-in pack

- prove generated source and lockfile behavior through the replacement commands

## `recipe`

Built-in recipes resolve as packs, but standalone legacy recipe-sidecar validation has no evidence-equivalent replacement.

| Legacy workflow | Primary replacement | Notes |
| --- | --- | --- |
| `bofbench recipe list` | `bofbench pack list` | Recipe IDs are retained as built-in pack IDs. |
| `bofbench recipe show <recipe>` | `bofbench pack show <recipe>` |  |
| `bofbench recipe apply <project> <recipe>` | `bofbench add <project> <recipe>` | Use new --pack <recipe> when creating a project. |
| `bofbench recipe validate <project>` | `bofbench build <project>; bofbench analyze <project>` | This validates the resolved project, not the legacy recipe sidecar itself. |

Open gaps:

- no primary command emits the legacy bofbench.recipe-validation evidence document

- existing bofbench.recipe.json migration must remain readable and preserve its original sidecar

Command-specific removal criteria:

- replace or explicitly retire standalone recipe-sidecar validation evidence

- test first-use migration for every built-in recipe ID

## `dev`

The primary workflow is an explicit build, analyze, and run sequence; its individual evidence is richer, but it does not yet replace the unified dev receipt.

| Legacy workflow | Primary replacement | Notes |
| --- | --- | --- |
| `bofbench dev <project>` | `bofbench build <project>; bofbench analyze <project>; bofbench run <project> --via <runtime>` |  |
| `bofbench dev <project> --skip-run` | `bofbench build <project>; bofbench analyze <project>` |  |
| `bofbench dev <project> --verify-reproducible` | `bofbench build <project> --verify-reproducible` | Follow with analyze and run when those phases are required. |

Open gaps:

- no aggregate primary report preserves the dev receipt's build, source, object, import-correlation, recipe, and runtime views together

- replacement commands do not emit the same unified next-action field

Command-specific removal criteria:

- define an aggregate evidence contract with equal or richer immutable phase references

- prove failure and suppression semantics match the explicit command sequence

## `preflight`

Analyze replaces single-object loader inspection; arsenal matrix is the nearest corpus replacement but does not preserve all preflight controls or evidence.

| Legacy workflow | Primary replacement | Notes |
| --- | --- | --- |
| `bofbench preflight <object>` | `bofbench analyze <object> --format text` | Text, JSON, and Markdown analysis already include loader support. |
| `bofbench preflight <arsenal> --arch all` | `bofbench arsenal matrix <arsenal> --format text` | Use JSON when machine-readable matrix output is required. |

Open gaps:

- arsenal matrix has no exact equivalents for preflight --select, --strict, or --report-only

- arsenal matrix does not emit the persisted bofbench.preflight evidence contract

Command-specific removal criteria:

- replace the selection, strict-exit, report-only, and persisted-matrix workflows

- prove single-object analyze reports every loader blocker represented by preflight

## `stage`

Stage is a Cobra alias of export and shares the same implementation.

| Legacy workflow | Primary replacement | Notes |
| --- | --- | --- |
| `bofbench stage <project-or-artifact> --target <target>` | `bofbench export <project-or-artifact> --for <target>` |  |
| `bofbench stage verify <directory-or-zip>` | `bofbench export verify <directory-or-zip>` |  |

Command-specific removal criteria:

- keep integration coverage proving stage and export accept equivalent inputs and produce equivalent packages

## Common removal criteria

- do not remove a compatibility command before version 1.0.0

- ship its complete replacement mapping for at least one minor release

- remove legacy invocations from current documentation and examples outside the compatibility reference

- keep historical receipt and sidecar schemas readable after command removal

- require integration tests showing replacement evidence is equal or richer for every supported workflow

## Machine-readable contract

The checked-in JSON contract is `docs/evidence/command-compatibility-v1.json`. Regenerate both files with `bofbench compatibility --format md` and `bofbench compatibility --format json`; the documentation check rejects drift.
