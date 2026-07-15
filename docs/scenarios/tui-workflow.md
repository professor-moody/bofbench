# Use the Operator TUI

## Objective

Compose packs, inspect analysis, enter typed arguments, select a runtime or topology, run proof, and review predicted-versus-observed behavior without leaving BOFBench.

## Start

```bash
bofbench tui
```

The TUI uses the same projects, catalogs, profiles, adapters, and receipts as CLI commands. It does not create a separate execution model.

## Compose and build

1. Open **Build**.
2. Select or create a project.
3. Search public and configured private catalogs.
4. Add packs and review dependency/cleanup relationships.
5. Select architecture and compiler.
6. Build and open the resulting object.

## Analyze

Open **Analyze** and read capabilities, behavior chains, effects, requirements, arguments, and runtime support. Use comparison when two objects are selected.

## Run

1. Select native, lab, Sliver, or Cobalt Strike.
2. Select a lab profile, session, or topology when required.
3. Enter typed arguments. Sensitive inputs are not echoed.
4. Choose optional guard, overwrite, backup, restore, or cleanup values when the pack exposes them.
5. Run and open the receipt.

## Inspect results

The Results view shows runtime, kind, exit state, session/task, execution state, output completeness, selected target, object hash, errors, and correlated predicted/observed capability.

## Reproduce in the CLI

The TUI previews direct commands for selected actions. Copy that command when you need scripting, review, or a repeatable operator handoff.

## Common problems

- Empty catalog: check configured paths with `catalog list`.
- No runtime: run `runtime status --lab <profile>`.
- Sensitive input missing: choose prompt/environment/file source.
- Task still submitted: inspect `runtime task <id> --wait`.
- Result absent: adjust Results filters for status, runtime, and artifact.
