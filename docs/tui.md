# TUI

`bofbench tui` opens a terminal UI built with Bubble Tea and Lip Gloss.

```sh
bofbench tui
```

Views:

| View | Purpose |
| --- | --- |
| Arsenal | Browse `arsenal/trustedsec-sa` entries with selected artifact details and command previews |
| Analyze | Analyzer command previews plus recent findings from analysis and test reports |
| Runs | Browse recent `runs/` directories, newest first, with status/runtime/selected-artifact filters and event snippets |
| Stage | Staging command previews for Cobalt Strike, Sliver, and raw |
| Help | Fast-path command reference |

Controls:

| Key | Action |
| --- | --- |
| `tab`, `right` | next view |
| `shift+tab`, `left` | previous view |
| `j`, `down` | move down |
| `k`, `up` | move up |
| `home`, `end` | jump within the current list |
| `f` | cycle run status filter in the Runs view |
| `t` | cycle run runtime filter in the Runs view |
| `a` | toggle selected-artifact filter in the Runs view |
| `r` | refresh |
| `q`, `ctrl+c` | quit |

The TUI does not maintain separate business logic. It is a navigator over the same CLI services so operator behavior stays consistent.

The TUI is intentionally command-forward instead of click-to-execute. It shows exact `bofbench inspect`, `analyze`, `run`, `test`, and `stage` commands for the selected artifact so an operator can copy the next action into a normal shell, review output, and keep reports under `runs/`.
