# Operator TUI

```bash
bofbench tui
```

The terminal workbench invokes the same commands as the CLI; it does not use wrapper scripts or a separate execution engine.

| Workspace | Enter action |
| --- | --- |
| Build | Build the selected project. |
| Analyze | Build and explain the selected project's capabilities. |
| Arsenal | Analyze the selected external object. |
| Run | Execute the selected project through the chosen runtime. |
| Lab | Run status, bootstrap, provider, snapshot, or restore action. |
| Results | Inspect recent receipts, events, findings, and output. |

Controls:

| Key | Action |
| --- | --- |
| `tab`, arrows | Switch workspace or selection. |
| `j`, `k` | Move within projects, objects, lab actions, or results. |
| `enter` | Execute the selected BOFBench action. |
| `v` | Cycle native, lab, Sliver, and Cobalt Strike in Run. |
| `f`, `t`, `a` | Filter Results by status, runtime, or selected artifact. |
| `r` | Refresh projects, arsenal, and receipts. |
| `q` | Quit. |

The header keeps the operator loop visible: `new → add packs → build → analyze → run → export`. The last command and its real output remain on screen for immediate review.
