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
| Packs | Browse catalogs, inspect capabilities, and compose the selected pack into a project. |
| Prove | Execute a declared native, lab, Sliver, or Cobalt Strike proof. |
| Topology | Inspect execution, target, and domain-controller role mappings. |
| Operations | Select a result-aware pack workflow, enter typed inputs, test or prove it, run it, and inspect captures, resume, and cleanup. |

Controls:

| Key | Action |
| --- | --- |
| `tab`, arrows | Switch workspace or selection. |
| `j`, `k` | Move within projects, objects, lab actions, or results. |
| `enter` | Execute the selected BOFBench action. |
| `v` | Cycle native, lab, Sliver, and Cobalt Strike in Run, Prove, and Operations. |
| `l` | Cycle configured lab profiles in Run, Prove, and Operations. |
| `[`, `]` | Select a typed project or operation argument. |
| `e` | Edit the selected argument; sensitive values are masked. |
| `x` | Run the selected operation's portable static test. |
| `p` | Run the selected operation's declared proof through the chosen runtime. |
| `g` | Collapse or expand nested child-operation routes in Operations. |
| `+`, `-` | Increase or decrease operation branch parallelism from 1–16. |
| `c` | Compose the selected pack into the selected project. |
| `f`, `t`, `a` | Filter Results by status, runtime, or selected artifact. |
| `r` | Refresh projects, arsenal, and receipts. |
| `q` | Quit. |

The Operations definition view shows ordered outcomes, child-operation breadcrumbs, route targets, parallel fork/join lanes, and the selected concurrency limit. Press `g` to move between collapsed and slash-qualified expanded graphs, and use `+`/`-` to select `--parallelism`. Its result view keeps runtime task state separate from result-contract state and displays parent/expanded paths, matched outcomes, skipped steps, branch state and start time, observed concurrency, child receipts, exported captures, and nested cleanup progress from version-5 receipts. A runtime failure never selects a fallback; captures appear only after a declared contract or outcome matches complete output. The Results workspace leads with predicted-versus-observed behavior: analyzer findings are shown beside receipt events and actual runtime output. The header keeps the operator loop visible: `new → add packs → build → analyze → run → export`. The last command and its real output remain on screen for immediate review.
