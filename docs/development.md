# Developer Loop

`bofbench new` creates small local modules for development and lab validation.

```sh
bofbench new echoer --template args
bofbench new hello --template hello
bofbench new pidcheck --template winapi
bofbench new badlink --template unresolved
bofbench new slow --template timeout
```

Templates:

| Template | Purpose |
| --- | --- |
| `args` | Beacon arg parser and output contract |
| `hello` | no-arg smoke module |
| `winapi` | benign WinAPI import fixture using `GetCurrentProcessId` |
| `unresolved` | negative fixture expecting `relocation_error` |
| `timeout` | negative fixture expecting `timeout` |

## Test Profiles

`bofbench.toml` can define named profiles for repeatable argument and output contracts:

```toml
name = "echoer"
entry = "go"
args = ["z:default", "i:1"]
expect = ["echoer: default count=1"]
timeout_ms = 5000

[profile.alt]
args = ["z:profile-message", "i:9"]
expect = ["echoer: profile-message count=9"]
forbid = ["panic"]
```

Run the default contract:

```sh
bofbench test bofs/echoer
```

Run a named profile:

```sh
bofbench test bofs/echoer --profile alt
```

## Expected Failures

Negative fixtures use `expect_exit` so a known loader/runtime failure can be tested intentionally:

```toml
name = "badlink"
entry = "go"
args = []
expect_exit = "relocation_error"
timeout_ms = 5000
```

The run report still records the real runtime status and exit state. The test command succeeds only because the configured failure matched.
