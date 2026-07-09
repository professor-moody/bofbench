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

## Build Configuration

Direct source builds are deterministic by default. Pin the toolchain and add toolchain-specific flags in `bofbench.toml` when a fixture needs them:

```toml
name = "echoer"
entry = "go"
compiler = "mingw"
cflags = ["-Os", "-DVARIANT=1"]
deterministic = true
args = ["z:default", "i:1"]
expect = ["echoer: default count=1"]
timeout_ms = 5000
```

Root keys are `name`, `entry`, `build`, `compiler`, `cflags`, `deterministic`, `args`, `expect`, `forbid`, `timeout_ms`, `expect_exit`, `expect_status`, and `operator_notes`. Compiler values are `auto`, `mingw`, or `msvc`. Project names use portable letters, numbers, dot, underscore, and hyphen characters and cannot start with a dot. String values and array elements must be quoted. Inline comments are supported outside quoted values.

The parser rejects unknown keys/sections, duplicate keys and aliases, invalid compiler or Boolean values, non-positive timeouts, and malformed arrays. A bad configuration still creates build failure evidence with one diagnostic per offending line.

Use the release-quality build gate during development:

```sh
bofbench build bofs/echoer --compiler mingw --verify-reproducible
```

For a custom `build` command, Makefile, or CMake project, BOFBench records the dispatcher rather than claiming to know the nested compiler. Reproducibility verification repeats that command and compares the resulting object.

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
