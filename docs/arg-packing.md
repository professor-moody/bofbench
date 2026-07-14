# Argument Packing

`bofbench` uses Cobalt Strike-style BOF packed arguments from CLI tokens.

Supported tokens:

| Token | Meaning |
| --- | --- |
| `z:value` | null-terminated ASCII string |
| `Z:value` | null-terminated UTF-16LE string |
| `i:123` | 32-bit little-endian integer |
| `s:7` | 16-bit little-endian short |
| `b:aGk=` | base64 buffer with length prefix |
| `x:4142` | hex buffer with length prefix |

Example:

```sh
bofbench run dist/arg_echo.x64.o --args z:test-message i:42
```

The native loader exposes `BeaconDataParse`, `BeaconDataExtract`, `BeaconDataInt`, `BeaconDataShort`, and `BeaconDataLength`.

Tiny repeatable test config:

```toml
name = "arg_echo"
entry = "go"
args = ["z:test-message", "i:42"]
expect = ["test-message"]
forbid = ["panic"]
timeout_ms = 5000
```

Use [Staging](staging.md) to carry the exact typed tokens and packed-byte fingerprint into an operator package, or [Runtime Model](runtime.md) to see how each runner receives arguments.
