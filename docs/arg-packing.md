# Argument Packing

`bofbench` uses the standard Beacon BOF argument buffer for native, lab, Sliver, and Cobalt Strike execution. The buffer begins with a four-byte little-endian payload length followed by the typed values below.

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

The native x64/x86 loaders expose `BeaconDataParse`, `BeaconDataExtract`, `BeaconDataInt`, `BeaconDataShort`, and `BeaconDataLength` with the standard `datap` layout (`original`, `buffer`, `length`, and `size`). The same packed payload can therefore be passed to BOFBench's loaders and C2 adapters without a project-specific parser.

Pack projects normally use named values instead of raw tokens:

```bash
bofbench run bofs/portable-survey --via lab --lab dedicated \
  --arg process_filter=lsass \
  --arg result_limit=5
```

`string`, `wstring`, `int`, `short`, `bytes`, and `file` pack arguments map to the corresponding packed types. Bytes accept base64 or `@path`; file arguments read the selected file at execution time.

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
