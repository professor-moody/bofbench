# Release

Use the Makefile for repeatable local release prep:

```sh
make test
make build
make build-windows
make native-loader
make docs
make release
```

It performs:

- `go test ./...`
- `mkdocs build --strict`
- native loader build when MinGW-w64 is available and the loader binary is missing
- exported-directory and exported-ZIP contract verification
- CLI builds for `darwin/amd64`, `darwin/arm64`, `linux/amd64`, and `windows/amd64`
- embedded release label, Git commit, and UTC build time in each CLI binary
- packaging under `dist/release/`
- `SHA256SUMS`

Release acceptance also verifies the current catalog and operation totals—90 embedded public packs, 154 private packs when the private catalog is available, eight public operations, and 42 private operations—plus operation schema v8, runtime receipt v6, pack schema v5, target schema v10, and arsenal-index v2 documentation/reference drift.

Set `VERSION` to label packages:

```sh
VERSION=0.1.0 make release
```

The Windows package includes `bofbench-loader.exe` and `bofbench-loader-x86.exe` when the native helpers exist.

Before cutting a release, export at least one known-good BOF and inspect the package:

```sh
bofbench run dist/hello.x64.o --args z:hello i:3
bofbench export dist/hello.x64.o --for raw --args z:hello i:3
bofbench export verify export/hello-raw
bofbench export verify export/hello-raw.zip --format json
```

Use [Reports](evidence.md) to inspect embedded build identity and [Export](staging.md) for package verification semantics.
