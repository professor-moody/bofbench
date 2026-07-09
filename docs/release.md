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

`make release` runs `scripts/release.sh`.

It performs:

- `go test ./...`
- `mkdocs build --strict`
- native loader build when MinGW-w64 is available and the loader binary is missing
- staged-directory and staged-ZIP contract verification
- CLI builds for `darwin/amd64`, `darwin/arm64`, `linux/amd64`, and `windows/amd64`
- embedded release label, Git commit, and UTC build time in each CLI binary
- packaging under `dist/release/`
- `SHA256SUMS`

Set `VERSION` to label packages:

```sh
VERSION=0.1.0 make release
```

The Windows package includes `bofbench-loader.exe` when `native/loader/bofbench-loader.exe` exists.

Before cutting a release, stage at least one known-good BOF and inspect the package:

```sh
bofbench run dist/hello.x64.o --args z:hello i:3
bofbench stage dist/hello.x64.o --target raw --args z:hello i:3
bofbench stage verify stage/hello-raw
bofbench stage verify stage/hello-raw.zip --format json
```
