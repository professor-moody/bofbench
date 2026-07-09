#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-dev}"
OUT="$ROOT/dist/release"
TMP="$ROOT/work/release"
export COPYFILE_DISABLE=1

rm -rf "$OUT" "$TMP"
mkdir -p "$OUT" "$TMP"

cd "$ROOT"

echo "[release] testing"
go test ./...

echo "[release] building docs"
mkdocs build --strict

if [[ ! -f native/loader/bofbench-loader.exe ]]; then
  if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[release] building native loader"
    make -C native/loader clean all
  else
    echo "[release] warning: native/loader/bofbench-loader.exe missing and MinGW-w64 not on PATH"
  fi
fi

build_cli() {
  local goos="$1"
  local goarch="$2"
  local ext="$3"
  local name="bofbench_${VERSION}_${goos}_${goarch}"
  local dir="$TMP/$name"
  mkdir -p "$dir"
  echo "[release] building $name"
  GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "-s -w" -o "$dir/bofbench$ext" ./cmd/bofbench
  cp README.md "$dir/"
  cp -R docs "$dir/docs"
  cp -R scripts "$dir/scripts"
  cp -R testdata "$dir/testdata"
  if [[ "$goos" == "windows" && -f native/loader/bofbench-loader.exe ]]; then
    cp native/loader/bofbench-loader.exe "$dir/"
  fi
  tar -czf "$OUT/$name.tar.gz" -C "$dir" .
}

build_cli darwin amd64 ""
build_cli darwin arm64 ""
build_cli linux amd64 ""
build_cli windows amd64 ".exe"

echo "[release] packaging docs site"
tar -czf "$OUT/bofbench_${VERSION}_docs-site.tar.gz" -C "$ROOT/site" .

echo "[release] checksums"
(
  cd "$OUT"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum *.tar.gz > SHA256SUMS
  else
    shasum -a 256 *.tar.gz > SHA256SUMS
  fi
)

echo "[release] wrote $OUT"
