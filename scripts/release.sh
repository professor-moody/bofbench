#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-dev}"
OUT="$ROOT/dist/release"
TMP="$ROOT/work/release"
GIT_COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X github.com/professor-moody/bofbench/internal/evidence.Version=$VERSION -X github.com/professor-moody/bofbench/internal/evidence.Commit=$GIT_COMMIT -X github.com/professor-moody/bofbench/internal/evidence.BuildTime=$BUILD_TIME"
export COPYFILE_DISABLE=1

rm -rf "$OUT" "$TMP"
mkdir -p "$OUT" "$TMP"

cd "$ROOT"

echo "[release] verifying generated loader capabilities"
go run ./cmd/capgen -check -out native/loader/capabilities.generated.h

echo "[release] testing"
go test ./...

echo "[release] building docs"
mkdocs build --strict

if [[ ! -f native/loader/bofbench-loader.exe || ! -f native/loader/bofbench-loader-x86.exe ]]; then
  if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "[release] building native loader"
    make -C native/loader clean all
  else
    echo "[release] warning: one or both Windows loaders are missing and MinGW-w64 is not on PATH"
  fi
fi

echo "[release] verifying export package contract"
SMOKE_ROOT="$TMP/export-smoke"
SMOKE_BIN="$TMP/bofbench-release-smoke"
mkdir -p "$SMOKE_ROOT"
go build -trimpath -ldflags "$LDFLAGS" -o "$SMOKE_BIN" ./cmd/bofbench
printf 'bofbench release export smoke\n' > "$SMOKE_ROOT/smoke.x64.o"
(
  cd "$SMOKE_ROOT"
  "$SMOKE_BIN" export smoke.x64.o --for raw >/dev/null
  "$SMOKE_BIN" export verify export/smoke-raw >/dev/null
  "$SMOKE_BIN" export verify export/smoke-raw.zip --format json >/dev/null
)

build_cli() {
  local goos="$1"
  local goarch="$2"
  local ext="$3"
  local name="bofbench_${VERSION}_${goos}_${goarch}"
  local dir="$TMP/$name"
  mkdir -p "$dir"
  echo "[release] building $name"
  GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "$LDFLAGS" -o "$dir/bofbench$ext" ./cmd/bofbench
  cp README.md "$dir/"
  cp -R docs "$dir/docs"
  rm -rf "$dir/docs/assets/downloads"
  find "$dir/docs" -name .DS_Store -delete
  mkdir -p "$dir/scripts"
  cp scripts/release.sh scripts/windows-lab-smoke.ps1 "$dir/scripts/"
  cp -R testdata "$dir/testdata"
  if [[ "$goos" == "windows" && -f native/loader/bofbench-loader.exe ]]; then
    cp native/loader/bofbench-loader.exe "$dir/"
  fi
  if [[ "$goos" == "windows" && -f native/loader/bofbench-loader-x86.exe ]]; then
    cp native/loader/bofbench-loader-x86.exe "$dir/"
  fi
  tar -czf "$OUT/$name.tar.gz" -C "$dir" .
}

build_cli darwin amd64 ""
build_cli darwin arm64 ""
build_cli linux amd64 ""
build_cli windows amd64 ".exe"

echo "[release] packaging docs site"
find "$ROOT/site" -name .DS_Store -delete
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
