#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/work/bin/bofbench"
LAB="${BOFBENCH_DOCS_LAB:-devbox}"

for tool in vhs ffmpeg; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

cd "$ROOT"
go build -o "$BIN" ./cmd/bofbench
export PATH="$ROOT/work/bin:$PATH"
export BOFBENCH_DOCS_LAB="$LAB"

cleanup() {
  rm -rf \
    bofs/docs-capture bofs/docs-lab bofs/docs-export \
    export/docs-capture-* export/docs-lab-* export/docs-export-* \
    dist/docs-capture.* dist/docs-lab.* dist/docs-export.* || true
}
trap cleanup EXIT
cleanup

for tape in docs/media-src/*.tape; do
  BOFBENCH_DOCS_LAB="$LAB" vhs "$tape"
done

for video in docs/assets/media/*.webm; do
  name="$(basename "$video" .webm)"
  case "$name" in
    arsenal-search) poster_second=12 ;;
    build-analyze) poster_second=10 ;;
    export-verify) poster_second=12 ;;
    lab-run) poster_second=12 ;;
    runtime-tasks) poster_second=27 ;;
    third-party-analysis) poster_second=6 ;;
    *) poster_second=6 ;;
  esac
  ffmpeg -y -ss "00:00:$poster_second" -i "$video" -frames:v 1 "docs/assets/images/$name.png" >/dev/null 2>&1
done

echo "documentation media rendered"
