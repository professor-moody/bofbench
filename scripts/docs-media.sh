#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/work/bin/bofbench"
LAB="${BOFBENCH_DOCS_LAB:-devbox}"
export BOFBENCH_PRIVATE_CATALOG="${BOFBENCH_PRIVATE_CATALOG:-$(dirname "$ROOT")/bofbench-packs-internal}"

for tool in vhs ffmpeg; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

cd "$ROOT"
go build -o "$BIN" ./cmd/bofbench
export PATH="$ROOT/work/bin:$PATH"
export BOFBENCH_DOCS_LAB="$LAB"
MEDIA_TARGET_DEPLOYED=0
MEDIA_RUN_STASH="$(mktemp -d "${TMPDIR:-/tmp}/bofbench-media-runs.XXXXXX")"
MEDIA_RUNS_STASHED=0

cleanup() {
	if [[ "$MEDIA_TARGET_DEPLOYED" == "1" ]]; then
		"$BIN" lab target remove --lab "$LAB" >/dev/null 2>&1 || true
	fi
	rm -f /tmp/bofbench-ret.bin
  rm -rf \
    bofs/docs-capture bofs/docs-lab bofs/docs-export \
    export/docs-capture-* export/docs-lab-* export/docs-export-* \
    dist/docs-capture.* dist/docs-lab.* dist/docs-export.* || true
	if [[ "$MEDIA_RUNS_STASHED" == "1" ]]; then
		rm -rf runs/*operation-adaptive-memory-execute* || true
		for saved in "$MEDIA_RUN_STASH"/*; do
			[[ -e "$saved" ]] || continue
			mv "$saved" runs/
		done
	fi
	rm -rf "$MEDIA_RUN_STASH"
}
trap cleanup EXIT
rm -f /tmp/bofbench-ret.bin
rm -rf \
  bofs/docs-capture bofs/docs-lab bofs/docs-export \
  export/docs-capture-* export/docs-lab-* export/docs-export-* \
  dist/docs-capture.* dist/docs-lab.* dist/docs-export.* || true
for existing in runs/*operation-adaptive-memory-execute*; do
	[[ -e "$existing" ]] || continue
	mv "$existing" "$MEDIA_RUN_STASH"/
done
MEDIA_RUNS_STASHED=1
printf '\303' > /tmp/bofbench-ret.bin

if [[ -f docs/media-src/operation-lifecycle.tape ]]; then
	if ! target_json="$("$BIN" lab target status --lab "$LAB" --format json 2>/dev/null)"; then
		target_json="$("$BIN" lab target deploy --lab "$LAB" --format json)"
		MEDIA_TARGET_DEPLOYED=1
	fi
	export BOFBENCH_TARGET_PID
	BOFBENCH_TARGET_PID="$(printf '%s' "$target_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"]["pid"])')"
	[[ "$BOFBENCH_TARGET_PID" =~ ^[0-9]+$ ]] || { echo "operation recording target returned no PID" >&2; exit 1; }
fi

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
    operation-lifecycle) poster_second=32 ;;
    runtime-tasks) poster_second=27 ;;
    third-party-analysis) poster_second=6 ;;
    *) poster_second=6 ;;
  esac
  ffmpeg -y -ss "00:00:$poster_second" -i "$video" -frames:v 1 "docs/assets/images/$name.png" >/dev/null 2>&1
done

echo "documentation media rendered"
