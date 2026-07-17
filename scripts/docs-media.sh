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
MEDIA_ONLY="${BOFBENCH_MEDIA_ONLY:-}"
if [[ -n "$MEDIA_ONLY" && ! "$MEDIA_ONLY" =~ ^[a-z0-9-]+$ ]]; then
	echo "BOFBENCH_MEDIA_ONLY must be a media stem such as operation-lifecycle" >&2
	exit 1
fi
MEDIA_TARGET_DEPLOYED=0
MEDIA_RUN_STASH="$(mktemp -d "${TMPDIR:-/tmp}/bofbench-media-runs.XXXXXX")"
MEDIA_RUNS_STASHED=0

cleanup() {
	if [[ "$MEDIA_TARGET_DEPLOYED" == "1" ]]; then
		"$BIN" lab target remove --lab "$LAB" >/dev/null 2>&1 || true
	fi
	rm -f /tmp/bofbench-ret.bin /tmp/bofbench-docs-request.bin
  rm -rf \
    bofs/docs-capture bofs/docs-lab bofs/docs-export \
    export/docs-capture-* export/docs-lab-* export/docs-export-* \
    dist/docs-capture.* dist/docs-lab.* dist/docs-export.* || true
	if [[ "$MEDIA_RUNS_STASHED" == "1" ]]; then
		rm -rf runs/*operation-network-transport-matrix* runs/*operation-http-transaction-roundtrip* runs/*operation-tcp-echo-roundtrip* || true
		for saved in "$MEDIA_RUN_STASH"/*; do
			[[ -e "$saved" ]] || continue
			mv "$saved" runs/
		done
	fi
	rm -rf "$MEDIA_RUN_STASH"
}
trap cleanup EXIT
rm -f /tmp/bofbench-ret.bin /tmp/bofbench-docs-request.bin
rm -rf \
  bofs/docs-capture bofs/docs-lab bofs/docs-export \
  export/docs-capture-* export/docs-lab-* export/docs-export-* \
  dist/docs-capture.* dist/docs-lab.* dist/docs-export.* || true
for existing in runs/*operation-secure-transport-matrix* runs/*operation-http-listener-roundtrip* runs/*operation-authenticated-http-roundtrip* runs/*operation-bits-control-lifecycle*; do
	[[ -e "$existing" ]] || continue
	mv "$existing" "$MEDIA_RUN_STASH"/
done
MEDIA_RUNS_STASHED=1
printf '\303' > /tmp/bofbench-ret.bin
printf 'BOFBenchDocsRequest\r\n' > /tmp/bofbench-docs-request.bin

if [[ -f docs/media-src/operation-lifecycle.tape && ( -z "$MEDIA_ONLY" || "$MEDIA_ONLY" == "operation-lifecycle" ) ]]; then
	if ! target_json="$("$BIN" lab target status --lab "$LAB" --format json 2>/dev/null)"; then
		target_json="$("$BIN" lab target deploy --lab "$LAB" --format json)"
		MEDIA_TARGET_DEPLOYED=1
	fi
	export BOFBENCH_TARGET_PID BOFBENCH_HOLDER_PID BOFBENCH_DOCS_REQUEST BOFBENCH_DOCS_REQUEST_SIZE BOFBENCH_DOCS_REQUEST_SHA256
	BOFBENCH_TARGET_PID="$(printf '%s' "$target_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"]["pid"])')"
	BOFBENCH_HOLDER_PID="$(printf '%s' "$target_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"]["holder_pid"])')"
	BOFBENCH_DOCS_REQUEST=/tmp/bofbench-docs-request.bin
	BOFBENCH_DOCS_REQUEST_SIZE="$(wc -c < "$BOFBENCH_DOCS_REQUEST" | tr -d ' ')"
	BOFBENCH_DOCS_REQUEST_SHA256="$(shasum -a 256 "$BOFBENCH_DOCS_REQUEST" | awk '{print $1}')"
	[[ "$BOFBENCH_TARGET_PID" =~ ^[0-9]+$ ]] || { echo "operation recording target returned no PID" >&2; exit 1; }
	[[ "$BOFBENCH_HOLDER_PID" =~ ^[0-9]+$ ]] || { echo "operation recording target returned no holder PID" >&2; exit 1; }
fi

if [[ -n "$MEDIA_ONLY" ]]; then
	TAPES=("docs/media-src/$MEDIA_ONLY.tape")
	[[ -f "${TAPES[0]}" ]] || { echo "unknown media tape: $MEDIA_ONLY" >&2; exit 1; }
else
	TAPES=(docs/media-src/*.tape)
fi
for tape in "${TAPES[@]}"; do
  BOFBENCH_DOCS_LAB="$LAB" vhs "$tape"
done

for video in docs/assets/media/*.webm; do
  name="$(basename "$video" .webm)"
  [[ -z "$MEDIA_ONLY" || "$name" == "$MEDIA_ONLY" ]] || continue
  case "$name" in
    arsenal-search) poster_second=12 ;;
    build-analyze) poster_second=10 ;;
    export-verify) poster_second=12 ;;
    lab-run) poster_second=12 ;;
    operation-lifecycle) poster_second=41 ;;
    runtime-tasks) poster_second=27 ;;
    third-party-analysis) poster_second=6 ;;
    *) poster_second=6 ;;
  esac
  ffmpeg -y -ss "00:00:$poster_second" -i "$video" -frames:v 1 "docs/assets/images/$name.png" >/dev/null 2>&1
done

echo "documentation media rendered"
