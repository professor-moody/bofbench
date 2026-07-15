#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/work/bin/bofbench"
LANE="${1:-host}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/bofbench-docs-smoke.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

if [[ ! -x "$BIN" ]]; then
  (cd "$ROOT" && go build -o "$BIN" ./cmd/bofbench)
fi

case "$LANE" in
  host)
    cd "$TMP"
    "$BIN" new docs-survey --pack host-discovery
    "$BIN" add bofs/docs-survey process-tree
    "$BIN" build bofs/docs-survey --arch x64
    "$BIN" build bofs/docs-survey --arch x86
    "$BIN" analyze bofs/docs-survey
    "$BIN" new docs-neighbors --pack network-neighbor-inventory
    "$BIN" build bofs/docs-neighbors --arch x64
    "$BIN" analyze dist/docs-survey.x64.o --compare dist/docs-neighbors.x64.o --format md
    "$BIN" arsenal inventory dist
    "$BIN" arsenal search dist --can process
    "$BIN" export bofs/docs-survey --for raw
    "$BIN" export bofs/docs-survey --for sliver
    "$BIN" export bofs/docs-survey --for cobaltstrike
    "$BIN" export verify export/docs-survey-raw
    "$BIN" export verify export/docs-survey-sliver.zip
    "$BIN" export verify export/docs-survey-cobaltstrike.zip
    ;;
  lab)
    : "${BOFBENCH_DOCS_LAB:?set BOFBENCH_DOCS_LAB to a named Windows profile}"
    "$BIN" lab status --lab "$BOFBENCH_DOCS_LAB"
    "$BIN" lab target deploy --lab "$BOFBENCH_DOCS_LAB"
    trap '"$BIN" lab target remove --lab "$BOFBENCH_DOCS_LAB" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT
    "$BIN" pack prove process-access-check --via lab --lab "$BOFBENCH_DOCS_LAB"
    "$BIN" pack prove module-export-inventory --via lab --lab "$BOFBENCH_DOCS_LAB"
    "$BIN" lab target remove --lab "$BOFBENCH_DOCS_LAB"
    "$BIN" lab verify clean --lab "$BOFBENCH_DOCS_LAB"
    ;;
  sliver)
    : "${BOFBENCH_DOCS_LAB:?set BOFBENCH_DOCS_LAB to a named Windows profile}"
    "$BIN" runtime status --lab "$BOFBENCH_DOCS_LAB"
    "$BIN" runtime sessions --via sliver --lab "$BOFBENCH_DOCS_LAB"
    "$BIN" runtime wait --via sliver --lab "$BOFBENCH_DOCS_LAB" --timeout 30s
    ;;
  *)
    echo "usage: $0 host|lab|sliver" >&2
    exit 2
    ;;
esac

echo "documentation $LANE smoke passed"
