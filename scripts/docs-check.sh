#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/work/bin/bofbench"
PRIVATE="${BOFBENCH_PRIVATE_CATALOG:-$(dirname "$ROOT")/bofbench-packs-internal}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/bofbench-docs-check.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

cd "$ROOT"
go build -o "$BIN" ./cmd/bofbench
go run ./cmd/capgen -check -out native/loader/capabilities.generated.h

"$BIN" pack docs --catalog-name builtin --output "$TMP/public-reference.md" >/dev/null
cmp "$TMP/public-reference.md" docs/pack-reference.md

mkdocs build --strict --site-dir "$TMP/public-site"
for stem in build-analyze third-party-analysis arsenal-search lab-run runtime-tasks export-verify; do
  test -s "$TMP/public-site/assets/media/$stem.webm"
  test -s "$TMP/public-site/assets/images/$stem.png"
done
CHECK_ARGS=(--root "$ROOT" --bin "$BIN")
if [[ -d "$PRIVATE/.git" ]]; then
  CHECK_ARGS+=(--private "$PRIVATE")
fi
python3 scripts/docs_check.py "${CHECK_ARGS[@]}"
scripts/docs-smoke.sh host

if [[ -d "$PRIVATE/.git" ]]; then
  "$BIN" pack docs --catalog "$PRIVATE" --catalog-name bofbench-packs-internal --output "$TMP/private-reference.md" >/dev/null
  cmp "$TMP/private-reference.md" "$PRIVATE/PACK_REFERENCE.md"
  cmp "$TMP/private-reference.md" "$PRIVATE/docs/pack-reference.md"
  mkdocs build --strict -f "$PRIVATE/mkdocs.yml" --site-dir "$TMP/private-site"
fi

echo "documentation checks passed"
