#!/bin/sh
set -eu
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/qualification/live/operator-lab"}
: "${EDRLAB_HOME:?set EDRLAB_HOME to the EDR Lab checkout}"
: "${EDRLAB_TARGET_SET:?set EDRLAB_TARGET_SET to the private Defender/Elastic target set}"
: "${BOFBENCH_OPERATOR_LAB_SSH_IDENTITY:?set BOFBENCH_OPERATOR_LAB_SSH_IDENTITY}"
: "${OPERATOR_LAB_URL:?set OPERATOR_LAB_URL}"
: "${OPERATOR_LAB_CA:?set OPERATOR_LAB_CA}"
: "${OPERATOR_LAB_CLIENT_CERT:?set OPERATOR_LAB_CLIENT_CERT}"
: "${OPERATOR_LAB_CLIENT_KEY:?set OPERATOR_LAB_CLIENT_KEY}"

mkdir -p "$OUT/bin" "$OUT/home" "$OUT/work" "$OUT/edr"
go build -trimpath -o "$OUT/bin/bofbench" "$ROOT/cmd/bofbench"
(cd "$EDRLAB_HOME" && go build -trimpath -o "$OUT/bin/edrlab" ./cmd/edrlab)
cp -R "$ROOT/bofs/portable-survey" "$OUT/work/portable-survey"
export HOME="$OUT/home"
export BOFBENCH_LOADER="$ROOT/native/loader/bofbench-loader.exe"

"$OUT/bin/bofbench" lab add shared-x64 --provider operator-lab --profile bofbench-dev-x64
"$OUT/bin/bofbench" build "$OUT/work/portable-survey"
"$OUT/bin/bofbench" run "$OUT/work/portable-survey" --via lab --lab shared-x64 --observe full
(cd "$OUT/work" && "$OUT/bin/bofbench" export portable-survey --for edrlab)

BUNDLE="$OUT/work/export/portable-survey-edrlab/windows-artifact-bundle.json"
"$OUT/bin/edrlab" artifact "$BUNDLE" --target-set "$EDRLAB_TARGET_SET" --products defender,elastic --litterbox --out "$OUT/edr"
python3 "$ROOT/qualification/verify_operator_lab_live.py" --bundle "$BUNDLE" --matrix "$OUT/edr/artifact-matrix.json" --visibility "$OUT/edr/visibility.json" --out "$OUT/receipt.json"

