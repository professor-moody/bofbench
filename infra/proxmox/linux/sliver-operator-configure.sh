#!/usr/bin/env bash
set -euo pipefail

# Create exactly one operator profile for the dedicated remote client account.
# The credential never leaves the runtime VM and is not included in receipts.
OPERATOR_NAME="${SLIVER_OPERATOR_NAME:-bofbench}"
OPERATOR_PERMISSIONS="${SLIVER_OPERATOR_PERMISSIONS:-all}"
CLIENT_HOME="/home/bofbench/.sliver-client"
TARGET_CONFIG="${CLIENT_HOME}/configs/bofbench.cfg"
ENV_FILE="/etc/bofbench/sliver.env"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi
if [[ ! "$OPERATOR_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "invalid Sliver operator name" >&2
  exit 1
fi
if [[ ! "$OPERATOR_PERMISSIONS" =~ ^(all|builder|crackstation)(,(all|builder|crackstation))*$ ]]; then
  echo "invalid Sliver operator permissions" >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"
: "${SLIVER_LHOST:?SLIVER_LHOST is required}"
: "${SLIVER_LPORT:?SLIVER_LPORT is required}"

install -d -o bofbench -g bofbench -m 0700 \
  "$CLIENT_HOME" "$CLIENT_HOME/configs" "$CLIENT_HOME/extensions"

mapfile -t existing_configs < <(find "$CLIENT_HOME/configs" -maxdepth 1 -type f -name '*.cfg' -print)
if [[ ${#existing_configs[@]} -gt 1 ]]; then
  echo "remote client home must contain exactly one operator profile" >&2
  exit 1
fi
if [[ -s "$TARGET_CONFIG" ]]; then
  chown bofbench:bofbench "$TARGET_CONFIG"
  chmod 0600 "$TARGET_CONFIG"
  echo "Sliver remote operator profile already ready at $TARGET_CONFIG"
  exit 0
fi

temporary_dir="$(mktemp -d /var/lib/sliver/bofbench-operator.XXXXXXXXXX)"
trap 'rm -rf -- "$temporary_dir"' EXIT
chown sliver:sliver "$temporary_dir"
chmod 0700 "$temporary_dir"

runuser -u sliver -- env HOME=/var/lib/sliver \
  /usr/local/bin/sliver-server operator \
  --name "$OPERATOR_NAME" \
  --permissions "$OPERATOR_PERMISSIONS" \
  --lhost "$SLIVER_LHOST" \
  --lport "$SLIVER_LPORT" \
  --save "$temporary_dir"

mapfile -t generated_configs < <(find "$temporary_dir" -maxdepth 1 -type f -name '*.cfg' -print)
if [[ ${#generated_configs[@]} -ne 1 || ! -s "${generated_configs[0]}" ]]; then
  echo "Sliver did not generate exactly one non-empty operator profile" >&2
  exit 1
fi
install -o bofbench -g bofbench -m 0600 "${generated_configs[0]}" "$TARGET_CONFIG"

cat > /var/lib/sliver/receipts/operator.json <<EOF
{"schema":"bofbench.runtime-control-operator","schema_version":1,"runtime":"sliver","operator":"${OPERATOR_NAME}","permissions":"${OPERATOR_PERMISSIONS}","client_user":"bofbench","config_path":"${TARGET_CONFIG}"}
EOF
chown sliver:sliver /var/lib/sliver/receipts/operator.json
chmod 0600 /var/lib/sliver/receipts/operator.json

echo "Sliver remote operator profile ready at $TARGET_CONFIG"
