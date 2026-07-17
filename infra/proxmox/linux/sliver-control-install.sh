#!/usr/bin/env bash
set -euo pipefail

# BOFBench pins the control-plane binary used by live runtime receipts. This
# script installs the server only; it does not create listeners, operators, or
# implants. Those remain explicit runtime-control/session actions.
SLIVER_VERSION="${SLIVER_VERSION:-1.7.3}"
SLIVER_SERVER_SHA256="${SLIVER_SERVER_SHA256:-e3216ecd12f6e7e97cb4588bb6d85c70eca3bdfad8b0818ffd53ccb2e357ccc8}"
SLIVER_URL="https://github.com/BishopFox/sliver/releases/download/v${SLIVER_VERSION}/sliver-server_linux-amd64"
INSTALL_PATH="/usr/local/bin/sliver-server"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

if ! id sliver >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/sliver --shell /usr/sbin/nologin sliver
fi
install -d -o sliver -g sliver -m 0700 /var/lib/sliver /var/lib/sliver/receipts

temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 "$SLIVER_URL" -o "$temporary"
echo "$SLIVER_SERVER_SHA256  $temporary" | sha256sum --check --status
install -o root -g root -m 0755 "$temporary" "$INSTALL_PATH"

install -o root -g root -m 0644 /opt/bofbench/sliver-server.service /etc/systemd/system/sliver-server.service
systemctl daemon-reload
systemctl enable sliver-server.service

installed_hash="$(sha256sum "$INSTALL_PATH" | awk '{print $1}')"
installed_version="$($INSTALL_PATH version 2>/dev/null | head -1 || true)"
cat > /var/lib/sliver/receipts/install.json <<EOF
{"schema":"bofbench.runtime-control-install","schema_version":1,"runtime":"sliver","version":"${SLIVER_VERSION}","reported_version":"${installed_version}","sha256":"${installed_hash}","service":"sliver-server.service"}
EOF
chown sliver:sliver /var/lib/sliver/receipts/install.json
chmod 0600 /var/lib/sliver/receipts/install.json

echo "Sliver ${SLIVER_VERSION} installed; configure the isolated bind address in /etc/bofbench/sliver.env before starting the service."
