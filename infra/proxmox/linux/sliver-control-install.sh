#!/usr/bin/env bash
set -euo pipefail

# BOFBench pins the control-plane binary used by live runtime receipts. This
# script installs the server and Linux client only; it does not create
# listeners, operators, or implants. Those remain explicit runtime-control and
# session actions on a disposable runtime VM.
SLIVER_VERSION="${SLIVER_VERSION:-1.7.3}"
SLIVER_SERVER_SHA256="${SLIVER_SERVER_SHA256:-e3216ecd12f6e7e97cb4588bb6d85c70eca3bdfad8b0818ffd53ccb2e357ccc8}"
SLIVER_CLIENT_SHA256="${SLIVER_CLIENT_SHA256:-b0e328a131e4d679e9b268552db99ca2d46051b9205a67f9b7f7c1628983daae}"
SLIVER_SERVER_URL="https://github.com/BishopFox/sliver/releases/download/v${SLIVER_VERSION}/sliver-server_linux-amd64"
SLIVER_CLIENT_URL="https://github.com/BishopFox/sliver/releases/download/v${SLIVER_VERSION}/sliver-client_linux-amd64"
SERVER_PATH="/usr/local/bin/sliver-server"
CLIENT_PATH="/usr/local/bin/sliver-client"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

if ! id sliver >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/sliver --shell /usr/sbin/nologin sliver
fi
install -d -o sliver -g sliver -m 0700 /var/lib/sliver /var/lib/sliver/receipts
if ! id bofbench >/dev/null 2>&1; then
  echo "the cloud-image operator account 'bofbench' is required" >&2
  exit 1
fi
install -d -o bofbench -g bofbench -m 0700 \
  /home/bofbench/.sliver-client \
  /home/bofbench/.sliver-client/configs \
  /home/bofbench/.sliver-client/extensions

server_temporary="$(mktemp)"
client_temporary="$(mktemp)"
trap 'rm -f "$server_temporary" "$client_temporary"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 "$SLIVER_SERVER_URL" -o "$server_temporary"
echo "$SLIVER_SERVER_SHA256  $server_temporary" | sha256sum --check --status
install -o root -g root -m 0755 "$server_temporary" "$SERVER_PATH"
curl --fail --location --proto '=https' --tlsv1.2 "$SLIVER_CLIENT_URL" -o "$client_temporary"
echo "$SLIVER_CLIENT_SHA256  $client_temporary" | sha256sum --check --status
install -o root -g root -m 0755 "$client_temporary" "$CLIENT_PATH"

install -o root -g root -m 0644 /opt/bofbench/sliver-server.service /etc/systemd/system/sliver-server.service
install -o root -g root -m 0755 /opt/bofbench/sliver-operator-configure.sh /usr/local/sbin/bofbench-sliver-operator-configure
systemctl daemon-reload
systemctl enable sliver-server.service

installed_hash="$(sha256sum "$SERVER_PATH" | awk '{print $1}')"
installed_client_hash="$(sha256sum "$CLIENT_PATH" | awk '{print $1}')"
installed_version="$($SERVER_PATH version 2>/dev/null | head -1 || true)"
cat > /var/lib/sliver/receipts/install.json <<EOF
{"schema":"bofbench.runtime-control-install","schema_version":2,"runtime":"sliver","version":"${SLIVER_VERSION}","reported_version":"${installed_version}","server_sha256":"${installed_hash}","client_sha256":"${installed_client_hash}","service":"sliver-server.service","client_path":"${CLIENT_PATH}","client_home":"/home/bofbench/.sliver-client"}
EOF
chown sliver:sliver /var/lib/sliver/receipts/install.json
chmod 0600 /var/lib/sliver/receipts/install.json

echo "Sliver ${SLIVER_VERSION} server and remote client installed; configure the isolated bind address, start the service, then run bofbench-sliver-operator-configure."
