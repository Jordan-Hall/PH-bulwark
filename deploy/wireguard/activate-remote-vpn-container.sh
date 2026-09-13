#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${BULWARK_CONTAINER:-bulwark-server}"
PORT="${BULWARK_PORT:-8443}"
WG_PORT="${BULWARK_WG_PORT:-51820}"
WG_HOST="${BULWARK_WG_HOST:-vpn.predatorhunters.co.uk}"
STATE_DIR="${BULWARK_STATE_DIR:-/var/lib/bulwark}"
PEER_TOOL="${BULWARK_WG_PEER_TOOL:-/usr/local/sbin/bulwark-wg-peers}"
FILTER_TOOL="${BULWARK_WG_FILTER_TOOL:-/usr/local/sbin/bulwark-wg-filter}"
LEASE_INSTALLER="${BULWARK_WG_LEASE_INSTALLER:-/usr/local/sbin/bulwark-install-remote-vpn-auth}"

fail() { echo "[remote-vpn] ERROR: $*" >&2; exit 1; }
note() { echo "[remote-vpn] $*"; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
command -v docker >/dev/null 2>&1 || fail "docker is required"
[ -x "$PEER_TOOL" ] || fail "missing WireGuard peer tool: $PEER_TOOL"
[ -x "$FILTER_TOOL" ] || fail "missing WireGuard filter tool: $FILTER_TOOL"
[ -x "$LEASE_INSTALLER" ] || fail "missing Remote VPN lease installer: $LEASE_INSTALLER"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || fail "invalid BULWARK_PORT"
[[ "$WG_PORT" =~ ^[0-9]{1,5}$ ]] || fail "invalid BULWARK_WG_PORT"

"$PEER_TOOL" init
[ -s /etc/wireguard/server.pub ] || fail "WireGuard server public key is missing"
server_public_key="$(tr -d '[:space:]' </etc/wireguard/server.pub)"
[ -n "$server_public_key" ] || fail "WireGuard server public key is empty"

"$LEASE_INSTALLER"

image="${BULWARK_IMAGE:-}"
if [ -z "$image" ]; then
  image="$(docker inspect -f '{{.Config.Image}}' "$CONTAINER" 2>/dev/null || true)"
fi
[ -n "$image" ] || fail "set BULWARK_IMAGE or keep an existing $CONTAINER container to resolve the image"

# Existing REDIRECT rules remain across restarts. With no listener they fail
# closed; removing them here would create a temporary NAT-only bypass.
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
mkdir -p "$STATE_DIR/tls"
chmod 700 "$STATE_DIR" "$STATE_DIR/tls"
# The image runs as uid 10001. Keep application state writable while preserving
# the cluster CA private key (if present) as root-only.
chown -R 10001:10001 "$STATE_DIR"
if [ -f "$STATE_DIR/tls/ca.key" ]; then
  chown root:root "$STATE_DIR/tls/ca.key"
  chmod 600 "$STATE_DIR/tls/ca.key"
fi

smtp_args=()
if [ -f "$STATE_DIR/smtp.env" ]; then
  smtp_args=(--env-file "$STATE_DIR/smtp.env")
fi

docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  --network host \
  -v "$STATE_DIR:/var/lib/bulwark" \
  "${smtp_args[@]}" \
  -e "BULWARK_BIND=0.0.0.0:${PORT}" \
  -e BULWARK_ACCOUNTS=1 \
  -e BULWARK_PRODUCTION=1 \
  -e BULWARK_STATE_DIR=/var/lib/bulwark \
  -e BULWARK_TLS_CERT=/var/lib/bulwark/tls/server.crt \
  -e BULWARK_TLS_KEY=/var/lib/bulwark/tls/server.key \
  -e BULWARK_WG_FILTER_ACTIVE=1 \
  -e "BULWARK_WG_SERVER_PUBLIC_KEY=${server_public_key}" \
  -e "BULWARK_WG_ENDPOINT=${WG_HOST}:${WG_PORT}" \
  -e BULWARK_WG_INSPECTION_CA_PEM=/var/lib/bulwark/wg_inspection_ca.pem \
  "$image" --role all-in-one >/dev/null

for _ in $(seq 1 40); do
  if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
    docker logs --tail 100 "$CONTAINER" >&2 || true
    fail "Remote VPN server container exited during startup"
  fi
  if docker logs "$CONTAINER" 2>&1 | grep -q 'Remote VPN region filter runtime active'; then
    break
  fi
  sleep 1
done

docker logs "$CONTAINER" 2>&1 | grep -q 'Remote VPN region filter runtime active' || {
  docker logs --tail 100 "$CONTAINER" >&2 || true
  fail "Remote VPN region filter never became ready"
}

"$FILTER_TOOL" enable
# On a fresh region there is no wg_peers.json until the first authenticated
# Remote VPN lease. That is a valid empty state; the enabled timer will converge
# immediately after provisioning creates the file.
systemctl start bulwark-wg-lease-reconcile.service || true

note "Remote VPN active: authenticated leases + wg0 + in-process filtering + live revocation"
