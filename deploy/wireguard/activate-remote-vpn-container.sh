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

# Install the 15-second expiry/guardian-authorization reconciler before any
# Remote VPN grant can be used.
"$LEASE_INSTALLER"

image="${BULWARK_IMAGE:-}"
if [ -z "$image" ]; then
  image="$(docker inspect -f '{{.Config.Image}}' "$CONTAINER" 2>/dev/null || true)"
fi
[ -n "$image" ] || fail "set BULWARK_IMAGE or keep an existing $CONTAINER container to resolve the image"

# IMPORTANT: do NOT disable an existing REDIRECT while restarting the server.
# With the listener absent, REDIRECT fails closed (connections fail). Removing
# the rules would restore the old NAT-only unfiltered path during the restart.

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
mkdir -p "$STATE_DIR/tls"
chmod 700 "$STATE_DIR" "$STATE_DIR/tls"

smtp_args=()
if [ -f "$STATE_DIR/smtp.env" ]; then
  smtp_args=(--env-file "$STATE_DIR/smtp.env")
fi

# Host networking is intentional: Linux netfilter REDIRECT and SO_ORIGINAL_DST
# live in the host namespace. The container remains an unprivileged user and
# does not need Docker socket, NET_ADMIN or WireGuard private-key mounts.
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

# First activation inserts the rules; upgrades/restarts simply re-assert the
# already-fail-closed rules after listener readiness.
"$FILTER_TOOL" enable
systemctl start bulwark-wg-lease-reconcile.service

note "Remote VPN active: authenticated leases + wg0 + in-process filtering + live revocation"
