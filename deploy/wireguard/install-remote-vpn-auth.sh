#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="${BULWARK_STATE_DIR:-/var/lib/bulwark}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SBIN_DIR="${SBIN_DIR:-/usr/local/sbin}"

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

install -d -m 0755 "$SBIN_DIR"
install -d -m 0700 "$STATE_DIR"
install -m 0700 "$ROOT/wg-peers.sh" "$SBIN_DIR/bulwark-wg-peers"
install -m 0700 "$ROOT/wg-filter.sh" "$SBIN_DIR/bulwark-wg-filter"
install -m 0700 "$ROOT/wg-lease-reconcile.sh" "$SBIN_DIR/bulwark-wg-lease-reconcile"
install -m 0700 "$ROOT/activate-remote-vpn-container.sh" "$SBIN_DIR/bulwark-activate-remote-vpn"
install -m 0644 "$ROOT/bulwark-wg-lease-reconcile.service" \
  "$SYSTEMD_DIR/bulwark-wg-lease-reconcile.service"
install -m 0644 "$ROOT/bulwark-wg-lease-reconcile.timer" \
  "$SYSTEMD_DIR/bulwark-wg-lease-reconcile.timer"

systemctl daemon-reload
systemctl enable --now bulwark-wg-lease-reconcile.timer
# A fresh region may not have wg_peers.json yet. The timer remains enabled and
# will converge as soon as the server writes its first authenticated lease.
systemctl start bulwark-wg-lease-reconcile.service || true
systemctl --no-pager --full status bulwark-wg-lease-reconcile.timer || true
