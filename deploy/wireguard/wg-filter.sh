#!/usr/bin/env bash
# PH Bulwark — server-side TLS-inspecting FILTER in the wg0 FORWARD path (Phase 3
# of docs/design/server-vpn-mode-and-ca-trust.md §1/§4 increment 3).
#
# wg-peers.sh (Phase 2) gives a connected child IP-anonymised but UNFILTERED NAT
# exit. This script bends that child's TCP/80 + TCP/443 into the LOCAL bulwark-net
# TLS-inspecting proxy (transparent listener; see crates/bulwark-net/src/vpn/
# transparent.rs) via `iptables REDIRECT`, and drops QUIC/UDP-443 so HTTP/3 can't
# sail past the TCP inspection (mirrors the on-device QUIC downgrade in
# bulwark-net::quic). DNS stays MASQUERADE'd out (filtering is at the TLS layer).
#
# FAIL-CLOSED (availability): REDIRECT to a port with no listener makes every
# child 80/443 connection RST — total breakage. So `enable` REFUSES unless the
# filter proxy is already listening on the redirect port. And REDIRECT failing
# closed (no internet) is the SAFE direction vs. an unfiltered leak: a real child
# on FILTER_ON_SERVER must NEVER get an unfiltered exit.
#
# OPT-IN + SEPARATE from Phase 2: nothing here runs unless you run it; it does not
# touch wg0.conf, peers, or the MASQUERADE rule wg-peers/setup-london installed.
#
# Usage (root, on the region box):
#   bulwark-wg-filter enable        # insert REDIRECT + QUIC drop (preflights the proxy)
#   bulwark-wg-filter disable       # remove every rule this tool added
#   bulwark-wg-filter status        # show rule + proxy-listener state
#   bulwark-wg-filter version
#
# Env: BULWARK_TPROXY_PORT (default 8081) = where the bulwark-net transparent
#      listener is bound (it MUST bind 0.0.0.0/wg0 addr, NOT loopback — REDIRECT
#      rewrites the dst to the wg0 local address).
set -euo pipefail

WG_IF="${WG_IF:-wg0}"
TP="${BULWARK_TPROXY_PORT:-8081}"
CHAIN="BULWARK_WG_FILTER"          # nat chain holding the REDIRECT rules
LOCK="${LOCK:-/run/bulwark-wg-filter.lock}"
VERSION="1.0.0"

die()  { echo "[wg-filter] ERROR: $*" >&2; exit 1; }
note() { echo "[wg-filter] $*"; }

[ "$(id -u)" -eq 0 ] || die "must run as root"
command -v iptables >/dev/null 2>&1 || die "iptables not installed"

# One mutator at a time (an SSM run and a manual ssh session can race).
exec 200>"$LOCK"
command -v flock >/dev/null 2>&1 && { flock -w 30 200 || die "another bulwark-wg-filter is running"; }

proxy_listening() {
  # True iff something is LISTENing on :$TP. ss is in iproute2 (present on the box).
  ss -lntH "sport = :$TP" 2>/dev/null | grep -q ":$TP\b"
}

cmd_enable() {
  [ "$TP" -ge 1 ] && [ "$TP" -le 65535 ] || die "bad BULWARK_TPROXY_PORT: $TP"
  # FAIL-CLOSED preflight: never redirect into a black hole.
  proxy_listening || die "no listener on :$TP — start the bulwark-net filter proxy \
(transparent.rs) BEFORE enabling the redirect, or children lose all 80/443"

  # net.ipv4.ip_forward is already 1 (wg-peers init sets it); assert, don't fight it.
  [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ] \
    || die "net.ipv4.ip_forward != 1 (run 'bulwark-wg-peers init' first)"

  # --- nat: REDIRECT chain (idempotent: recreate + reflush, re-ensure the jump) ---
  iptables -t nat -N "$CHAIN" 2>/dev/null || true
  iptables -t nat -F "$CHAIN"
  iptables -t nat -A "$CHAIN" -p tcp --dport 80  -j REDIRECT --to-ports "$TP"
  iptables -t nat -A "$CHAIN" -p tcp --dport 443 -j REDIRECT --to-ports "$TP"
  iptables -t nat -C PREROUTING -i "$WG_IF" -p tcp -j "$CHAIN" 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$WG_IF" -p tcp -j "$CHAIN"

  # --- filter: accept the locally-delivered REDIRECT'd flow (in case INPUT policy
  #     is not ACCEPT) and the proxy's re-originated egress is normal OUTPUT ---
  iptables -C INPUT -i "$WG_IF" -p tcp --dport "$TP" -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -i "$WG_IF" -p tcp --dport "$TP" -j ACCEPT

  # --- QUIC/UDP-443 drop on the FORWARD path (mirror on-device downgrade) ---
  iptables -C FORWARD -i "$WG_IF" -p udp --dport 443 -j DROP 2>/dev/null \
    || iptables -I FORWARD 1 -i "$WG_IF" -p udp --dport 443 -j DROP

  # --- belt-and-braces: the WG subnet is IPv4-only (clients tunnel ::/0 but the
  #     region routes no v6), so drop ANY forwarded IPv6 to stop a v6 leak past
  #     the v4 redirect ---
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C FORWARD -i "$WG_IF" -j DROP 2>/dev/null \
      || ip6tables -I FORWARD 1 -i "$WG_IF" -j DROP 2>/dev/null || true
  fi

  note "ENABLED: $WG_IF tcp/80,443 -> REDIRECT :$TP ; udp/443 dropped ; v6 fwd dropped"
  note "every connected child on $WG_IF is now TLS-inspected + content-filtered"
}

cmd_disable() {
  # Remove in reverse; tolerate already-absent (idempotent teardown).
  iptables -t nat -D PREROUTING -i "$WG_IF" -p tcp -j "$CHAIN" 2>/dev/null || true
  iptables -t nat -F "$CHAIN" 2>/dev/null || true
  iptables -t nat -X "$CHAIN" 2>/dev/null || true
  iptables -D INPUT   -i "$WG_IF" -p tcp --dport "$TP"  -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$WG_IF" -p udp --dport 443    -j DROP   2>/dev/null || true
  command -v ip6tables >/dev/null 2>&1 && { ip6tables -D FORWARD -i "$WG_IF" -j DROP 2>/dev/null || true; }
  note "DISABLED: redirect + QUIC drop removed; $WG_IF is back to NAT-only exit"
  note "NOTE: with the filter off, connected children get UNFILTERED exit — set"
  note "      them back to FILTER_ON_DEVICE (or disconnect) before leaving it off"
}

cmd_status() {
  echo "[wg-filter] interface         : $WG_IF"
  echo "[wg-filter] redirect port     : $TP"
  echo -n "[wg-filter] proxy listening   : "; proxy_listening && echo "YES" || echo "NO (redirect would black-hole)"
  echo -n "[wg-filter] nat PREROUTING   : "; iptables -t nat -C PREROUTING -i "$WG_IF" -p tcp -j "$CHAIN" 2>/dev/null && echo "active" || echo "absent"
  echo -n "[wg-filter] QUIC/443 drop    : "; iptables -C FORWARD -i "$WG_IF" -p udp --dport 443 -j DROP 2>/dev/null && echo "active" || echo "absent"
  echo "[wg-filter] nat $CHAIN rules:"
  iptables -t nat -S "$CHAIN" 2>/dev/null | sed 's/^/[wg-filter]   /' || echo "[wg-filter]   (chain absent)"
}

cmd="${1:-}"; [ $# -gt 0 ] && shift || true
case "$cmd" in
  enable)         cmd_enable "$@" ;;
  disable)        cmd_disable "$@" ;;
  status)         cmd_status "$@" ;;
  version)        echo "bulwark-wg-filter v$VERSION" ;;
  -h|--help|help) sed -n '2,30p' "$0" ;;
  *)              die "usage: bulwark-wg-filter {enable|disable|status|version}" ;;
esac
