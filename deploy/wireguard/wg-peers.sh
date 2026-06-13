#!/usr/bin/env bash
# PH Bulwark — per-device WireGuard peer lifecycle for the region endpoint (wg0).
#
# Phase 2 of docs/design/server-vpn-mode-and-ca-trust.md §1/§4 ("WG server
# hardening"): one WireGuard peer PER ENROLLED CHILD DEVICE, replacing the
# single shared test peer from setup-london.sh.
#
# Peer <-> bulwark identity: every peer block this tool writes is tagged
#     # bulwark-device: <device_id> added: <utc-timestamp>
# where <device_id> is the SAME supervised-device id the engine uses everywhere
# else: AccountStore links device_id -> child and redeem_pair_code mints the
# per-device token for it (crates/bulwark-server/src/accounts.rs), and
# ChildControl resolves child configs by it (child_control.rs). Phase 3+ will
# drive this script from a gRPC provisioning call gated on verify_device_token;
# until then this is the manual/SSM surface for peer lifecycle.
#
# Key handling (privacy invariant — mirrors the per-install inspection CA):
# the NORMAL path is `add-peer <device_id> <client-public-key>`: the child
# device generates its own keypair (boringtun) and only the PUBLIC key crosses
# the wire, so private keys never leave the child's device. `--gen` (server-
# side keypair; prints the private key once) exists for manual tunnel testing
# ONLY — never use it for a real enrollment.
#
# Persistence + live apply: /etc/wireguard/wg0.conf is the single source of
# truth. After every change the live interface is updated with
#     wg syncconf wg0 <(wg-quick strip wg0)
# which adds/removes peers atomically WITHOUT bouncing wg0 (a wg-quick restart
# would drop every connected child mid-session). We deliberately do NOT use
# `wg-quick save` / SaveConfig=true: those regenerate wg0.conf from runtime
# state and would erase the `# bulwark-device:` identity comments. Peer blocks
# in wg0.conf are MACHINE-MANAGED (hand-edits to [Peer] blocks may be
# normalised on the next add/remove); the [Interface] section is preserved
# verbatim.
#
# The legacy setup-london.sh test peer shows up in list-peers with device '-';
# retire it with `bulwark-wg-peers remove-peer <its-public-key>`.
#
# Usage (root):
#   bulwark-wg-peers init                            ensure wg0 exists + is up (adds no peers)
#   bulwark-wg-peers add-peer <device_id> <client-pubkey> [--psk]
#   bulwark-wg-peers add-peer <device_id> --gen [--psk]   # TESTING ONLY
#   bulwark-wg-peers remove-peer <device_id|public-key>
#   bulwark-wg-peers list-peers [--endpoints]
#   bulwark-wg-peers version
set -euo pipefail

WG_IF=wg0
WG_DIR=${WG_DIR:-/etc/wireguard}
CONF="$WG_DIR/$WG_IF.conf"
SUBNET_PREFIX="10.8.0"      # server = 10.8.0.1/24; peers = 10.8.0.2 .. 10.8.0.254 (/32 each)
PORT_DEFAULT=51820
LOCK=${LOCK:-/run/bulwark-wg-peers.lock}
SYSCTL_D=${SYSCTL_D:-/etc/sysctl.d}   # overridable (with WG_DIR/LOCK) for tests
VERSION="1.0.0"

die()  { echo "[wg] ERROR: $*" >&2; exit 1; }
note() { echo "[wg] $*"; }

usage() {
  echo "usage: bulwark-wg-peers init                                  # ensure wg0 exists + is up (adds no peers)"
  echo "       bulwark-wg-peers add-peer <device_id> <client-pubkey> [--psk]"
  echo "       bulwark-wg-peers add-peer <device_id> --gen [--psk]    # TESTING ONLY (prints a private key)"
  echo "       bulwark-wg-peers remove-peer <device_id|public-key>"
  echo "       bulwark-wg-peers list-peers [--endpoints]"
  echo "       bulwark-wg-peers version"
  exit "${1:-2}"
}

[ "$(id -u)" -eq 0 ] || die "must run as root"
command -v wg >/dev/null 2>&1 || die "wireguard-tools not installed (apt-get install -y wireguard)"
umask 077

# One mutator at a time (an SSM run and a manual ssh session can race).
exec 200>"$LOCK"
flock -w 30 200 || die "another bulwark-wg-peers is running (lock: $LOCK)"

valid_device_id() {
  [ "$1" != "-" ] || return 1                 # '-' is reserved for "unlabelled"
  [[ "$1" =~ ^[A-Za-z0-9._:-]{1,64}$ ]]
}
valid_wg_key() {                              # 32 bytes -> 44-char base64 ending '='
  [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 1
  [ "$(printf '%s' "$1" | base64 -d 2>/dev/null | wc -c)" -eq 32 ]
}
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

listen_port() { sed -n 's/^[ \t]*ListenPort[ \t]*=[ \t]*//p' "$CONF" 2>/dev/null | head -n1; }

server_pub() {
  if   [ -s "$WG_DIR/server.pub" ]; then cat "$WG_DIR/server.pub"
  elif [ -s "$WG_DIR/server.key" ]; then wg pubkey < "$WG_DIR/server.key" | tee "$WG_DIR/server.pub"
  else sed -n 's/^[ \t]*PrivateKey[ \t]*=[ \t]*//p' "$CONF" | head -n1 | wg pubkey
  fi
}

# ---- wg0.conf parsing -------------------------------------------------------
# One TSV row per [Peer] block: device_id, added_ts, pubkey, psk, allowed_ips
# ('-' for absent fields; unlabelled blocks, e.g. setup-london's test peer, get
# device_id '-'). A `# bulwark-device:` comment labels the NEXT [Peer] block.
peers_tsv() {
  [ -f "$CONF" ] || return 0
  awk '
    function emit() {
      if (inpeer) printf "%s\t%s\t%s\t%s\t%s\n",
        (cdev==""?"-":cdev), (cts==""?"-":cts), (pk==""?"-":pk), (psk==""?"-":psk), (ips==""?"-":ips)
      inpeer=0; cdev=""; cts=""; pk=""; psk=""; ips=""
    }
    /^#[ \t]*bulwark-device:/ {
      line=$0; sub(/^#[ \t]*bulwark-device:[ \t]*/, "", line)
      pts=""
      if (match(line, /[ \t]+added:[ \t]*/)) { pts=substr(line, RSTART+RLENGTH); sub(/[ \t]+added:.*/, "", line) }
      pdev=line; next
    }
    /^\[Peer\]/ { emit(); cdev=pdev; cts=pts; pdev=""; pts=""; inpeer=1; next }
    /^\[/       { emit(); pdev=""; pts=""; next }
    inpeer && /^[ \t]*PublicKey[ \t]*=/    { pk=$0;  sub(/^[^=]*=[ \t]*/, "", pk);  gsub(/[ \t]/, "", pk);  next }
    inpeer && /^[ \t]*PresharedKey[ \t]*=/ { psk=$0; sub(/^[^=]*=[ \t]*/, "", psk); gsub(/[ \t]/, "", psk); next }
    inpeer && /^[ \t]*AllowedIPs[ \t]*=/   { ips=$0; sub(/^[^=]*=[ \t]*/, "", ips); gsub(/[ \t]/, "", ips); next }
    END { emit() }
  ' "$CONF"
}

# Everything before the first peer (or first device label), trailing blank
# lines trimmed — the [Interface] section, preserved verbatim across rewrites.
interface_section() {
  awk '/^\[Peer\]/ || /^#[ \t]*bulwark-device:/ { exit } { lines[++n]=$0 }
       END { while (n>0 && lines[n] ~ /^[ \t]*$/) n--; for (i=1;i<=n;i++) print lines[i] }' "$CONF"
}

# Rebuild wg0.conf from the [Interface] section + a peers TSV on stdin. Atomic
# (same-dir mktemp + mv); previous version kept at wg0.conf.bak.
rewrite_conf() {
  local tmp dev ts pk psk ips
  tmp="$(mktemp "$WG_DIR/.wg0.conf.XXXXXX")"
  interface_section > "$tmp"
  while IFS=$'\t' read -r dev ts pk psk ips; do
    [ -n "$pk" ] && [ "$pk" != "-" ] || continue
    {
      echo ""
      [ "$dev" != "-" ] && echo "# bulwark-device: $dev added: $ts"
      echo "[Peer]"
      echo "PublicKey = $pk"
      [ "$psk" != "-" ] && echo "PresharedKey = $psk"
      # A peer block parsed without AllowedIPs must not round-trip to a literal
      # "AllowedIPs = -": wg setconf rejects it AFTER the mv, bricking every
      # later add/remove and the next wg-quick up. (`if` on purpose: as the last
      # command of this redirected group a failed `[ … ] &&` would fail the group.)
      if [ "$ips" != "-" ]; then echo "AllowedIPs = $ips"; fi
    } >> "$tmp"
  done
  cp -p "$CONF" "$CONF.bak" 2>/dev/null || true
  chmod 600 "$tmp"
  mv "$tmp" "$CONF"
}

# Push the file state onto the LIVE interface without a restart (no dropped
# tunnels). If wg0 is down the file is still authoritative for the next up.
apply_live() {
  local stripped
  if ip link show "$WG_IF" >/dev/null 2>&1; then
    # Two steps so a wg-quick strip failure aborts (set -e) instead of
    # syncconf'ing partial/empty output and silently dropping every live peer
    # (process substitution swallows strip's exit status). The strip output
    # carries the server PRIVATE key: keep it in $WG_DIR (0600 via umask) and
    # remove it immediately.
    stripped="$(mktemp "$WG_DIR/.wg0.strip.XXXXXX")"
    wg-quick strip "$WG_IF" > "$stripped"
    wg syncconf "$WG_IF" "$stripped"
    rm -f "$stripped"
    note "live $WG_IF synced (no tunnel restart)"
  else
    note "$WG_IF is not up; config saved — it applies on the next 'init' / wg-quick up"
  fi
}

next_free_ip() {
  local used i
  used="$(peers_tsv | awk -F'\t' '{print $5}' | tr ',' '\n' \
          | grep -oE "^${SUBNET_PREFIX//./\\.}\.[0-9]+" | awk -F. '{print $4}' | sort -un)" || true
  for i in $(seq 2 254); do
    grep -qx "$i" <<<"$used" || { echo "$SUBNET_PREFIX.$i"; return 0; }
  done
  die "subnet $SUBNET_PREFIX.0/24 exhausted (253 peers) — grow the subnet first"
}

# What the device needs to build ITS OWN config (its private key never existed
# here on the normal path). Endpoint host is the region's public DNS name.
print_client_info() {
  local ip="$1" port host
  port="$(listen_port)"; port="${port:-$PORT_DEFAULT}"
  host="${WG_ENDPOINT:-vpn.predatorhunters.co.uk}"
  note "client-side settings (device keeps its own private key):"
  echo "  [Interface] Address   = $ip/32"
  echo "  [Peer] PublicKey      = $(server_pub)"
  echo "  [Peer] Endpoint       = $host:$port"
  echo "  [Peer] AllowedIPs     = 0.0.0.0/0, ::/0    (full-tunnel; PersistentKeepalive = 25)"
  echo "  (::/0 on purpose: the region is IPv4-only, so the child's IPv6 is blackholed"
  echo "   inside the tunnel instead of leaking the home IPv6 address around it)"
}

# ---- subcommands -------------------------------------------------------------

cmd_init() {
  local port="${WG_PORT:-$PORT_DEFAULT}" egress spriv
  mkdir -p "$WG_DIR"
  if [ ! -s "$WG_DIR/server.key" ]; then
    if [ -f "$CONF" ]; then
      # An existing wg0.conf is the source of truth for the key: derive the
      # sidecar from its PrivateKey. Generating a fresh one here would make
      # server_pub()/add-peer print a public key wg-quick doesn't use — newly
      # enrolled devices could never handshake.
      sed -n 's/^[ \t]*PrivateKey[ \t]*=[ \t]*//p' "$CONF" | head -n1 > "$WG_DIR/server.key"
      [ -s "$WG_DIR/server.key" ] || die "$CONF exists but has no PrivateKey — fix the config first"
      note "derived server.key from the existing $CONF (config stays the source of truth)"
    else
      wg genkey > "$WG_DIR/server.key"
      note "generated new server key (private key stays in $WG_DIR, never printed)"
    fi
  fi
  wg pubkey < "$WG_DIR/server.key" > "$WG_DIR/server.pub"
  if [ ! -f "$CONF" ]; then
    egress="$(ip route get 1.1.1.1 | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    [ -n "$egress" ] || die "could not detect the egress device (ip route get 1.1.1.1)"
    spriv="$(cat "$WG_DIR/server.key")"
    cat > "$CONF" <<EOF
[Interface]
Address = $SUBNET_PREFIX.1/24
ListenPort = $port
PrivateKey = $spriv
PostUp   = iptables -A FORWARD -i $WG_IF -d 169.254.169.254 -j DROP; iptables -A FORWARD -i $WG_IF -j ACCEPT; iptables -t nat -A POSTROUTING -o $egress -j MASQUERADE
PostDown = iptables -D FORWARD -i $WG_IF -d 169.254.169.254 -j DROP; iptables -D FORWARD -i $WG_IF -j ACCEPT; iptables -t nat -D POSTROUTING -o $egress -j MASQUERADE
EOF
    chmod 600 "$CONF"
    note "wrote new $CONF (NAT exit via $egress; no peers yet — use add-peer)"
  else
    note "$CONF already present (ListenPort $(listen_port)) — left untouched"
  fi
  sysctl -qw net.ipv4.ip_forward=1
  echo 'net.ipv4.ip_forward=1' > "$SYSCTL_D/99-wg.conf"
  systemctl enable "wg-quick@$WG_IF"
  systemctl is-active --quiet "wg-quick@$WG_IF" || systemctl start "wg-quick@$WG_IF"
  note "$WG_IF up; server public key: $(server_pub)"
  note "enrolled peers: $(peers_tsv | wc -l)"
}

cmd_add() {
  [ $# -ge 2 ] || usage
  local device="$1" key_arg="$2"; shift 2
  local want_psk=0 gen=0 cpriv="" cpub="" psk="-" ip ts row kdev ep_port
  while [ $# -gt 0 ]; do
    case "$1" in
      --psk) want_psk=1 ;;
      *) die "unknown flag: $1" ;;
    esac
    shift
  done
  valid_device_id "$device" || die "invalid device_id (A-Za-z0-9 . _ : - only, max 64): '$device'"
  [ -f "$CONF" ] || die "$CONF missing — run 'bulwark-wg-peers init' first"

  if [ "$key_arg" = "--gen" ]; then
    gen=1
    cpriv="$(wg genkey)"; cpub="$(wg pubkey <<<"$cpriv")"
    note "TESTING ONLY: server-generated keypair. Real enrollments must send the"
    note "device's own public key so private keys never leave the child's device."
  else
    cpub="$key_arg"
    valid_wg_key "$cpub" || die "not a valid WireGuard public key: '$cpub'"
  fi

  # Uniqueness: one key <-> one device.
  row="$(peers_tsv | awk -F'\t' -v k="$cpub" '$3==k' | head -n1)"
  if [ -n "$row" ]; then
    kdev="$(cut -f1 <<<"$row")"
    if [ "$kdev" = "$device" ]; then
      note "idempotent no-op: device '$device' already enrolled with this key (IP $(cut -f5 <<<"$row"))"
      print_client_info "$(cut -f5 <<<"$row" | cut -d/ -f1)"
      return 0
    fi
    die "key already enrolled for device '$kdev' — remove-peer that first (one key per device)"
  fi

  ts="$(now_utc)"
  row="$(peers_tsv | awk -F'\t' -v d="$device" '$1==d' | head -n1)"
  if [ -n "$row" ]; then
    # Key rotation / re-pair: keep the device's stable tunnel IP, swap the key.
    # Any previous PSK is dropped unless a new --psk is minted now.
    ip="$(cut -f5 <<<"$row" | cut -d/ -f1)"
    note "device '$device' re-enrolling with a new key — rotating, keeping IP $ip"
  else
    ip="$(next_free_ip)"
  fi
  [ "$want_psk" -eq 1 ] && psk="$(wg genpsk)"

  {
    peers_tsv | awk -F'\t' -v d="$device" '$1!=d'
    printf '%s\t%s\t%s\t%s\t%s/32\n' "$device" "$ts" "$cpub" "$psk" "$ip"
  } | rewrite_conf
  apply_live

  note "peer enrolled: device=$device ip=$ip/32"
  print_client_info "$ip"
  if [ "$want_psk" -eq 1 ]; then
    note "PresharedKey (shown ONCE — deliver out of band; avoid --psk in logged/SSM runs):"
    echo "$psk"
  fi
  if [ "$gen" -eq 1 ]; then
    note "--- TEST client config (contains a PRIVATE key: do not commit/log; delete after use) ---"
    echo "[Interface]"
    echo "PrivateKey = $cpriv"
    echo "Address = $ip/32"
    echo "DNS = 1.1.1.1"
    echo ""
    echo "[Peer]"
    echo "PublicKey = $(server_pub)"
    [ "$psk" != "-" ] && echo "PresharedKey = $psk"
    ep_port="$(listen_port)"
    echo "Endpoint = ${WG_ENDPOINT:-vpn.predatorhunters.co.uk}:${ep_port:-$PORT_DEFAULT}"
    echo "AllowedIPs = 0.0.0.0/0, ::/0"
    echo "PersistentKeepalive = 25"
    note "-----------------------------------------------------------------------------------"
  fi
}

cmd_remove() {
  [ $# -eq 1 ] || usage
  local target="$1" row pk
  [ -f "$CONF" ] || { note "no $CONF — nothing to remove"; return 0; }
  row="$(peers_tsv | awk -F'\t' -v t="$target" '$1==t || $3==t' | head -n1)"
  if [ -z "$row" ]; then
    note "idempotent no-op: no peer matches '$target' (already removed?)"
    return 0
  fi
  pk="$(cut -f3 <<<"$row")"
  peers_tsv | awk -F'\t' -v k="$pk" '$3!=k' | rewrite_conf
  # syncconf below removes it too; the explicit remove cuts any live session NOW.
  if ip link show "$WG_IF" >/dev/null 2>&1; then
    wg set "$WG_IF" peer "$pk" remove || true
  fi
  apply_live
  note "peer removed: device=$(cut -f1 <<<"$row") ip=$(cut -f5 <<<"$row")"
}

cmd_list() {
  local show_endpoints=0 live dev ts pk psk ips lrow ep hs rx tx
  [ "${1:-}" = "--endpoints" ] && show_endpoints=1
  [ -f "$CONF" ] || { note "no $CONF — run init first"; return 0; }
  # `wg show dump`: line 1 is the interface (contains the server PRIVATE key —
  # never print it; NR>1 skips it). Peer cols: 1=pubkey 2=psk 3=endpoint
  # 4=allowed-ips 5=latest-handshake 6=rx 7=tx 8=keepalive. We take 1,3,5,6,7 —
  # the PSK (col 2) is never read. Endpoint = the CHILD'S current public IP:
  # REDACTED by default so SSM/CI logs never record children's home IPs
  # (pass --endpoints in a local root shell when debugging).
  live="$(wg show "$WG_IF" dump 2>/dev/null | awk -F'\t' 'NR>1 {print $1 "\t" $3 "\t" $5 "\t" $6 "\t" $7}')" || true
  [ -n "$live" ] || note "$WG_IF not up (or no live peers) — config-file view only"
  printf '%-32s %-16s %-14s %-21s %-4s %s\n' "device_id" "allowed_ips" "handshake" "rx/tx" "psk" "endpoint"
  peers_tsv | while IFS=$'\t' read -r dev ts pk psk ips; do
    ep="-"; hs="never"; rx=0; tx=0
    lrow="$(awk -F'\t' -v k="$pk" '$1==k' <<<"$live" | head -n1)"
    if [ -n "$lrow" ]; then
      ep="$(cut -f2 <<<"$lrow")"
      hs="$(cut -f3 <<<"$lrow")"; rx="$(cut -f4 <<<"$lrow")"; tx="$(cut -f5 <<<"$lrow")"
      if [ "$hs" != "0" ] && [ -n "$hs" ]; then hs="$(( $(date +%s) - hs ))s ago"; else hs="never"; fi
    fi
    [ "$show_endpoints" -eq 1 ] || ep="(redacted)"
    printf '%-32s %-16s %-14s %-21s %-4s %s\n' "$dev" "$ips" "$hs" "${rx}B/${tx}B" \
      "$( [ "$psk" != "-" ] && echo yes || echo no )" "$ep"
  done
  note "total peers: $(peers_tsv | wc -l)"
}

cmd="${1:-}"
[ $# -gt 0 ] && shift || true
case "$cmd" in
  init)           cmd_init "$@" ;;
  add-peer)       cmd_add "$@" ;;
  remove-peer)    cmd_remove "$@" ;;
  list-peers)     cmd_list "$@" ;;
  version)        echo "bulwark-wg-peers v$VERSION" ;;
  -h|--help|help) usage 0 ;;
  *)              usage ;;
esac
