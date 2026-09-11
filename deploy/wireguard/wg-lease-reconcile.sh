#!/usr/bin/env bash
set -euo pipefail

STATE_FILE="${1:-${BULWARK_WG_PEERS_FILE:-/var/lib/bulwark/wg_peers.json}}"
PEER_TOOL="${BULWARK_WG_PEER_TOOL:-/usr/local/sbin/bulwark-wg-peers}"
LOCK="${BULWARK_WG_LEASE_LOCK:-/run/bulwark-wg-lease-reconcile.lock}"

fail() { echo "[wg-lease] ERROR: $*" >&2; exit 1; }
note() { echo "[wg-lease] $*"; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
command -v jq >/dev/null 2>&1 || fail "jq is required"
[ -x "$PEER_TOOL" ] || fail "peer tool not executable: $PEER_TOOL"
[ -f "$STATE_FILE" ] || fail "desired peer state missing: $STATE_FILE"

exec 201>"$LOCK"
command -v flock >/dev/null 2>&1 && flock -w 15 201 || true

now_ms="$(( $(date +%s) * 1000 ))"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

jq -er --argjson now "$now_ms" '
  (.peers // [])
  | map(select(
      (.device_id | type == "string" and length > 0)
      and (.public_key | type == "string" and length > 0)
      and (.address | type == "string" and length > 0)
      and (((.expires_ts // 0) > $now) or ((.expires_ts // 0) == 9223372036854775807))
    ))
  | sort_by(.address | split(".")[-1] | tonumber)
  | .[]
  | [.device_id, .public_key, .address] | @tsv
' "$STATE_FILE" >"$tmp" || fail "invalid desired peer state"

declare -A desired_key
declare -A desired_ip
while IFS=$'\t' read -r device key address; do
  [ -n "$device" ] || continue
  desired_key["$device"]="$key"
  desired_ip["$device"]="$address"
done <"$tmp"

declare -A current_ip
while read -r device allowed _rest; do
  [ "$device" = "device_id" ] && continue
  [[ "$device" == \[* ]] && continue
  [ -n "$device" ] || continue
  current_ip["$device"]="${allowed%/32}"
done < <("$PEER_TOOL" list-peers 2>/dev/null || true)

for device in "${!current_ip[@]}"; do
  if [ -z "${desired_key[$device]+x}" ]; then
    note "revoking expired/unauthorized peer: $device"
    "$PEER_TOOL" remove-peer "$device"
  fi
done

while IFS=$'\t' read -r device key address; do
  [ -n "$device" ] || continue
  if [ -n "${current_ip[$device]+x}" ] && [ "${current_ip[$device]}" != "$address" ]; then
    note "repairing tunnel address drift for $device (${current_ip[$device]} -> $address)"
    "$PEER_TOOL" remove-peer "$device"
  fi
  "$PEER_TOOL" add-peer "$device" "$key" >/dev/null
  current="$("$PEER_TOOL" list-peers 2>/dev/null | awk -v d="$device" '$1==d {print $2; exit}')"
  current="${current%/32}"
  [ "$current" = "$address" ] || fail "address reconciliation failed for $device: wanted $address got ${current:-none}"
done <"$tmp"

note "active authenticated Remote VPN peers: ${#desired_key[@]}"
