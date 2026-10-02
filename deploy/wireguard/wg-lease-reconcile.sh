#!/usr/bin/env bash
set -euo pipefail

STATE_FILE="${1:-${BULWARK_WG_PEERS_FILE:-/var/lib/bulwark/wg_peers.json}}"
CONFIG_FILE="${BULWARK_CHILD_CONFIG_FILE:-/var/lib/bulwark/child_config.json}"
PEER_TOOL="${BULWARK_WG_PEER_TOOL:-/usr/local/sbin/bulwark-wg-peers}"
LOCK="${BULWARK_WG_LEASE_LOCK:-/run/bulwark-wg-lease-reconcile.lock}"

fail() { echo "[wg-lease] ERROR: $*" >&2; exit 1; }
note() { echo "[wg-lease] $*"; }

[ "$(id -u)" -eq 0 ] || fail "must run as root"
command -v jq >/dev/null 2>&1 || fail "jq is required"
[ -x "$PEER_TOOL" ] || fail "peer tool not executable: $PEER_TOOL"
[ -f "$STATE_FILE" ] || fail "desired peer state missing: $STATE_FILE"

exec 201>"$LOCK"
if command -v flock >/dev/null 2>&1; then
  flock -w 15 201 || fail "another WireGuard lease reconciliation is still running"
fi

now_ms="$(( $(date +%s) * 1000 ))"
tmp="$(mktemp)"
config_tmp="$(mktemp)"
trap 'rm -f "$tmp" "$config_tmp"' EXIT

# Missing/corrupt guardian authorization must never preserve tunnel access. A
# missing file becomes an empty authority set; malformed JSON fails the run
# before any desired peers are applied. Existing peers are removed below when
# the authority set is empty.
if [ -f "$CONFIG_FILE" ]; then
  cp "$CONFIG_FILE" "$config_tmp"
else
  printf '%s\n' '{"configs":[]}' >"$config_tmp"
fi

jq -ner \
  --slurpfile peers "$STATE_FILE" \
  --slurpfile configs "$config_tmp" \
  --argjson now "$now_ms" '
  ($configs[0].configs // []
    | map(select(
        (.device_id | type == "string" and length > 0)
        and (.filtering_enabled == true)
        and ((.filter_location // 0) == 1)
      ))
    | map(.device_id)
    | unique) as $authorized
  | ($peers[0].peers // [])
  | map(select(
      . as $peer
      | ($peer.device_id | type == "string" and length > 0)
        and ($peer.public_key | type == "string" and length > 0)
        and ($peer.address | type == "string" and length > 0)
        and ((($peer.expires_ts // 0) > $now) or (($peer.expires_ts // 0) == 9223372036854775807))
        and (($authorized | index($peer.device_id)) != null)
    ))
  | sort_by(.address | split(".")[-1] | tonumber)
  | .[]
  | [.device_id, .public_key, .address] | @tsv
' >"$tmp" || fail "invalid peer/config authorization state"

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
    note "revoking expired or guardian-unauthorized Remote VPN peer: $device"
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

note "active authenticated + guardian-authorized Remote VPN peers: ${#desired_key[@]}"
