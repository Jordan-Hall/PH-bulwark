#!/usr/bin/env bash
#
# Resumable, disconnect-tolerant adb pull (READ-ONLY).
#
# Pulls a device directory to a local dir, but only files that are MISSING or a
# DIFFERENT SIZE locally. Safe to re-run after a USB drop — it skips everything
# already pulled and continues. Never writes to / modifies the phone.
#
# Useful for a big /sdcard/DCIM over flaky USB (where `adb pull -a` restarts from
# scratch on every disconnect).
#
# Usage:
#   bash tools/device-backup/sync-pull.sh [SERIAL] <DEVICE_DIR> <LOCAL_DIR>
#   e.g. bash tools/device-backup/sync-pull.sh 32161FDH20039M /sdcard ./pixel-sdcard
#
set -uo pipefail

ADB="${ADB:-/c/Android/sdk/platform-tools/adb.exe}"
if [ "$#" -ge 3 ]; then SERIAL="$1"; shift; else SERIAL=""; fi
SRC="${1:-}"; DEST="${2:-}"
if [ -z "$SRC" ] || [ -z "$DEST" ]; then
    echo "usage: bash sync-pull.sh [SERIAL] <DEVICE_DIR> <LOCAL_DIR>" >&2; exit 2
fi
SRC="${SRC%/}"   # strip trailing slash

adbc() { if [ -n "$SERIAL" ]; then "$ADB" -s "$SERIAL" "$@"; else "$ADB" "$@"; fi; }
# Device paths must be doubled-slash so Git Bash/MSYS doesn't rewrite them to a
# Windows path (see backup.sh). dsrc //... ; local paths stay single-slash.
dd() { printf '/%s' "$1"; }   # "/sdcard" -> "//sdcard"

if [ "$(adbc get-state 2>/dev/null | tr -d '\r')" != "device" ]; then
    echo "ERROR: device '${SERIAL:-(any)}' not connected. Plug it in + keep the screen on." >&2
    exit 1
fi

mkdir -p "$DEST"
list="$(mktemp)"; trap 'rm -f "$list"' EXIT

echo "[sync] enumerating device files under $SRC (size + path)…"
# toybox stat on Android supports -c; find -exec batches it. size<TAB>path.
# -L FOLLOWS SYMLINKS: /sdcard is a symlink (→ /storage/emulated/0), so a plain
# `find /sdcard` descends nothing and returns 0 files. -L is mandatory here.
adbc shell "find -L '$SRC' -type f -exec stat -c '%s	%n' {} + 2>/dev/null" | tr -d '\r' > "$list"
total=$(wc -l < "$list" | tr -d ' ')
echo "[sync] $total file(s) on device. Pulling missing / size-mismatched only…"

pulled=0; skipped=0; failed=0; i=0
while IFS=$'\t' read -r dsize dpath; do
    [ -z "$dpath" ] && continue
    i=$((i+1))
    rel="${dpath#"$SRC"/}"                 # path relative to SRC
    local="$DEST/$rel"
    if [ -f "$local" ]; then
        lsize=$(stat -c '%s' "$local" 2>/dev/null || echo -1)
        if [ "$lsize" = "$dsize" ]; then skipped=$((skipped+1)); continue; fi
    fi
    mkdir -p "$(dirname "$local")"
    if adbc pull -a "$(dd "$dpath")" "$local" >/dev/null 2>&1; then
        pulled=$((pulled+1))
        [ $((pulled % 25)) -eq 0 ] && echo "[sync]   …$pulled pulled / $i of $total seen"
    else
        failed=$((failed+1))
        echo "[sync]   WARN: failed $dpath (device may have dropped — re-run to resume)"
        # if the device vanished, stop cleanly so a re-run resumes.
        if [ "$(adbc get-state 2>/dev/null | tr -d '\r')" != "device" ]; then
            echo "[sync] device disconnected — stopping. RECONNECT and re-run to continue." >&2
            break
        fi
    fi
done < "$list"

echo "[sync] done: $pulled pulled, $skipped already-present, $failed failed (of $total)."
if [ "$failed" -gt 0 ] || [ "$((pulled+skipped))" -lt "$total" ]; then
    echo "[sync] INCOMPLETE — re-run the same command to resume (it skips what's done)."
    exit 1
fi
echo "[sync] COMPLETE — every device file under $SRC is present locally with matching size."
