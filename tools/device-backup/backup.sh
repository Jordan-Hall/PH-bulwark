#!/usr/bin/env bash
#
# PH Bulwark — pre-flash full device backup (READ-ONLY).
#
# Captures everything recoverable off a phone over adb BEFORE any
# unlock/root/flash. It ONLY reads from the device (adb pull / adb shell
# queries). It NEVER writes to, modifies, roots, factory-resets, or flashes the
# phone. See README.md — and do the Step-0 manual app exports FIRST, or
# app-private data (e.g. Google Recorder voice notes) will be missed.
#
# Usage:
#   bash tools/device-backup/backup.sh [SERIAL]
#   ADB=/path/to/adb OUT=./mybackup bash tools/device-backup/backup.sh 32161FDH20039M
#
set -uo pipefail

ADB="${ADB:-/c/Android/sdk/platform-tools/adb.exe}"
SERIAL="${1:-}"
OUT="${OUT:-./device-backup-$(date +%Y%m%d-%H%M%S)}"

adbc() { if [ -n "$SERIAL" ]; then "$ADB" -s "$SERIAL" "$@"; else "$ADB" "$@"; fi; }
log()  { printf '[backup] %s\n' "$*"; }
# adb shell output carries CRLF line endings on Windows; strip the CR.
nocr() { tr -d '\r'; }

# ---- 0. sanity: exactly one device (or a serial) -------------------------------
if ! command -v "$ADB" >/dev/null 2>&1 && [ ! -x "$ADB" ]; then
    echo "ERROR: adb not found at '$ADB' (set ADB=...)." >&2; exit 1
fi
mapfile -t DEVS < <("$ADB" devices 2>/dev/null | awk '/\tdevice$/{print $1}')
if [ "${#DEVS[@]}" -eq 0 ]; then
    echo "ERROR: no device in 'adb devices'. Plug in + authorise USB debugging." >&2; exit 1
fi
if [ -z "$SERIAL" ] && [ "${#DEVS[@]}" -gt 1 ]; then
    echo "ERROR: ${#DEVS[@]} devices attached — pass a SERIAL: ${DEVS[*]}" >&2; exit 1
fi
[ -z "$SERIAL" ] && SERIAL="${DEVS[0]}"
log "device = $SERIAL"

mkdir -p "$OUT"/{meta,apks,sdcard,adb-backup}
log "output = $OUT"

# ---- 1. device inventory (so we know how to restore) ---------------------------
log "inventory…"
adbc shell getprop                  2>/dev/null | nocr > "$OUT/meta/getprop.txt"
adbc shell pm list packages -f      2>/dev/null | nocr > "$OUT/meta/packages-all.txt"
adbc shell pm list packages -3 -f   2>/dev/null | nocr > "$OUT/meta/packages-thirdparty.txt"
adbc shell settings list system     2>/dev/null | nocr > "$OUT/meta/settings-system.txt"
adbc shell settings list secure     2>/dev/null | nocr > "$OUT/meta/settings-secure.txt"
adbc shell settings list global     2>/dev/null | nocr > "$OUT/meta/settings-global.txt"
adbc shell dumpsys account          2>/dev/null | nocr > "$OUT/meta/accounts.txt"
adbc shell df -h                    2>/dev/null | nocr > "$OUT/meta/storage.txt"

# NOTE on the leading `//` before DEVICE paths below (e.g. //sdcard, "/$apk"):
# under Git Bash / MSYS on Windows, a bare `/sdcard` argument gets auto-rewritten
# to a Windows path (e.g. C:/Program Files/Git/sdcard) before reaching adb.exe,
# which then fails. A doubled leading slash is NOT rewritten by MSYS, and the
# device side normalises `//sdcard` back to `/sdcard`. On Linux/macOS `//` == `/`,
# so this is safe everywhere. (LOCAL dest paths must stay single-slash so MSYS
# DOES convert them to a Windows path adb.exe understands.)

# ---- 2. pull every third-party APK (exact versions, base + splits) -------------
log "pulling third-party APKs…"
# packages-thirdparty.txt lines look like: package:/data/app/.../base.apk=com.foo
while IFS= read -r line; do
    pkg="${line##*=}"
    [ -z "$pkg" ] && continue
    mkdir -p "$OUT/apks/$pkg"
    # pm path can return several lines (split APKs).
    adbc shell pm path "$pkg" 2>/dev/null | nocr | sed 's/^package://' | while IFS= read -r apk; do
        [ -z "$apk" ] && continue
        adbc pull "/$apk" "$OUT/apks/$pkg/" >/dev/null 2>&1 \
            && log "  apk: $pkg <- $(basename "$apk")" \
            || log "  WARN: could not pull $apk ($pkg)"
    done
done < "$OUT/meta/packages-thirdparty.txt"

# ---- 3. pull ALL of internal storage (the user data) ---------------------------
# This is the primary copy. Includes DCIM, Pictures, Movies, Music, Download,
# Documents, Recordings, Android/media/<app>, Ringtones, etc.
log "pulling /sdcard (this is the big one — may take a while)…"
adbc pull -a "//sdcard" "$OUT/sdcard" 2>&1 | tail -3 || log "WARN: /sdcard pull reported errors (review above)"

# Some OEMs alias /sdcard; also try the canonical path if it's different content.
adbc pull -a "//storage/emulated/0" "$OUT/sdcard-emulated0" >/dev/null 2>&1 || true

# ---- 4. best-effort full adb backup (deprecated; needs on-device confirm) -------
log "attempting 'adb backup -all' — CONFIRM THE PROMPT ON THE PHONE (don't set a"
log "password unless you'll remember it). Skips automatically if it stalls."
( adbc backup -apk -obb -shared -all -system -f "$OUT/adb-backup/full-backup.ab" ) &
bpid=$!
# give it up to 10 min; this path is a bonus, not the primary copy.
( sleep 600; kill "$bpid" 2>/dev/null ) & watch=$!
wait "$bpid" 2>/dev/null; kill "$watch" 2>/dev/null
if [ -s "$OUT/adb-backup/full-backup.ab" ]; then
    log "  adb backup wrote $(du -h "$OUT/adb-backup/full-backup.ab" | cut -f1)"
else
    log "  adb backup produced nothing (expected on Android 12+/opted-out apps) — rely on sdcard/ + Step-0 exports"
fi

# ---- 5. explicitly surface audio / voice recordings ----------------------------
log "scanning the backup for audio files (verify the voice notes are here)…"
find "$OUT/sdcard" "$OUT/sdcard-emulated0" -type f 2>/dev/null \
    -iregex '.*\.\(m4a\|mp3\|amr\|wav\|ogg\|oga\|aac\|3gp\|opus\|flac\)$' \
    > "$OUT/meta/audio-files.txt" 2>/dev/null || true
AUDIO_N=$(wc -l < "$OUT/meta/audio-files.txt" 2>/dev/null | tr -d ' ')
log "  found ${AUDIO_N:-0} audio file(s) — see meta/audio-files.txt"

# ---- 6. checksums + manifest ---------------------------------------------------
log "computing SHA256 manifest (integrity / restore proof)…"
( cd "$OUT" && find sdcard sdcard-emulated0 apks adb-backup -type f 2>/dev/null \
    -exec sha256sum {} \; > meta/SHA256SUMS.txt 2>/dev/null ) || true
FILE_N=$(wc -l < "$OUT/meta/SHA256SUMS.txt" 2>/dev/null | tr -d ' ')

echo
log "================ BACKUP COMPLETE ================"
log "  location : $OUT"
log "  size     : $(du -sh "$OUT" 2>/dev/null | cut -f1)"
log "  files    : ${FILE_N:-0} hashed   |   audio: ${AUDIO_N:-0}"
log "NEXT: open meta/audio-files.txt and CONFIRM the voice notes are present;"
log "      play a few off the backup; then copy this folder to TWO places"
log "      (one OFFLINE). Do NOT unlock/flash until that's verified."
log "================================================"
