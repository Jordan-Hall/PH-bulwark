#!/usr/bin/env bash
#
# PH Bulwark — verify a device backup produced by backup.sh (READ-ONLY).
#
# Operates ONLY on the backup folder on disk — it never touches the phone.
# Run this BEFORE you unlock/flash anything. It must print "VERIFY: PASS".
#
# Usage:
#   bash tools/device-backup/verify.sh ./device-backup-YYYYMMDD-HHMMSS
#
set -uo pipefail

B="${1:-}"
if [ -z "$B" ] || [ ! -d "$B" ]; then
    echo "usage: bash tools/device-backup/verify.sh <backup-dir>" >&2
    exit 2
fi

fail=0
say() { printf '%s\n' "$*"; }

say "== Verifying backup: $B =="

# 1. checksums --------------------------------------------------------------------
if [ -s "$B/meta/SHA256SUMS.txt" ]; then
    say "-- checksums (sha256 -c) --"
    bad=$( (cd "$B" && sha256sum -c meta/SHA256SUMS.txt 2>/dev/null) | grep -vc ': OK$' || true )
    total=$(wc -l < "$B/meta/SHA256SUMS.txt" | tr -d ' ')
    if [ "${bad:-0}" -eq 0 ]; then
        say "   OK: all $total file(s) match their hash."
    else
        say "   FAIL: $bad of $total file(s) FAILED checksum — backup is CORRUPT/incomplete."
        (cd "$B" && sha256sum -c meta/SHA256SUMS.txt 2>/dev/null | grep -v ': OK$' | head)
        fail=1
    fi
else
    say "   FAIL: meta/SHA256SUMS.txt missing — backup.sh did not finish."
    fail=1
fi

# 2. the voice notes / audio (the make-or-break content) --------------------------
say "-- audio files (CONFIRM the voice notes are here) --"
if [ -s "$B/meta/audio-files.txt" ]; then
    n=$(wc -l < "$B/meta/audio-files.txt" | tr -d ' ')
    say "   $n audio file(s) captured:"
    sed 's/^/     /' "$B/meta/audio-files.txt" | head -50
    [ "$n" -gt 50 ] && say "     … ($((n-50)) more — see meta/audio-files.txt)"
    if [ "$n" -eq 0 ]; then
        say "   WARNING: ZERO audio files. If voice notes exist, they were NOT captured —"
        say "            they are likely in app-PRIVATE storage. EXPORT them via the recorder"
        say "            app to /sdcard (README Step 0), then re-run backup.sh BEFORE any wipe."
        fail=1
    fi
else
    say "   WARNING: no audio-files.txt — re-run backup.sh."
    fail=1
fi

# 3. coverage sanity --------------------------------------------------------------
say "-- coverage --"
say "   internal storage : $(du -sh "$B/sdcard" 2>/dev/null | cut -f1 || echo '??')"
say "   APKs             : $(find "$B/apks" -name '*.apk' 2>/dev/null | wc -l | tr -d ' ') file(s)"
say "   adb backup .ab   : $( [ -s "$B/adb-backup/full-backup.ab" ] && du -h "$B/adb-backup/full-backup.ab" | cut -f1 || echo 'none (expected on modern Android — rely on sdcard/ + exports)')"
say "   total size       : $(du -sh "$B" 2>/dev/null | cut -f1 || echo '??')"

echo
if [ "$fail" -eq 0 ]; then
    say "VERIFY: PASS — now PLAY a few audio files off this backup, then copy the whole"
    say "        folder to TWO places (one OFFLINE) before you unlock/flash anything."
    exit 0
else
    say "VERIFY: FAIL — do NOT unlock/flash. Fix the issues above and re-run backup.sh."
    exit 1
fi
