#!/usr/bin/env bash
# FOSS guard — fail CI if a PROPRIETARY Android dependency reappears.
#
# PH Bulwark ships 100% free/open-source (docs/FOSS.md): no Google Play Services,
# no Firebase/FCM, no ML Kit, no closed SDK — in ANY app (child :app, :camera,
# and the Manager's dx-generated Android project). Push is self-hosted
# UnifiedPush (ntfy), never FCM/APNs. This script greps every Gradle build file
# for banned coordinates and exits non-zero on a hit, so a regression can't
# merge.
#
# ALLOWED Google coordinates (these ARE FOSS, Apache-2.0): androidx.* and
# com.google.android.material (Material Components). Everything else under
# com.google.* / firebase / play-services is BANNED.
set -euo pipefail

ROOT="${1:-.}"

# Banned proprietary coordinate fragments (case-insensitive). Each is a closed
# Google/Firebase binary with no FOSS source build.
BANNED='com\.google\.mlkit|com\.google\.firebase|firebase-|com\.google\.android\.gms|play-services|com\.google\.android\.play[:.]|com\.google\.gms|com\.android\.installreferrer|com\.google\.ar[:.]'

# Find every Gradle build script under the repo (child, camera, and any
# dx-generated Manager Android project), excluding build output dirs.
mapfile -t gradle_files < <(
  find "$ROOT" \
    \( -path '*/build/*' -o -path '*/.gradle/*' -o -path '*/node_modules/*' -o -path '*/target/*' -o -path '*/.claude/*' -o -path '*/.git/*' \) -prune -false \
    -o \( -name 'build.gradle' -o -name 'build.gradle.kts' \) -print
)

if [ "${#gradle_files[@]}" -eq 0 ]; then
  echo "[foss-guard] no Gradle build files found under $ROOT (nothing to check)"
  exit 0
fi

echo "[foss-guard] scanning ${#gradle_files[@]} Gradle build file(s) for proprietary deps…"
hits=0
for f in "${gradle_files[@]}"; do
  # A real dependency line, not a comment. Strip leading whitespace then drop
  # lines that start with // so the documented "use Tesseract, never a
  # proprietary SDK" guidance comments don't trip the guard.
  while IFS= read -r line; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    case "$trimmed" in
      '//'*|'*'*|'/*'*) continue ;;  # comment lines
    esac
    if printf '%s\n' "$trimmed" | grep -qiE "$BANNED"; then
      echo "::error file=$f::proprietary Android dependency is banned (FOSS-only): $trimmed"
      hits=$((hits + 1))
    fi
  done < "$f"
done

if [ "$hits" -gt 0 ]; then
  echo "[foss-guard] FAILED: $hits proprietary dependency line(s). PH Bulwark is FOSS-only —"
  echo "[foss-guard] use a FOSS alternative (Tesseract for OCR, UnifiedPush for push, ZXing for QR)."
  exit 1
fi
echo "[foss-guard] OK — no proprietary Android dependencies."
