#!/usr/bin/env bash
# Rebrand harness — rename the internal codename `aegis` -> `bulwark` across the
# WHOLE repo: file contents + file/dir names, case-preserving (AEGIS->BULWARK,
# Aegis->Bulwark, aegis->bulwark). Binary assets (.onnx/images) are renamed but
# never content-edited. Run from anywhere inside the repo on a CLEAN branch:
#
#     bash scripts/rebrand-aegis-to-bulwark.sh
#     cargo build --workspace        # verify
#
# Idempotent-ish: re-running on an already-renamed tree is a no-op.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

rebrand() { sed -e 's/AEGIS/BULWARK/g' -e 's/Aegis/Bulwark/g' -e 's/aegis/bulwark/g'; }
export -f rebrand

echo "1/3  rewriting file contents..."
git ls-files | while IFS= read -r f; do
  case "$f" in
    *.onnx|*.png|*.jpg|*.jpeg|*.gif|*.webp|*.bmp|*.ico|*.so|*.a|*.gguf|Cargo.lock) continue;;
  esac
  grep -Iq . "$f" 2>/dev/null || continue            # skip binary files
  grep -Eiq 'aegis' "$f" 2>/dev/null || continue     # skip files with no `aegis`
  tmp="$(mktemp)"; rebrand <"$f" >"$tmp"; cat "$tmp" >"$f"; rm -f "$tmp"
done

echo "2/3  renaming files + directories (longest path first)..."
git ls-files | grep -iE 'aegis' | awk '{print length, $0}' | sort -rn | cut -d' ' -f2- \
| while IFS= read -r p; do
    np="$(printf '%s' "$p" | rebrand)"
    [ "$p" = "$np" ] && continue
    mkdir -p "$(dirname "$np")"
    git mv -f "$p" "$np"
  done

echo "3/3  regenerating Cargo.lock..."
cargo build --workspace >/dev/null 2>&1 || true   # regenerates the lock for the renamed crates

echo "done — review with 'git status' and verify with 'cargo build --workspace'."
