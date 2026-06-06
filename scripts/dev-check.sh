#!/usr/bin/env bash
# PH Bulwark — local CI mirror. Run before pushing to catch what ci.yml catches,
# instead of round-tripping through GitHub Actions.
#
# Mirrors .github/workflows/ci.yml (rustfmt, clippy -D warnings, test) across the
# main workspace PLUS the two DETACHED workspaces that main CI builds separately:
#   - apps/parent                      (the Dioxus console)
#   - platform/android/rust/aegis-android (the JNI bridge; clippy only — needs NDK to build)
#
# Windows note: Smart App Control blocks executing fresh build-script/test binaries
# (os error 4551). fmt + clippy on the non-SQLite crates usually pass; full `cargo
# test` and the SQLite crates (aegis-store/client/ui) need Linux/WSL/CI. The `touch`
# forces a fresh aegis-proto build-script binary past SAC. For the full suite, run
# this on Linux or in CI.
#
# Usage:  bash scripts/dev-check.sh            # full
#         FAST=1 bash scripts/dev-check.sh     # fmt + clippy only (skip tests)
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
section() { echo; echo "──────── $1 ────────"; }
run() { local name="$1"; shift; section "$name"; if "$@"; then echo "  ✓ $name"; else echo "  ✗ $name"; fail=1; fi; }

touch crates/aegis-proto/build.rs 2>/dev/null || true  # SAC (os error 4551) workaround

run "workspace: rustfmt"  cargo fmt --all --check
run "workspace: clippy"   cargo clippy --workspace --all-targets -- -D warnings
if [ "${FAST:-0}" != 1 ]; then
  run "workspace: test"   cargo test --workspace
fi

run "parent console: rustfmt"  cargo fmt --manifest-path apps/parent/Cargo.toml --check
run "parent console: clippy"   cargo clippy --manifest-path apps/parent/Cargo.toml --all-targets -- -D warnings

run "android jni: rustfmt"  cargo fmt --manifest-path platform/android/rust/aegis-android/Cargo.toml --check
# clippy for the android crate needs the NDK target; skip the build, lint host-side.
run "android jni: clippy"   cargo clippy --manifest-path platform/android/rust/aegis-android/Cargo.toml -- -D warnings

echo
if [ "$fail" = 0 ]; then
  echo "✅ dev-check: all green"
else
  echo "❌ dev-check: failures above — fix before pushing (run 'cargo fmt --all' for fmt)"
  exit 1
fi
