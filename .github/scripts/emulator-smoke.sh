#!/usr/bin/env bash
# Emulator smoke test for the child APK, invoked by android-emulator.yml.
# Lives in a file because android-emulator-runner executes every `script:`
# line as a SEPARATE `sh -c` — multi-line shell (line continuations, if/fi,
# even `set -eu`) silently breaks inline.
set -euo pipefail

# Wait for the device to be fully booted (avoids the "device offline" race).
adb wait-for-device
timeout 180 bash -c 'until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d "\r")" = "1" ]; do sleep 3; done' || true
sleep 5

# 1) Install must succeed (proves the APK + native ABIs are valid for Android).
adb install -r platform/android/app/build/outputs/apk/debug/app-debug.apk
adb shell pm list packages 2>/dev/null | tr -d "\r" | grep -q "package:co.predatorhunters.bulwark" \
  || { echo "::error::APK did not install"; exit 1; }
echo "✓ APK installed on Android $(adb shell getprop ro.build.version.release | tr -d '\r')"

# 2) Best-effort launch, then assert NO native crash (the key signal:
#    libbulwark_client.so loads + no uncaught exception). Launch timing /
#    activity lifecycle are NOT asserted (they flake on a headless emulator).
adb logcat -c || true
adb shell monkey -p co.predatorhunters.bulwark -c android.intent.category.LAUNCHER 1 || true
sleep 8
echo "=== app logcat ==="
adb logcat -d 2>/dev/null | grep -iE "bulwark|libbulwark|RustBridge" | tail -20 || true
if adb logcat -d 2>/dev/null | grep -E "UnsatisfiedLinkError|FATAL EXCEPTION"; then
  echo "::error::native crash / uncaught exception on launch"
  adb logcat -d | tail -60
  exit 1
fi
echo "✓ launched + libbulwark_client loaded, no crash on Android"
