# Bulwark — Android child app

The Android child shell pairs the device to a guardian account, runs the
transparent child-safety surfaces Android allows, and hosts the Rust bridge used
by the on-device analysis/VPN paths.

## What's here
- `app/src/main/java/co/predatorhunters/bulwark/`
  - `MainActivity.kt` — child setup: choose UK/US/self-hosted server, redeem a
    parent-generated pair code, show local enrollment/protection state.
  - `vpn/BulwarkVpnService.kt` — the `VpnService`: builds the TUN and hands its fd
    plus the saved enrollment config to the Rust core for the filtering loop.
  - `accessibility/BulwarkAccessibilityService.kt` — reads rendered chat text +
    notifications for E2E / cert-pinned apps (the network can't read those) and
    feeds the **same** grooming pipeline. Conventional capture, **not** a vision-LLM.
  - `core/RustBridge.kt` — JNI surface to `libbulwark_client.so`.
- `app/src/main/AndroidManifest.xml` — VpnService + AccessibilityService + perms.
- `app/src/main/res/xml/accessibility_service_config.xml` — capture config.

## The Rust bridge
The app loads `libbulwark_client.so`, built from
`platform/android/rust/bulwark-android` as a C-ABI `cdylib`. It exports the JNI
functions declared in `RustBridge.kt`:

```
Java_co_predatorhunters_bulwark_core_RustBridge_startVpn(env, _, vpnService, tunFd: jint, configJson: jstring) -> jlong
Java_co_predatorhunters_bulwark_core_RustBridge_stopVpn(env, _, handle: jlong)
Java_co_predatorhunters_bulwark_core_RustBridge_analyzeText(env, _, app, threadId, text) -> jstring
Java_co_predatorhunters_bulwark_core_RustBridge_redeemPairCode(env, _, endpoint, code, deviceId) -> jstring
Java_co_predatorhunters_bulwark_core_RustBridge_nextAlert(env, _) -> jstring
```

`redeemPairCode` calls the shared `Accounts.RedeemPairCode` gRPC service used by
the parent app and E2E workflow harness. `analyzeText` runs the deterministic
`bulwark-text` grooming engine locally and returns content-free/redacted verdict
JSON. `startVpn` currently receives the Android TUN fd and serialized child
config; the full forwarding data path is still tracked separately.

## Build
1. **Build the Rust bridge for Android** with
   [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk):
   ```bash
   cargo install cargo-ndk
   rustup target add aarch64-linux-android armv7-linux-androideabi
   cd platform/android/rust/bulwark-android
   cargo ndk -t arm64-v8a -t armeabi-v7a \
     -o ../../app/src/main/jniLibs \
     build --release
   ```
   (produces `app/src/main/jniLibs/<abi>/libbulwark_client.so`)
2. **Build the app** in Android Studio (open `platform/android/`) or with Gradle:
   ```bash
   cd platform/android
   gradle :app:assembleDebug
   ```
   Requires Android SDK 34, NDK, JDK 17.

## Setup on the child's device (guardian)
1. In the parent app, choose the server (UK/London, US, or self-hosted), log in,
   and create a pair code for the child.
2. Install the APK on the child device, choose the same server, and enter the
   pair code. The app stores `device_id`, `child_id`, `family_id`, and endpoint.
3. Tap **Turn on protection** and enable Bulwark in Android Accessibility settings.
4. Device Owner provisioning remains the stronger managed-device path for
   anti-removal lockdown; pairing alone does not claim that state.

## Honest limits (same as PLAN §0a)
- The VPN filters ordinary web/video and non-pinned HTTPS. **E2E / cert-pinned
  apps are covered only by the accessibility/OCR path**, never the wire.
- Play Store distribution of a parental-control VPN needs disclosure, a Data
  Safety declaration (no plaintext exfiltration), and a **MASA Level 2**
  assessment — see `docs/security/legal-consent.md`.
