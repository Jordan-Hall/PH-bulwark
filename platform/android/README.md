# Aegis — Android app (parent + filtering VPN client)

A single Android app that is both the **parent dashboard** and the **filtering
VPN client**, plus the **on-device OCR** path for end-to-end-encrypted chats.

## What's here
- `app/src/main/java/co/libertyware/aegis/`
  - `MainActivity.kt` — parent dashboard (enable VPN, grant accessibility).
  - `vpn/AegisVpnService.kt` — the `VpnService`: builds the TUN and hands its fd
    to the Rust core for the real-time filtering loop.
  - `accessibility/AegisAccessibilityService.kt` — reads rendered chat text +
    notifications for E2E / cert-pinned apps (the network can't read those) and
    feeds the **same** grooming pipeline. Conventional capture, **not** a vision-LLM.
  - `core/RustBridge.kt` — JNI surface to `libaegis_client.so`.
- `app/src/main/AndroidManifest.xml` — VpnService + AccessibilityService + perms.
- `app/src/main/res/xml/accessibility_service_config.xml` — capture config.

## The Rust core (the missing native piece)
The app loads `libaegis_client.so`, built from `crates/aegis-client` as a C-ABI
`cdylib`. That requires a small **`android` cargo feature on `aegis-client`** that
exports the JNI functions declared in `RustBridge.kt`:

```
Java_co_libertyware_aegis_core_RustBridge_startVpn(env, _, tunFd: jint, configJson: jstring) -> jlong
Java_co_libertyware_aegis_core_RustBridge_stopVpn(env, _, handle: jlong)
Java_co_libertyware_aegis_core_RustBridge_analyzeText(env, _, app, threadId, text) -> jstring
Java_co_libertyware_aegis_core_RustBridge_nextAlert(env, _) -> jstring
```

`startVpn` takes the VpnService TUN fd and runs the `aegis-client` pipeline
(`Interceptor` over an Android TUN backend — the `aegis-net::tun` Android stub is
filled in here, using the fd Android already opened, so no extra TUN permission
is needed). `analyzeText` runs the `aegis-text` grooming engine and routes
flagged verdicts to `aegis-alert`. This native bridge is the remaining Rust work
(tracked in `docs/integration-todo.md`).

## Build
1. **Build the Rust core for Android** with [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk):
   ```bash
   cargo install cargo-ndk
   rustup target add aarch64-linux-android armv7-linux-androideabi
   cargo ndk -t arm64-v8a -t armeabi-v7a \
     -o platform/android/app/src/main/jniLibs \
     build -p aegis-client --release --features android
   ```
   (produces `app/src/main/jniLibs/<abi>/libaegis_client.so`)
2. **Build the app** in Android Studio (open `platform/android/`) or:
   ```bash
   cd platform/android && ./gradlew assembleDebug
   ```
   Requires Android SDK 34, NDK, JDK 17.

## Setup on the child's device (guardian)
1. Install the APK, open Aegis, tap **Enable filtering VPN** → accept the system VPN consent.
2. Tap **Grant accessibility (on-device OCR)** → enable Aegis in Settings ▸ Accessibility
   (this is what lets it check E2E chats on-device).
3. Pair with your home cluster endpoint (config) so heavy media offloads there.

## Honest limits (same as PLAN §0a)
- The VPN filters ordinary web/video and non-pinned HTTPS. **E2E / cert-pinned
  apps are covered only by the accessibility/OCR path**, never the wire.
- Play Store distribution of a parental-control VPN needs disclosure, a Data
  Safety declaration (no plaintext exfiltration), and a **MASA Level 2**
  assessment — see `docs/security/legal-consent.md`.
