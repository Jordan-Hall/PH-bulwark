# Child Safety ROM — Increment 2 + 3 Design Runbook

> **STATUS: DRAFT — pending owner review.** Decisions marked OPEN QUESTION require
> owner or architect sign-off before implementation begins. Do not merge as
> authoritative until those items are resolved.
>
> **Scope:** Increments 2 (B) and 3 (C) only. Increment 1 (A — Device-Owner on
> stock firmware) is code-complete; see `docs/design/child-safety-rom.md` for its
> runbook and status (PRs #217/#218, held for on-device validation).
>
> **Framing:** this is a consensual, guardian-provisioned child-protection product.
> All capture and detection runs on a device the guardian owns, used by a minor
> they are the legal guardian of, with consent obtained once at provisioning on a
> dedicated, freshly wiped device. "Silent capture without a per-use prompt" means
> exactly that — no per-session prompt after provisioning — and is the same
> technical mechanism used by every enterprise MDM and parental-control ROM. It
> does not mean covert. See `docs/FRAMING.md`.

---

## 1. Base choice — AOSP-vanilla vs GrapheneOS for `lynx`

### What is current (as of 2026-06-19)

**GrapheneOS** ships `lynx` (Pixel 7a) as a fully supported device, stable channel
release `2026061600`. It is currently on Android 16 QPR2/QPR3 and actively
maintained, tracking upstream security patches monthly.

**AOSP** latest tags for `lynx`:
- Android 15: `android-15.0.0_r24` (build `BD4A.240925.111`, 2025-01-05 SPL)
- Android 16: `android-16.0.0_r3` (build `BP3A.250905.014`, 2025-09-05 SPL)
- Android 17: in beta upstream; `lynx` factory images available via
  https://source.android.com/docs/setup/reference/build-numbers — pick the latest
  `android-16.0.0_r*` stable tag for the initial build; plan an Android 17 rebase
  once it reaches stable for `lynx`.

Both bases ship the Linux kernel (GPL-2) as the platform. All detection code and
deps are MIT/Apache on top. This satisfies the owner's GPL-kernel-as-platform
ruling (2026-06-16).

Both require self-signing with custom AVB (Android Verified Boot) keys and
relocking the bootloader with `fastboot flashing lock` after flashing.

### Comparison

| Factor | AOSP-vanilla | GrapheneOS |
|---|---|---|
| Licence | Apache-2.0 userspace + GPL-2 kernel | Same base + hardening patches (Apache/GPL). GrapheneOS's trademark policy does **not** sanction forks marketed under its name. |
| `lynx` support | Official AOSP factory images + vendor/driver binaries from Google. Documented and reproducible. | Active and well-maintained — but forking it requires diverging from its signed OTA channel entirely. |
| Verified boot | Standard AVB2 self-signed with our own keys; relocked bootloader, same as any custom ROM. | GrapheneOS adds its own AVB extension + key-pinning in its updater. Those benefits apply only to GrapheneOS's own signed builds, not to a fork. |
| OTA | `update_engine` + our own OTA server (or simple adb sideload for a dedicated single device). | Same after a fork. GrapheneOS's update channel is lost. |
| Framework fork cost | One codebase to maintain (AOSP). Security patches = cherrypick from `android-security-*` tags. | Two codebases (AOSP upstream + GrapheneOS delta). GrapheneOS has an aggressive rebase cadence; our fork adds a third layer. |
| Privacy hardening | Baseline AOSP (fine for a dedicated, freshly wiped child device with no Google account). | Hardened — but most of GrapheneOS's user-privacy additions (sandboxed Google Play, network-permission toggle) are irrelevant or counterproductive on a tightly controlled child device. |
| Priv-app + custom service | Standard AOSP mechanism, fully documented. | Same mechanism, slightly more complex due to GrapheneOS build system overlays. |

### Recommendation

**Use AOSP-vanilla (`android-16.0.0_r3` for `lynx`).**

GrapheneOS's verified-boot hardening applies only to its own signed chain; the
moment we fork and self-sign, we inherit the same trust model as plain AOSP while
adding significant out-of-tree maintenance burden. AOSP-vanilla gives us the
documented, unsurprising base for deep framework customisation, official Pixel 7a
factory/vendor binaries, and the simplest security-patch cadence. The dedicated
child device, freshly wiped, with no Google account and our own signing key, does
not need GrapheneOS's user-privacy features.

---

## 2. Build host and pipeline

> **THIS ENTIRE SECTION IS PARKED.**
> The image build, signing, flashing, OTA, and on-device validation cannot be run
> in the current Windows dev environment. They require a Linux build host and the
> physical Pixel 7a (`lynx`). Mark as BLOCKED until both are available.

### 2.1 Build host requirements

- OS: Ubuntu 22.04 LTS (or 24.04) x86_64. AOSP does not support macOS for
  production builds or Windows at all.
- Disk: ≥ 400 GB free (AOSP source ~300 GB checked out + build artifacts).
- RAM: ≥ 64 GB (AOSP link step can spike above 32 GB; 64 GB is comfortable).
- CPU: ≥ 8 cores. A full AOSP build for one target takes 2–4 h on 16 cores.
- Java: OpenJDK 21 (Android 15/16 requirement).
- Python 3.9+ and standard AOSP build deps (`repo`, `make`, `ninja`, etc.).

### 2.2 Repo init and sync

```bash
# Install repo tool (Google-signed binary).
mkdir -p ~/bin && curl -o ~/bin/repo https://storage.googleapis.com/git-repo-downloads/repo
chmod +x ~/bin/repo

# Choose the target tag — OPEN QUESTION: pin to android-16.0.0_r3 or await
# android-17.0.0_r* stable once lynx factory images ship.
cd /aosp
repo init -u https://android.googlesource.com/platform/manifest \
    -b android-16.0.0_r3
repo sync -c -j$(nproc) --no-tags
```

Download the Pixel 7a vendor/driver binaries for the chosen build fingerprint from
https://developers.google.com/android/drivers (lynx, matching SPL). Extract to the
AOSP root and run `./extract-google_devices-lynx.sh`.

### 2.3 Build

```bash
source build/envsetup.sh
lunch aosp_lynx-userdebug          # userdebug for initial validation
# After validation: aosp_lynx-user (production)

make -j$(nproc)
```

Add PH Bulwark modules **before** the `make` step (see §3 and §4).

### 2.4 Signing (release keys)

Use `user` (not `userdebug`) for any guardian-provisioned image.

```bash
# Generate per-install release keys (done ONCE, stored offline — see §5.3).
# Keys for: platform, media, shared, releasekey, verity (AVB).
development/tools/make_key_star.sh  # or generate with openssl per AOSP signing docs

# Sign the target files package.
sign_target_files_apks \
    -o \
    -d /path/to/release/keys \
    out/target/product/lynx/lynx-target_files-*.zip \
    signed-lynx-target-files.zip

# Build flashable OTA + fastboot images.
ota_from_target_files signed-lynx-target-files.zip lynx-ota.zip
img_from_target_files signed-lynx-target-files.zip lynx-imgs.zip
```

### 2.5 Flashing

```bash
# Unlock bootloader (factory reset — only on a fresh, dedicated device).
fastboot flashing unlock

# Flash all partitions.
fastboot update lynx-imgs.zip

# Relock with our own AVB key — the device now only boots images we sign.
# OPEN QUESTION: exact avbtool relock procedure for Android 16 lynx — confirm
# against platform/bootable/libbootloader and avb docs before executing.
fastboot flashing lock
```

NEVER unlock/flash the Pixel 7 with irreplaceable family data — only the dedicated
Pixel 7a (`lynx`) acquired specifically for this purpose (owner ruling 2026-06-16).

### 2.6 OTA update delivery

For a fleet of one dedicated device: sideload via `adb sideload lynx-ota.zip` in
recovery. For a small managed fleet: a minimal OTA server (nginx serving the OTA
zip at a known URL) consumed by `update_engine` on the device. Full-channel OTA
infra (A/B streaming) is out of scope for a single-device deployment; add it when
the fleet grows.

---

## 3. Increment 2 (B) — child app as a privileged system app

### 3.1 What changes from Increment 1

In Increment 1 (Device-Owner on stock), `platform/android` is a normal APK granted
Device-Owner permissions at provisioning time. It can be removed by a determined
child who navigates deep enough into Settings, even though DO makes it harder.

In Increment 2, the same APK is embedded in the read-only `/system/priv-app`
partition. It cannot be removed without reflashing the device. Device-Owner
provisioning continues to apply on top (the DO permission grants survive the
priv-app move).

### 3.2 Soong module (`Android.bp` sketch)

**Signing posture for Increment 2:** `certificate: "platform"` (signed with the
same key as `system_server`). This is the preferred posture for a child-protection
system app: platform signature match alone grants all `signature|privileged`
permissions without requiring a per-permission allowlist entry. The
`ro.control_privapp_permissions=enforce` boot-block risk (§3.3) applies primarily
to priv-apps signed with a **non-platform** certificate; a platform-signed app is
granted `signature` perms by key match. The allowlist in §3.3 is added as
belt-and-suspenders hardening and to document which permissions the app actually
uses, but it is not the sole grant mechanism here.

Add to `platform/android/app/Android.bp` (create if absent):

```bp
android_app {
    name: "PHBulwark",
    srcs: ["src/main/java/**/*.kt"],
    resource_dirs: ["src/main/res"],
    manifest: "src/main/AndroidManifest.xml",
    platform_apis: true,          // access to @hide APIs; needed for Inc 3 hooks
    privileged: true,             // installs to /system/priv-app
    certificate: "platform",      // signed with the platform key (same as system_server)
    // The NSFW ONNX model asset.
    asset_dirs: ["src/main/assets"],
    jni_libs: ["libbulwark_client"],
    // Keep the .so from being stripped; the Rust cdylib exports JNI symbols by name.
    jni_uses_sdk_apis: true,
    required: ["libbulwark_client"],
    optimize: {
        enabled: false,  // ProGuard off; Rust JNI symbol names must not be mangled.
    },
}

// The Rust JNI cdylib (built separately via cargo-ndk; prebuilt here).
cc_prebuilt_library_shared {
    name: "libbulwark_client",
    srcs: ["../rust/bulwark-android/jniLibs/arm64-v8a/libbulwark_client.so"],
    shared_libs: [],
    strip: { none: true },
    compile_multilib: "64",
}
```

Place the module directory reference in `device/google/lynx/device.mk` (or the
project overlay):

```makefile
PRODUCT_PACKAGES += PHBulwark
```

### 3.3 Privileged-permission allowlist

With `ro.control_privapp_permissions=enforce` (set in Android 8+), any signature|
privileged permission used by a priv-app that is NOT listed in the allowlist causes
a boot-time policy violation (`PackageManager` marks the app as having a disabled
component or throws a hard error, depending on the Android version). This can block
boot. Allowlist file must exist before the first boot with the app present.

Create `/system/etc/permissions/privapp-permissions-phbulwark.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!--
  Privileged-permission allowlist for PHBulwark (PH Bulwark child-protection app).
  Required by ro.control_privapp_permissions=enforce (Android 8+).
  Only permissions actually used by the app are listed here.
-->
<permissions>
    <privapp-permissions package="co.predatorhunters.bulwark">
        <!-- System screenshot without a per-use dialog (platform-signed priv-app). -->
        <permission name="android.permission.READ_FRAME_BUFFER"/>
        <!-- Screen capture for the detection pipeline (no MediaProjection dialog). -->
        <permission name="android.permission.CAPTURE_VIDEO_OUTPUT"/>
        <!-- Foreground service exemptions (detection service runs always-on). -->
        <permission name="android.permission.FOREGROUND_SERVICE"/>
        <permission name="android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION"/>
        <!-- Status-bar control (for the protection-status indicator). -->
        <permission name="android.permission.STATUS_BAR"/>
        <!-- Device policy (Device Owner continues to apply on top of priv-app). -->
        <permission name="android.permission.MANAGE_DEVICE_ADMINS"/>
        <!-- System-level overlay (block overlay at WindowManager). -->
        <permission name="android.permission.INTERNAL_SYSTEM_WINDOW"/>
        <!-- Non-removable package protection. -->
        <permission name="android.permission.DELETE_PACKAGES"/>
    </privapp-permissions>
</permissions>
```

Add to `Android.bp` or `device.mk`:

```makefile
PRODUCT_COPY_FILES += \
    device/google/lynx/phbulwark/privapp-permissions-phbulwark.xml: \
    system/etc/permissions/privapp-permissions-phbulwark.xml
```

OPEN QUESTION: audit the final permission set against the actual
`AndroidManifest.xml` in `platform/android/app/src/main/AndroidManifest.xml` once
the Do-mode feature set is stable. Add any missed `signature|privileged` perms;
remove any not declared in the manifest. An allowlist that is too broad is a
security risk; too narrow blocks boot.

### 3.4 Silent capture without an AccessibilityService

A core goal of Increment 2 is removing the AccessibilityService dependency
(fragile, defeat-able by toggling a11y off in Settings). Platform-signed priv-apps
are granted `READ_FRAME_BUFFER` and `CAPTURE_VIDEO_OUTPUT` by signature match with
no per-use dialog.

**Increment 2 capture path (no AccessibilityService for screen capture):**

Replace `BulwarkAccessibilityService.takeScreenshot()` with a direct call to
`SurfaceControl.screenshot()` (or `ScreenshotHelper.takeScreenshot()` from the
internal API, both accessible to platform-signed apps). This runs in a background
`HandlerThread` inside the `PHBulwark` app process, triggered by a
`DisplayEventReceiver` (VSYNC listener) at the chosen cadence (~1 Hz), independent
of any `AccessibilityService` lifecycle.

```kotlin
// Simplified sketch — platform-signed priv-app only.
val result = SurfaceControl.screenshot(
    SurfaceControl.createDisplay("PHBulwark capture", false),
    displayBounds
)
// result is a Bitmap in hardware buffer; copy to software for ONNX inference.
```

`BulwarkAccessibilityService` is **retained in Increment 2** only for the
node-tree TEXT path (extracting chat text from `AccessibilityNodeInfo` — it is
still the most reliable way to read text from E2E-encrypted apps without a
framework patch). The screenshot/capture path is fully migrated off it. In
Increment 3, the node-tree text path is also promoted to a framework hook (§4.3)
and the AccessibilityService dependency is eliminated entirely.

OPEN QUESTION (Inc 2): confirm `SurfaceControl.screenshot()` call signature for
Android 16 against `frameworks/base/core/java/android/view/SurfaceControl.java`
before integrating. The internal API surface changes across major Android versions.

### 3.5 Non-removability

Packages installed in `/system/priv-app` are mounted read-only. `adb uninstall`
and Settings > Apps > Uninstall both fail with `INSTALL_FAILED_INTERNAL_ERROR` or
simply grey out the Uninstall button. The child cannot remove the app without
reflashing. The guardian retains control via the Manager console.

The existing uninstall-guard in `BulwarkAccessibilityService.guardAgainstUninstall`
and `TamperReporter` remain active as belt-and-suspenders for navigation-level
attempts (the child opening Settings → Apps to look at the app).

### 3.6 SELinux notes (Increment 2)

AOSP ships a default `untrusted_app` domain. A priv-app with `certificate: "platform"`
runs in the `platform_app` domain. This grants significantly more MAC permissions
than `untrusted_app` and is appropriate for a guardian-provisioned protection app.

For Increment 2, the `platform_app` domain is sufficient. No custom SELinux policy
is required. If any `avc: denied` messages appear in `logcat` during on-device
validation, add targeted `allow` rules in `device/google/lynx/sepolicy/` rather
than broadening the domain.

For Increment 3 (dedicated system service), a custom SELinux domain is required —
see §4.6.

---

## 4. Increment 3 (C) — framework-baked protection system service

### 4.1 Service architecture: system_server companion vs native daemon

Two options:

**Option A — `system_server` companion (Java/Kotlin, registered in
`SystemServer.java`):**
- Runs in the same process as `system_server`; access to all internal Android APIs
  (`WindowManager`, `SurfaceControl`, `AccessibilityManagerService`) without JNI
  indirection at the Java layer.
- A crash or OOM in the detection code can destabilise `system_server`, causing a
  system restart (the "watchdog" kills the process if it hangs).
- JNI to the Rust cdylib (`libbulwark_client`) is straightforward from Java.

**Option B — dedicated native daemon (`/system/bin/bulwarkd`, init.rc service):**
- Runs in its own process with its own SELinux domain; a crash restarts only
  the daemon (init `restart on_failure`), not the whole system.
- Communicates with `system_server` via Binder or a Unix socket for capture
  (frames pushed to it by a hook in `SurfaceFlinger` or `DisplayManager`).
- The Rust binary runs natively (no JNI); `bulwark-android` cdylib becomes a
  standalone binary or a static lib linked into `bulwarkd`.
- More complex IPC plumbing but better isolation.

**Recommendation: Option B (dedicated daemon) for Increment 3.**

Keeping detection logic outside `system_server` isolates any model-inference OOM
or Rust panic from the core OS. The IPC cost (Binder frame delivery) is acceptable
given the per-second cadence of detection. A `system_server` hook is used only for
the block-overlay and alert dispatch, not for the inference itself.

### 4.2 Compositor/SurfaceFlinger capture hook

SurfaceFlinger provides `ScreenCapture::captureDisplay()` (in
`libs/gui/ScreenCapture.cpp`), exposed to privileged callers as
`SurfaceControl.screenshot()` in the Java layer. For a native daemon:

- Register a `DisplayEventReceiver` (VSYNC listener) in `bulwarkd` to trigger
  capture on each frame (or on a cadence, e.g. every 500 ms — OPEN QUESTION on the
  right cadence; more frequent = more CPU; event-driven on content change is
  preferred but requires a `SurfaceFlinger` callback not currently public).
- Alternative: hook `SurfaceFlinger::onCompositionPresented()` to push a frame
  reference to `bulwarkd` via a Binder callback. This is the cleanest source
  (post-composition, exactly what the user sees) but requires a small SurfaceFlinger
  patch.
- For Increment 3 MVP: use periodic `ScreenCapture::captureDisplay()` at ~1 Hz
  (the same effective rate as `AccessibilityService.takeScreenshot` which the OS
  already throttles to ~1/s). Event-driven hook is a follow-on.

Frame lifetime: the frame buffer lives in memory only for the duration of the
inference call. No frame is written to storage, transmitted, or hashed. The buffer
is released immediately after classification (no-media invariant, same as the
existing `BulwarkAccessibilityService` — Bitmap recycled in `captureAndScan()`).

### 4.3 Text path — native text vs OCR

This is the critical design distinction from Increment 1/2.

**Native text (selectable / accessibility-tree text):**

In Increment 3, `bulwarkd` registers as a trusted client of
`AccessibilityManagerService` (AMS) at the framework layer, not as a user-space
`AccessibilityService`. AMS delivers `AccessibilityEvent` objects (including
`TYPE_VIEW_TEXT_CHANGED`, `TYPE_WINDOW_CONTENT_CHANGED`) to all registered
listeners without requiring the user to enable an accessibility service in Settings
— because `bulwarkd` is a system service with a trusted Binder identity
(`DUMP` + `PACKAGE` protection level = `signature`).

For all apps where the text is readable in the accessibility node tree (chat apps
with `TextView`, `EditText`, web `WebView` DOM nodes exposed via AMS), the text
path is:

```
AMS event → bulwarkd Binder callback
          → bulwark-text grooming rule engine (deterministic, rules-first)
          → verdict → action (block overlay / guardian alert)
```

No OCR. No screenshot. No vision model. This is the primary text path and covers
the vast majority of chat apps (`WhatsApp`, `Signal`, `Telegram`, `Messenger`,
`Instagram`, `Snapchat` — all expose text to the a11y tree when the user is
reading it on screen).

**Pixel text (OCR + NSFW vision model):**

OCR (`Tesseract`, `tesseract4android`) and the NSFW vision model
(`bulwark-vision`, `crates/bulwark-vision/models/nsfw_detector.onnx`,
AdamCodd ViT Apache-2.0) run ONLY for content that cannot be read from the
accessibility node tree:
- Images, memes, screenshots rendered as `<img>` or `Bitmap`.
- Canvas/WebGL/GPU-drawn surfaces (games, animated apps, video overlays).
- Text drawn into images (meme captions, video subtitles burned into frames).
- Any surface where `getContentDescription()` is absent and node text is empty.

Decision tree in `bulwarkd`:

```
frame captured
  ├── AMS node-tree text available for this surface?
  │     YES → grooming engine (no OCR, no screenshot for text)
  │     NO  → OCR the frame → grooming engine
  └── always → NSFW vision model on the frame (pixel content)
```

This matches the design in `docs/design/child-safety-rom.md §C` exactly: "read
native text directly at the framework layer — no OCR for selectable text; OCR (+
NSFW vision model) stays only for pixel text."

The existing `BulwarkAccessibilityService` implements this split already at the
app level (see `onAccessibilityEvent` in `BulwarkAccessibilityService.kt` —
`collectText(root)` for tree text, `maybeCapture(…, ocrText = true)` only when
needed). Increment 3 promotes the same logic into the framework service.

### 4.4 Block action — WindowManager overlay

When the verdict is `BLOCK` (high-confidence harmful content or `CsamSuspected`):

`bulwarkd` calls `WindowManager` via Binder (using the `INTERNAL_SYSTEM_WINDOW`
permission granted to its SELinux domain) to add a `TYPE_APPLICATION_OVERLAY`
window at the maximum `Z`-order, covering the harmful surface. This is equivalent
to `showBlockOverlay()` in `BulwarkAccessibilityService.kt` but dispatched from a
native daemon rather than an accessibility service.

For localized cover-up (explicit imagery, partial tile): same tiling approach as
`Nsfw.localize()` — N×N grid scored, offending region covered with a
`FrameLayout`-equivalent native overlay, rest of screen visible.

**Fail-CLOSED invariant:** In Increment 3, the framework service is the PRIMARY
protection, not an additive layer. If `bulwarkd` cannot deliver a verdict (ONNX
Runtime unavailable, OOM, inference timeout), the default action is BLOCK
(equivalently: fail closed on the coverage gap), consistent with
`bulwark-policy`'s `fail_closed_uncovered` and the engine invariants. This differs
from the Increment 1/2 accessibility service which is additive and deliberately
fail-open (see `Nsfw.kt` header comment and `StubScorer` in `bulwark-vision`).

### 4.5 Guardian alert path

No change to the alert protocol. On a BLOCK or FLAG verdict:

```
bulwarkd verdict (on-device)
  → redacted alert payload (category + severity + content-free rationale, no raw media)
  → mTLS to the PH Bulwark cluster (same gRPC+TLS :8443 path as today)
  → guardian's PH Bulwark Manager console
```

The guardian-alert path (`AlertNotifier.kt` / `AlertRelay` gRPC service) is
unchanged. `bulwarkd` calls the existing Rust client library (`libbulwark_client`)
over JNI (or directly if `bulwarkd` is a native binary linking the same crate
statically). No raw message content, no raw image, no raw audio leaves the device.
Evidence carries only SHA-256 hashes and redacted excerpts, same as today.

CSAM path is unchanged: detect → block → NCMEC report path via the cluster. Never
stored, never remediated, never served.

### 4.6 SELinux policy for `bulwarkd`

A new SELinux type is required. Minimal policy sketch (add to
`device/google/lynx/sepolicy/`):

```te
# bulwarkd.te
type bulwarkd, domain;
type bulwarkd_exec, exec_type, file_type, system_file_type;

init_daemon_domain(bulwarkd)

# Frame capture via SurfaceFlinger / ScreenCapture.
allow bulwarkd surfaceflinger_service:service_manager find;
allow bulwarkd surfaceflinger:binder call;
binder_use(bulwarkd)

# WindowManager overlay for the block window.
allow bulwarkd windowmanager_service:service_manager find;
allow bulwarkd windowmanager:binder call;

# AccessibilityManagerService events (node-tree text path).
allow bulwarkd accessibility_service:service_manager find;

# AudioRecord / privileged audio capture (voice detection path).
allow bulwarkd audio_device:chr_file { read write };
allow bulwarkd audioserver_service:service_manager find;
allow bulwarkd audioserver:binder call;

# Read model assets from /system/etc/bulwark/ (NSFW model baked in).
allow bulwarkd system_file:file { read open getattr };
allow bulwarkd system_file:dir { read open getattr search };

# Read/write the guardian-provisioned grooming model at /data/misc/bulwark/models/.
# This path is labelled bulwarkd_data_file (add to file_contexts):
#   /data/misc/bulwark(/.*)?  u:object_r:bulwarkd_data_file:s0
type bulwarkd_data_file, file_type, data_file_type;
allow bulwarkd bulwarkd_data_file:dir { create read write search add_name remove_name };
allow bulwarkd bulwarkd_data_file:file { create read write open getattr unlink };

# Alert relay: network access to the cluster (mTLS).
allow bulwarkd self:tcp_socket { create connect read write shutdown };
allow bulwarkd port:tcp_socket name_connect;
```

This is a starting sketch. The exact set of `avc: denied` rules will be determined
during on-device validation. Use `audit2allow` on validation logs, review each rule
before adding. Do not use the `permissive bulwarkd` shortcut in production.

### 4.7 init.rc service declaration

```rc
# /system/etc/init/bulwarkd.rc
service bulwarkd /system/bin/bulwarkd
    class late_start
    user system
    group system audio inet
    capabilities NET_BIND_SERVICE
    seclabel u:r:bulwarkd:s0
    restart_on_failure
    # Shut down gracefully on shutdown; the kernel kills it if it doesn't exit.
    shutdown SIGTERM
    oneshot
```

`class late_start` ensures `bulwarkd` starts after `SurfaceFlinger` and
`WindowManager` are ready. `restart_on_failure` lets init recover from a transient
crash without a full `system_server` restart.

### 4.8 System audio capture for grooming-over-voice

Grooming increasingly occurs over voice/video calls (WhatsApp calls, Messenger
Rooms, Discord). Increment 3 adds a privileged audio capture path:

- `bulwarkd` holds the `CAPTURE_AUDIO_OUTPUT` privilege (a `signature`-level
  permission, grantable to a system service in its SELinux domain). This permission
  allows recording the device's audio output mix (what the speaker is playing),
  not the microphone — i.e. it captures the remote caller's voice as heard by the
  child, which is the predatory content risk.
- The captured audio stream is sent to the existing `bulwark-text` grooming
  pipeline via speech-to-text. The on-device STT path uses the capability-detect
  model: ML Kit on-device STT if available, else the bundled Whisper (CPU) fallback
  (per `on-device-AI-fallback` memory note).
- No raw audio ever leaves the device. The STT transcript is processed in the same
  pipeline as text (redacted evidence only). No audio is stored.
- The audio path runs at lower priority than the visual path and can be disabled
  per guardian policy (a child device used by a deaf child, for example, should not
  run an always-on audio pipeline with no benefit).

OPEN QUESTION: `CAPTURE_AUDIO_OUTPUT` captures the speaker mix. This includes the
child's own voice in a call if the device echoes it. Confirm with counsel whether
this falls within the guardian's consent scope for a child device they own. The
intent is the remote caller's speech (incoming grooming), not local recording.

### 4.9 Guardian-provisioned model weights delivery

Per the owner ruling (2026-06-16), the grooming detector ONNX weights
(`grooming_detector.onnx`) are NOT baked into the public ROM image. They are
delivered via the signed provisioning flow:

1. The guardian enrolls the device with the Manager console (QR/NFC provisioning,
   same as Increment 1 `Enrollment.kt`).
2. Over the established mTLS channel, the server delivers the signed model package
   (a signed OTA-style zip containing `grooming_detector.onnx` + a signature
   over it with the cluster's private key).
3. `bulwarkd` verifies the signature before installing the model to
   `/data/misc/bulwark/models/` (a labelled SELinux path, not world-readable).
4. If no model is present (device enrolled but model not yet delivered),
   `bulwarkd` operates in NSFW-only mode until delivery completes.

The NSFW model (`nsfw_detector.onnx`, Apache-2.0, baked into `/system/etc/bulwark/`)
is present from first boot. The grooming model is guardian-gated.

---

## 5. Buildable now vs PARKED, and open questions

### 5.1 Buildable in the current dev environment (Windows + existing Gradle)

- The `platform/android` APK (Increment 2 priv-app candidate): already builds with
  Gradle + `cargo ndk`. The Soong `Android.bp` module and allowlist XML can be
  authored and reviewed now.
- The SELinux policy sketches (§3.6, §4.6): writable now, tested only on a Linux
  build host.
- The `bulwarkd` native daemon design (§4): architecture and Rust API surface can
  be designed and prototyped now against the existing `libbulwark_client` cdylib.
- This design document.

### 5.2 PARKED — needs a Linux build host + the physical Pixel 7a

- Repo sync + full AOSP build for `lynx`.
- Integration of the `Android.bp` module into the AOSP tree.
- First boot with the priv-app embedded.
- SELinux policy validation (`avc: denied` logs + `audit2allow` iteration).
- The block overlay and WindowManager hook integration.
- `bulwarkd` daemon build + init.rc registration + first-boot test.
- OTA signing and sideload test.
- Performance profiling: detection latency at 1 Hz capture cadence, memory
  footprint of `bulwarkd` (Rust ONNX inference + Tesseract).

### 5.3 Open questions for owner/architect sign-off

1. **Verified-boot key custody.** Self-signing with our own AVB keys means the
   device only boots images we sign. The signing key is the root of trust for the
   device. Loss of the key = inability to deliver future OTA updates to that device
   (must reflash with a new key, or the device is stuck). The same key also signs
   the guardian-provisioned model package (§4.9). Key generation, backup, rotation
   policy, and HSM/offline storage need explicit owner sign-off before the first
   keyed build. This is the single highest-risk item in the ROM path.

2. **Android version to target.** The recommendation is `android-16.0.0_r3`
   (`lynx`). Android 17 is approaching stable; if the ROM build is 6+ months away,
   starting on Android 17 avoids an immediate major-version rebase. OPEN: owner to
   confirm target version once the build host timeline is known.

3. **Bootloader relock and OEM unlock status.** `fastboot flashing lock` on a
   device with a custom AVB key requires the device to have been unlocked first
   (factory reset). Confirm the dedicated Pixel 7a has never been relocked with
   Google's keys in a state we cannot undo, and that the owner is ready to perform
   the factory-reset + reflash on that specific device (not the family Pixel 7).

4. **`CAPTURE_AUDIO_OUTPUT` consent scope** (§4.8). See note above. Legal/guardian
   review before enabling the voice capture path.

5. **`ro.control_privapp_permissions` audit.** The allowlist in §3.3 is a draft.
   Before the first build, run `aapt2 dump permissions
   platform/android/app/src/main/AndroidManifest.xml` and cross-reference every
   `signature|privileged` permission against the allowlist. A missing entry causes
   a boot-time policy violation.

6. **SurfaceFlinger frame hook cadence.** The §4.2 recommendation of ~1 Hz periodic
   capture matches the current AccessibilityService rate. Confirm with the guardian
   UI/UX brief whether this cadence is sufficient or whether a content-change-event-
   driven hook (requiring a SurfaceFlinger patch) is required for Increment 3.

7. **`system_server` companion vs dedicated daemon.** The recommendation is Option B
   (dedicated daemon, §4.1). If inference OOM is low-risk (the ONNX ViT is ~80 MB
   resident), Option A is simpler. Owner/architect to confirm the risk tolerance.

---

## 6. Detection reuse summary

No new detectors are introduced by Increments 2 or 3. All detection is reused from
existing, already-landed crates:

| Detector | Crate | What it detects | Where used in Inc 3 |
|---|---|---|---|
| NSFW vision | `crates/bulwark-vision` (`nsfw_detector.onnx`, Apache-2.0) | Sexual/explicit imagery in frames | `bulwarkd` frame capture path |
| Grooming rules | `crates/bulwark-text` (`GroomingRuleEngine`) | Predatory conversation patterns | `bulwarkd` AMS node-tree text path |
| Grooming classifier | `crates/bulwark-text` (`grooming_detector.onnx`, guardian-provisioned) | Classifier backstop (confirm-only, never gates) | Same text path |
| OCR | `tesseract4android` / Tesseract | Text in images, video overlays, memes | `bulwarkd` pixel-text path only |
| STT (voice) | ML Kit / bundled Whisper | Speech → text for grooming detection | `bulwarkd` audio capture path |

Engine invariants unchanged: `#![forbid(unsafe_code)]` (except audited FFI), no
LLM in any hot path, no explicit-media persistence, mTLS between nodes, CSAM =
detect + block + NCMEC report + never stored.

---

*Document authored 2026-06-19. DRAFT — pending owner review of all OPEN QUESTIONs
before any build host or signing-key work is commenced.*
