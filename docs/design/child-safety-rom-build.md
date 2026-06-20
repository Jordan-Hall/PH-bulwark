# Child Safety ROM — Increment 2 + 3 Design Runbook

> **STATUS: DRAFT — open questions resolved per owner decisions 2026-06-20; document
> remains DRAFT pending owner review (especially the new §7 camera section, which is
> a first-pass design and has unresolved HAL compatibility risks).**
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

### What is current (as of 2026-06-20)

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

**RESOLVED (D2, 2026-06-20): Target Android 16 (`android-16.0.0_r3`) now and track
upstream — periodically rebase / merge AOSP security and bug-fix tags as they are
published. This replaces the "await Android 17 stable" alternative. Android 17 is
not yet stable for `lynx`; rebase to it once stable factory images ship.**

---

## 2. Build host, pipeline, and emulator-first strategy

> **PARTIALLY PARKED — emulator (Cuttlefish) path is active design and the target
> for initial CI validation; physical `lynx` flashing remains blocked until a
> Linux build host and the dedicated Pixel 7a are available.**
>
> **RESOLVED (D3, 2026-06-20): Validate on the Cuttlefish emulator first
> (`aosp_cf_x86_64_phone` / `aosp_cf_arm64_only_phone`). The physical Pixel 7a
> (`lynx`) is a later step. This removes the device dependency for early
> development and CI, while keeping the build-host (Linux) requirement.**

### 2.1 Build host requirements

- OS: Ubuntu 22.04 LTS (or 24.04) x86_64. AOSP does not support macOS for
  production builds or Windows at all.
- Disk: ≥ 400 GB free (AOSP source ~300 GB checked out + build artifacts).
- RAM: ≥ 64 GB (AOSP link step can spike above 32 GB; 64 GB is comfortable).
- CPU: ≥ 8 cores. A full AOSP build for one target takes 2–4 h on 16 cores.
- Java: OpenJDK 21 (Android 15/16 requirement).
- Python 3.9+ and standard AOSP build deps (`repo`, `make`, `ninja`, etc.).
- **Cuttlefish host additional requirements:** KVM-capable kernel
  (`/dev/kvm` available); `libvirt`/`crosvm` or the Cuttlefish host packages
  from `device/google/cuttlefish/debian/` (see AOSP Cuttlefish docs).

### 2.2 Repo init and sync

```bash
# Install repo tool (Google-signed binary).
mkdir -p ~/bin && curl -o ~/bin/repo https://storage.googleapis.com/git-repo-downloads/repo
chmod +x ~/bin/repo

# Target: android-16.0.0_r3 (RESOLVED D2 — Android 16 + track upstream).
cd /aosp
repo init -u https://android.googlesource.com/platform/manifest \
    -b android-16.0.0_r3
repo sync -c -j$(nproc) --no-tags
```

When tracking upstream: after Google publishes an `android-security-*` or
`android-16.0.0_rN` tag, `repo sync` to that tag and rebuild. Cherry-pick any
diverged PH Bulwark patches on top.

For Cuttlefish validation, no vendor/driver binary download from
`developers.google.com/android/drivers` is required — Cuttlefish uses its own
software HAL stack. For the physical `lynx` image, download the matching
vendor/driver binaries (lynx, matching SPL) from that URL and run
`./extract-google_devices-lynx.sh`.

### 2.3 Build targets

**Cuttlefish (primary — CI + early development):**

```bash
source build/envsetup.sh

# x86_64 host (standard CI):
lunch aosp_cf_x86_64_phone-userdebug

# ARM64 host (optional; use branch aosp-android-latest-release):
# lunch aosp_cf_arm64_only_phone-userdebug

make -j$(nproc)
```

**Physical Pixel 7a (`lynx`) — deferred until build host + device available:**

```bash
source build/envsetup.sh
lunch aosp_lynx-userdebug          # userdebug for initial validation
# After validation: aosp_lynx-user (production)
make -j$(nproc)
```

Add PH Bulwark modules **before** the `make` step (see §3 and §4).

### 2.4 Cuttlefish launch (emulator-first validation)

```bash
# After build, launch the Cuttlefish instance:
launch_cvd \
    --daemon \
    --num_instances=1 \
    --cpus=4 \
    --memory_mb=4096

# Connect via adb:
adb -s 0.0.0.0:6520 shell

# Tear down:
stop_cvd
```

The Cuttlefish camera HAL is a software virtual camera
(`device/google/cuttlefish/guest/hals/camera/`) — it serves synthetic frames
from a configurable fake sensor. This is sufficient for validating the camera
hook in §7 (the interception logic, NSFW gate wiring, fail-closed behaviour)
without real camera hardware. Vendor-binary HAL compatibility (a risk for `lynx`
in §7.6) does not apply to Cuttlefish.

### 2.5 Signing (release keys)

Use `user` (not `userdebug`) for any guardian-provisioned image.

**RESOLVED (D1, 2026-06-20): AVB signing keys must be hardware-backed — stored in
an HSM, YubiHSM, or cloud KMS (e.g. Google Cloud KMS, AWS CloudHSM). Software
file-based key generation is NOT acceptable for the AVB root of trust. Key
generation, custody procedure, and KMS integration must be agreed with the owner
before the first signed build. This is the single highest-risk item in the ROM
path.**

```bash
# Sign the target files package (avbtool invocation + sign_target_files_apks
# must be wired to the KMS signing backend — exact CLI depends on chosen KMS).
sign_target_files_apks \
    -o \
    -d /path/to/release/keys \   # KMS-backed keys; not a raw file path
    out/target/product/<target>/target_files-*.zip \
    signed-target-files.zip

# Build flashable OTA + fastboot images.
ota_from_target_files signed-target-files.zip target-ota.zip
img_from_target_files signed-target-files.zip target-imgs.zip
```

**Cuttlefish signing note:** Cuttlefish builds accept `userdebug` test keys for
emulator validation. Hardware-backed KMS signing is required only for the `lynx`
production image.

### 2.6 Flashing — Cuttlefish vs physical device

**Cuttlefish:** no bootloader unlock/relock needed — images load directly via
`launch_cvd`. Skip `fastboot flashing unlock/lock`. AVB key relock procedure
applies only to the physical device step.

**Physical Pixel 7a (`lynx`) — deferred:**

```bash
# Unlock bootloader (factory reset — only on the dedicated, freshly wiped 7a).
fastboot flashing unlock

# Flash all partitions.
fastboot update lynx-imgs.zip

# Relock with our KMS-backed AVB key — the device then boots only images we sign.
# Exact avbtool + fastboot --set-active relock procedure: confirm against
# platform/bootable/libbootloader and AVB docs for android-16.0.0_r3 before
# executing. Mechanical confirm required; do not execute against a device with
# data until procedure is reviewed.
fastboot flashing lock
```

NEVER unlock/flash the Pixel 7 with irreplaceable family data — only the dedicated
Pixel 7a (`lynx`) acquired specifically for this purpose (owner ruling 2026-06-16).

### 2.7 OTA update delivery

For a fleet of one dedicated device: sideload via `adb sideload target-ota.zip` in
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

**RESOLVED (D5, 2026-06-20): Proceed with this allowlist as drafted. Before the
first build, run a mechanical audit:**

```bash
aapt2 dump permissions \
    platform/android/app/src/main/AndroidManifest.xml
```

Cross-reference every `signature|privileged` permission against this allowlist.
Add any missing entries; remove any not declared in the manifest. An allowlist too
broad is a security risk; too narrow blocks boot. This audit is mechanical and must
be completed before the first image build — it is not an open question.

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

**RESOLVED (D8, 2026-06-20): The `SurfaceControl.screenshot()` call signature must
be confirmed against Android 16 source before integrating.**
Target file: `frameworks/base/core/java/android/view/SurfaceControl.java` in the
`android-16.0.0_r3` tree. The method exists on Android 15 as
`SurfaceControl.screenshot(Rect sourceCrop, int width, int height,
boolean useIdentityTransform, int rotation)` or the newer
`ScreenshotHelper.takeScreenshot(...)` variant. The exact overload and parameter
set changes across major Android versions. Mechanical confirm required — check the
actual source in the synced AOSP tree and update the Kotlin call site to match
before the first Cuttlefish boot.

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

**RESOLVED (D7, 2026-06-20): Option B — dedicated daemon (`bulwarkd`)**, its own
process, not inside `system_server`. Keeping detection logic outside `system_server`
isolates any model-inference OOM or Rust panic from the core OS. The IPC cost
(Binder frame delivery) is acceptable given the per-second cadence of detection.
A `system_server` hook is used only for the block overlay and alert dispatch, not
for the inference itself.

### 4.2 Compositor/SurfaceFlinger capture hook

SurfaceFlinger provides `ScreenCapture::captureDisplay()` (in
`libs/gui/ScreenCapture.cpp`), exposed to privileged callers as
`SurfaceControl.screenshot()` in the Java layer. For a native daemon:

- Register a `DisplayEventReceiver` (VSYNC listener) in `bulwarkd` to trigger
  capture at the chosen cadence.
- Alternative: hook `SurfaceFlinger::onCompositionPresented()` to push a frame
  reference to `bulwarkd` via a Binder callback. This is the cleanest source
  (post-composition, exactly what the user sees) but requires a small SurfaceFlinger
  patch.
- For Increment 3 MVP: use periodic `ScreenCapture::captureDisplay()` at 1 Hz.
  Event-driven hook is a follow-on (see D6 below).

**RESOLVED (D6, 2026-06-20): Start at 1 Hz, move to event-driven once proven.**
The 1 Hz periodic cadence matches the current AccessibilityService rate and is the
MVP. Event-driven (content-change-triggered) capture, requiring a SurfaceFlinger
patch, is a follow-on once 1 Hz is validated on-device.

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

**RESOLVED (D4, 2026-06-20): Audio capture is ENABLED by default with an OPT-OUT
toggle on the guardian setup screen.**

Design:
- Default ON at provisioning. The guardian setup wizard (Increment 1 QR/NFC
  provisioning flow, Manager console) shows a clear disclosure screen before
  provisioning completes: "Voice grooming detection is on by default. The child
  device's speaker audio (incoming calls and media) is analysed on-device to detect
  predatory conversation patterns. No audio is transmitted or stored. You can turn
  this off now or later in the Manager console."
- A toggle in the Manager console (`AudioCaptureEnabled` device policy flag,
  enforced via `DevicePolicyManager` custom bundle or `bulwarkd` config in
  `/data/misc/bulwark/config.json`) lets the guardian disable it post-provisioning.
- `CAPTURE_AUDIO_OUTPUT` scope note: this permission captures the device speaker
  output mix — i.e. the remote caller's voice as played to the child. Whether it
  also picks up the child's own microphone input echoed back (hardware-dependent)
  is a legal/consent nuance. **A guardian-facing disclosure in the setup wizard must
  clearly state that the audio analysis covers all audio played on the device.**
- Legal scope: in the UK (primary deployment), monitoring a minor's device by the
  legal guardian with disclosed, provisioned consent falls within the guardian's
  parental responsibility (Children Act 1989 / GDPR Art. 8 child-consent age).
  Confirm with counsel before commercial deployment, particularly for PECR and ICO
  guidance on monitoring. This is a guardian disclosure requirement, not a block
  on the feature.

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

## 5. Buildable now vs PARKED, and resolved decisions summary

### 5.1 Buildable in the current dev environment (Windows + existing Gradle)

- The `platform/android` APK (Increment 2 priv-app candidate): already builds with
  Gradle + `cargo ndk`. The Soong `Android.bp` module and allowlist XML can be
  authored and reviewed now.
- The SELinux policy sketches (§3.6, §4.6): writable now, tested only on a Linux
  build host.
- The `bulwarkd` native daemon design (§4): architecture and Rust API surface can
  be designed and prototyped now against the existing `libbulwark_client` cdylib.
  ✅ DONE (2026-06-20, PR #222): `platform/rom/` scaffold landed — `bulwarkd/`
  (Android.bp, .rc, main.cpp, sepolicy), `libbulwark_safety/` (C ABI header + C++
  wrapper), `camera-gate/` (the returnBufferLocked `.patch` + INTEGRATION.md).
  SCAFFOLD only — compiles against AOSP on a Linux host, not built/validated here.
- **Rust core via FFI** ✅ DONE host-side / IN PROGRESS on Android (2026-06-20,
  PR #223, branch `feat/rom-rust-ffi`, NOT merged): `platform/rom/libbulwark_safety/rust/`
  reuses `crates/bulwark-vision` (NSFW, `onnx`-gated) + `crates/bulwark-text`
  (rules-first grooming/adult text) and exports `bw_init_once` / `bw_score_nsfw` /
  `bw_score_text` over the C ABI — so ROM detection NEVER drifts from the shipping
  engine and detection is NOT re-implemented in C++. Fail-CLOSED throughout.
  Host-verified no-onnx (unit tests green); `ort`-on-Android cross-compile confirmed
  (`ort` + `bulwark-vision` build for `aarch64-linux-android`); the C++ wrapper
  (`bulwark_safety.cpp`) + camera-gate/`bulwarkd` wiring to call this ABI is the
  remaining integration step (currently the C++ side is a fail-closed stub).
- The camera hook design (§7): design and prototype work now; build validation
  needs the Cuttlefish emulator on a Linux host. The scaffold patch landed (#222,
  §7.3 `Camera3OutputStream::returnBufferLocked`) — still DRAFT, pending owner/architect
  sign-off, unvalidated.
- This design document.

### 5.2 PARKED — needs a Linux build host + Cuttlefish (emulator-first, then physical `lynx`)

- Repo sync + full AOSP build (`aosp_cf_x86_64_phone` first; `aosp_lynx` later).
- Integration of the `Android.bp` module into the AOSP tree.
- Cuttlefish launch and first boot with the priv-app embedded.
- SELinux policy validation (`avc: denied` logs + `audit2allow` iteration).
- The block overlay and WindowManager hook integration.
- `bulwarkd` daemon build + init.rc registration + first Cuttlefish boot test.
- OTA signing and sideload test.
- Performance profiling: detection latency at 1 Hz capture cadence, memory
  footprint of `bulwarkd` (Rust ONNX inference + Tesseract).
- Camera hook `Camera3Stream` patch (§7) — Cuttlefish software camera HAL is the
  dev/CI vehicle; `lynx` vendor HAL compat is a separate step.
- Physical `lynx` flashing — deferred until build host + dedicated 7a available.

### 5.3 Owner decisions — resolved (2026-06-20)

All 8 open questions are now resolved:

| # | Decision | Resolution |
|---|---|---|
| D1 | **Verified-boot key custody** | Hardware-backed (HSM / YubiHSM / cloud KMS) — not a file key. Procedure to be agreed before first signed build. |
| D2 | **Android version** | Android 16 (`android-16.0.0_r3`) now; track upstream with periodic rebases. |
| D3 | **Bootloader / device** | Validate on Cuttlefish emulator first (`aosp_cf_x86_64_phone`). Physical `lynx` is a later step. Bootloader relock deferred to physical step. |
| D4 | **Audio capture** | Enabled by default; guardian OPT-OUT toggle on setup screen + guardian disclosure. |
| D5 | **Privapp-permissions allowlist** | Proceed as drafted; mechanical audit against `AndroidManifest.xml` required before first build. |
| D6 | **Screen-scan cadence** | Start at 1 Hz; move to event-driven once proven. |
| D7 | **Service architecture** | Dedicated daemon (`bulwarkd`) — not inside `system_server`. |
| D8 | **`SurfaceControl.screenshot()` signature** | Mechanical confirm against Android 16 source (`android-16.0.0_r3` tree) before integrating. |

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

## 7. System-wide camera content-safety gate (every app) — DRAFT

> **DRAFT — this section is a first-pass design for owner/architect review. The hook
> architecture has unresolved risks (see §7.6). Do not begin implementation without
> owner sign-off on this section specifically.**

### 7.1 Motivation: the gap that stock parental controls cannot close

In a standard Android install, every third-party camera app (Snapchat, Instagram,
BeReal, etc.) accesses the camera HAL directly by calling
`CameraManager.openCamera()` → `CameraService.connectDevice()`. The resulting
camera stream goes from the HAL to the app's own `ImageReader` or `SurfaceTexture`
— bypassing any content-safety gate installed at the app layer.

Since Android 11, `ACTION_IMAGE_CAPTURE` intents are routed only to the preinstalled
system camera — so the standalone camera app (our `platform/android` child camera)
cannot see what Snapchat or Instagram capture. There is no user-space hook that
intercepts another app's live camera stream.

**The ROM opportunity:** because we own the AOSP framework source, we can add a
content-safety gate inside the camera pipeline at the system layer — below every
app, including those with their own embedded camera UI. Every capture from every
app passes through `CameraService` in `frameworks/av/services/camera/`. This is
the unique capability that a custom ROM provides and that no Play Store app can
replicate.

**Protective framing:** this gate prevents children from generating or sending
explicit self-imagery under coercion (sextortion), and from being exposed to
explicit imagery shared through camera-based UIs. It is equivalent to the content-
safety gate on the standalone camera app (§4.2 in the screen-capture path), now
applied system-wide. It runs exclusively on a guardian-owned device with disclosure
at provisioning. No frames are transmitted or stored.

### 7.2 Android 16 camera pipeline architecture (research summary, 2026-06-20)

Based on AOSP documentation and source review:

**Stack layers (top to bottom):**

```
App (Camera2 API / CameraManager)
  ↓  Binder IPC (ICameraService AIDL)
CameraService (frameworks/av/services/camera/libcameraservice/)
  ↓  creates per-session Camera2Client / Camera3Device
Camera3Device (frameworks/av/services/camera/libcameraservice/device3/)
  ↓  submits requests via ICameraDeviceSession (AIDL, Android 13+)
Camera HAL provider (vendor binary — ICameraProvider / ICameraDevice AIDL)
  ↓  sensor + ISP pipeline
Camera sensor hardware
```

**Key findings:**

1. **AIDL-based HAL (Android 13+).** The HAL interface is no longer HIDL; it uses
   `ICameraProvider` and `ICameraDevice` AIDL interfaces (spec at
   `hardware/interfaces/camera/provider/aidl/` and `.../device/aidl/`). The
   Cuttlefish software camera HAL implements this AIDL interface at
   `device/google/cuttlefish/guest/hals/camera/`.

2. **Buffer flow.** Capture result buffers (`buffer_handle_t` / gralloc handles)
   flow: HAL → `processCaptureResult()` callback → `Camera3Device` →
   `Camera3Stream::returnBuffer()` → the app's output `Surface` (BufferQueue). The
   buffer handle is passed through `Camera3Device` as an opaque handle; `Camera3Device`
   does not lock or read the pixel data. **The pixel data is first readable in
   `Camera3Stream::returnBuffer()` before the buffer is queued into the app's
   `Surface`** — this is the correct insertion point.

3. **`CameraService` does not touch pixel data.** `CameraService` manages
   connection lifecycle and permission checks but does not receive or inspect capture
   result buffers. Patching `CameraService` alone is not sufficient to read frames.

4. **`Camera3Stream::returnBuffer()` is the hook point.** This method is called for
   every completed capture buffer — still images, video frames, and preview frames
   — before the buffer is signalled to the app's consumer. It can be patched to:
   - Lock the gralloc buffer (via `GraphicBuffer::lock()`).
   - Copy or directly read the pixel data.
   - Call the NSFW gate.
   - Unlock and either pass through or substitute with a blocked frame.

   Source reference: `frameworks/av/services/camera/libcameraservice/device3/`
   (Camera3Stream.cpp / Camera3OutputStream.cpp). Confirm exact class and method
   name in the `android-16.0.0_r3` tree.

### 7.3 Recommended hook point: `Camera3Stream` / `Camera3OutputStream` patch

**Recommendation: patch `Camera3OutputStream::returnBufferLocked()` in
`frameworks/av/services/camera/libcameraservice/device3/Camera3OutputStream.cpp`.**

Rationale:
- **Universal coverage.** Every app — including apps with embedded camera UI —
  must go through `CameraService` → `Camera3Device` → `Camera3Stream`. There is no
  app-accessible bypass below the AIDL HAL interface.
- **Framework source ownership.** We own AOSP's `frameworks/av` source. This is a
  pure framework patch — no vendor binary modification needed. This also means
  Cuttlefish's software camera HAL and the `lynx` vendor camera HAL are both above
  this layer; the patch works with any HAL.
- **Pixel access at the right moment.** `returnBufferLocked()` is called after the
  HAL has written pixels into the gralloc buffer and before the app's
  `ImageReader`/`SurfaceTexture` dequeues it. The buffer is in a complete,
  hardware-fenced state; after the release fence fires, pixel data is CPU-accessible
  via `GraphicBuffer::lock()`.
- **Composability.** The standalone camera app (§4.2) and the screen-capture path
  (§4.2 / §3.4) remain independent. The `Camera3Stream` gate applies only to camera
  capture pipelines; screen content goes through SurfaceFlinger as before.

**Why not a HAL provider shim (`ICameraProvider` wrapper):**
- Would require inserting an AIDL service between `CameraService` and the vendor
  HAL. On `lynx`, this means competing with the Qualcomm vendor camera HAL binary
  — fragile, requires HAL binary compat testing, and the shim must re-implement the
  full AIDL camera provider interface.
- Does not offer pixel access any earlier or more cleanly than `Camera3Stream`.
- Higher risk, more plumbing, no coverage advantage.

**Why not `CameraService` itself:**
- `CameraService` does not receive or inspect pixel buffers — it only manages
  connections and permissions (confirmed by source review above).

### 7.4 Implementation sketch

**Patch location:**
`frameworks/av/services/camera/libcameraservice/device3/Camera3OutputStream.cpp`

**Conceptual patch (Increment 3 addition):**

```cpp
// In Camera3OutputStream::returnBufferLocked() — after release fence is
// signalled, before queueBuffer() hands the buffer to the app's Surface:

status_t Camera3OutputStream::returnBufferLocked(
        const camera_stream_buffer_t &buffer, nsecs_t timestamp,
        int32_t transform, const std::vector<size_t>& surface_ids) {

    // --- PH BULWARK: on-device content-safety gate ---
    // Only inspect streams that carry pixel content (still/video/preview).
    // Skip metadata-only streams (stream format CAMERA_METADATA).
    if (shouldInspectStream(mFormat)) {
        // Wait for the release fence (pixel data is ready).
        sp<Fence> fence = new Fence(buffer.release_fence);
        fence->wait(kBulwarkFenceTimeoutMs);

        // Lock gralloc buffer for CPU read (read-only, no write).
        sp<GraphicBuffer> gb = GraphicBuffer::from(buffer.buffer);
        void* pixels = nullptr;
        gb->lock(GRALLOC_USAGE_SW_READ_OFTEN, &pixels);

        if (pixels != nullptr) {
            // Hand to bulwarkd via Binder for NSFW scoring.
            // bulwarkd runs the scoring; CameraService thread is not blocked
            // (post to a bounded queue; if the queue is full, fail-CLOSED).
            bool nsfw = BulwarkCameraGate::getInstance()
                            .submitFrame(pixels, mWidth, mHeight, mFormat,
                                         kBulwarkFrameTimeoutMs);
            gb->unlock();

            if (nsfw) {
                // Fail-CLOSED: replace with a solid-black frame (or drop).
                substituteBlockedFrame(gb);
            }
        } else {
            // Lock failed — fail-CLOSED: block.
            substituteBlockedFrame(gb);
        }
    }
    // --- end PH BULWARK ---

    return Camera3OutputStream::queueBufferToConsumer(/*...*/);
}
```

`BulwarkCameraGate` is a thin Binder client (in `libcameraservice`) that calls
`bulwarkd` over a local Binder socket. `bulwarkd` runs `crates/bulwark-vision`'s
`NsfwGate` — the same model used by the standalone camera app.

**Fail-CLOSED behaviour:**
- If `bulwarkd` is not running: block all frames (treat as high-risk).
- If inference times out (`kBulwarkFrameTimeoutMs`, e.g. 500 ms): block the frame.
- If gralloc lock fails: block the frame.
- If the NSFW score exceeds threshold: replace with a solid opaque frame (not
  dropped — dropping breaks the BufferQueue lifecycle; replacement is safer).

### 7.5 Sampling / throttle strategy (preview vs capture)

Running the NSFW gate on every preview frame (30–60 fps) would be prohibitive:
the `nsfw_detector.onnx` ViT model takes ~50–200 ms per frame on NNAPI (per
profiling in the camera app). This must be throttled:

| Stream type | Cadence | Rationale |
|---|---|---|
| **Preview / viewfinder** | 1 frame per second (1 Hz) | Same as screen-scan gate. Subsampled from the preview stream — skip N-1 frames, inspect 1. Matches the visual cadence children experience. |
| **Still capture (JPEG / RAW)** | Every frame | There are typically 1–3 still captures per shutter press. Each must be inspected before delivery to the app's `ImageReader`. Latency added (~200 ms) appears as normal post-processing delay. |
| **Video recording** | 1 frame per second (1 Hz), plus keyframes | Video recording can run at 30–60 fps. Sample at 1 Hz for live content-safety; always inspect the first frame of a recording session. |

Implementation: `Camera3OutputStream` knows the stream format and use-case
(configured via `StreamConfigurationMap`). The throttle is a frame counter per
stream instance, reset on session configuration.

### 7.6 Composition with the standalone camera app

The standalone PH Bulwark camera app (`platform/android`, PR #213) already runs
the `NsfwGate` at the app level before saving a still image. In a custom ROM with
the `Camera3Stream` hook:

- The `Camera3Stream` hook **supersedes** the app-level gate for `still capture`
  streams: the frame is inspected before it reaches the app's `ImageReader`, so the
  app-level gate never sees an NSFW frame.
- The app-level gate is retained as belt-and-suspenders for the standalone camera
  app (defence-in-depth). It costs one extra inference per still capture for the
  standalone app; this is acceptable.
- For all other apps (Snapchat, Instagram, etc.) the `Camera3Stream` hook is the
  ONLY gate — these apps do not have an app-level gate.

### 7.7 No-explicit-media-persistence invariant

The camera gate complies with the engine invariant (no explicit-media persistence):

- Frame pixels are read from the locked gralloc buffer in memory; no copy is
  written to the filesystem.
- The NSFW score (a float) is used for the verdict and then discarded.
- If the score exceeds the CSAM threshold: the frame is blocked, the SHA-256 hash
  of the frame is included in the NCMEC evidence payload, and the pixel data is
  immediately released. No pixel data is stored or transmitted; only the hash +
  redacted metadata.
- Blocked/replaced frames use a solid opaque colour — no partial image retained.

### 7.8 Cuttlefish tie-in (emulator-first validation)

Decision D3 (Cuttlefish-first) directly benefits the camera hook:

- Cuttlefish ships a **software camera HAL** (`virtual_camera_service`, AIDL
  provider) that generates synthetic frames from a configurable source (colour
  bars, or a test video file). This provides a fully controlled frame stream for
  validating the `Camera3Stream` hook without real camera hardware.
- The hook can be exercised with known NSFW-positive and NSFW-negative synthetic
  frames to validate fail-CLOSED behaviour, latency, and the score→block pipeline.
- Cuttlefish validates the framework patch (`frameworks/av`) independently of the
  `lynx` vendor HAL binary — the vendor-binary compat risk (§7.9) only bites when
  moving to the physical device.

Development approach for the hook:
1. Develop and validate on Cuttlefish (software HAL, synthetic frames).
2. Port to `lynx` (verify no HAL/Binder ABI conflicts with the Qualcomm vendor
   camera provider binary).

### 7.9 Open risks (DRAFT — owner/architect review required)

The following risks could not be fully resolved from design-time research alone.
Each is a potential blocker for the physical `lynx` step:

1. **Vendor HAL binary compatibility on `lynx`.** The `Camera3Stream` hook is
   a patch to `libcameraservice` (an AOSP framework library). The Qualcomm vendor
   camera HAL for `lynx` is a pre-compiled binary that uses the AIDL HAL interface.
   The hook sits above the HAL interface — it should not require vendor binary
   changes. However, if the `lynx` vendor HAL uses private extensions or calls
   `Camera3OutputStream` via internal coupling, the patch could conflict. **This
   must be validated by inspecting the `lynx` camera HAL interface surface on
   Android 16 before production use.** The Cuttlefish software HAL will pass; the
   risk is specific to the physical device.

2. **Per-frame gralloc lock latency.** Locking a gralloc buffer for CPU read on
   a hardware-accelerated capture path adds latency (the fence wait + DMA sync).
   For preview (1 Hz sample), this is not on the app's critical path. For still
   capture, the added latency (~100–500 ms depending on GPU/DMA state) may be
   noticeable to the user as a slight shutter-to-preview delay. Profiling on
   Cuttlefish will give a lower bound; physical device may be worse (or better with
   NNAPI acceleration). Target: stay under 300 ms added latency for still captures.

3. **DRM / protected content surfaces.** Secure video buffers (DRM-protected
   playback) are allocated with `GRALLOC_USAGE_PROTECTED` and cannot be CPU-locked.
   Attempting to `lock()` a protected buffer returns an error.
   **The gate must detect `GRALLOC_USAGE_PROTECTED` and fail-CLOSED only for camera
   streams** (camera captures are never DRM-protected; DRM protection applies to
   video playback surfaces, not camera output). Camera output buffers should never
   be marked protected, but this must be confirmed with a `usage` flag check before
   locking.

4. **`Camera3Stream` hook scope — metadata-only streams.** Camera2 supports
   metadata-only output streams (e.g. for face-detection without capturing pixels).
   The `mFormat == CAMERA_METADATA` check in the sketch above handles this, but
   confirm the exact format constants in Android 16 source.

5. **BufferQueue lifecycle on block/substitute.** Replacing the frame content with
   a solid-colour block (rather than dropping the buffer) must preserve the
   `BufferQueue` sequence numbers and timestamps expected by the app's consumer. An
   incorrect substitution can freeze the app's camera preview. This must be
   validated end-to-end on Cuttlefish before shipping.

6. **`bulwarkd` Binder IPC latency on the camera path.** Submitting a frame to
   `bulwarkd` via Binder from within `Camera3OutputStream` adds an IPC round-trip.
   For preview (1 Hz, off the critical path) this is acceptable. For still capture
   (user-visible delay), the IPC + NNAPI inference must complete within the target
   latency budget. Consider an in-process scorer (linking `libbulwark_client`
   directly into `libcameraservice`) to avoid the Binder hop on the capture path,
   at the cost of tighter coupling.

---

## 8. References (research sources, 2026-06-20)

- [Camera HAL — Android Open Source Project](https://source.android.com/docs/core/camera/camera3)
- [HAL subsystem / request-result model — AOSP](https://source.android.com/docs/core/camera/camera3_requests_hal)
- [Camera HAL3 buffer management APIs — AOSP](https://source.android.com/docs/core/camera/buffer-management-api)
- [AIDL for HALs — AOSP](https://source.android.com/docs/core/architecture/aidl/aidl-hals)
- [ICameraService AIDL — android.googlesource.com](https://android.googlesource.com/platform/frameworks/av/+/master/camera/aidl/android/hardware/ICameraService.aidl)
- [Camera3Device.cpp — android.googlesource.com (frameworks/av)](https://android.googlesource.com/platform/frameworks/av/+/b04aee833c5cfb6b31b8558350feb14bb1a0f353/services/camera/libcameraservice/device3/Camera3Device.cpp)
- [BufferQueue and Gralloc — AOSP](https://source.android.com/docs/core/graphics/arch-bq-gralloc)
- [Cuttlefish virtual Android devices — AOSP](https://source.android.com/docs/devices/cuttlefish)
- [Cuttlefish on ARM64 (16 KB page size) — AOSP](https://source.android.com/docs/core/architecture/16kb-page-size/getting-started-cf-arm64-pgagnostic)
- [device/google/cuttlefish — android.googlesource.com](https://android.googlesource.com/device/google/cuttlefish/)

---

*Document authored 2026-06-19. Owner decisions applied 2026-06-20. DRAFT — §7
camera section pending owner/architect review before any implementation begins.*
