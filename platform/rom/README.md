# PH Bulwark ROM Scaffold

> **SCAFFOLD — NOT BUILT HERE.**
> This directory contains skeleton source files, interface headers, build
> descriptors, and integration notes for the PH Bulwark Child Safety ROM.
> Nothing in this tree has been compiled or tested. Every file that describes
> build output is illustrative only and must be validated against a full AOSP
> tree on a Linux build host before use.
>
> **DO NOT attempt to build this on the Windows dev host.** AOSP does not
> support Windows build hosts. These files exist so the interfaces, SELinux
> policy stubs, and patch locations can be reviewed and iterated without
> requiring a Linux build machine.

---

## What this is

A custom AOSP ROM ("Increment 3 / Build C") for the dedicated Pixel 7a (`lynx`)
child device. It bakes the PH Bulwark child-protection system directly into the
AOSP framework, providing protection that cannot be removed by the child and
that covers all apps — including third-party camera apps that the stock child
app cannot intercept.

The ROM adds two native pieces on top of the priv-app child app (Increment 2 /
Build B, `platform/android`):

1. **`bulwarkd`** — a dedicated native daemon (`/system/bin/bulwarkd`) for the
   screen/text scan path. Runs as a persistent `init.rc` service. Scores frames
   via `libbulwark_safety` (the shared scoring library). Talks to `WindowManager`
   for the block overlay and to the cluster for guardian alerts.

2. **Camera gate** — a framework patch to
   `frameworks/av/services/camera/libcameraservice/device3/Camera3OutputStream.cpp`
   that intercepts every camera capture buffer system-wide (all apps, including
   Snapchat, Instagram, BeReal) before it reaches the app's `ImageReader`. Scores
   via `libbulwark_safety` in-process. Fail-CLOSED.

Both pieces share **`libbulwark_safety`** (this scaffold: `libbulwark_safety/`),
a thin C/C++ shim over the Rust `bulwark-vision` ONNX scorer
(`crates/bulwark-vision`). The same model, threshold, and pre/post-processing
as `platform/android/camera/.../NsfwGate.kt` — scoring cannot drift between
the ROM gate and the app gate.

Protective framing: this is a consensual, guardian-provisioned child-protection
product. Capture and detection run exclusively on a device the guardian owns,
used by a minor they are the legal guardian of, with consent obtained once at
provisioning on a freshly wiped dedicated device. See `docs/FRAMING.md`.

---

## AOSP base

| Item | Value |
|---|---|
| Base tag | `android-16.0.0_r3` |
| Build fingerprint | `BP3A.250905.014` |
| Device | `lynx` (Pixel 7a) |
| Lunch target (dev) | `aosp_lynx-userdebug` |
| Lunch target (prod) | `aosp_lynx-user` |
| Emulator target | `aosp_cf_x86_64_phone-userdebug` (Cuttlefish) |
| Reference doc | `docs/design/child-safety-rom-build.md` §2 |

Development approach: **Cuttlefish first** (emulator, software camera HAL),
then port to physical `lynx`. The Cuttlefish software camera HAL generates
synthetic frames that are sufficient to validate the camera-gate hook and
`bulwarkd` screen-scan path without real hardware.

---

## Pieces in this scaffold and where they slot in

| This scaffold path | AOSP tree destination | Purpose |
|---|---|---|
| `libbulwark_safety/` | `vendor/phbulwark/libbulwark_safety/` (or `frameworks/av/services/camera/libbulwark_safety/`) | Shared scoring library linked by both `bulwarkd` and the camera hook |
| `bulwarkd/` | `system/phbulwark/bulwarkd/` | Native detection daemon |
| `bulwarkd/bulwarkd.rc` | `system/etc/init/bulwarkd.rc` (via `LOCAL_INIT_RC` in `Android.bp`) | init service declaration |
| `bulwarkd/sepolicy/bulwarkd.te` | `device/google/lynx/sepolicy/bulwarkd.te` | SELinux type enforcement |
| `bulwarkd/sepolicy/file_contexts` | `device/google/lynx/sepolicy/file_contexts` (append) | SELinux file labels |
| `camera-gate/Camera3OutputStream.returnBufferLocked.patch` | Apply to `frameworks/av/services/camera/libcameraservice/device3/Camera3OutputStream.cpp` | Camera buffer interception hook |

### Applying the pieces

Set `AOSP_ROOT` to your synced AOSP tree root:

```bash
export AOSP_ROOT=/aosp

# 1. Copy the shared library.
cp -r platform/rom/libbulwark_safety/ \
    "$AOSP_ROOT/vendor/phbulwark/libbulwark_safety/"

# 2. Copy the daemon.
cp -r platform/rom/bulwarkd/ \
    "$AOSP_ROOT/system/phbulwark/bulwarkd/"

# 3. Copy SELinux policy (review each rule before applying).
cp platform/rom/bulwarkd/sepolicy/bulwarkd.te \
    "$AOSP_ROOT/device/google/lynx/sepolicy/"
cat platform/rom/bulwarkd/sepolicy/file_contexts >> \
    "$AOSP_ROOT/device/google/lynx/sepolicy/file_contexts"

# 4. Apply the camera-gate patch (validate line numbers against android-16.0.0_r3 first).
# See camera-gate/INTEGRATION.md before applying.
cd "$AOSP_ROOT"
patch -p1 --dry-run < /path/to/platform/rom/camera-gate/Camera3OutputStream.returnBufferLocked.patch
# If --dry-run succeeds, remove --dry-run and apply for real.

# 5. Add modules to device.mk.
# In device/google/lynx/device.mk, add:
#   PRODUCT_PACKAGES += libbulwark_safety bulwarkd
```

After applying, run a full AOSP build per `docs/design/child-safety-rom-build.md`
§2.3. Validate on Cuttlefish before flashing to the physical `lynx`.

---

## Key design decisions (from `docs/design/child-safety-rom-build.md`)

- **AOSP-vanilla, not GrapheneOS.** One codebase to maintain; GrapheneOS's
  hardening benefits apply only to its own signed chain (§1 of the design doc).
- **`bulwarkd` as a dedicated native daemon**, not a `system_server` companion,
  to isolate inference OOM/panics from the core OS (§4.1).
- **Camera hook in `Camera3OutputStream::returnBufferLocked()`** — the one point
  in the AOSP camera pipeline where pixel data is accessible before delivery to
  any app's `Surface` (§7.3).
- **In-process scoring for the camera hot path.** `libbulwark_safety` is linked
  directly into `libcameraservice` to avoid a Binder round-trip on the camera
  critical path. `bulwarkd` links the same library for the screen-scan path. This
  avoids IPC overhead on still-capture (where latency is user-visible) while
  keeping the implementation in one place (§7.9 risk D6).
- **Fail-CLOSED everywhere.** No model → block. Score above threshold → block.
  Lock failure → block. Missing daemon → block. This is the primary protection,
  not a belt-and-suspenders layer (§4.4).
- **`bulwarkd` device build MUST define `-DBULWARK_HAVE_AOSP_CAPTURE`** (set in
  `bulwarkd/Android.bp` cppflags). It arms the real capture/scan paths in
  `main.cpp`; without it the daemon compiles an inert fallback that scans nothing
  (fail-open). The non-AOSP path exists only for source inspection — it emits a
  compile-time `#warning` so an inert build is never silent, and cannot produce a
  runnable daemon. The framework glue (display capture, IWindowManager overlay,
  IAccessibilityManager text source) lives behind that macro and is built only on
  the AOSP host.
- **No explicit-media persistence.** Pixels are read from the gralloc buffer in
  memory, scored, and released. No pixel data is stored, hashed for evidence,
  or transmitted. Only the NSFW verdict (boolean + score) is used. Engine
  invariant: `crates/bulwark-vision` only records SHA-256 of frames in evidence
  payloads, never the raw pixels.
- **Guardian-provisioned grooming weights.** The `nsfw_detector.onnx` model is
  baked into `/system/etc/bulwark/` at build time (Apache-2.0, safe for public
  ROM). The grooming detector weights are delivered over the mTLS provisioning
  channel after pairing (§4.9 of the design doc) and stored at
  `/data/misc/bulwark/models/` (SELinux-labelled, not world-readable).

---

## Licensing

All PH Bulwark code in this scaffold: **Apache-2.0**.
AOSP framework files modified by the camera-gate patch: already Apache-2.0 in
the AOSP tree — our additions carry the same licence.
The Linux kernel used as the ROM base: GPL-2 (kernel-as-platform ruling
2026-06-16; not linked into or redistributed with the product APK or native libs).

No GPL dependencies may be added to `libbulwark_safety`, `bulwarkd`, or the
camera-gate patch. See `CLAUDE.md` hard constraints.

---

## What is NOT in this scaffold

- A full ONNX model build. The model (`nsfw_detector.onnx`) is sourced from
  `crates/bulwark-vision/models/` and embedded at build time (see
  `libbulwark_safety/Android.bp`).
- The Rust FFI bridge (`cbindgen` output / `bulwark_safety_ffi.h`). The header in
  `libbulwark_safety/include/bulwark_safety.h` declares the C API; the actual
  cbindgen-generated binding must be produced from `crates/bulwark-vision` on the
  Linux host and placed at `libbulwark_safety/include/` before building.
- SELinux policy for `bulwarkd`'s Binder clients in `libcameraservice`. Add
  targeted `allow` rules after observing `avc: denied` in `logcat` during
  Cuttlefish validation.
- OTA signing, AVB key management, bootloader relock. See
  `docs/design/child-safety-rom-build.md` §2.4 and §5.3 open question 1
  (key custody — highest-risk item, requires owner sign-off before first keyed build).
