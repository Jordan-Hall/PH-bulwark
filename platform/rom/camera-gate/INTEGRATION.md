# Camera Gate — Integration Notes and Open Risks

> **SCAFFOLD — not built here.**
> This document records the 6 open risks identified during design-time research
> (2026-06-20) for the `Camera3OutputStream::returnBufferLocked()` camera-gate
> hook. Each risk must be resolved — by inspection of the android-16.0.0_r3
> source on a Linux build host and by on-device validation on Cuttlefish — before
> shipping to the physical `lynx` device.
>
> Design reference: `docs/design/child-safety-rom-build.md` §7.9

---

## Context

The camera-gate hook patches
`frameworks/av/services/camera/libcameraservice/device3/Camera3OutputStream.cpp`
to intercept every camera capture buffer system-wide — before it reaches any
app's `ImageReader` or `SurfaceTexture`. This gives universal coverage over all
camera apps (Snapchat, Instagram, BeReal, and any future app) without requiring
per-app integration.

The hook:
1. Waits for the gralloc release fence to fire (pixel data is ready for CPU read).
2. Locks the gralloc buffer for CPU read (`GRALLOC_USAGE_SW_READ_OFTEN`).
3. Calls `bw_score_nsfw()` (in-process, via `libbulwark_safety`) to score the frame.
4. If the verdict is `BW_VERDICT_NSFW` or `BW_VERDICT_FAIL_CLOSED`: substitutes a
   solid-colour blocked frame before queueing to the app's `Surface`.
5. Unlocks the gralloc buffer.
6. Proceeds to `queueBufferToConsumer()` (existing path, unchanged).

Protective framing: this gate prevents children from generating or sending explicit
self-imagery under coercion, and from being exposed to explicit imagery shared
through camera-based UIs. It runs exclusively on a guardian-provisioned device.
No frames are stored or transmitted. See `docs/FRAMING.md`.

---

## Risk D1 — Vendor HAL binary compatibility on `lynx`

**Risk:** The `Camera3OutputStream` hook is a patch to `libcameraservice` (an
AOSP framework library). The Qualcomm vendor camera HAL for `lynx` is a
pre-compiled binary that communicates with `libcameraservice` via the AIDL
HAL interface (`ICameraProvider` / `ICameraDevice`, Android 13+). The hook
sits above that interface — it does not modify the HAL ABI — so it should not
require vendor binary changes.

**Unresolved concern:** If the `lynx` vendor HAL uses private extensions or
internal coupling with `Camera3OutputStream` (e.g. casting to a concrete type
via a vendor-private `android::hardware` namespace), the patch could conflict
at link time or at runtime.

**Resolution path:**
- Inspect the `lynx` vendor camera HAL interface surface from the vendor
  binaries extracted by `./extract-google_devices-lynx.sh`.
- Confirm that `libcameraservice` and the vendor HAL communicate exclusively
  via the AIDL interface (no private symbol sharing).
- Validate on Cuttlefish first (software HAL, no vendor binary) — if the hook
  passes on Cuttlefish, the remaining risk is specific to the `lynx` vendor binary.
- If a conflict is found: move the hook to the AIDL HAL shim layer (higher-risk
  alternative — see §7.3 of the design doc for why this is not preferred).

**Blocking for:** physical `lynx` flash. Not blocking for Cuttlefish validation.

---

## Risk D2 — Per-frame gralloc lock latency

**Risk:** Locking a gralloc buffer for CPU read (`GraphicBuffer::lock()`) on a
hardware-accelerated capture path involves:
- Waiting for the GPU/DMA release fence to fire.
- A DMA cache sync (if the buffer is in GPU-cached memory).

For preview streams (1 Hz throttle), this occurs off the app's critical path and
is acceptable. For still-capture streams (every frame, user presses shutter), the
added latency is on the critical path and will be perceived as a shutter-to-preview
delay.

**Target budget:** ≤ 300 ms added latency for still captures (fence wait 50 ms +
NNAPI inference ~50–200 ms + lock/unlock overhead).

**Resolution path:**
- Profile on Cuttlefish (lower bound — no GPU, no NNAPI; use CPU ORT as baseline).
- Profile on physical `lynx` (Qualcomm Tensor G2; NNAPI acceleration changes the
  picture significantly vs CPU).
- If budget is exceeded: consider pre-allocating a shadow RGB buffer per stream
  and using async DMA copy (avoids blocking the camera thread during inference).
  This is a significant complexity increase; validate the simple path first.

**Blocking for:** performance SLA sign-off before production release.

---

## Risk D3 — DRM / protected-content surfaces

**Risk:** Gralloc buffers allocated with `GRALLOC_USAGE_PROTECTED` (DRM-protected
video playback) cannot be CPU-locked. Calling `GraphicBuffer::lock()` on a
protected buffer returns an error (typically `PERMISSION_DENIED` or `BAD_VALUE`).

**Analysis:** Camera capture output buffers should NEVER be marked protected —
`GRALLOC_USAGE_PROTECTED` applies to video playback surfaces (e.g. Widevine
L1 decrypted frames), not to camera output. The camera HAL is not permitted to
produce DRM-protected capture buffers by the Android CDD.

**Resolution path:**
- Add a defensive `usage` flag check in `bulwark_should_inspect_stream()`:
  if `(buffer.buffer != nullptr && GraphicBuffer::from(buffer.buffer)->getUsage() & GRALLOC_USAGE_PROTECTED)` then skip inspection (pass through without scoring).
  This prevents a failed lock from triggering fail-CLOSED on a non-camera surface.
- Document in the security design: if a DRM-protected buffer somehow reaches
  `Camera3OutputStream` (which would be a HAL bug), the gate skips it rather than
  blocking it. The DRM content is protected by the OS; the camera gate does not need
  to inspect it.
- Validate: confirm on Cuttlefish that no camera test generates a buffer with
  `GRALLOC_USAGE_PROTECTED` set.

**Blocking for:** correctness validation on Cuttlefish.

---

## Risk D4 — Metadata-only streams and JPEG blob handling

**Risk:** Camera2 supports streams that carry compressed data (JPEG blobs,
`HAL_PIXEL_FORMAT_BLOB`) and metadata-only streams (face detection, etc.) that
contain no displayable pixel data. The NSFW gate must skip these streams.

**JPEG-specific sub-risk:** For still-capture, the most common format is JPEG
(`HAL_PIXEL_FORMAT_BLOB` with JPEG-compressed content). The gate cannot call
`bw_score_nsfw()` on raw JPEG bytes — the model expects RGBA pixel data.

**Resolution path (metadata-only):**
- The `bulwark_should_inspect_stream(format, ...)` helper already skips
  `HAL_PIXEL_FORMAT_BLOB` (0x21). Confirm this is the correct constant in
  android-16.0.0_r3 (`hardware/libhardware/include/hardware/gralloc.h`).
- Add a check for any other non-pixel formats (RAW_SENSOR, RAW10, RAW12) —
  these carry camera sensor data, not displayable content; skip.

**Resolution path (JPEG):**
- Option A: intercept at a different stream type for still-capture. On some HALs,
  the still-capture pipeline produces a `HAL_PIXEL_FORMAT_YCbCr_420_888` frame
  before JPEG encoding, in a separate output stream. Gate on that stream instead.
- Option B: decode the JPEG blob to RGBA before scoring (using `libjpeg-turbo`,
  already in AOSP). Adds latency but provides complete coverage.
- Option C: skip JPEG blobs in the camera-gate hook; rely on the app-level
  `NsfwGate.kt` gate in the PH Bulwark camera app for still captures (defence-in-
  depth already provides this for our camera app; third-party apps lose this path).

**Decision required:** owner/architect sign-off on which option to pursue for JPEG
before implementation. This is OPEN.

**Blocking for:** correctness validation. Option C is the simplest fallback if A/B
are too complex for the initial implementation.

---

## Risk D5 — BufferQueue lifecycle on block / substitute

**Risk:** Replacing the content of a gralloc buffer (solid-colour substitution in
`bulwark_substitute_blocked_frame()`) must not disturb the `BufferQueue` lifecycle.
Specifically:
- The buffer must still be dequeued and queued with the correct sequence number.
- The acquire fence, release fence, and timestamp must be correct.
- `SurfaceTexture` / EGL consumers may have cached the buffer identity (slot number)
  and expect it to contain different pixel data on each frame.

**Analysis:** Writing into the pixel data of an already-acquired buffer (before
`queueBuffer()`) is the standard pattern used by SurfaceFlinger's
`ScreenCaptureListener` and by the AOSP MediaRecorder pipeline; it does not violate
the BufferQueue contract, as long as:
1. The lock/unlock wraps the write correctly.
2. The buffer is unlocked before `queueBuffer()` is called.
3. The timestamp passed to `queueBuffer()` is not modified (use the original
   `timestamp` parameter from `returnBufferLocked()`).

**Resolution path:**
- Validate end-to-end on Cuttlefish: run a camera preview app, trigger a block,
  and confirm the preview does not freeze or show a corrupted frame.
- Validate with a video recording app: confirm that recording continues after a
  substituted frame (the video codec should accept a solid-black frame without
  issue).
- If `SurfaceTexture` consumers freeze: investigate whether `queueBuffer()` needs
  a different `Rect` (dirty region) to invalidate the texture cache.

**Blocking for:** correctness validation on Cuttlefish (must pass before `lynx` flash).

---

## Risk D6 — In-process vs Binder IPC for scoring on the camera path

**Risk:** The design doc (§7.4, §7.9 D6) notes two options for how the camera
hook calls the NSFW scorer:

**Option A (chosen): in-process.** Link `libbulwark_safety` directly into
`libcameraservice`. `bw_score_nsfw()` is called on the camera service thread
without any IPC. Fast (no Binder round-trip) but tightly coupled: the ORT session
lives in the `cameraserver` process.

**Option B: Binder IPC to `bulwarkd`.** The camera hook calls `bulwarkd` via a
local Binder socket; `bulwarkd` runs inference in its own process. Looser coupling
but adds an IPC round-trip (~1–5 ms typically, but variable under load).

**Rationale for Option A (in-process):**
- Still-capture latency budget is tight (≤ 300 ms). A Binder round-trip adds
  variance that is hard to bound under system load.
- `libbulwark_safety` (the Rust core .so, ORT baked in) is stateless between calls;
  loading it into `cameraserver` does not create shared mutable state with other
  libraries.
- `bulwarkd` continues to use `libbulwark_safety` independently for the screen-scan
  path (its own process-local ORT session).
- The `libbulwark_safety.so` library is the abstraction boundary: each process that
  links it gets its own in-process ORT session. The Rust scorer is thread-safe
  (mirrors `NsfwGate.kt`'s `@Synchronized score()`).

**Resolution path:**
- Confirm that loading `libbulwark_safety` (ORT + ONNX model baked in, ~80 MB
  resident) into `cameraserver` does not cause unacceptable RSS growth. Monitor with
  `adb shell dumpsys meminfo cameraserver` on Cuttlefish.
- If RSS is a problem: move to Option B (IPC). The `Android.bp` for `libcameraservice`
  would then add a Binder client stub instead of `libbulwark_safety` as a direct
  shared_lib.
- If choosing Option B: the `BulwarkCameraGate` Binder client sketch in the design
  doc (§7.4) replaces the in-process `bw_score_nsfw()` call.

**Current status:** Option A implemented in the scaffold patch. Re-evaluate after
memory profiling on Cuttlefish.

**Blocking for:** memory footprint validation on Cuttlefish before production release.

---

## Integration checklist

Before applying the camera-gate patch to a production build:

- [ ] D1: Confirm `lynx` vendor HAL uses no private `Camera3OutputStream` symbols.
- [ ] D2: Measure still-capture latency overhead on Cuttlefish and on `lynx`.
       Confirm ≤ 300 ms added latency (or document trade-off and get owner sign-off).
- [ ] D3: Add `GRALLOC_USAGE_PROTECTED` defensive check; validate no camera buffer
       in Cuttlefish camera tests is marked protected.
- [ ] D4: Decide on JPEG stream handling (Option A/B/C); implement and validate.
- [ ] D5: End-to-end preview and video recording test on Cuttlefish with a triggered
       block substitution. Camera preview must not freeze; video must not corrupt.
- [ ] D6: Memory profile `cameraserver` with `libbulwark_safety` loaded. Confirm
       RSS budget is acceptable. Decide in-process vs IPC.
- [ ] Apply `patch --dry-run` against the actual `android-16.0.0_r3` source;
       fix any rejects before the live apply.
- [ ] Code review of the patched `Camera3OutputStream.cpp` by the AOSP codebase
       owner and the PH Bulwark security lead.
- [ ] `avc: denied` sweep on Cuttlefish; add any missing SELinux rules to
       `bulwarkd.te` (and to `cameraserver.te` for in-process option).
