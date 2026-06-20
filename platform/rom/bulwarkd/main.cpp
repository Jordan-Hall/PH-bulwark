/*
 * SCAFFOLD — not built here.
 * See platform/rom/README.md for integration instructions.
 *
 * Licence: Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 *
 * main.cpp — PH Bulwark native daemon (bulwarkd) entry point.
 *
 * Protective framing: this daemon runs exclusively on a guardian-provisioned
 * child device. It captures screen frames for content-safety scoring. No frame
 * content is stored, transmitted, or hashed. Only NSFW verdicts and redacted
 * alert payloads leave the inference pipeline. See docs/FRAMING.md.
 *
 * Design reference: docs/design/child-safety-rom-build.md §4
 *
 * ============================================================
 * Architecture summary
 * ============================================================
 *
 * bulwarkd is a persistent native daemon (/system/bin/bulwarkd) started by
 * init (bulwarkd.rc, class late_start). It runs in the 'bulwarkd' SELinux
 * domain (sepolicy/bulwarkd.te).
 *
 * Three scan paths run concurrently:
 *
 *  1. SCREEN SCAN (visual)
 *     Captures the display at ~1 Hz via ScreenCapture::captureDisplay()
 *     (the same API as SurfaceControl.screenshot() at the Java layer).
 *     Each frame is scored by libbulwark_safety (bw_score_nsfw()).
 *     On NSFW verdict: call WindowManager via Binder to add a block overlay.
 *
 *  2. TEXT SCAN (accessibility node tree)
 *     Registers as a trusted AMS client via Binder to receive
 *     AccessibilityEvent objects (TYPE_VIEW_TEXT_CHANGED,
 *     TYPE_WINDOW_CONTENT_CHANGED) without requiring a user-space
 *     AccessibilityService.
 *     Text is passed to the bulwark-text grooming rule engine
 *     (via libbulwark_client — the existing Rust JNI cdylib, linked
 *     here as a native library rather than through JNI).
 *     OCR fallback: for surfaces with no text in the node tree, the
 *     screen frame is OCR'd with Tesseract and the result fed to the
 *     same grooming engine.
 *
 *  3. AUDIO SCAN (voice call detection — gated on guardian policy)
 *     Captures the device speaker mix via CAPTURE_AUDIO_OUTPUT.
 *     On-device STT (ML Kit → Whisper CPU fallback per on-device-AI-fallback
 *     doctrine) produces a transcript, fed to the grooming rule engine.
 *     Disabled by default; enabled only when the guardian enables voice
 *     monitoring in the Manager console.
 *
 * On any BLOCK verdict across the three paths:
 *   - Block overlay is applied immediately (WindowManager Binder call).
 *   - A redacted alert payload is dispatched to the cluster (mTLS gRPC,
 *     same path as today's AlertNotifier.kt / AlertRelay gRPC service).
 *   - CSAM path: detect → block → NCMEC report via cluster. Never stored.
 *
 * Fail-CLOSED invariant (§4.4): if bulwarkd cannot deliver a verdict
 * (libbulwark_safety BW_VERDICT_FAIL_CLOSED, OOM, inference timeout),
 * the default action is BLOCK. This differs from the Increment 1/2
 * AccessibilityService which is additive and fail-open.
 *
 * ============================================================
 * SCAFFOLD TODOs (Linux host)
 * ============================================================
 *
 *  TODO-1: Wire ScreenCapture::captureDisplay() for the 1 Hz screen scan.
 *          Confirm the call signature in frameworks/base/core/java/android/view/
 *          SurfaceControl.java for android-16.0.0_r3 (§3.4 of the design doc).
 *          Native equivalent: libs/gui/ScreenCapture.cpp.
 *
 *  TODO-2: Register as a trusted AMS client for node-tree text events.
 *          Internal API: IAccessibilityManager (frameworks/base/core/java/
 *          android/view/accessibility/IAccessibilityManager.aidl).
 *          Requires the 'accessibility_service' SELinux allow rule (bulwarkd.te).
 *
 *  TODO-3: Wire libbulwark_client for alert dispatch and grooming text scan.
 *          The existing Rust cdylib exports a C ABI via JNI; for native use
 *          we need a dedicated extern "C" entry point (not the JNI-mangled name).
 *          TODO: add a native entrypoint to crates/bulwark-android.
 *
 *  TODO-4: Implement the WindowManager block overlay call.
 *          Binder call to IWindowManager::addView with TYPE_APPLICATION_OVERLAY
 *          at max Z-order. Internal API (platform_apis equivalent for native).
 *
 *  TODO-5: Add the audio capture path (CAPTURE_AUDIO_OUTPUT).
 *          Gate on guardian policy flag delivered via the provisioning channel.
 *
 *  TODO-6: Validate on Cuttlefish before porting to lynx.
 *          Cuttlefish's software camera HAL and display simulate the stack
 *          that bulwarkd talks to. First boot target: Cuttlefish (emulator).
 */

// AOSP system headers (available in the AOSP build environment; not on Windows).
// #include <binder/ProcessState.h>
// #include <binder/IServiceManager.h>
// #include <gui/ScreenCapture.h>
// #include <android/log.h>

#include <stdint.h>
#include <time.h>

// libbulwark_safety (in this scaffold: platform/rom/libbulwark_safety/).
#include "bulwark_safety.h"

#define LOG_TAG "bulwarkd"

// ---- constants -------------------------------------------------------------

/** Screen scan cadence: 1 capture per second (matches AccessibilityService rate). */
static constexpr long SCREEN_SCAN_INTERVAL_NS = 1'000'000'000L;

/** Maximum time to wait for a single NSFW inference before failing CLOSED. */
static constexpr int  INFERENCE_TIMEOUT_MS    = 500;

// ---- screen scan -----------------------------------------------------------

/**
 * screen_scan_once() — capture one display frame and score it.
 *
 * SCAFFOLD: the capture and scoring logic is a placeholder.
 * Real implementation requires ScreenCapture::captureDisplay() from libgui
 * and GraphicBuffer::lock() for CPU pixel access.
 *
 * Returns true if the frame was NSFW (caller should apply block overlay).
 */
static bool screen_scan_once() {
    // TODO-1: call ScreenCapture::captureDisplay() to get a GraphicBuffer.
    //
    //   sp<SyncFence> fence;
    //   ScreenCaptureResults captureResults;
    //   status_t err = ScreenCapture::captureDisplay(
    //       displayToken, captureArgs, captureResults);
    //   if (err != OK) {
    //       // Fail-CLOSED: cannot capture → treat as NSFW.
    //       return true;
    //   }
    //   sp<GraphicBuffer> gb = captureResults.buffer;
    //
    // TODO: lock the gralloc buffer for CPU read.
    //   void* pixels = nullptr;
    //   gb->lock(GRALLOC_USAGE_SW_READ_OFTEN, &pixels);
    //   if (pixels == nullptr) return true; // fail-CLOSED
    //
    // TODO: call bw_score_nsfw() with the pixel data.
    //   BwVerdict verdict = bw_score_nsfw(
    //       static_cast<const uint8_t*>(pixels),
    //       gb->getWidth(), gb->getHeight(),
    //       BW_FMT_RGBA8888,
    //       nullptr);
    //   gb->unlock();
    //   return (verdict != BW_VERDICT_SAFE);

    // SCAFFOLD stub: always returns false (safe) so the daemon loop runs
    // without crashing in any smoke-test that manages to link this binary.
    return false;
}

// ---- block overlay ---------------------------------------------------------

/**
 * apply_block_overlay() — cover the display with a full-screen block surface.
 *
 * SCAFFOLD: real implementation calls IWindowManager via Binder.
 * Mirrors showBlockOverlay() in BulwarkAccessibilityService.kt but dispatched
 * from a native daemon via a WindowManager Binder call.
 *
 * TODO-4: implement using IWindowManager::addView with TYPE_APPLICATION_OVERLAY
 * and LayoutParams.FLAG_NOT_TOUCH_MODAL at the maximum Z-order.
 */
static void apply_block_overlay() {
    // TODO-4: Binder call to IWindowManager.
    // For now, log the would-be action (content-free).
    // __android_log_print(ANDROID_LOG_WARN, LOG_TAG, "block overlay triggered");
}

// ---- main service loop -----------------------------------------------------

int main(int /*argc*/, char** /*argv*/) {
    // Step 1: initialise the NSFW scoring library.
    // NULL → use the baked-in model (/system/etc/bulwark/nsfw_detector.onnx
    //         installed by Android.bp PRODUCT_COPY_FILES, or the in-binary
    //         bundled model from libbulwark_safety_rs).
    int init_rc = bw_init_once(nullptr);
    if (init_rc == BW_ERR_NO_MODEL) {
        // Fail-CLOSED: no model → the daemon must still run so it can apply
        // block overlays from the text-scan path, but the visual gate will
        // return BW_VERDICT_FAIL_CLOSED (block) for every frame.
        // Log is content-free.
        // __android_log_print(ANDROID_LOG_WARN, LOG_TAG,
        //     "NSFW model unavailable (model=%s); visual gate is fail-CLOSED",
        //     bw_model_id());
    }

    // Step 2: start the Binder thread pool (required for IPC callers that
    // need to call us back, e.g. AMS event delivery).
    // TODO: ProcessState::self()->startThreadPool();

    // Step 3: register as a trusted AMS client for node-tree text events.
    // TODO-2: IAccessibilityManager registration.

    // Step 4: service loop — screen scan at ~1 Hz.
    // The text scan (AMS events) and audio scan (if enabled) run on separate
    // Binder threads delivered by the thread pool.
    struct timespec next_scan;
    clock_gettime(CLOCK_MONOTONIC, &next_scan);

    while (true) {
        // Wait until the next 1 Hz tick.
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_scan, nullptr);
        next_scan.tv_sec  += SCREEN_SCAN_INTERVAL_NS / 1'000'000'000L;
        next_scan.tv_nsec += SCREEN_SCAN_INTERVAL_NS % 1'000'000'000L;
        if (next_scan.tv_nsec >= 1'000'000'000L) {
            next_scan.tv_sec++;
            next_scan.tv_nsec -= 1'000'000'000L;
        }

        bool nsfw = screen_scan_once();
        if (nsfw) {
            apply_block_overlay();
            // TODO-3: dispatch redacted guardian alert via libbulwark_client.
        }
    }

    return 0; // unreachable; init will restart us if we exit
}
