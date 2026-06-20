/*
 * SCAFFOLD — the AOSP framework bindings are not built here (they need the AOSP
 * source tree on a Linux host). The detection/verdict/fail-closed LOGIC below is
 * real and final; only the capture/overlay/AMS glue is gated behind
 * BULWARK_HAVE_AOSP_CAPTURE. See platform/rom/README.md.
 *
 * Licence: Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 *
 * main.cpp — PH Bulwark native daemon (bulwarkd) entry point.
 *
 * Protective framing: this daemon runs exclusively on a guardian-provisioned
 * child device. It captures screen frames + on-screen text for content-safety
 * scoring. No frame content or text is stored, transmitted, or hashed. Only
 * verdicts and redacted alert payloads leave the inference pipeline. See
 * docs/FRAMING.md.
 *
 * Design reference: docs/design/child-safety-rom-build.md §4
 *
 * Scoring is done IN-PROCESS via libbulwark_safety (the Rust core, PR #223):
 *   bw_init_once()  — load the NSFW model once.
 *   bw_score_nsfw() — score a captured display frame (RGBA).
 *   bw_score_text() — score an on-screen text snapshot (rules-first grooming).
 *   bw_model_id()   — content-free diagnostics.
 * Same engine as the app, so detection never drifts.
 *
 * ============================================================
 * FAIL-CLOSED invariant (§4.4)
 * ============================================================
 * If a frame/text snapshot is OBTAINED but cannot be scored (model missing,
 * inference error, capture/lock failure), the verdict is BW_VERDICT_FAIL_CLOSED
 * and the daemon BLOCKS. We NEVER manufacture a SAFE verdict for content we did
 * not actually score — that would be fail-OPEN. A scan path that is not active
 * (e.g. the AOSP capture binding is not compiled in) produces NO verdict at all,
 * which is distinct from "scored and safe".
 *
 * ============================================================
 * AOSP seams (Linux host) — all behind BULWARK_HAVE_AOSP_CAPTURE
 * ============================================================
 *  - capture_display_rgba(): ScreenCapture / SurfaceComposerClient::captureDisplay
 *    (confirm the android-16.0.0_r3 signature — §3.4 of the design doc).
 *  - next_screen_text(): trusted IAccessibilityManager client for node-tree text
 *    (no user-space AccessibilityService) — §4.3; needs the 'accessibility_service'
 *    sepolicy allow rule (bulwarkd.te).
 *  - apply_block_overlay(): IWindowManager TYPE_APPLICATION_OVERLAY at max Z (§4).
 *  - dispatch_guardian_alert(): redacted alert to the cluster (mTLS gRPC), same
 *    path as AlertNotifier.kt / AlertRelay.
 *  - audio path (CAPTURE_AUDIO_OUTPUT, guardian-gated) — TODO, §4 / decision (4).
 */

#include <stdint.h>
#include <time.h>

// libbulwark_safety (this scaffold: platform/rom/libbulwark_safety/include).
#include "bulwark_safety.h"

#define LOG_TAG "bulwarkd"

// Define BULWARK_HAVE_AOSP_CAPTURE when building inside the AOSP tree, where the
// framework libraries (libgui/ScreenCapture, libui/GraphicBuffer, libbinder,
// IWindowManager, IAccessibilityManager) are available. They are NOT available on
// the dev host, so by default this compiles the inert (still fail-closed-correct)
// variants and the real glue is conditionally compiled.
#ifdef BULWARK_HAVE_AOSP_CAPTURE
#include <android/log.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <gui/SurfaceComposerClient.h>
#include <ui/GraphicBuffer.h>
#include <string>
#define BW_LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define BW_LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else
// Building WITHOUT the AOSP framework: the scan paths are INACTIVE (see main()).
// This compiles the file for source inspection only and can NOT produce a working
// daemon. A real device build MUST define BULWARK_HAVE_AOSP_CAPTURE (bulwarkd's
// Android.bp does). Warn loudly so an inert (fail-open) build is never silent — with
// AOSP's -Werror this becomes a hard build stop, which is the fail-closed default.
#warning \
    "bulwarkd built WITHOUT BULWARK_HAVE_AOSP_CAPTURE: scan paths INACTIVE (fail-open). Define it in the device build (bulwarkd/Android.bp)."
#include <cstdio>
#define BW_LOGW(...)                          \
    do {                                      \
        (void)fprintf(stderr, "[bulwarkd] "); \
        (void)fprintf(stderr, __VA_ARGS__);   \
        (void)fprintf(stderr, "\n");          \
    } while (0)
#define BW_LOGI(...) BW_LOGW(__VA_ARGS__)
#endif

// Screen scan cadence: 1 Hz to start (decision (6): move to event-driven once
// proven). The text path is also polled here; AMS delivery can later push events.
static constexpr long SCREEN_SCAN_INTERVAL_S = 1L;

// ---- one scan attempt ------------------------------------------------------

// Either a real verdict (scanned == true), or "no content this tick"
// (scanned == false). We never fabricate a SAFE verdict for unscanned content.
struct ScanResult {
    bool scanned;
    BwVerdict verdict;  // meaningful only when scanned == true
};

static inline ScanResult inactive() { return ScanResult{false, BW_VERDICT_FAIL_CLOSED}; }

// ---- AOSP-gated glue -------------------------------------------------------

#ifdef BULWARK_HAVE_AOSP_CAPTURE
using android::GraphicBuffer;
using android::sp;

// Capture one display frame as RGBA. Returns nullptr on capture failure (the
// caller fails CLOSED). Confirm the captureDisplay() signature for android-16.
static sp<GraphicBuffer> capture_display_rgba();
// Pull the next unseen on-screen text snapshot from the AMS node-tree source.
// Returns false when there is no new text this tick.
static bool next_screen_text(std::string* out);
// Cover the display with a full-screen block surface (IWindowManager).
static void apply_block_overlay();
// Dispatch a redacted guardian alert to the cluster (mTLS gRPC). Content-free.
static void dispatch_guardian_alert(const char* path, BwVerdict verdict);
#else
static void apply_block_overlay() {}
static void dispatch_guardian_alert(const char* /*path*/, BwVerdict /*verdict*/) {}
#endif

// ---- scan paths ------------------------------------------------------------

static ScanResult screen_scan_once() {
#ifdef BULWARK_HAVE_AOSP_CAPTURE
    sp<GraphicBuffer> gb = capture_display_rgba();
    if (gb == nullptr) {
        BW_LOGW("display capture failed -> fail CLOSED (block)");
        return ScanResult{true, BW_VERDICT_FAIL_CLOSED};
    }
    void* pixels = nullptr;
    if (gb->lock(GraphicBuffer::USAGE_SW_READ_OFTEN, &pixels) != android::OK ||
        pixels == nullptr) {
        BW_LOGW("gralloc lock failed -> fail CLOSED (block)");
        return ScanResult{true, BW_VERDICT_FAIL_CLOSED};
    }
    // In-process score — no Binder hop on the scan path.
    BwVerdict v = bw_score_nsfw(static_cast<const uint8_t*>(pixels),
                                static_cast<int>(gb->getWidth()),
                                static_cast<int>(gb->getHeight()),
                                BW_FMT_RGBA8888, nullptr);
    gb->unlock();
    return ScanResult{true, v};
#else
    // Capture binding not compiled in: the visual gate is INACTIVE in this build.
    // No frame -> no verdict (returning SAFE would be fail-OPEN; returning BLOCK
    // would brick the screen with no input). The real build defines the macro.
    return inactive();
#endif
}

static ScanResult text_scan_once() {
#ifdef BULWARK_HAVE_AOSP_CAPTURE
    std::string text;
    if (!next_screen_text(&text) || text.empty()) {
        return inactive();  // no new text this tick
    }
    int v = bw_score_text(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    return ScanResult{true, static_cast<BwVerdict>(v)};
#else
    return inactive();
#endif
}

// ---- act on a verdict ------------------------------------------------------

static void act_on(ScanResult r, const char* path) {
    if (!r.scanned) {
        return;  // path inactive this tick — nothing was scored
    }
    if (r.verdict == BW_VERDICT_SAFE) {
        return;  // scored and safe
    }
    // NSFW or FAIL_CLOSED -> block (fail closed) + redacted alert.
    BW_LOGW("%s: verdict=%d -> BLOCK", path, static_cast<int>(r.verdict));
    apply_block_overlay();
    dispatch_guardian_alert(path, r.verdict);
}

// ---- main service loop -----------------------------------------------------

int main(int /*argc*/, char** /*argv*/) {
    // Load the NSFW model once. NULL -> the baked-in model
    // (/system/etc/bulwark/nsfw_detector.onnx, or include_bytes! in the .so).
    int init_rc = bw_init_once(nullptr);
    if (init_rc == BW_ERR_NO_MODEL) {
        // Not fatal: the text path (rules-first, no model) still works, and the
        // visual path returns BW_VERDICT_FAIL_CLOSED for every real frame.
        BW_LOGW("NSFW model unavailable (id=%s); visual gate is fail-CLOSED",
                bw_model_id());
    } else {
        BW_LOGI("NSFW model ready (id=%s)", bw_model_id());
    }

#ifdef BULWARK_HAVE_AOSP_CAPTURE
    // Binder thread pool for IPC callers (AMS event delivery, WindowManager).
    android::ProcessState::self()->startThreadPool();
    // TODO (host): register as a trusted IAccessibilityManager client (§4.3).
#else
    BW_LOGW("AOSP capture binding not compiled (BULWARK_HAVE_AOSP_CAPTURE unset): "
            "visual + text scan paths are INACTIVE in this scaffold build");
#endif

    struct timespec next_scan;
    clock_gettime(CLOCK_MONOTONIC, &next_scan);
    for (;;) {
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_scan, nullptr);
        next_scan.tv_sec += SCREEN_SCAN_INTERVAL_S;  // 1 Hz tick

        act_on(screen_scan_once(), "screen");
        act_on(text_scan_once(), "text");
    }
    return 0;  // unreachable; init restarts us if we exit
}
