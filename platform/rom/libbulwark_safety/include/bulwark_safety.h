/*
 * SCAFFOLD — not built here.
 * See platform/rom/README.md for integration instructions.
 *
 * Licence: Apache-2.0
 * SPDX-License-Identifier: Apache-2.0
 *
 * bulwark_safety.h — C API for the PH Bulwark content-safety scoring library.
 *
 * This header is the stable ABI surface between libbulwark_safety.so and its
 * two callers:
 *   - libcameraservice  (camera-gate hook, in-process, camera hot path)
 *   - bulwarkd          (screen/text scan daemon, separate process)
 *
 * Implementation: bulwark_safety.cpp wraps the Rust cdylib
 * (libbulwark_safety_rs), which provides the actual ONNX inference via
 * crates/bulwark-vision (ORT backend, AdamCodd vit-base-nsfw-detector,
 * Apache-2.0, int8-quantised, 384×384 input).
 *
 * CONTRACT (mirrors NsfwGate.kt and crates/bulwark-vision/src/lib.rs):
 *   - Input: RGBA pixels, row-major, no padding.
 *   - The library rescales to 384×384 internally (mirrors NsfwGate.kt INPUT_SIZE).
 *   - Normalisation: (x/255 − 0.5) / 0.5 per channel (Normalization::half()).
 *   - NSFW threshold: 0.7 (VisionConfig::default().nsfw_threshold).
 *   - Fail-CLOSED: if the model is not loaded or inference fails, returns
 *     BW_VERDICT_FAIL_CLOSED (not BW_VERDICT_SAFE). Callers MUST treat
 *     BW_VERDICT_FAIL_CLOSED as "block the frame."
 *   - No pixels are stored, hashed, logged, or transmitted by this library.
 *     The engine invariant (no explicit-media persistence) is enforced here.
 *   - Thread-safety: bw_score_nsfw() is safe to call from multiple threads
 *     concurrently after bw_init_once() has returned BW_OK. The Rust scorer
 *     holds an internal mutex over the ORT session (mirrors NsfwGate's
 *     @Synchronized score()).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Return codes                                                         */
/* ------------------------------------------------------------------ */

/** Returned by bw_init_once() on success. */
#define BW_OK            0
/** Returned by bw_init_once() if the model could not be loaded.
 *  In this state bw_score_nsfw() returns BW_VERDICT_FAIL_CLOSED. */
#define BW_ERR_NO_MODEL  1
/** Returned by bw_init_once() if already initialised (idempotent — not an error). */
#define BW_ALREADY_INIT  2

/* ------------------------------------------------------------------ */
/* Verdict                                                             */
/* ------------------------------------------------------------------ */

/**
 * Verdict returned by bw_score_nsfw().
 *
 * Callers must block the frame (substitute a solid-colour replacement)
 * for BW_VERDICT_NSFW and BW_VERDICT_FAIL_CLOSED alike. The distinction
 * matters only for metrics/logging.
 */
typedef enum BwVerdict {
    /** Frame scored below the NSFW threshold (0.7). Pass through. */
    BW_VERDICT_SAFE        = 0,
    /** Frame scored at/above the NSFW threshold. Block (substitute). */
    BW_VERDICT_NSFW        = 1,
    /**
     * Scoring failed (model not loaded, ORT unavailable, inference error,
     * or input too small to score). Callers MUST treat this as NSFW and
     * block the frame. This enforces the fail-CLOSED invariant: a frame
     * that cannot be scored is not safe to deliver.
     */
    BW_VERDICT_FAIL_CLOSED = 2,
} BwVerdict;

/* ------------------------------------------------------------------ */
/* Pixel format                                                        */
/* ------------------------------------------------------------------ */

/**
 * Pixel format of the input buffer.
 *
 * The library accepts RGBA (most common gralloc output after CPU lock)
 * and NV21/NV12 (YUV — common for preview/video streams). Convert to
 * RGBA on the caller side if neither format matches the gralloc layout.
 *
 * TODO: validate against the gralloc formats used by Camera3OutputStream
 * on android-16.0.0_r3 (lynx vendor HAL). Additional formats can be added
 * here without breaking the ABI.
 */
typedef enum BwPixelFormat {
    /** 4 bytes per pixel: R, G, B, A (alpha ignored). */
    BW_FMT_RGBA8888 = 0,
    /** YUV 4:2:0 semi-planar (NV21 — Y plane then interleaved VU). */
    BW_FMT_NV21     = 1,
    /** YUV 4:2:0 semi-planar (NV12 — Y plane then interleaved UV). */
    BW_FMT_NV12     = 2,
} BwPixelFormat;

/* ------------------------------------------------------------------ */
/* Init (call once at process start before any bw_score_nsfw() call)  */
/* ------------------------------------------------------------------ */

/**
 * bw_init_once() — load and warm up the NSFW ONNX model.
 *
 * Must be called exactly once per process before bw_score_nsfw(). Safe to
 * call from multiple threads; subsequent calls return BW_ALREADY_INIT without
 * re-loading the model.
 *
 * @param model_path  Filesystem path to the ONNX model, or NULL to use the
 *                    model baked into libbulwark_safety_rs at build time
 *                    (crates/bulwark-vision/models/nsfw_detector.onnx).
 *                    Passing NULL is the expected production path (baked model).
 *                    An operator-supplied model path overrides the baked model
 *                    (mirrors VisionAnalyzer::from_env() in bulwark-vision).
 *
 * @return BW_OK on success, BW_ERR_NO_MODEL if the model cannot be loaded,
 *         BW_ALREADY_INIT if already initialised.
 *
 * On BW_ERR_NO_MODEL the library is still safe to call — bw_score_nsfw()
 * will return BW_VERDICT_FAIL_CLOSED (fail-CLOSED, not crash).
 *
 * SCAFFOLD TODO: the actual model path on the system partition will be
 * /system/etc/bulwark/nsfw_detector.onnx (installed via Android.bp PRODUCT_COPY_FILES).
 * The baked-in model (NULL path) is preferred so the system works from first boot
 * before any provisioning step.
 */
int bw_init_once(const char* model_path);

/* ------------------------------------------------------------------ */
/* Scoring                                                             */
/* ------------------------------------------------------------------ */

/**
 * bw_score_nsfw() — score a single camera frame for NSFW content.
 *
 * Thread-safe after bw_init_once(). May be called concurrently from the
 * camera-gate hook (camera hot path) and from bulwarkd (screen-scan path)
 * if both processes link this library (each process has its own in-process
 * copy of the ORT session).
 *
 * @param pixels  Pointer to the first pixel byte of the frame. The buffer
 *                must be CPU-accessible (gralloc-locked with
 *                GRALLOC_USAGE_SW_READ_OFTEN before calling). The library
 *                does NOT hold a reference to this pointer after returning.
 * @param width   Frame width in pixels (before any rotation).
 * @param height  Frame height in pixels.
 * @param fmt     Pixel format (see BwPixelFormat).
 * @param score_out  If non-NULL and the verdict is not BW_VERDICT_FAIL_CLOSED,
 *                   written with the raw NSFW probability in [0.0, 1.0].
 *                   Useful for logging/metrics — callers must not use this
 *                   to make per-frame policy decisions (use the verdict).
 *                   Never written if BW_VERDICT_FAIL_CLOSED.
 *
 * @return BW_VERDICT_SAFE, BW_VERDICT_NSFW, or BW_VERDICT_FAIL_CLOSED.
 *
 * CONTRACT (fail-CLOSED):
 *   - pixels == NULL               → BW_VERDICT_FAIL_CLOSED
 *   - width < 1 || height < 1      → BW_VERDICT_FAIL_CLOSED
 *   - model not loaded             → BW_VERDICT_FAIL_CLOSED
 *   - inference error / OOM        → BW_VERDICT_FAIL_CLOSED
 *   - score >= 0.7 (threshold)     → BW_VERDICT_NSFW
 *   - score <  0.7                 → BW_VERDICT_SAFE
 *
 * PRIVACY: the library never writes pixel data to any file, memory-mapped
 * region, socket, or Binder buffer. Scoring is in-memory only.
 */
BwVerdict bw_score_nsfw(
    const uint8_t* pixels,
    int            width,
    int            height,
    BwPixelFormat  fmt,
    float*         score_out);

/* ------------------------------------------------------------------ */
/* Text path — on-screen text grooming / adult-content scan           */
/* ------------------------------------------------------------------ */

/**
 * bw_score_text() — score one snapshot of on-screen text (bulwarkd's screen
 * path) for grooming / adult content using the SHIPPING `bulwark-text`
 * rules-first detector, so detection never drifts from the engine. No ONNX
 * model is needed (rules-first), so this path is active even when the NSFW
 * model is absent.
 *
 * @param utf8  Pointer to `len` bytes of UTF-8 text (does NOT need to be
 *              NUL-terminated). NULL or len == 0 → BW_VERDICT_FAIL_CLOSED.
 * @param len   Number of bytes at `utf8`.
 *
 * @return BwVerdict:
 *   BW_VERDICT_SAFE        — the detector allowed the text.
 *   BW_VERDICT_NSFW        — flagged (rules engine returned block/blur/mute/
 *                            warn/log). Here "NSFW" means "flagged content".
 *   BW_VERDICT_FAIL_CLOSED — NULL/empty input, invalid UTF-8, analyzer
 *                            unavailable, or a panic. Treat as "flagged".
 *
 * PRIVACY: nothing about the text is logged, hashed, or persisted; scoring
 * is in-memory only (same content-free contract as bw_score_nsfw()).
 */
int bw_score_text(const uint8_t* utf8, size_t len);

/* ------------------------------------------------------------------ */
/* Diagnostics (content-free — safe to log)                           */
/* ------------------------------------------------------------------ */

/**
 * bw_model_id() — returns a short string identifying the loaded model.
 *
 * Content-free: the string identifies the model build (e.g.
 * "nsfw-vit-384-bundled-int8" or "stub-noop"). It never contains frame
 * content, scores, or paths that could leak PII.
 *
 * Returns "not-initialised" if bw_init_once() has not been called.
 * Returns "stub-noop" if the model failed to load (BW_ERR_NO_MODEL state).
 *
 * The returned pointer is valid for the lifetime of the process.
 */
const char* bw_model_id(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
