/*
 * aegis_apple.h — C ABI for aegis-apple-ffi.
 *
 * Hand-authored to match, exactly, the #[no_mangle] extern "C" exports in
 * src/ffi.rs. (cbindgen is not installed on the dev host; cbindgen.toml is
 * provided so this header can be regenerated on a Mac. If you regenerate, keep
 * this file and the Swift bridging header in sync with the Rust source.)
 *
 * The Apple Network Extension (NEFilterDataProvider) links the staticlib built
 * from aegis-apple-ffi and calls these functions to classify extracted text.
 *
 * SCOPE: filter + alerts ONLY. Nothing here reads other apps' messages, captures
 * the screen, tracks location, or blocks uninstall — those are forbidden for
 * third-party apps on Apple and are out of scope for Aegis by design.
 */

#ifndef AEGIS_APPLE_H
#define AEGIS_APPLE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Action codes — the value returned by aegis_apple_classify_text().          */
/* ------------------------------------------------------------------------- */

/** Forward the flow unchanged (ALLOW / LOG). */
#define AEGIS_APPLE_ALLOW 0
/** Forward but warn (interstitial / redacted local notification; WARN/BLUR/MUTE). */
#define AEGIS_APPLE_WARN  1
/** Drop / reset the flow (BLOCK, including CSAM-suspected). */
#define AEGIS_APPLE_BLOCK 2

/* ------------------------------------------------------------------------- */
/* Category codes — written to the optional out_category out-param. Mirrors   */
/* aegis.v1.Category. Carry a redacted reason to the UI WITHOUT message text.  */
/* ------------------------------------------------------------------------- */

typedef enum AegisAppleCategory {
  AEGIS_APPLE_CATEGORY_UNSPECIFIED    = 0,
  AEGIS_APPLE_CATEGORY_SAFE           = 1,
  AEGIS_APPLE_CATEGORY_ADULT_IMAGE    = 2,
  AEGIS_APPLE_CATEGORY_ADULT_AUDIO    = 3,
  AEGIS_APPLE_CATEGORY_ADULT_TEXT     = 4,
  AEGIS_APPLE_CATEGORY_GROOMING       = 5,
  AEGIS_APPLE_CATEGORY_CSAM_SUSPECTED = 6,
  AEGIS_APPLE_CATEGORY_VIOLENCE       = 7,
  AEGIS_APPLE_CATEGORY_SELF_HARM      = 8,
  AEGIS_APPLE_CATEGORY_HATE           = 9
} AegisAppleCategory;

/* ------------------------------------------------------------------------- */
/* Opaque engine handle.                                                      */
/* ------------------------------------------------------------------------- */

/** Opaque handle to the Rust engine (deterministic text analyzer + policy). */
typedef struct AegisEngine AegisEngine;

/* ------------------------------------------------------------------------- */
/* Functions.                                                                 */
/* ------------------------------------------------------------------------- */

/**
 * Construct a new engine.
 *
 * @return an owning, opaque pointer to free exactly once with
 *         aegis_apple_engine_free(), or NULL if construction failed
 *         (e.g. the built-in lexicon could not load).
 *
 * The engine is not internally synchronized across threads; serialize calls or
 * use one engine per thread.
 */
AegisEngine *aegis_apple_engine_new(void);

/**
 * Free an engine created by aegis_apple_engine_new().
 *
 * Passing NULL is a no-op. Passing a pointer not from aegis_apple_engine_new(),
 * or double-freeing, is undefined behaviour.
 *
 * @param ptr NULL, or a live pointer from aegis_apple_engine_new().
 */
void aegis_apple_engine_free(AegisEngine *ptr);

/**
 * Classify a UTF-8 text span.
 *
 * @param engine        engine from aegis_apple_engine_new(); if NULL, the call
 *                      fails open and returns AEGIS_APPLE_ALLOW.
 * @param text_utf8     pointer to UTF-8 bytes (need NOT be NUL-terminated); if
 *                      NULL, fails open (AEGIS_APPLE_ALLOW).
 * @param text_len      length of text_utf8 in bytes.
 * @param thread_utf8   OPTIONAL UTF-8 conversation id used to correlate messages
 *                      for cross-message grooming escalation; NULL for none.
 * @param thread_len    length of thread_utf8 in bytes.
 * @param out_category  OPTIONAL out-param; if non-NULL, receives an
 *                      AegisAppleCategory code on every non-erroring call.
 *
 * @return AEGIS_APPLE_ALLOW (0), AEGIS_APPLE_WARN (1), or AEGIS_APPLE_BLOCK (2).
 *         Invalid UTF-8 is treated as allow (fail-open). No message content is
 *         logged.
 */
int aegis_apple_classify_text(const AegisEngine *engine,
                              const char *text_utf8,
                              size_t text_len,
                              const char *thread_utf8,
                              size_t thread_len,
                              int *out_category);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AEGIS_APPLE_H */
