//! The C ABI surface — the only `unsafe` code in the crate.
//!
//! Every exported function is `#[no_mangle] extern "C"`, null-checks every
//! pointer, and is documented with its exact safety contract. The matching
//! C declarations live in `include/aegis_apple.h` (kept byte-for-byte in sync;
//! see `cbindgen.toml`).
//!
//! ## Fail-open invariant
//! On *any* invalid input (null engine, null text pointer, or text that is not
//! valid UTF-8) the classifier returns [`AEGIS_APPLE_ALLOW`] and logs nothing
//! about the content. A child-safety filter must never wedge a device's network
//! because of a decoding hiccup, and it must never leak message bytes into logs.

use std::os::raw::{c_char, c_int};

use crate::{AegisEngine, AppleAction, AppleCategory};

// --- Public C ABI constants (mirrored in the header) ----------------------

/// Action code: forward the flow unchanged.
pub const AEGIS_APPLE_ALLOW: c_int = AppleAction::Allow as c_int;
/// Action code: forward but warn (interstitial / redacted local notification).
pub const AEGIS_APPLE_WARN: c_int = AppleAction::Warn as c_int;
/// Action code: drop / reset the flow.
pub const AEGIS_APPLE_BLOCK: c_int = AppleAction::Block as c_int;

/// Construct a new engine (deterministic text analyzer + default policy).
///
/// # Returns
/// An owning, opaque pointer to be freed exactly once with
/// [`aegis_apple_engine_free`]. Returns `null` if the engine could not be
/// built (e.g. the built-in lexicon failed to load).
///
/// # Safety
/// The returned pointer must not be used after it has been passed to
/// [`aegis_apple_engine_free`]. The engine is not internally synchronized
/// across threads; serialize calls or use one engine per thread.
#[no_mangle]
pub extern "C" fn aegis_apple_engine_new() -> *mut AegisEngine {
    match AegisEngine::new() {
        Some(engine) => Box::into_raw(Box::new(engine)),
        None => std::ptr::null_mut(),
    }
}

/// Free an engine created by [`aegis_apple_engine_new`].
///
/// Passing `null` is a no-op. Passing any other pointer that did not come from
/// [`aegis_apple_engine_new`], or freeing the same pointer twice, is undefined
/// behaviour.
///
/// # Safety
/// `ptr` must be either `null` or a pointer previously returned by
/// [`aegis_apple_engine_new`] that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn aegis_apple_engine_free(ptr: *mut AegisEngine) {
    if ptr.is_null() {
        return;
    }
    // Reconstitute the Box and drop it.
    drop(unsafe { Box::from_raw(ptr) });
}

/// Classify a UTF-8 text span and return the action code
/// (`0`=allow, `1`=warn, `2`=block).
///
/// # Parameters
/// * `engine`       — an engine from [`aegis_apple_engine_new`]; if `null`, the
///                    call fails open and returns [`AEGIS_APPLE_ALLOW`].
/// * `text_utf8`    — pointer to UTF-8 bytes (NOT required to be NUL-terminated).
///                    If `null`, the call fails open and returns
///                    [`AEGIS_APPLE_ALLOW`].
/// * `text_len`     — length of `text_utf8` in bytes.
/// * `thread_utf8`  — OPTIONAL pointer to a UTF-8 conversation id used to
///                    correlate messages for cross-message grooming escalation.
///                    Pass `null` (and `thread_len == 0`) for no correlation.
/// * `thread_len`   — length of `thread_utf8` in bytes.
/// * `out_category` — OPTIONAL out-param; if non-null, receives the category
///                    code (see `AegisAppleCategory` in the header). Written on
///                    every non-erroring call, including allow.
///
/// # Returns
/// `0` (allow), `1` (warn), or `2` (block). Invalid UTF-8 in `text_utf8` is
/// treated as allow (fail-open); no message content is logged.
///
/// # Safety
/// `text_utf8` must point to at least `text_len` readable bytes (or be `null`).
/// `thread_utf8` must point to at least `thread_len` readable bytes (or be
/// `null`). `out_category` must be `null` or point to a writable `int32`.
/// `engine` must be `null` or a live pointer from [`aegis_apple_engine_new`].
#[no_mangle]
pub unsafe extern "C" fn aegis_apple_classify_text(
    engine: *const AegisEngine,
    text_utf8: *const c_char,
    text_len: usize,
    thread_utf8: *const c_char,
    thread_len: usize,
    out_category: *mut c_int,
) -> c_int {
    // Helper: write the category out-param if the caller provided one.
    let write_category = |cat: AppleCategory| {
        if !out_category.is_null() {
            // SAFETY: caller contract — non-null `out_category` is writable.
            unsafe { *out_category = cat as c_int };
        }
    };

    // Null engine or null text → fail open (allow), category unspecified.
    if engine.is_null() || text_utf8.is_null() {
        write_category(AppleCategory::Unspecified);
        return AEGIS_APPLE_ALLOW;
    }

    // SAFETY: `engine` is non-null and (per contract) a live engine pointer.
    let engine = unsafe { &*engine };

    // Borrow the text bytes and decode as UTF-8. Invalid UTF-8 fails open.
    // SAFETY: caller contract — `text_utf8` points to `text_len` readable bytes.
    let text_bytes = unsafe { std::slice::from_raw_parts(text_utf8 as *const u8, text_len) };
    let text = match std::str::from_utf8(text_bytes) {
        Ok(s) => s,
        Err(_) => {
            write_category(AppleCategory::Unspecified);
            return AEGIS_APPLE_ALLOW; // fail open; log nothing sensitive
        }
    };

    // Optional thread id; invalid/absent → empty (no correlation).
    let thread_id = if thread_utf8.is_null() || thread_len == 0 {
        ""
    } else {
        // SAFETY: caller contract — `thread_utf8` points to `thread_len` bytes.
        let bytes = unsafe { std::slice::from_raw_parts(thread_utf8 as *const u8, thread_len) };
        std::str::from_utf8(bytes).unwrap_or("")
    };

    let (action, category) = engine.classify(text, thread_id);
    write_category(category);
    action as c_int
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_engine_fails_open() {
        let text = b"send me a pic of you";
        let mut cat: c_int = -1;
        let r = unsafe {
            aegis_apple_classify_text(
                std::ptr::null(),
                text.as_ptr() as *const c_char,
                text.len(),
                std::ptr::null(),
                0,
                &mut cat,
            )
        };
        assert_eq!(r, AEGIS_APPLE_ALLOW);
        assert_eq!(cat, AppleCategory::Unspecified as c_int);
    }

    #[test]
    fn null_text_fails_open() {
        let e = aegis_apple_engine_new();
        assert!(!e.is_null());
        let r = unsafe {
            aegis_apple_classify_text(e, std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null_mut())
        };
        assert_eq!(r, AEGIS_APPLE_ALLOW);
        unsafe { aegis_apple_engine_free(e) };
    }

    #[test]
    fn invalid_utf8_fails_open() {
        let e = aegis_apple_engine_new();
        // Lone 0xFF is not valid UTF-8.
        let bad = [0xFFu8, 0xFE, 0x00, 0x41];
        let mut cat: c_int = -1;
        let r = unsafe {
            aegis_apple_classify_text(
                e,
                bad.as_ptr() as *const c_char,
                bad.len(),
                std::ptr::null(),
                0,
                &mut cat,
            )
        };
        assert_eq!(r, AEGIS_APPLE_ALLOW);
        assert_eq!(cat, AppleCategory::Unspecified as c_int);
        unsafe { aegis_apple_engine_free(e) };
    }

    #[test]
    fn image_request_blocks_via_ffi() {
        let e = aegis_apple_engine_new();
        let text = b"can you send me a pic of you";
        let thread = b"groomer";
        let mut cat: c_int = -1;
        let r = unsafe {
            aegis_apple_classify_text(
                e,
                text.as_ptr() as *const c_char,
                text.len(),
                thread.as_ptr() as *const c_char,
                thread.len(),
                &mut cat,
            )
        };
        assert_eq!(r, AEGIS_APPLE_BLOCK);
        assert_eq!(cat, AppleCategory::CsamSuspected as c_int);
        unsafe { aegis_apple_engine_free(e) };
    }

    #[test]
    fn free_null_is_noop() {
        unsafe { aegis_apple_engine_free(std::ptr::null_mut()) };
    }
}
