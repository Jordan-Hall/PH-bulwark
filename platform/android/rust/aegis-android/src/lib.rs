//! # aegis-android — JNI bridge for `co.libertyware.aegis.core.RustBridge`.
//!
//! This is the Rust side of the contract declared in
//! `platform/android/app/src/main/java/co/libertyware/aegis/core/RustBridge.kt`.
//! The Kotlin `object RustBridge` loads us via `System.loadLibrary("aegis_client")`
//! and declares six `external fun`s. We export the matching
//! `Java_co_libertyware_aegis_core_RustBridge_<method>` C-ABI symbols and forward
//! the on-device-captured text into the LEGITIMATE, deterministic analyzers:
//!
//!   * [`aegis_text::TextAnalyzer`] — rules-first grooming / adult-text detector.
//!   * [`aegis_policy::Policy`]     — the `Verdict -> Action` policy engine.
//!
//! ## What this bridge is (and is NOT)
//! It is a TRANSPARENT content-safety bridge: text the child's apps have already
//! rendered on screen (the accessibility path) is analysed on-device by the same
//! deterministic grooming pipeline the network path uses, and a content-free
//! verdict is returned. It performs **no** device-control / surveillance surface
//! — no anti-uninstall, no screen mirroring, no remote control/wipe, no hidden
//! location, no reading of other apps beyond this on-device safety check.
//!
//! ## Privacy
//! Evidence and logs carry only category names, scores and **redacted excerpts**
//! produced by `aegis-text` — never raw message text. We never log captured
//! content. On any bad/again input (null pointer, non-UTF-8 jstring, poisoned
//! lock) we **fail open** (return a SAFE/ALLOW verdict, or a no-op) rather than
//! crash the host app — a content filter must never take down the device.
//!
//! ## Handle model
//! `RustBridge.analyzeText` is a method on a Kotlin `object` (no per-call handle),
//! so the analyzer engine lives in a process-global [`OnceLock`] built on first
//! use. `startVpn` additionally boxes a [`VpnSession`] and returns its pointer as
//! the opaque `jlong` handle the Kotlin keeps and later passes back to `stopVpn`,
//! which frees it. Every raw pointer and every jstring is null-checked/validated.
//!
//! FFI requires `unsafe`, so we `allow` (never `forbid`) it and keep every unsafe
//! block tiny and pointer-validated.

#![allow(unsafe_code)]

use std::sync::OnceLock;

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::JNIEnv;

use aegis_policy::{AgeProfile, Policy, PolicyContext, PolicyDecision};
use aegis_proto::v1::{Category, SourceChannel, TextSpan, Verdict};
use aegis_proto::DeviceId;
use aegis_text::TextAnalyzer;

// ---------------------------------------------------------------------------
// The on-device engine: deterministic analyzer + policy. Built once per process.
// ---------------------------------------------------------------------------

/// The legitimate content-analysis engine shared by every bridge call.
///
/// `TextAnalyzer::new()` returns a `Result` (it loads the built-in lexicon); the
/// `Policy` defaults are pure thresholds. We construct both lazily and keep them
/// for the life of the process — the analyzer also owns per-thread grooming
/// memory keyed by `thread_id`, so it MUST be a single shared instance.
struct Engine {
    text: TextAnalyzer,
    policy: Policy,
}

impl Engine {
    fn build() -> Option<Engine> {
        // If the lexicon fails to load we fail open: no engine -> SAFE verdicts.
        let text = TextAnalyzer::new().ok()?;
        Some(Engine {
            text,
            policy: Policy::default(),
        })
    }
}

/// Process-global engine. `None` until first successful build; if building ever
/// fails we leave it unset and every call fails open.
static ENGINE: OnceLock<Option<Engine>> = OnceLock::new();

fn engine() -> Option<&'static Engine> {
    ENGINE.get_or_init(Engine::build).as_ref()
}

// ---------------------------------------------------------------------------
// VPN session — the opaque boxed handle returned by startVpn / freed by stopVpn.
// ---------------------------------------------------------------------------

/// The boxed state behind the `jlong` handle `startVpn` returns.
///
/// SCOPE NOTE: the real TUN intercept loop lives in the networking crates owned
/// by other agents (aegis-net / aegis-client) and is intentionally NOT built
/// here — this crate is the content-analysis bridge only. We record the fd and
/// config so the handle round-trips cleanly (and so `stopVpn` has something well
/// defined to free), and leave the loop wiring to the owning crate.
// Fields are intentionally stored-but-not-yet-read: the TUN intercept loop that
// would consume them lives in the networking crate owned by another agent. We
// keep them so the handle round-trips meaningfully and the loop wiring has a
// well-defined place to read them from.
#[allow(dead_code)]
struct VpnSession {
    /// The TUN file descriptor handed over by `AegisVpnService` (informational;
    /// we do not read/write it here).
    tun_fd: i32,
    /// The serialized client config string (cluster endpoint, device id, …).
    config_json: String,
}

// ---------------------------------------------------------------------------
// Small JNI helpers — all fail-safe, never panic across the FFI boundary.
// ---------------------------------------------------------------------------

/// Read a `JString` into an owned Rust `String`. Returns `None` for a null
/// reference or non-UTF-8 content (caller then fails open). Never logs content.
fn jstring_to_string(env: &mut JNIEnv, s: &JString) -> Option<String> {
    if s.is_null() {
        return None;
    }
    // get_string validates the reference and decodes modified-UTF-8.
    env.get_string(s).ok().map(|js| js.into())
}

/// Build a Java string from a Rust `&str`, returning a null jstring on failure
/// (the Kotlin side treats null/empty as "bridge unavailable", which is safe).
fn string_to_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(js) => js.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The fail-open verdict JSON used whenever input is bad or the engine is
/// unavailable: SAFE / ALLOW, no grooming signal. A filter must never block the
/// device just because it could not analyse a fragment.
fn safe_verdict_json() -> String {
    // Category::Safe == 1, Action::Allow == 1 in the proto. We emit the stable
    // string `category` the Kotlin substring check keys on, plus the numeric
    // fields callers expect.
    r#"{"category":"SAFE","action":"ALLOW","severity":"INFO","score":0.0,"rationale":"bridge fail-open: not analysed"}"#
        .to_string()
}

/// Stable, content-free uppercase name for a category — this is what the Kotlin
/// accessibility service substring-matches on (`"GROOMING"`, `"CSAM"`), and what
/// `AlertNotifier`/review code reads. Mirrors the proto enum names.
fn category_name(c: Category) -> &'static str {
    match c {
        Category::Unspecified => "UNSPECIFIED",
        Category::Safe => "SAFE",
        Category::AdultImage => "ADULT_IMAGE",
        Category::AdultAudio => "ADULT_AUDIO",
        Category::AdultText => "ADULT_TEXT",
        Category::Grooming => "GROOMING",
        Category::CsamSuspected => "CSAM_SUSPECTED",
        Category::Violence => "VIOLENCE",
        Category::SelfHarm => "SELF_HARM",
        Category::Hate => "HATE",
    }
}

/// Stable, content-free name for the policy-decided action.
fn action_name(a: aegis_proto::v1::Action) -> &'static str {
    use aegis_proto::v1::Action;
    match a {
        Action::Unspecified => "UNSPECIFIED",
        Action::Allow => "ALLOW",
        Action::Log => "LOG",
        Action::Warn => "WARN",
        Action::Blur => "BLUR",
        Action::Mute => "MUTE",
        Action::Block => "BLOCK",
    }
}

/// Serialize a `Verdict` + the policy `PolicyDecision` into the compact JSON the
/// Kotlin side consumes. Carries ONLY content-free fields plus the analyzer's
/// already-redacted excerpt — never raw message text.
fn verdict_json(verdict: &Verdict, decision: &PolicyDecision) -> String {
    let category = category_name(verdict.category());
    // The policy engine is the authority on the action actually taken.
    let action = action_name(decision.action);

    let fired: Vec<&str> = verdict
        .grooming
        .as_ref()
        .map(|g| g.fired_categories.iter().map(String::as_str).collect())
        .unwrap_or_default();

    // PRIVACY: the guardian-facing `redacted_context` (the AlertNotifier body)
    // is the policy engine's CONTENT-FREE `reason` string — never the analyzer's
    // text excerpt. The analyzer's "[redacted · rule] …" excerpt is fine for most
    // rules, but a few (e.g. image_request) echo the quoted source phrase, so the
    // bridge does NOT forward it. The fired-rule names already explain *what*
    // tripped, content-free.
    //
    // Hand-build via serde_json so strings are correctly escaped. `category` is
    // a STRING (not the proto's numeric enum) so the Kotlin `contains("\"GROOMING")`
    // / `contains("\"CSAM")` checks fire as intended.
    let obj = serde_json::json!({
        "category": category,
        "action": action,
        "score": verdict.score,
        "report": decision.report,
        "reason": decision.reason,
        "fired_categories": fired,
        // The notification body AlertNotifier reads: content-free policy reason.
        "redacted_context": decision.reason,
    });
    serde_json::to_string(&obj).unwrap_or_else(|_| safe_verdict_json())
}

// ---------------------------------------------------------------------------
// JNI exports — one per `external fun` in RustBridge.kt. Symbol names are
//   Java_<package with '.'->'_'>_<Class>_<method>
// i.e. Java_co_libertyware_aegis_core_RustBridge_<method>.
// ---------------------------------------------------------------------------

/// `external fun startVpn(tunFd: Int, configJson: String): Long`
///
/// Box a [`VpnSession`] and return its pointer as the opaque handle. The actual
/// TUN intercept loop is owned by the networking crates (out of scope here); we
/// give the Kotlin a well-defined handle to hold and later free via `stopVpn`.
/// Also warms the analyzer engine so the first `analyzeText` is fast.
///
/// # Safety
/// JNI entry point. `env`/`class` are valid for the call; `config_json` may be
/// any reference and is validated. Returns `0` on failure (Kotlin treats a `0`
/// handle as "not started").
#[no_mangle]
pub extern "system" fn Java_co_libertyware_aegis_core_RustBridge_startVpn(
    mut env: JNIEnv,
    _class: JClass,
    tun_fd: jint,
    config_json: JString,
) -> jlong {
    // Warm the engine (ignore failure — analyzeText will fail open if absent).
    let _ = engine();

    let config = jstring_to_string(&mut env, &config_json).unwrap_or_default();
    let session = Box::new(VpnSession {
        tun_fd: tun_fd as i32,
        config_json: config,
    });
    // Leak the box into a raw pointer the caller owns; stopVpn reclaims it.
    Box::into_raw(session) as jlong
}

/// `external fun stopVpn(handle: Long)`
///
/// Reclaim and drop the [`VpnSession`] the handle points at. A `0` / null handle
/// is a no-op (idempotent), so a double stop or a never-started service is safe.
///
/// # Safety
/// `handle` must be either `0` or a value previously returned by `startVpn` and
/// not yet freed. We null-check and only reconstruct the `Box` once.
#[no_mangle]
pub extern "system" fn Java_co_libertyware_aegis_core_RustBridge_stopVpn(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: non-zero handles are pointers produced by `startVpn`'s
    // `Box::into_raw`; we reconstruct the Box exactly once and drop it.
    unsafe {
        drop(Box::from_raw(handle as *mut VpnSession));
    }
}

/// `external fun analyzeText(app: String, threadId: String, text: String): String`
///
/// THE on-device grooming path. Runs the deterministic rules + policy engine on
/// the already-rendered text and returns a content-free `Verdict` JSON (string
/// `category`, policy `action`, score, redacted excerpt). Fails open to a SAFE
/// verdict on any bad input or if the engine is unavailable.
///
/// # Safety
/// JNI entry point. Every jstring argument is null-/UTF-8-validated.
#[no_mangle]
pub extern "system" fn Java_co_libertyware_aegis_core_RustBridge_analyzeText(
    mut env: JNIEnv,
    _class: JClass,
    app: JString,
    thread_id: JString,
    text: JString,
) -> jstring {
    // Validate every input; any failure -> fail open (SAFE).
    let app = jstring_to_string(&mut env, &app).unwrap_or_default();
    let thread_id = match jstring_to_string(&mut env, &thread_id) {
        Some(t) if !t.is_empty() => t,
        // No usable thread id -> still analyse, but with an empty (isolated) id.
        _ => String::new(),
    };
    let text = match jstring_to_string(&mut env, &text) {
        Some(t) => t,
        None => return string_to_jstring(&mut env, &safe_verdict_json()),
    };

    let Some(engine) = engine() else {
        return string_to_jstring(&mut env, &safe_verdict_json());
    };

    // Build the TextSpan the analyzer expects. `from_minor` is unknown from the
    // accessibility tree; default false. No prior excerpts passed inline — the
    // analyzer keeps its own per-thread memory.
    let span = TextSpan {
        text,
        lang: String::new(), // empty -> analyzer falls back to English lexicon
        app,
        thread_id,
        from_minor: false,
        prior_excerpts: Vec::new(),
    };

    // Deterministic analysis. `analyze_span` is pure CPU/in-memory and infallible
    // (it returns a Verdict, never an error). Timestamp 0 = "now unknown"; the
    // analyzer's rapid-escalation window degrades gracefully without real ts.
    let verdict = engine.text.analyze_span("a11y", &span, 0);

    // Policy authority: map the verdict -> action under a default (Teen) context.
    // The supervised child's real age band is configured in the parent app; the
    // bridge uses the engine default until that config is wired through.
    let ctx = PolicyContext::new(
        DeviceId(String::new()),
        SourceChannel::OcrOnscreen,
        AgeProfile::default(),
    );
    let decision = engine.policy.evaluate(&verdict, &ctx);

    let json = verdict_json(&verdict, &decision);
    string_to_jstring(&mut env, &json)
}

/// `external fun nextAlert(): String?`
///
/// Poll the next pending guardian alert as JSON, or return `null` when none is
/// pending. Alert generation/queueing is owned by the alert crates
/// (aegis-alert), which are out of scope for this bridge; until that queue is
/// wired through here, there are no alerts to surface, so we return `null`. The
/// Kotlin poller (`AegisVpnService.startAlertPoller`) treats `null` as "nothing
/// pending" and sleeps — so this is the correct, safe no-op.
///
/// # Safety
/// JNI entry point with no pointer arguments.
#[no_mangle]
pub extern "system" fn Java_co_libertyware_aegis_core_RustBridge_nextAlert(
    _env: JNIEnv,
    _class: JClass,
) -> jstring {
    // null jstring == Kotlin `null`.
    std::ptr::null_mut()
}

/// `external fun submitReviewDecision(alertId: String, approve: Boolean)`
///
/// Route the guardian's approve / keep-blocked decision to the policy/allowlist
/// layer. The persistent allowlist lives in aegis-store (DB), which is out of
/// scope for this bridge (and intentionally not depended on — rusqlite does not
/// build on this host). We validate the inputs and no-op safely; the owning
/// crate wires the decision into the device allowlist.
///
/// # Safety
/// JNI entry point. `alert_id` is null-/UTF-8-validated; a bad value is ignored.
#[no_mangle]
pub extern "system" fn Java_co_libertyware_aegis_core_RustBridge_submitReviewDecision(
    mut env: JNIEnv,
    _class: JClass,
    alert_id: JString,
    _approve: jboolean,
) {
    // Validate (and thereby ignore obviously-bad ids); never log the value.
    let _alert_id = jstring_to_string(&mut env, &alert_id).unwrap_or_default();
    // No-op until the aegis-store-backed allowlist is wired through this bridge.
}

/// `external fun registerParentPushToken(token: String)`
///
/// Register this parent device's FCM push token so the cluster can deliver alerts
/// remotely. Push delivery is owned by the server/alert crates; this bridge only
/// validates the token and no-ops (same-device review needs no token).
///
/// # Safety
/// JNI entry point. `token` is null-/UTF-8-validated; a bad value is ignored.
#[no_mangle]
pub extern "system" fn Java_co_libertyware_aegis_core_RustBridge_registerParentPushToken(
    mut env: JNIEnv,
    _class: JClass,
    token: JString,
) {
    let _token = jstring_to_string(&mut env, &token).unwrap_or_default();
    // No-op until remote FCM delivery is wired through this bridge.
}

// ---------------------------------------------------------------------------
// Host-target tests. These exercise the pure analysis/serialization logic that
// sits behind the JNI shims (the JNI calls themselves need a live JVM, so they
// are validated by the host `cargo build` type-checking the signatures).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(engine: &Engine, thread: &str, text: &str) -> (Verdict, PolicyDecision) {
        let span = TextSpan {
            text: text.to_string(),
            lang: String::new(),
            app: "testchat".to_string(),
            thread_id: thread.to_string(),
            from_minor: false,
            prior_excerpts: Vec::new(),
        };
        let v = engine.text.analyze_span("t", &span, 0);
        let ctx = PolicyContext::new(
            DeviceId(String::new()),
            SourceChannel::OcrOnscreen,
            AgeProfile::default(),
        );
        let d = engine.policy.evaluate(&v, &ctx);
        (v, d)
    }

    #[test]
    fn engine_builds() {
        assert!(Engine::build().is_some(), "lexicon must load on host");
    }

    #[test]
    fn benign_text_is_safe_allow_json() {
        let e = Engine::build().unwrap();
        let (v, d) = analyze(&e, "t1", "are you coming to football practice tonight?");
        let json = verdict_json(&v, &d);
        assert!(json.contains("\"category\":\"SAFE\""), "{json}");
        assert!(json.contains("\"action\":\"ALLOW\""), "{json}");
        // No raw text leaks for a safe verdict (no evidence at all).
        assert!(!json.contains("football"), "{json}");
    }

    #[test]
    fn image_request_is_csam_and_json_triggers_kotlin_check() {
        let e = Engine::build().unwrap();
        let (v, d) = analyze(&e, "t2", "send me a pic of you in your room");
        assert_eq!(v.category(), Category::CsamSuspected);
        let json = verdict_json(&v, &d);
        // The Kotlin accessibility service keys on these exact substrings.
        assert!(json.contains("\"CSAM"), "{json}");
        // CSAM policy: BLOCK + report flag.
        assert!(json.contains("\"action\":\"BLOCK\""), "{json}");
        assert!(json.contains("\"report\":true"), "{json}");
        // Evidence is a redacted excerpt only — never the raw message.
        assert!(!json.contains("send me a pic"), "raw text leaked: {json}");
    }

    #[test]
    fn grooming_thread_escalates_and_json_has_grooming_marker() {
        let e = Engine::build().unwrap();
        // Secrecy then platform switch in one thread should reach a grooming
        // verdict whose JSON the Kotlin `contains("\"GROOMING")` check catches.
        analyze(&e, "g1", "hey this is our little secret ok, dont tell your parents");
        let (v, d) = analyze(&e, "g1", "lets move to telegram so we can talk there");
        assert_eq!(v.category(), Category::Grooming);
        let json = verdict_json(&v, &d);
        assert!(json.contains("\"GROOMING"), "{json}");
    }

    #[test]
    fn fail_open_json_is_safe_allow() {
        let json = safe_verdict_json();
        assert!(json.contains("\"SAFE\""));
        assert!(json.contains("\"ALLOW\""));
    }
}
