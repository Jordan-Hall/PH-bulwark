//! # bulwark-android — JNI bridge for `co.predatorhunters.bulwark.core.RustBridge`.
//!
//! This is the Rust side of the contract declared in
//! `platform/android/app/src/main/java/co/predatorhunters/bulwark/core/RustBridge.kt`.
//! The Kotlin `object RustBridge` loads us via `System.loadLibrary("bulwark_client")`
//! and declares the `external fun`s. We export the matching
//! `Java_co_predatorhunters_bulwark_core_RustBridge_<method>` C-ABI symbols and forward
//! the on-device-captured text into the LEGITIMATE, deterministic analyzers:
//!
//!   * [`bulwark_text::TextAnalyzer`] — rules-first grooming / adult-text detector.
//!   * [`bulwark_policy::Policy`]     — the `Verdict -> Action` policy engine.
//!
//! ## What this bridge is (and is NOT)
//! It is a TRANSPARENT content-safety + tamper-EVIDENCE bridge: text the child's
//! apps have already rendered on screen (the accessibility path) is analysed
//! on-device by the same deterministic grooming pipeline the network path uses and
//! a content-free verdict is returned; and `reportTamper` relays redacted
//! PROTECTION_DISABLED events (an uninstall attempt, or a protection turned off) so
//! the guardian is told. Anti-removal *enforcement* (device admin / Device Owner /
//! always-on-VPN lockdown) lives in the consented Android policy layer
//! (`co.predatorhunters.bulwark.admin`), applied OPENLY on a managed child device — never
//! covertly from here. This bridge still performs **no** screen mirroring, remote
//! control/wipe, hidden location, or reading of other apps beyond the on-device
//! safety check + the uninstall-guard the child app transparently runs.
//!
//! ## Privacy
//! Evidence and logs carry only category names, scores and **redacted excerpts**
//! produced by `bulwark-text` — never raw message text. We never log captured
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

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use jni::objects::{GlobalRef, JClass, JObject, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::JNIEnv;

use bulwark_policy::{AgeProfile, Policy, PolicyContext, PolicyDecision};
use bulwark_proto::v1::accounts_client::AccountsClient;
use bulwark_proto::v1::child_control_client::ChildControlClient;
use bulwark_proto::v1::{
    Category, ChildConfig, ChildConfigFilter, FilteringProfile, PairResult, RedeemPairCodeRequest,
    SourceChannel, TextSpan, Verdict,
};
use bulwark_proto::DeviceId;
use bulwark_text::TextAnalyzer;
use tonic::transport::Endpoint;

pub mod flow;
pub mod relay;

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
// Tamper queue — child-device protection-downgrade events (uninstall attempt,
// device-admin/accessibility/VPN turned off). `reportTamper` enqueues a redacted
// PROTECTION_DISABLED alert JSON; `nextAlert` drains it (so the existing alert
// poller surfaces it, and the same path relays it to the cluster once wired).
// Content-free: only WHICH protection changed. Bounded so a misbehaving caller
// can't grow it without limit.
// ---------------------------------------------------------------------------

const TAMPER_QUEUE_CAP: usize = 64;

fn tamper_queue() -> &'static Mutex<VecDeque<String>> {
    static Q: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    Q.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Enqueue a content-free PROTECTION_DISABLED alert so the existing Kotlin
/// alert poller (`nextAlert`) surfaces it to the guardian. Used by
/// `reportTamper` and by the VPN data path when it exits with an error (a
/// captive TUN with a dead pump would otherwise be a silent blackhole).
/// Enqueue any guardian alert JSON for the Kotlin `nextAlert` poller. Bounded
/// so a misbehaving caller can't grow the queue without limit.
fn enqueue_alert_json(json: String) {
    if let Ok(mut q) = tamper_queue().lock() {
        if q.len() < TAMPER_QUEUE_CAP {
            q.push_back(json);
        }
    }
}

fn enqueue_protection_alert(tag: &str, message: &str) {
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let alert_id = format!("{tag}-{now_s}");
    // AlertKind::PROTECTION_DISABLED == 3; category 0 (a status signal, not content).
    let obj = serde_json::json!({
        "alert_id": alert_id,
        "kind": 3,
        "category": 0,
        "redacted_context": message,
    });
    enqueue_alert_json(obj.to_string());
    // ALSO relay to the enrolled cluster (best-effort, content-free, never
    // blocks or crashes) so a guardian on ANOTHER device learns of the
    // downgrade. No-op until startVpn has seen an enrolled config.
    relay::relay_alert_best_effort(bulwark_proto::v1::AlertEvent {
        alert_id,
        kind: bulwark_proto::v1::AlertKind::ProtectionDisabled as i32,
        severity: bulwark_proto::v1::Severity::High as i32,
        ts: relay::now_ms(),
        redacted_context: message.to_string(),
        ..Default::default()
    });
}

/// Guardian-facing, content-free description for an `bulwark.v1.TamperKind` ordinal.
fn tamper_message(kind: i32) -> &'static str {
    match kind {
        1 => "Someone tried to remove the Bulwark app on the child's device.",
        2 => "Bulwark device management was turned off on the child's device.",
        3 => "Bulwark on-device monitoring was turned off on the child's device.",
        4 => "The Bulwark filtering VPN was turned off on the child's device.",
        6 => "The child's device entered safe mode or was factory-reset.",
        _ => "Protection status changed on the child's device.",
    }
}

// ---------------------------------------------------------------------------
// VPN session — the opaque boxed handle returned by startVpn / freed by stopVpn.
// ---------------------------------------------------------------------------

/// The boxed state behind the `jlong` handle `startVpn` returns.
///
/// SCOPE NOTE: the real TUN intercept loop lives in the networking crates owned
/// by other agents (bulwark-net / bulwark-client) and is intentionally NOT built
/// here — this crate is the content-analysis bridge only. We record the fd and
/// config so the handle round-trips cleanly (and so `stopVpn` has something well
/// defined to free), and leave the loop wiring to the owning crate.
/// The boxed state behind the `jlong` handle: the tokio runtime running the VPN
/// data path (`bulwark_net::vpn::run_android_data_path`) and a `CancellationToken`
/// to stop it. `stopVpn` cancels + tears it down. The `GlobalRef` keeps the
/// `VpnService` alive for the session's lifetime.
struct VpnSession {
    runtime: tokio::runtime::Runtime,
    shutdown: bulwark_net::vpn::CancellationToken,
    _vpn_service: Option<GlobalRef>,
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

/// Pair codes are shown to humans, so tolerate spaces/dashes and normalize to the
/// compact uppercase token the server minted. Empty remains empty so validation
/// can return a clear error.
fn normalize_pair_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn ok_pairing_json(pair: &PairResult) -> String {
    let obj = serde_json::json!({
        "ok": true,
        "child_id": pair.child_id,
        "family_id": pair.family_id,
    });
    serde_json::to_string(&obj).unwrap_or_else(|_| {
        r#"{"ok":false,"error":"could not serialize enrollment result"}"#.to_string()
    })
}

fn err_pairing_json(error: impl AsRef<str>) -> String {
    let obj = serde_json::json!({
        "ok": false,
        "error": error.as_ref(),
    });
    serde_json::to_string(&obj)
        .unwrap_or_else(|_| r#"{"ok":false,"error":"enrollment failed"}"#.to_string())
}

async fn redeem_pair_code_rpc(
    endpoint: String,
    code: String,
    device_id: String,
) -> Result<PairResult, String> {
    let endpoint = endpoint.trim();
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return Err("server must start with http:// or https://".to_string());
    }

    let code = normalize_pair_code(&code);
    if code.is_empty() {
        return Err("enter the pair code from the parent app".to_string());
    }
    let device_id = device_id.trim();
    if device_id.is_empty() {
        return Err("device id is not ready yet".to_string());
    }

    let builder = Endpoint::from_shared(endpoint.to_string())
        .map_err(|_| "server address is not valid".to_string())?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));
    let channel = builder
        .connect()
        .await
        .map_err(|e| format!("could not reach server: {e}"))?;
    let mut accounts = AccountsClient::new(channel);
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        accounts.redeem_pair_code(RedeemPairCodeRequest {
            code,
            device_id: device_id.to_string(),
        }),
    )
    .await
    .map_err(|_| "server timed out while redeeming the code".to_string())?
    .map_err(|e| match e.code() {
        tonic::Code::NotFound => "pair code is invalid, expired, or for another server".to_string(),
        tonic::Code::AlreadyExists => "this device is already enrolled on that server".to_string(),
        tonic::Code::InvalidArgument => "pair code or device id was rejected".to_string(),
        _ => format!("server rejected enrollment: {}", e.code()),
    })?
    .into_inner();

    Ok(result)
}

// ---------------------------------------------------------------------------
// ChildControl fetch — the child-side half of the parent-controlled VPN
// (docs/design/parent-controlled-vpn.md §3, workflow B step 2). The device
// fetches ITS OWN desired config by device_id over the same transport pattern
// as enrollment. CONTENT-FREE: policy + routing only, never message/media.
// The strictly-newer config_version gate (replay/rollback defense) lives on
// the Kotlin side, which persists the last applied version.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Age-profile global — the guardian's strictness band (ChildConfig.profile),
// applied to every on-device policy evaluation. Content-free: a band name only.
// Written by startVpn (from deviceConfigJson's persisted `profile`) and by
// fetchChildConfig (from a fresh, not-older guardian config); read by
// analyzeText. Defaults to the engine baseline (Teen) until a config arrives.
// ---------------------------------------------------------------------------

fn age_profile_cell() -> &'static Mutex<AgeProfile> {
    static P: OnceLock<Mutex<AgeProfile>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(AgeProfile::default()))
}

/// Map a ChildConfig profile name (the stable UPPERCASE strings `profile_name`
/// emits) onto the policy engine's band. CUSTOM has no on-device thresholds
/// yet, so it maps to the engine's Teen baseline; unknown/empty returns `None`
/// (leave the band as-is — never silently change strictness on a parse hiccup).
fn age_profile_from_name(name: &str) -> Option<AgeProfile> {
    match name.trim() {
        "YOUNG_CHILD" => Some(AgeProfile::YoungChild),
        "PRETEEN" => Some(AgeProfile::PreTeen),
        "TEEN" => Some(AgeProfile::Teen),
        "CUSTOM" => Some(AgeProfile::Teen),
        _ => None,
    }
}

fn set_age_profile(profile: AgeProfile) {
    if let Ok(mut p) = age_profile_cell().lock() {
        *p = profile;
    }
}

fn current_age_profile() -> AgeProfile {
    age_profile_cell().lock().map(|p| *p).unwrap_or_default()
}

/// Apply the `profile` field of a device-config JSON (the Kotlin
/// `BulwarkVpnService.deviceConfigJson()`). Anything malformed or missing is
/// ignored — fail open, never crash, never downgrade on bad input.
fn apply_profile_from_config_json(config_json: &str) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return;
    };
    if let Some(p) = v
        .get("profile")
        .and_then(|p| p.as_str())
        .and_then(age_profile_from_name)
    {
        set_age_profile(p);
    }
}

/// Stable, content-free uppercase name for a strictness band — mirrors the
/// proto enum names (same style as `category_name`), so the Kotlin side keys
/// on strings, never bare ordinals.
fn profile_name(p: FilteringProfile) -> &'static str {
    match p {
        FilteringProfile::Unspecified => "UNSPECIFIED",
        FilteringProfile::YoungChild => "YOUNG_CHILD",
        FilteringProfile::Preteen => "PRETEEN",
        FilteringProfile::Teen => "TEEN",
        FilteringProfile::Custom => "CUSTOM",
    }
}

/// Serialize the guardian's desired config for the Kotlin reconciler. Carries
/// ONLY policy/routing fields (the control plane is content-free by contract).
/// The guardian's account id (`updated_by`) is server-side audit detail the
/// child does not need, so it is deliberately omitted.
fn ok_child_config_json(cfg: &ChildConfig) -> String {
    let obj = serde_json::json!({
        "ok": true,
        "child_id": cfg.child_id,
        "device_id": cfg.device_id,
        "filtering_enabled": cfg.filtering_enabled,
        "server_region": cfg.server_region,
        "server_endpoint": cfg.server_endpoint,
        "profile": profile_name(cfg.profile()),
        "require_always_on": cfg.require_always_on,
        "config_version": cfg.config_version,
        "updated_ts": cfg.updated_ts,
    });
    serde_json::to_string(&obj).unwrap_or_else(|_| {
        r#"{"ok":false,"error":"could not serialize child config"}"#.to_string()
    })
}

fn err_child_config_json(error: impl AsRef<str>) -> String {
    let obj = serde_json::json!({
        "ok": false,
        "error": error.as_ref(),
    });
    serde_json::to_string(&obj)
        .unwrap_or_else(|_| r#"{"ok":false,"error":"config fetch failed"}"#.to_string())
}

async fn fetch_child_config_rpc(
    endpoint: String,
    device_id: String,
    applied_version: u64,
) -> Result<ChildConfig, String> {
    let endpoint = endpoint.trim();
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return Err("server must start with http:// or https://".to_string());
    }
    let device_id = device_id.trim();
    if device_id.is_empty() {
        return Err("device id is not ready yet".to_string());
    }

    let builder = Endpoint::from_shared(endpoint.to_string())
        .map_err(|_| "server address is not valid".to_string())?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));
    let channel = builder
        .connect()
        .await
        .map_err(|e| format!("could not reach server: {e}"))?;
    let mut control = ChildControlClient::new(channel);
    let config = tokio::time::timeout(
        Duration::from_secs(10),
        // One-shot Get: the server returns the CURRENT config unconditionally,
        // and RECORDS `have_version` as this device's applied-version report —
        // the poll doubles as the "applied ✓ vN" ack the parent console shows
        // via GetChildStatus. The strictly-newer apply check still happens on
        // the Kotlin side against the persisted applied version.
        control.get_child_config(ChildConfigFilter {
            device_id: device_id.to_string(),
            have_version: applied_version,
        }),
    )
    .await
    .map_err(|_| "server timed out while fetching the config".to_string())?
    .map_err(|e| match e.code() {
        tonic::Code::NotFound => "no guardian config for this device yet".to_string(),
        tonic::Code::InvalidArgument => "device id was rejected".to_string(),
        _ => format!("server rejected the config fetch: {}", e.code()),
    })?
    .into_inner();

    Ok(config)
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
fn action_name(a: bulwark_proto::v1::Action) -> &'static str {
    use bulwark_proto::v1::Action;
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
// i.e. Java_co_predatorhunters_bulwark_core_RustBridge_<method>.
// ---------------------------------------------------------------------------

/// `external fun startVpn(vpnService: VpnService, tunFd: Int, configJson: String): Long`
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
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_startVpn(
    mut env: JNIEnv,
    _class: JClass,
    vpn_service: JObject,
    tun_fd: jint,
    config_json: JString,
) -> jlong {
    // Warm the engine (ignore failure — analyzeText will fail open if absent).
    let _ = engine();

    // Parse the device config: the guardian's strictness band (`profile`,
    // persisted by ChildConfigSync) seeds the policy global so the on-device
    // engine comes back up under the right band after a process restart.
    // Anything malformed is ignored (fail open) — never crashes the bridge.
    let config = jstring_to_string(&mut env, &config_json).unwrap_or_default();
    apply_profile_from_config_json(&config);
    // Arm the cluster relay (alerts + heartbeats) with the enrolled endpoint
    // and identity from the device config; no-op when not yet enrolled.
    relay::set_target_from_config_json(&config);
    // App-private directory (Kotlin filesDir/ca) where the per-install
    // inspection CA persists across sessions. Absent -> no persisted CA.
    let ca_dir = serde_json::from_str::<serde_json::Value>(&config)
        .ok()
        .and_then(|v| {
            v.get("ca_dir")
                .and_then(|p| p.as_str())
                .map(std::path::PathBuf::from)
        });
    let vpn_service = if vpn_service.is_null() {
        None
    } else {
        env.new_global_ref(vpn_service).ok()
    };

    // A multi-threaded runtime is required: the smoltcp pump parks a worker via
    // `block_in_place` while the proxy/DNS tasks run on the others.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("bulwark-vpn")
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return 0, // 0 handle == "not started" (Kotlin treats it as failure)
    };
    let shutdown = bulwark_net::vpn::CancellationToken::new();
    // The transparent data path only exists on-device; host builds of this
    // crate (unit tests on the dev machine) still compile + test the JSON/JNI
    // surface without it.
    #[cfg(not(target_os = "android"))]
    let _ = (tun_fd, ca_dir);
    #[cfg(target_os = "android")]
    {
        let fd = tun_fd as std::os::fd::RawFd;
        match bulwark_net::vpn::build_interceptor(ca_dir) {
            Ok(interceptor) => {
                // Honest liveness for heartbeats: flipped false if the pump dies.
                let vpn_up = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));

                // 1. Flow consumer: classifies captured flows and ANSWERS the
                //    proxy's decision gate (without it, every gated image/video
                //    segment stalls 5s then drops). Ends when the proxy closes
                //    the flow channel on shutdown.
                runtime.spawn(flow::run_flow_consumer(interceptor.clone()));

                // 2. Protection heartbeats to the enrolled cluster (no-op when
                //    unenrolled); the server's missed-heartbeat sweep is the
                //    backstop if this whole process dies.
                runtime.spawn(relay::run_heartbeats(shutdown.clone(), vpn_up.clone()));

                // 3. The transparent pump itself.
                let token = shutdown.clone();
                runtime.spawn(async move {
                    // Never panic across the host (a filter must not take down
                    // the device), but NEVER fail silent either: if the data
                    // path exits with an error while the VpnService still owns
                    // the TUN, every packet would route into an fd nobody reads
                    // (a blackhole). Surface it as a content-free
                    // protection-status alert so the guardian learns filtering
                    // is down.
                    if let Err(e) =
                        bulwark_net::vpn::run_android_data_path(fd, interceptor, token).await
                    {
                        vpn_up.store(false, std::sync::atomic::Ordering::Relaxed);
                        tracing::error!(error = %e, "VPN data path exited with an error");
                        enqueue_protection_alert(
                            "vpn-datapath",
                            "The filtering VPN on the child's device stopped unexpectedly. \
                             Protection may be off until the app restarts it.",
                        );
                    }
                });
            }
            Err(e) => {
                // Fail-closed on the crown jewel (no CA -> no inspection), but
                // never silent: the guardian is told protection is down.
                tracing::error!(error = %e, "VPN interceptor could not be built");
                enqueue_protection_alert(
                    "vpn-start",
                    "The filtering VPN on the child's device could not start its \
                     inspection engine. Protection may be off until the app restarts it.",
                );
            }
        }
    }

    let session = Box::new(VpnSession {
        runtime,
        shutdown,
        _vpn_service: vpn_service,
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
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_stopVpn(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: non-zero handles are pointers produced by `startVpn`'s
    // `Box::into_raw`; we reconstruct the Box exactly once.
    let session = *unsafe { Box::from_raw(handle as *mut VpnSession) };
    // Signal the pump to stop, then give the runtime a bounded window to drain
    // (the pump observes cancellation within a poll tick) before dropping it.
    session.shutdown.cancel();
    session
        .runtime
        .shutdown_timeout(std::time::Duration::from_secs(2));
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
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_analyzeText(
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

    // Policy authority: map the verdict -> action under the guardian's CURRENT
    // strictness band (ChildConfig.profile, kept fresh by startVpn + the config
    // poll). Defaults to the engine's Teen baseline until a config arrives.
    let ctx = PolicyContext::new(
        DeviceId(String::new()),
        SourceChannel::OcrOnscreen,
        current_age_profile(),
    );
    let decision = engine.policy.evaluate(&verdict, &ctx);

    let json = verdict_json(&verdict, &decision);
    string_to_jstring(&mut env, &json)
}

/// `external fun redeemPairCode(endpoint: String, code: String, deviceId: String): String`
///
/// Child enrollment path. The Android setup screen calls this after the guardian
/// has selected the same server in the parent app and generated a short-lived
/// code. The code is the credential; the device id is the stable child-device
/// routing key. Returns compact JSON:
///
/// * `{"ok":true,"child_id":"...","family_id":"..."}`
/// * `{"ok":false,"error":"..."}`
///
/// No pair code or device id is echoed in errors.
///
/// # Safety
/// JNI entry point. Every jstring argument is null-/UTF-8-validated; invalid
/// input returns an error JSON instead of panicking.
#[no_mangle]
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_redeemPairCode(
    mut env: JNIEnv,
    _class: JClass,
    endpoint: JString,
    code: JString,
    device_id: JString,
) -> jstring {
    let endpoint = match jstring_to_string(&mut env, &endpoint) {
        Some(s) => s,
        None => return string_to_jstring(&mut env, &err_pairing_json("server address is missing")),
    };
    let code = jstring_to_string(&mut env, &code).unwrap_or_default();
    let device_id = jstring_to_string(&mut env, &device_id).unwrap_or_default();

    let json = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("bulwark-android-enroll")
        .build()
    {
        Ok(rt) => match rt.block_on(redeem_pair_code_rpc(endpoint, code, device_id)) {
            Ok(pair) => ok_pairing_json(&pair),
            Err(e) => err_pairing_json(e),
        },
        Err(_) => err_pairing_json("enrollment runtime could not start"),
    };
    string_to_jstring(&mut env, &json)
}

/// `external fun fetchChildConfig(endpoint: String, deviceId: String, appliedVersion: Long): String`
///
/// Child-side half of the parent-controlled VPN: fetch this device's
/// guardian-set desired config (`ChildControl.GetChildConfig`) from the
/// enrolled server. `appliedVersion` is the config_version this device last
/// applied — sent as `have_version`, which the server records as the
/// applied-version ack the parent console shows; the bridge also live-applies
/// the fetched strictness band when the config is not older than it.
/// CONTENT-FREE — policy + routing only. Returns compact JSON:
///
/// * `{"ok":true,"filtering_enabled":...,"server_region":"...","server_endpoint":"...",
///    "profile":"TEEN","require_always_on":...,"config_version":N,"updated_ts":...}`
/// * `{"ok":false,"error":"..."}` ("no config yet" is a normal, expected state)
///
/// The Kotlin reconciler ignores any config strictly OLDER than the version it
/// last applied (replay/rollback defense) and persists the applied version.
///
/// # Safety
/// JNI entry point. Every jstring argument is null-/UTF-8-validated; invalid
/// input returns an error JSON instead of panicking.
#[no_mangle]
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_fetchChildConfig(
    mut env: JNIEnv,
    _class: JClass,
    endpoint: JString,
    device_id: JString,
    applied_version: jlong,
) -> jstring {
    let endpoint = match jstring_to_string(&mut env, &endpoint) {
        Some(s) => s,
        None => {
            return string_to_jstring(
                &mut env,
                &err_child_config_json("server address is missing"),
            )
        }
    };
    let device_id = jstring_to_string(&mut env, &device_id).unwrap_or_default();
    // Negative can't come from the Kotlin prefs (default 0); clamp defensively.
    let applied_version = applied_version.max(0) as u64;

    let json = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("bulwark-android-config")
        .build()
    {
        Ok(rt) => match rt.block_on(fetch_child_config_rpc(endpoint, device_id, applied_version)) {
            Ok(cfg) => {
                // Live profile reconcile: a fetched config that is NOT older
                // than what this device already applied updates the strictness
                // band for analyzeText immediately (no service restart). The
                // version gate mirrors the Kotlin rollback defense.
                if cfg.config_version >= applied_version {
                    if let Some(p) = age_profile_from_name(profile_name(cfg.profile())) {
                        set_age_profile(p);
                    }
                }
                ok_child_config_json(&cfg)
            }
            Err(e) => err_child_config_json(e),
        },
        Err(_) => err_child_config_json("config runtime could not start"),
    };
    string_to_jstring(&mut env, &json)
}

/// `external fun nextAlert(): String?`
///
/// Poll the next pending guardian alert as JSON, or return `null` when none is
/// pending. Alert generation/queueing is owned by the alert crates
/// (bulwark-alert), which are out of scope for this bridge; until that queue is
/// wired through here, there are no alerts to surface, so we return `null`. The
/// Kotlin poller (`BulwarkVpnService.startAlertPoller`) treats `null` as "nothing
/// pending" and sleeps — so this is the correct, safe no-op.
///
/// # Safety
/// JNI entry point with no pointer arguments.
#[no_mangle]
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_nextAlert(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    // Drain a pending tamper (PROTECTION_DISABLED) alert if any. Content verdicts
    // from the live filtering loop are queued by the owning crate (SEAM); until
    // that is wired the only entries are the tamper events `reportTamper` enqueues.
    let next = tamper_queue().lock().ok().and_then(|mut q| q.pop_front());
    match next {
        Some(json) => string_to_jstring(&mut env, &json),
        None => std::ptr::null_mut(), // null jstring == Kotlin `null`
    }
}

/// `external fun submitReviewDecision(alertId: String, approve: Boolean)`
///
/// Route the guardian's approve / keep-blocked decision to the policy/allowlist
/// layer. The persistent allowlist lives in bulwark-store (DB), which is out of
/// scope for this bridge (and intentionally not depended on — rusqlite does not
/// build on this host). We validate the inputs and no-op safely; the owning
/// crate wires the decision into the device allowlist.
///
/// # Safety
/// JNI entry point. `alert_id` is null-/UTF-8-validated; a bad value is ignored.
#[no_mangle]
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_submitReviewDecision(
    mut env: JNIEnv,
    _class: JClass,
    alert_id: JString,
    _approve: jboolean,
) {
    // Validate (and thereby ignore obviously-bad ids); never log the value.
    let _alert_id = jstring_to_string(&mut env, &alert_id).unwrap_or_default();
    // No-op until the bulwark-store-backed allowlist is wired through this bridge.
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
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_registerParentPushToken(
    mut env: JNIEnv,
    _class: JClass,
    token: JString,
) {
    let _token = jstring_to_string(&mut env, &token).unwrap_or_default();
    // No-op until remote FCM delivery is wired through this bridge.
}

/// `external fun reportTamper(kind: Int)`
///
/// Enqueue a redacted PROTECTION_DISABLED alert for a child-device protection
/// downgrade (`bulwark.v1.TamperKind` ordinal) so the guardian is told via the same
/// alert path as content alerts (`nextAlert` drains it). Content-free — only the
/// kind of change. Never panics across the FFI boundary.
///
/// # Safety
/// JNI entry point with a primitive `jint` argument only.
#[no_mangle]
pub extern "system" fn Java_co_predatorhunters_bulwark_core_RustBridge_reportTamper(
    _env: JNIEnv,
    _class: JClass,
    kind: jint,
) {
    enqueue_protection_alert(&format!("tamper-{kind}"), tamper_message(kind));
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
        analyze(
            &e,
            "g1",
            "hey this is our little secret ok, dont tell your parents",
        );
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

    #[test]
    fn pair_code_normalization_is_human_tolerant() {
        assert_eq!(normalize_pair_code(" abcd-2345 "), "ABCD2345");
        assert_eq!(normalize_pair_code("a b c 1 2 3"), "ABC123");
        assert!(normalize_pair_code(" - ").is_empty());
    }

    #[test]
    fn pairing_json_shapes_are_stable() {
        let ok = ok_pairing_json(&PairResult {
            child_id: "child-1".to_string(),
            family_id: "family-1".to_string(),
        });
        assert!(ok.contains("\"ok\":true"), "{ok}");
        assert!(ok.contains("\"child_id\":\"child-1\""), "{ok}");
        assert!(ok.contains("\"family_id\":\"family-1\""), "{ok}");

        let err = err_pairing_json("pair code is invalid");
        assert!(err.contains("\"ok\":false"), "{err}");
        assert!(err.contains("pair code is invalid"), "{err}");
    }

    #[test]
    fn child_config_json_is_content_free_and_stable() {
        let cfg = ChildConfig {
            child_id: "child-1".to_string(),
            device_id: "dev-1".to_string(),
            filtering_enabled: true,
            server_region: "uk".to_string(),
            server_endpoint: "https://lon.example:8443".to_string(),
            profile: FilteringProfile::Teen as i32,
            require_always_on: false,
            config_version: 7,
            updated_ts: 1_700_000_000_000,
            updated_by: "guardian-acct-1".to_string(),
        };
        let json = ok_child_config_json(&cfg);
        assert!(json.contains("\"ok\":true"), "{json}");
        assert!(json.contains("\"filtering_enabled\":true"), "{json}");
        assert!(json.contains("\"config_version\":7"), "{json}");
        assert!(json.contains("\"profile\":\"TEEN\""), "{json}");
        assert!(json.contains("\"server_region\":\"uk\""), "{json}");
        // The guardian's account id is server-side audit detail — never forwarded.
        assert!(!json.contains("guardian-acct-1"), "{json}");

        let err = err_child_config_json("no guardian config for this device yet");
        assert!(err.contains("\"ok\":false"), "{err}");
        assert!(err.contains("no guardian config"), "{err}");
    }

    #[test]
    fn age_profile_names_map_to_policy_bands() {
        assert_eq!(
            age_profile_from_name("YOUNG_CHILD"),
            Some(AgeProfile::YoungChild)
        );
        assert_eq!(age_profile_from_name("PRETEEN"), Some(AgeProfile::PreTeen));
        assert_eq!(age_profile_from_name("TEEN"), Some(AgeProfile::Teen));
        // CUSTOM has no on-device thresholds yet — engine baseline, never a crash.
        assert_eq!(age_profile_from_name("CUSTOM"), Some(AgeProfile::Teen));
        // Unknown/empty must NOT silently change strictness.
        assert_eq!(age_profile_from_name(""), None);
        assert_eq!(age_profile_from_name("nonsense"), None);
        // Round-trip: every proto band name resolves to a policy band.
        for p in [
            FilteringProfile::YoungChild,
            FilteringProfile::Preteen,
            FilteringProfile::Teen,
            FilteringProfile::Custom,
        ] {
            assert!(age_profile_from_name(profile_name(p)).is_some());
        }
    }

    #[test]
    fn device_config_json_sets_the_profile_global() {
        set_age_profile(AgeProfile::default());
        apply_profile_from_config_json(r#"{"device_id":"d","profile":"YOUNG_CHILD"}"#);
        assert_eq!(current_age_profile(), AgeProfile::YoungChild);
        // Malformed JSON / a missing field leaves the band untouched (fail open,
        // never a silent strictness change).
        apply_profile_from_config_json("{not json");
        apply_profile_from_config_json(r#"{"device_id":"d"}"#);
        assert_eq!(current_age_profile(), AgeProfile::YoungChild);
        set_age_profile(AgeProfile::default()); // restore for other tests
    }
}
