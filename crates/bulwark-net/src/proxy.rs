//! The transparent MITM proxy (`hudsucker` = hyper + rustls + rcgen).
//!
//! TUN-redirected TCP lands here; `hudsucker` terminates TLS using a leaf cert
//! minted by our per-install CA ([`crate::ca::CaManager`]), decrypts the
//! request/response, and we emit a [`CapturedFlow`](bulwark_proto-style) on the
//! channel `bulwark-flow` consumes. Pinned hosts reject the leaf at handshake →
//! [`crate::pinning`] records the gap and we fail-open per policy.
//!
//! ## Privacy (threat-model Asset 3)
//! Decrypted bodies are **plaintext intermediates** — the most sensitive data we
//! handle. They live in memory only, flow straight to classification over a
//! bounded channel (backpressure caps how much plaintext is buffered), and are
//! never written to disk or logs here. We never `Debug`-print bodies.
//!
//! ## hudsucker 0.24 integration shape (now wired)
//! `hudsucker` wants a [`hudsucker::certificate_authority::CertificateAuthority`]
//! and an [`hudsucker::HttpHandler`]. We feed our [`CaManager`] into hudsucker's
//! [`RcgenAuthority`](hudsucker::certificate_authority::RcgenAuthority) by building
//! an [`rcgen::Issuer`] from the stored root cert DER + the unwrapped key (the
//! authority then caches the per-host leaves itself), and provide [`FlowHandler`]
//! which:
//!   * collects the (now-plaintext) request/response body,
//!   * emits a [`CapturedFlow`] onto the bounded flow channel, and
//!   * on **scorable image** responses only, blocks on a per-`flow_id`
//!     rendezvous for the policy [`InterceptDecision`] (Forward / Rewrite / Drop)
//!     supplied by [`MitmProxy::apply`] — bounded by a timeout that fails
//!     **CLOSED** (Drop) so a slow/absent classifier blocks the image rather than
//!     leaking it (owner directive: "block instantly by default"). Every other
//!     response (html/js/css/json/text/non-image/tiny icon) forwards immediately
//!     with no gate, so page-structural resources add zero latency.
//!
//! WebSocket frames are passed through unchanged (hudsucker's default
//! `NoopHandler` forwards every message both directions).
//!
//! All `hudsucker` 0.24 symbol use is contained in [`run_hudsucker`] /
//! [`FlowHandler`] so an API bump touches one place. Types/traits used:
//! `hudsucker::{Proxy, HttpHandler, HttpContext, RequestOrResponse, Body}`,
//! `hudsucker::certificate_authority::RcgenAuthority`,
//! `hudsucker::rcgen::{Issuer, KeyPair}`,
//! `hudsucker::rustls::{pki_types::CertificateDer, crypto::aws_lc_rs}`,
//! `hudsucker::hyper::{Request, Response, StatusCode, header}`, and
//! `http_body_util::BodyExt` (to collect a decrypted body).

use std::collections::HashMap;
use std::sync::Arc;

use http_body_util::BodyExt;
use hudsucker::hyper::{Request, Response, StatusCode};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use tokio::sync::{mpsc, oneshot, Mutex};

use bulwark_core::flow::InterceptDecision;

use crate::ca::CaManager;
use crate::pinning::PinningRegistry;
use crate::{NetError, Result};

/// How long a gated **image** response waits for a policy decision before the gate
/// resolves. The classifier round-trip is fast; this bound guards against a
/// stalled/absent decision sink. Owner directive: "block instantly by default" —
/// so a timeout/dropped sender here fails **CLOSED** (Drop), not open. Only
/// scorable image responses are ever gated; everything else forwards immediately
/// with no wait, so this timeout never touches page-structural resources.
const DECISION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Max leaf-cert cache entries held by the `RcgenAuthority` (one per visited
/// host). Bounds memory; evicted entries are simply re-minted on next visit.
const LEAF_CACHE_SIZE: u64 = 1_000;

/// Bounded prefix of a decrypted body forwarded to the classifier. We never ship
/// the whole body up the flow channel — the head + this peek drive classification
/// (the streaming ring buffer handles media segments separately).
const BODY_PEEK_CAP: usize = 64 * 1024;

/// Upper bound on a captured **image** body surfaced for NSFW scoring. An image
/// response (`image/jpeg|png|webp|gif`) is handed up WHOLE (not just the peek) so
/// the classifier can actually decode + score it, but capped so a single huge
/// image can't blow out the bounded flow channel's plaintext budget. 8 MiB
/// comfortably covers real web imagery; larger bodies are skipped (fail-open).
const IMAGE_BODY_CAP: usize = 8 * 1024 * 1024;

/// Lower bound on an **image** body before we bother scoring/gating it. Icons,
/// sprites, tracking pixels, emoji and the like are all well under 16 KiB; they
/// carry no NSFW risk worth a model run and gating each one would stall page
/// loads. Image bodies smaller than this are NOT surfaced for scoring (`None`),
/// so they forward immediately like any other non-image resource.
const MIN_SCORABLE_IMAGE_BYTES: usize = 16 * 1024;

/// Source channel of a captured flow (mirrors `bulwark_proto::SourceChannel`; kept
/// as a small enum here so the proxy layer doesn't construct proto messages —
/// the orchestrator maps it onto the wire type).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowSource {
    /// MITM'd HTTP(S) page / web chat.
    Web,
    /// Progressive / HLS / DASH video (buffered).
    VideoStream,
    /// Low-latency live stream.
    LiveStream,
}

/// A captured, MITM-decrypted (or marked-unreadable) network unit handed up to
/// `bulwark-flow`. Mirrors `CapturedFlow` in interfaces.md; the orchestrator
/// converts this into the proto/in-process `CapturedFlow` the `Interceptor`
/// trait yields. Kept proxy-local so this module needn't depend on the trait's
/// exact struct layout.
#[derive(Clone, Debug)]
pub struct CapturedFlow {
    /// Monotonic per-session flow id.
    pub flow_id: u64,
    /// Where it came from.
    pub source: FlowSource,
    /// Host or app the flow is for (SNI / Host header).
    pub app_or_host: String,
    /// `false` = pinned/E2E, unreadable → route to OcrSource.
    pub readable: bool,
    /// HTTP method (requests) or empty for responses.
    pub method: String,
    /// Request path / URL.
    pub uri: String,
    /// Decrypted body bytes (plaintext intermediate — in-memory only). This is a
    /// bounded *peek* used for classification; the full body is forwarded and
    /// dropped without being buffered here.
    pub body: Vec<u8>,
    /// `true` if this unit is a response (vs a request).
    pub is_response: bool,
    /// The response `Content-Type` (lowercased, params stripped) when known, so
    /// `bulwark-flow`'s content-type fast-path engages instead of magic-sniffing.
    pub content_type: Option<String>,
    /// The WHOLE decrypted image body when this response carries a still image
    /// (`image/jpeg|png|webp|gif`) under [`IMAGE_BODY_CAP`]. Surfaced separately
    /// from `body` (a mere peek) because the NSFW scorer must decode the full
    /// image. In-memory only, never logged or persisted (threat-model Asset 3).
    pub image_body: Option<Vec<u8>>,
    /// The WHOLE decrypted body when this response carries an HLS/DASH/progressive
    /// VIDEO SEGMENT (`video/*`) under [`VIDEO_SEGMENT_CAP`] — the video analyzer
    /// decodes it (frames + audio) and the decision may swap in a remediated segment.
    pub video_body: Option<Vec<u8>>,
}

/// Receiver end of the flow channel given to `bulwark-flow` via the interceptor.
pub type FlowReceiver = mpsc::Receiver<CapturedFlow>;
/// Sender end held by the proxy handler.
pub type FlowSender = mpsc::Sender<CapturedFlow>;

/// The per-`flow_id` decision rendezvous shared between the running handler and
/// [`MitmProxy::apply`].
///
/// When a response handler emits a flow it registers a [`oneshot::Sender`] keyed
/// by the flow id and awaits the matching [`InterceptDecision`]. The
/// orchestrator's `apply(flow_id, decision)` resolves it via
/// [`DecisionGate::resolve`]. Cloneable (it is just `Arc`s), so the handler —
/// which hudsucker requires be `Clone` — and the `MitmProxy` handle can both hold
/// it cheaply.
///
/// ## Gating is opt-in (`armed`)
/// Inline decision-gating means the response handler **blocks** until `apply()`
/// supplies a decision (bounded by [`DECISION_TIMEOUT`]). That is only correct
/// when a decision *sink* is actually wired (the interceptor's `apply` forwarding
/// here). Until then, gating is **disarmed by default**: responses are emitted
/// for classification and forwarded immediately, with zero added latency — the
/// machinery is fully present and unit-tested, ready for the interceptor to
/// [`MitmProxy::set_gating`]`(true)` the moment `apply` is connected.
#[derive(Clone)]
pub struct DecisionGate {
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<InterceptDecision>>>>,
    /// Whether the response handler should block awaiting a decision. Off by
    /// default so the unwired path never stalls a connection.
    armed: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for DecisionGate {
    fn default() -> Self {
        DecisionGate {
            pending: Arc::new(Mutex::new(HashMap::new())),
            armed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl DecisionGate {
    /// Arm/disarm inline decision-gating. Arm this once a consumer is wired to
    /// call [`resolve`](Self::resolve)/[`MitmProxy::apply`]; leave disarmed and
    /// responses forward immediately (emit-only).
    pub fn set_armed(&self, armed: bool) {
        self.armed
            .store(armed, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether inline gating is currently armed.
    fn is_armed(&self) -> bool {
        self.armed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Register interest in a decision for `flow_id`, returning the receiver the
    /// handler awaits. A second registration for the same id drops the older
    /// sender (its waiter then times out and forwards — safe default).
    async fn register(&self, flow_id: u64) -> oneshot::Receiver<InterceptDecision> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(flow_id, tx);
        rx
    }

    /// Drop any pending registration for `flow_id` (handler gave up / timed out).
    async fn cancel(&self, flow_id: u64) {
        self.pending.lock().await.remove(&flow_id);
    }

    /// Deliver `decision` to the handler waiting on `flow_id`. Returns `true` if a
    /// waiter was present and the decision was delivered, `false` if there was no
    /// outstanding flow (already resolved, timed out, gating disarmed, or a
    /// request-leg flow id, which is not decision-gated).
    pub async fn resolve(&self, flow_id: u64, decision: InterceptDecision) -> bool {
        match self.pending.lock().await.remove(&flow_id) {
            Some(tx) => tx.send(decision).is_ok(),
            None => false,
        }
    }
}

/// Handle to a running MITM proxy; dropping it / calling [`MitmProxy::stop`]
/// shuts the proxy down.
pub struct MitmProxy {
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
    listen_addr: std::net::SocketAddr,
    gate: DecisionGate,
}

impl MitmProxy {
    /// The address the proxy actually bound (useful when `proxy_listen` used port 0).
    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.listen_addr
    }

    /// Apply a policy [`InterceptDecision`] to a live (in-flight) flow, keyed by
    /// `flow_id`. The handler for that flow's response is blocked awaiting this;
    /// `Forward` passes it through, `Rewrite` swaps the response body, `Drop`
    /// returns a blocked-content response.
    ///
    /// Returns `Ok(true)` if a handler was waiting (decision delivered), `Ok(false)`
    /// if the flow was no longer in flight (already forwarded / timed out / a
    /// request-leg id, which is emit-only). The interceptor's `apply` forwards here.
    pub async fn apply(&self, flow_id: u64, decision: InterceptDecision) -> Result<bool> {
        Ok(self.gate.resolve(flow_id, decision).await)
    }

    /// The shared decision gate, so the interceptor can resolve decisions without
    /// holding the whole proxy handle if it prefers.
    pub fn decision_gate(&self) -> DecisionGate {
        self.gate.clone()
    }

    /// Arm/disarm inline decision-gating (see [`DecisionGate`]). Call with `true`
    /// once a consumer is wired to call [`MitmProxy::apply`]; while disarmed
    /// (default) responses are emitted and forwarded immediately, no stall.
    pub fn set_gating(&self, armed: bool) {
        self.gate.set_armed(armed);
    }

    /// Signal the proxy to stop and await its task.
    pub async fn stop(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
        Ok(())
    }
}

/// Start the MITM proxy on `listen` using `ca` to mint leaves, emitting captured
/// flows on `flow_tx`. Returns once the listener is bound.
///
/// The `hudsucker`-specific wiring is intentionally contained in [`run_hudsucker`].
pub async fn spawn(
    listen: std::net::SocketAddr,
    ca: Arc<CaManager>,
    pinning: Arc<PinningRegistry>,
    flow_tx: FlowSender,
) -> Result<MitmProxy> {
    // Bind first so we can report the actual address (port 0 → ephemeral) and so
    // a bind failure surfaces here rather than inside the spawned task.
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| NetError::proxy(format!("binding MITM listener on {listen}: {e}")))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|e| NetError::proxy(format!("resolving bound addr: {e}")))?;

    // Build the per-install authority up front so a bad CA key fails the start
    // call (fail-closed) instead of failing every connection silently later.
    let authority = build_authority(&ca)?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let gate = DecisionGate::default();

    let handler = FlowHandler {
        flow_tx,
        pinning,
        ca: ca.clone(),
        gate: gate.clone(),
        next_flow_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
    };

    let ca_fp = ca.fingerprint_hex().to_owned();
    let join = tokio::spawn(async move {
        run_hudsucker(listener, authority, handler, shutdown_rx).await;
    });

    tracing::info!(%listen_addr, %ca_fp, "MITM proxy started (hudsucker 0.24)");
    Ok(MitmProxy {
        shutdown: Some(shutdown_tx),
        join: Some(join),
        listen_addr,
        gate,
    })
}

/// Adapt our per-install [`CaManager`] into hudsucker's `RcgenAuthority`.
///
/// The authority needs an in-process [`rcgen::Issuer`] (root cert + signing key)
/// to mint and cache per-host leaves. We build it from the stored PUBLIC cert DER
/// and the key the keystore unwrapped, so the leaf's issuer DN matches the
/// installed root exactly. The unwrapped key stays in-process (the crown jewel is
/// never serialized off-host — only the leaf-signing material is reconstructed).
fn build_authority(
    ca: &Arc<CaManager>,
) -> Result<hudsucker::certificate_authority::RcgenAuthority> {
    use hudsucker::certificate_authority::RcgenAuthority;
    use hudsucker::rcgen::{Issuer, KeyPair};
    use hudsucker::rustls::crypto::aws_lc_rs;
    use hudsucker::rustls::pki_types::CertificateDer;

    // Reconstruct the rcgen KeyPair from the unwrapped PKCS#8 DER (same form
    // `CaManager` persists). `KeyPair: TryFrom<&[u8]>` infers the algorithm.
    let key_pair = KeyPair::try_from(ca.ca_key_der())
        .map_err(|e| NetError::ca(format!("reparse CA key for authority: {e}")))?;

    // `from_ca_cert_der` copies the DN / key-usage / key-id out (Cow::Owned), so
    // the resulting `Issuer` borrows nothing and unifies to `'static`.
    let ca_cert_der = CertificateDer::from(ca.cert_der().to_vec());
    let issuer: Issuer<'static, KeyPair> = Issuer::from_ca_cert_der(&ca_cert_der, key_pair)
        .map_err(|e| NetError::ca(format!("build issuer from CA cert: {e}")))?;

    Ok(RcgenAuthority::new(
        issuer,
        LEAF_CACHE_SIZE,
        aws_lc_rs::default_provider(),
    ))
}

/// The hudsucker run-loop wrapper. All 0.24 builder symbols live here.
///
/// WebSocket passthrough: we set only an HTTP handler; the websocket handler
/// defaults to hudsucker's `NoopHandler`, which forwards every message verbatim
/// in both directions.
async fn run_hudsucker(
    listener: tokio::net::TcpListener,
    authority: hudsucker::certificate_authority::RcgenAuthority,
    handler: FlowHandler,
    shutdown_rx: oneshot::Receiver<()>,
) {
    use hudsucker::rustls::crypto::aws_lc_rs;
    use hudsucker::Proxy;

    let proxy = match Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        // websocket handler left as the default NoopHandler → passthrough.
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .build()
    {
        Ok(proxy) => proxy,
        Err(e) => {
            tracing::error!("failed to build hudsucker proxy: {e}");
            return;
        }
    };

    if let Err(e) = proxy.start().await {
        tracing::error!("hudsucker proxy exited with error: {e}");
    } else {
        tracing::info!("MITM proxy shut down");
    }
}

/// hudsucker [`HttpHandler`]: turns decrypted requests/responses into
/// [`CapturedFlow`]s on the channel, records MITM success, and applies the
/// per-`flow_id` policy decision to responses.
///
/// Must be `Clone + Send + Sync + 'static` (hudsucker clones it per connection),
/// so all shared state is behind `Arc` / cheaply-cloneable handles.
#[derive(Clone)]
pub struct FlowHandler {
    flow_tx: FlowSender,
    pinning: Arc<PinningRegistry>,
    ca: Arc<CaManager>,
    gate: DecisionGate,
    next_flow_id: Arc<std::sync::atomic::AtomicU64>,
}

impl FlowHandler {
    /// Build a `CapturedFlow` and emit it (drops on backpressure — never blocks
    /// the data path, never unbounded-buffers plaintext). Returns the flow id.
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &self,
        source: FlowSource,
        app_or_host: &str,
        method: &str,
        uri: &str,
        body: Vec<u8>,
        is_response: bool,
        content_type: Option<String>,
        image_body: Option<Vec<u8>>,
        video_body: Option<Vec<u8>>,
    ) -> u64 {
        let flow_id = self
            .next_flow_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let flow = CapturedFlow {
            flow_id,
            source,
            app_or_host: app_or_host.to_owned(),
            readable: true,
            method: method.to_owned(),
            uri: uri.to_owned(),
            body,
            is_response,
            content_type,
            image_body,
            video_body,
        };
        if self.flow_tx.try_send(flow).is_err() {
            // Bounded channel full → shed (fail-safe on memory). Log metadata only.
            tracing::warn!(host = %app_or_host, "flow channel full; dropping captured flow (backpressure)");
        }
        // Only learn a capability for a real host. Response flows carry no host
        // (it is request-side), so we skip the empty marker to avoid polluting the
        // pinning registry with a `""` entry.
        if !app_or_host.is_empty() {
            self.pinning.record_mitmable(app_or_host);
        }
        flow_id
    }

    /// Record a pinned host (handshake rejected our leaf). Returns whether we
    /// forward (fail-open) the flow.
    pub fn on_pinned(&self, app_or_host: &str) -> bool {
        let sig = self.pinning.record_pinned(app_or_host);
        sig.failed_open
    }

    /// Access the CA (e.g. to mint a leaf for a specific host directly).
    pub fn ca(&self) -> &CaManager {
        &self.ca
    }
}

/// hudsucker 0.24 `HttpHandler` is an RPITIT trait (`async fn` methods); it is
/// **not** `#[async_trait]`. We implement `handle_request` (emit-only, always
/// forward) and `handle_response` (emit + decision rendezvous).
impl HttpHandler for FlowHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let host = host_of_request(&req);
        let method = req.method().to_string();
        let uri = req.uri().to_string();

        // Collect the FULL (decrypted) request body so we can both forward it
        // intact upstream and hand the classifier a bounded peek of it.
        let (parts, body) = req.into_parts();
        let full = collect_full(body).await;
        self.emit(
            classify_source(&uri),
            &host,
            &method,
            &uri,
            peek(&full),
            false,
            content_type_of(&parts.headers),
            None, // request bodies are not image-scored (the response carries the image)
            None, // nor video-segment-scored on the request leg
        );

        // Request leg is emit-only (forward the full body unchanged). Blocking a
        // request before its response is seen is not part of the policy model;
        // the response leg is where Forward/Rewrite/Drop are applied.
        RequestOrResponse::Request(Request::from_parts(parts, Body::from(full)))
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let status = res.status().as_u16();
        let content_type = content_type_of(res.headers());
        let (mut parts, body) = res.into_parts();
        // Collect the FULL decrypted response so we can forward it intact; the
        // classifier only receives a bounded peek (bounded plaintext on the channel).
        let full = collect_full(body).await;

        // If this response is a still image of a type the NSFW scorer can decode
        // AND large enough to be worth scoring, surface the WHOLE body (capped) so
        // the pipeline can score the actual pixels — not just the magic-byte peek.
        // Tiny/oversized images and every non-image body return `None` here.
        let image_body = image_body_for(content_type.as_deref(), &full);

        // Scorable images AND HLS/DASH/progressive video segments are decision-gated:
        // the video analyzer can blur/mute the segment and the decision swaps in the
        // cleaned bytes. Decided BEFORE `emit` moves the bodies up the channel.
        let video_body = video_segment_body_for(content_type.as_deref(), &full);
        let is_gatable = image_body.is_some() || video_body.is_some();
        let source = if video_body.is_some() {
            FlowSource::VideoStream
        } else {
            FlowSource::Web
        };

        // Emit the response flow for classification.
        let flow_id = self.emit(
            source,
            "", // host is request-side; response carries none
            "", // no method on a response
            &format!("status:{status}"),
            peek(&full),
            true,
            content_type,
            image_body,
            video_body,
        );

        // Forward IMMEDIATELY (no gate registration, no wait) when EITHER:
        //   * inline gating is disarmed (default, until the interceptor wires
        //     `apply`), OR
        //   * this is not a scorable image (html/js/css/json/text/icons/etc.).
        // This is what removes the per-resource latency that was killing page
        // loads — only the actual still images a guardian cares about are gated.
        if !self.gate.is_armed() || !is_gatable {
            return Response::from_parts(parts, Body::from(full));
        }

        // Gated image: register the per-flow_id waiter, then await the policy
        // decision bounded by DECISION_TIMEOUT. Owner directive — "block instantly
        // by default": a timeout OR a dropped sender fails **CLOSED** (Drop), so a
        // slow/absent classifier blocks the image rather than leaking it through.
        let rx = self.gate.register(flow_id).await;
        let decision = match tokio::time::timeout(DECISION_TIMEOUT, rx).await {
            Ok(Ok(d)) => d,
            Ok(Err(_)) | Err(_) => {
                self.gate.cancel(flow_id).await;
                InterceptDecision::Drop
            }
        };

        match decision {
            InterceptDecision::Forward => {
                tracing::trace!(flow_id, "decision: forward response");
                Response::from_parts(parts, Body::from(full))
            }
            InterceptDecision::Rewrite(new_body) => {
                tracing::debug!(
                    flow_id,
                    len = new_body.len(),
                    "decision: rewrite response body"
                );
                // Drop a stale Content-Length; hyper recomputes from the Full body.
                parts
                    .headers
                    .remove(hudsucker::hyper::header::CONTENT_LENGTH);
                Response::from_parts(parts, Body::from(new_body))
            }
            InterceptDecision::Drop => {
                tracing::debug!(flow_id, "decision: drop/block response");
                blocked_response()
            }
        }
    }
}

/// Best-effort host for a (decrypted) request: prefer the URI authority that
/// hudsucker restores after the CONNECT, else the `Host` header.
fn host_of_request(req: &Request<Body>) -> String {
    if let Some(authority) = req.uri().authority() {
        return authority.host().to_owned();
    }
    req.headers()
        .get(hudsucker::hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_owned())
        .unwrap_or_default()
}

/// Coarse source classification from the request URI/path. The classifier refines
/// this; we only need a sane initial channel (manifests/segments → video).
fn classify_source(uri: &str) -> FlowSource {
    let lower = uri.to_ascii_lowercase();
    if lower.contains(".m3u8") || lower.contains(".ts?") || lower.ends_with(".ts") {
        // HLS manifests/segments; .m3u8 may also be a live edge but we default to
        // VideoStream and let the classifier promote to LiveStream.
        FlowSource::VideoStream
    } else if lower.contains(".mpd") || lower.contains(".m4s") {
        FlowSource::VideoStream
    } else {
        FlowSource::Web
    }
}

/// Collect a hudsucker `Body` into the FULL byte buffer, so it can be forwarded
/// intact. On a body error we return what we have (never panics on the data
/// path). The whole body is held in memory only transiently — long enough to
/// forward it — and never logged or persisted (threat-model Asset 3).
async fn collect_full(body: Body) -> Vec<u8> {
    match body.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => Vec::new(),
    }
}

/// A bounded prefix of `full` for the classifier (magic-byte sniff / manifest
/// peek). Capping here is what keeps *channel* plaintext bounded — the full body
/// is forwarded then dropped, but only this peek is buffered on the flow channel.
fn peek(full: &[u8]) -> Vec<u8> {
    full[..full.len().min(BODY_PEEK_CAP)].to_vec()
}

/// The `Content-Type` header value, lowercased with any `; charset=…`/`; boundary=…`
/// parameters stripped (e.g. `"image/JPEG; foo"` → `"image/jpeg"`). `None` if the
/// header is absent or non-UTF-8.
fn content_type_of(headers: &hudsucker::hyper::HeaderMap) -> Option<String> {
    headers
        .get(hudsucker::hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.split(';')
                .next()
                .unwrap_or(ct)
                .trim()
                .to_ascii_lowercase()
        })
}

/// True for the still-image content-types the NSFW scorer can decode and score.
/// Limited to the four the task targets (jpeg/png/webp/gif).
fn is_scorable_image_ct(ct: &str) -> bool {
    matches!(ct, "image/jpeg" | "image/png" | "image/webp" | "image/gif")
}

/// Decide whether to surface the WHOLE response body as an image for scoring.
/// Returns `Some(bytes)` only for a scorable image content-type whose size is in
/// `[MIN_SCORABLE_IMAGE_BYTES, IMAGE_BODY_CAP]`; otherwise `None` (the peek alone
/// is carried and the response forwards immediately, ungated).
///
/// * Tiny images (icons/sprites/pixels under [`MIN_SCORABLE_IMAGE_BYTES`]) are
///   skipped: not worth a model run, and gating them would stall page loads.
/// * Oversized images (over [`IMAGE_BODY_CAP`]) are skipped to protect the
///   channel's plaintext budget.
///
/// Only a `Some` result triggers the decision gate downstream; everything else
/// forwards with zero added latency.
fn image_body_for(content_type: Option<&str>, full: &[u8]) -> Option<Vec<u8>> {
    let ct = content_type?;
    if !is_scorable_image_ct(ct) {
        return None;
    }
    if full.len() < MIN_SCORABLE_IMAGE_BYTES || full.len() > IMAGE_BODY_CAP {
        return None;
    }
    Some(full.to_vec())
}

/// HLS/DASH/progressive video segments up to this size are surfaced WHOLE for the
/// video analyzer (decode → blur/mute). Segments are short chunks; a larger body is
/// a full progressive download we skip (plaintext-channel budget protection).
const VIDEO_SEGMENT_CAP: usize = 16 * 1024 * 1024;

/// `Some(whole body)` when the response is an HLS/DASH/progressive **video segment**
/// (`video/*` — mp2t/.ts, mp4/.m4s, iso.segment) within [`VIDEO_SEGMENT_CAP`]; else
/// `None` (forwards ungated). Playlists/manifests (`application/vnd.apple.mpegurl`,
/// `application/dash+xml`) are not `video/*`, so they pass through here untouched.
fn video_segment_body_for(content_type: Option<&str>, full: &[u8]) -> Option<Vec<u8>> {
    let ct = content_type?;
    if !ct.starts_with("video/") {
        return None;
    }
    if full.is_empty() || full.len() > VIDEO_SEGMENT_CAP {
        return None;
    }
    Some(full.to_vec())
}

/// The response served when policy says **Drop**: a minimal blocked-content
/// 403 with no upstream body (never leak the original bytes downstream).
fn blocked_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(
            hudsucker::hyper::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )
        .body(Body::from("Blocked by Bulwark".as_bytes().to_vec()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::DevInMemoryKeyStore;

    fn test_ca() -> Arc<CaManager> {
        Arc::new(CaManager::generate(Arc::new(DevInMemoryKeyStore::new()), "T", 365).unwrap())
    }

    fn test_handler(flow_tx: FlowSender, gate: DecisionGate) -> FlowHandler {
        FlowHandler {
            flow_tx,
            pinning: Arc::new(PinningRegistry::new(true)),
            ca: test_ca(),
            gate,
            next_flow_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    #[tokio::test]
    async fn proxy_binds_and_stops() {
        let ca = test_ca();
        let pinning = Arc::new(PinningRegistry::new(true));
        let (tx, _rx) = mpsc::channel(16);
        let proxy = spawn("127.0.0.1:0".parse().unwrap(), ca, pinning, tx)
            .await
            .unwrap();
        // Bound to a real ephemeral loopback port.
        assert!(proxy.listen_addr().port() > 0);
        assert!(proxy.listen_addr().ip().is_loopback());
        proxy.stop().await.unwrap();
    }

    #[tokio::test]
    async fn build_authority_succeeds_for_valid_ca() {
        // The CA → RcgenAuthority adaptation must not fail for a freshly generated
        // per-install CA (fail-closed start would otherwise reject every flow).
        let ca = test_ca();
        assert!(build_authority(&ca).is_ok());
    }

    #[tokio::test]
    async fn handler_emits_flow_and_marks_mitmable() {
        let (tx, mut rx) = mpsc::channel(4);
        let h = test_handler(tx, DecisionGate::default());
        let id = h.emit(
            FlowSource::Web,
            "example.com",
            "GET",
            "/",
            b"<html/>".to_vec(),
            true,
            Some("text/html".to_owned()),
            None,
            None,
        );
        assert_eq!(id, 1);
        let flow = rx.recv().await.unwrap();
        assert_eq!(flow.app_or_host, "example.com");
        assert!(flow.readable);
        assert!(flow.is_response);
        assert!(h.pinning.capability("example.com") == crate::pinning::HostCapability::Mitmable);
    }

    #[tokio::test]
    async fn pinned_host_fails_open_by_policy() {
        let (tx, _rx) = mpsc::channel(4);
        let h = test_handler(tx, DecisionGate::default());
        assert!(h.on_pinned("signal.org")); // forwarded (fail-open)
        assert!(h.pinning.is_pinned("signal.org"));
    }

    #[tokio::test]
    async fn decision_gate_rendezvous_delivers_decision() {
        let gate = DecisionGate::default();
        // No waiter yet → resolve reports false.
        assert!(!gate.resolve(42, InterceptDecision::Drop).await);

        // Register, then resolve → the waiting receiver gets the decision.
        let rx = gate.register(7).await;
        assert!(gate.resolve(7, InterceptDecision::Drop).await);
        assert!(matches!(rx.await.unwrap(), InterceptDecision::Drop));

        // A second resolve for the same id finds no waiter.
        assert!(!gate.resolve(7, InterceptDecision::Forward).await);
    }

    #[test]
    fn scorable_image_content_types() {
        for ct in ["image/jpeg", "image/png", "image/webp", "image/gif"] {
            assert!(is_scorable_image_ct(ct), "{ct} should be scorable");
        }
        for ct in [
            "image/avif",
            "image/svg+xml",
            "text/html",
            "video/mp4",
            "application/json",
        ] {
            assert!(!is_scorable_image_ct(ct), "{ct} should NOT be scorable");
        }
    }

    #[test]
    fn image_body_surfaced_only_for_scorable_image_types() {
        // A scorable image type, large enough to score → whole body surfaced.
        let jpeg = vec![0xABu8; MIN_SCORABLE_IMAGE_BYTES];
        assert_eq!(
            image_body_for(Some("image/jpeg"), &jpeg).as_deref(),
            Some(jpeg.as_slice())
        );
        // HTML / non-image → no image body (peek path only).
        assert!(image_body_for(Some("text/html"), &jpeg).is_none());
        // Missing content-type → none.
        assert!(image_body_for(None, &jpeg).is_none());
        // Empty body → none (nothing to score).
        assert!(image_body_for(Some("image/png"), &[]).is_none());
    }

    #[test]
    fn tiny_image_body_is_skipped_so_it_forwards_ungated() {
        // Icons/sprites/pixels under the min are never surfaced for scoring, so
        // they forward immediately (no gate, no latency) like any non-image.
        let icon = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 1, 2, 3]; // 7 bytes
        assert!(
            image_body_for(Some("image/jpeg"), &icon).is_none(),
            "a sub-{MIN_SCORABLE_IMAGE_BYTES}-byte image must be skipped (forwards ungated)"
        );
        let just_under = vec![0u8; MIN_SCORABLE_IMAGE_BYTES - 1];
        assert!(image_body_for(Some("image/png"), &just_under).is_none());
        // Exactly at the threshold → scored.
        let at_min = vec![0u8; MIN_SCORABLE_IMAGE_BYTES];
        assert!(image_body_for(Some("image/png"), &at_min).is_some());
    }

    #[test]
    fn oversized_image_body_is_skipped_fail_open() {
        let huge = vec![0u8; IMAGE_BODY_CAP + 1];
        assert!(
            image_body_for(Some("image/jpeg"), &huge).is_none(),
            "an image over the cap must be skipped (fail-open), not surfaced"
        );
        let at_cap = vec![0u8; IMAGE_BODY_CAP];
        assert!(image_body_for(Some("image/jpeg"), &at_cap).is_some());
    }

    #[test]
    fn video_segments_surfaced_for_remediation_but_not_manifests() {
        let seg = vec![0u8; 64 * 1024];
        // HLS .ts (mp2t) and DASH/fMP4 segments are surfaced whole for the analyzer.
        assert!(video_segment_body_for(Some("video/mp2t"), &seg).is_some());
        assert!(video_segment_body_for(Some("video/mp4"), &seg).is_some());
        // Playlists/manifests are NOT video/* → pass through ungated.
        assert!(video_segment_body_for(Some("application/vnd.apple.mpegurl"), &seg).is_none());
        assert!(video_segment_body_for(Some("application/dash+xml"), &seg).is_none());
        assert!(video_segment_body_for(Some("text/html"), &seg).is_none());
        assert!(video_segment_body_for(None, &seg).is_none());
        // Empty / oversized are skipped.
        assert!(video_segment_body_for(Some("video/mp2t"), &[]).is_none());
        let huge = vec![0u8; VIDEO_SEGMENT_CAP + 1];
        assert!(video_segment_body_for(Some("video/mp4"), &huge).is_none());
    }

    #[tokio::test]
    async fn gated_image_timeout_fails_closed_to_drop() {
        // Mirror the handler's gated-image branch: a registered waiter that never
        // receives a decision must, on timeout, resolve to Drop (block instantly),
        // NOT Forward. We use a near-zero timeout so the test is fast.
        let gate = DecisionGate::default();
        let flow_id = 99u64;
        let rx = gate.register(flow_id).await;
        let decision = match tokio::time::timeout(std::time::Duration::from_millis(1), rx).await {
            Ok(Ok(d)) => d,
            Ok(Err(_)) | Err(_) => {
                gate.cancel(flow_id).await;
                InterceptDecision::Drop
            }
        };
        assert!(
            matches!(decision, InterceptDecision::Drop),
            "a gated image whose decision times out must fail CLOSED (Drop)"
        );
    }

    #[tokio::test]
    async fn gated_image_dropped_sender_fails_closed_to_drop() {
        // If the decision sender is dropped (classifier gone), the waiter sees a
        // RecvError and must also fail CLOSED to Drop.
        let gate = DecisionGate::default();
        let flow_id = 100u64;
        let rx = gate.register(flow_id).await;
        // Drop the registered sender out from under the waiter.
        gate.cancel(flow_id).await;
        let decision = match tokio::time::timeout(DECISION_TIMEOUT, rx).await {
            Ok(Ok(d)) => d,
            Ok(Err(_)) | Err(_) => {
                gate.cancel(flow_id).await;
                InterceptDecision::Drop
            }
        };
        assert!(
            matches!(decision, InterceptDecision::Drop),
            "a gated image whose sender is dropped must fail CLOSED (Drop)"
        );
    }

    #[test]
    fn content_type_of_strips_params_and_lowercases() {
        let mut headers = hudsucker::hyper::HeaderMap::new();
        headers.insert(
            hudsucker::hyper::header::CONTENT_TYPE,
            "Image/JPEG; charset=binary".parse().unwrap(),
        );
        assert_eq!(content_type_of(&headers).as_deref(), Some("image/jpeg"));
        assert!(content_type_of(&hudsucker::hyper::HeaderMap::new()).is_none());
    }

    #[tokio::test]
    async fn classify_source_routes_media_extensions() {
        assert_eq!(
            classify_source("https://x/y/index.m3u8"),
            FlowSource::VideoStream
        );
        assert_eq!(
            classify_source("https://x/seg1.m4s"),
            FlowSource::VideoStream
        );
        assert_eq!(
            classify_source("https://x/manifest.mpd"),
            FlowSource::VideoStream
        );
        assert_eq!(classify_source("https://x/page.html"), FlowSource::Web);
    }
}
