//! Low-latency TLS inspection proxy with bounded safety gates.
//!
//! Ordinary resources stream through without whole-body buffering. Text that is
//! inspected is decompressed and captured only to a fixed bound. Protected media
//! is fully buffered only up to a strict per-kind limit; unknown-size overflow,
//! decode failure, classifier backpressure, or decision timeout fails closed.
//! WebSocket text frames use the same text/policy gate; transport control frames
//! and opaque binary frames are passed without pretending they are inspectable media.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{stream, StreamExt};
use http::response::Parts as ResponseParts;
use http_body_util::BodyExt;
use hudsucker::hyper::{Request, Response, StatusCode};
use hudsucker::tokio_tungstenite::tungstenite::Message;
use hudsucker::{
    decode_request, decode_response, Body, Error as HudsuckerError, HttpContext, HttpHandler,
    RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use tokio::sync::{mpsc, oneshot, Mutex};

use bulwark_core::flow::InterceptDecision;

use crate::blocklist::HostBlocklist;
use crate::ca::CaManager;
use crate::pinning::PinningRegistry;
use crate::{NetError, Result};

const MEDIA_DECISION_TIMEOUT: Duration = Duration::from_millis(1_500);
const HTML_DECISION_TIMEOUT: Duration = Duration::from_millis(350);
const WEBSOCKET_DECISION_TIMEOUT: Duration = Duration::from_millis(250);
const HTML_GATE_CAP: usize = 2 * 1024 * 1024;
const BODY_PEEK_CAP: usize = 64 * 1024;
const IMAGE_BODY_CAP: usize = 8 * 1024 * 1024;
const AUDIO_BODY_CAP: usize = 8 * 1024 * 1024;
const VIDEO_SEGMENT_CAP: usize = 16 * 1024 * 1024;
const LEAF_CACHE_SIZE: u64 = 1_000;

/// Coarse source of an inspected flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowSource {
    /// Normal HTTP(S) web traffic.
    Web,
    /// Buffered/progressive video traffic.
    VideoStream,
    /// Low-latency live media traffic.
    LiveStream,
}

/// Proxy-local decrypted unit surfaced to the canonical interceptor.
#[derive(Clone, Debug)]
pub struct CapturedFlow {
    /// Monotonic per-proxy flow identifier.
    pub flow_id: u64,
    /// Origin channel.
    pub source: FlowSource,
    /// Request host retained for both request and response legs.
    pub app_or_host: String,
    /// Whether the payload was readable after TLS interception.
    pub readable: bool,
    /// HTTP method on request legs, empty for responses.
    pub method: String,
    /// Request URI or a response-status marker.
    pub uri: String,
    /// Bounded text/magic prefix, or the full bounded audio body.
    pub body: Vec<u8>,
    /// True for response legs.
    pub is_response: bool,
    /// Normalized MIME type when present.
    pub content_type: Option<String>,
    /// Complete bounded still image selected for scoring.
    pub image_body: Option<Vec<u8>>,
    /// Complete bounded video segment selected for scoring/remediation.
    pub video_body: Option<Vec<u8>>,
}

/// Receiver for the bounded classifier flow channel.
pub type FlowReceiver = mpsc::Receiver<CapturedFlow>;
/// Sender held by the proxy handler.
pub type FlowSender = mpsc::Sender<CapturedFlow>;

/// Per-flow response-decision rendezvous.
#[derive(Clone)]
pub struct DecisionGate {
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<InterceptDecision>>>>,
    armed: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for DecisionGate {
    fn default() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            armed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl DecisionGate {
    /// Enable or disable inline response gating.
    pub fn set_armed(&self, armed: bool) {
        self.armed
            .store(armed, std::sync::atomic::Ordering::Relaxed);
    }

    fn is_armed(&self) -> bool {
        self.armed.load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn register(&self, flow_id: u64) -> oneshot::Receiver<InterceptDecision> {
        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(flow_id, sender);
        receiver
    }

    async fn cancel(&self, flow_id: u64) {
        self.pending.lock().await.remove(&flow_id);
    }

    /// Resolve a still-live response gate.
    pub async fn resolve(&self, flow_id: u64, decision: InterceptDecision) -> bool {
        self.pending
            .lock()
            .await
            .remove(&flow_id)
            .map(|sender| sender.send(decision).is_ok())
            .unwrap_or(false)
    }
}

/// Handle for a running MITM proxy.
pub struct MitmProxy {
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
    listen_addr: SocketAddr,
    gate: DecisionGate,
}

impl MitmProxy {
    /// Address actually bound by the proxy.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Apply a policy decision to an in-flight response.
    pub async fn apply(&self, flow_id: u64, decision: InterceptDecision) -> Result<bool> {
        Ok(self.gate.resolve(flow_id, decision).await)
    }

    /// Clone the shared decision gate.
    pub fn decision_gate(&self) -> DecisionGate {
        self.gate.clone()
    }

    /// Arm or disarm inline response gating.
    pub fn set_gating(&self, armed: bool) {
        self.gate.set_armed(armed);
    }

    /// Gracefully stop the proxy.
    pub async fn stop(mut self) -> Result<()> {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
        Ok(())
    }
}

/// Bind and start the TLS-inspection proxy.
pub async fn spawn(
    listen: SocketAddr,
    ca: Arc<CaManager>,
    pinning: Arc<PinningRegistry>,
    blocklist: Arc<HostBlocklist>,
    flow_tx: FlowSender,
) -> Result<MitmProxy> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| NetError::proxy(format!("binding TLS proxy on {listen}: {error}")))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|error| NetError::proxy(format!("reading bound proxy address: {error}")))?;
    let authority = build_authority(&ca)?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let gate = DecisionGate::default();
    let handler = FlowHandler {
        flow_tx,
        pinning,
        ca: ca.clone(),
        blocklist,
        gate: gate.clone(),
        next_flow_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        request_host: String::new(),
    };
    let websocket_handler = handler.clone();
    let fingerprint = ca.fingerprint_hex().to_owned();
    let join = tokio::spawn(async move {
        run_hudsucker(
            listener,
            authority,
            handler,
            websocket_handler,
            shutdown_rx,
        )
        .await;
    });
    tracing::info!(%listen_addr, %fingerprint, "bounded TLS-inspection proxy started");
    Ok(MitmProxy {
        shutdown: Some(shutdown_tx),
        join: Some(join),
        listen_addr,
        gate,
    })
}

fn build_authority(
    ca: &Arc<CaManager>,
) -> Result<hudsucker::certificate_authority::RcgenAuthority> {
    use hudsucker::certificate_authority::RcgenAuthority;
    use hudsucker::rcgen::{Issuer, KeyPair};
    use hudsucker::rustls::crypto::aws_lc_rs;
    use hudsucker::rustls::pki_types::CertificateDer;

    let key_pair = KeyPair::try_from(ca.ca_key_der())
        .map_err(|error| NetError::ca(format!("reparse CA key: {error}")))?;
    let cert = CertificateDer::from(ca.cert_der().to_vec());
    let issuer: Issuer<'static, KeyPair> = Issuer::from_ca_cert_der(&cert, key_pair)
        .map_err(|error| NetError::ca(format!("build CA issuer: {error}")))?;
    Ok(RcgenAuthority::new(
        issuer,
        LEAF_CACHE_SIZE,
        aws_lc_rs::default_provider(),
    ))
}

async fn run_hudsucker(
    listener: tokio::net::TcpListener,
    authority: hudsucker::certificate_authority::RcgenAuthority,
    handler: FlowHandler,
    websocket_handler: FlowHandler,
    shutdown_rx: oneshot::Receiver<()>,
) {
    use hudsucker::rustls::crypto::aws_lc_rs;
    use hudsucker::Proxy;

    let proxy = match Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_websocket_handler(websocket_handler)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .build()
    {
        Ok(proxy) => proxy,
        Err(error) => {
            tracing::error!(%error, "failed to build TLS-inspection proxy");
            return;
        }
    };
    if let Err(error) = proxy.start().await {
        tracing::error!(%error, "TLS-inspection proxy exited");
    }
}

/// HTTP handler that keeps request/response attribution on the handler instance
/// Hudsucker guarantees for one pair.
#[derive(Clone)]
pub struct FlowHandler {
    flow_tx: FlowSender,
    pinning: Arc<PinningRegistry>,
    ca: Arc<CaManager>,
    blocklist: Arc<HostBlocklist>,
    gate: DecisionGate,
    next_flow_id: Arc<std::sync::atomic::AtomicU64>,
    request_host: String,
}

impl FlowHandler {
    fn next_id(&self) -> u64 {
        self.next_flow_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        flow_id: u64,
        source: FlowSource,
        app_or_host: &str,
        method: &str,
        uri: &str,
        body: Vec<u8>,
        is_response: bool,
        content_type: Option<String>,
        image_body: Option<Vec<u8>>,
        video_body: Option<Vec<u8>>,
    ) -> bool {
        let sent = self
            .flow_tx
            .try_send(CapturedFlow {
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
            })
            .is_ok();
        if !sent {
            tracing::warn!(host = %app_or_host, flow_id, "classifier channel full");
        }
        if !app_or_host.is_empty() {
            self.pinning.record_mitmable(app_or_host);
        }
        sent
    }

    /// Record a pinning failure and return the configured pass/block result.
    pub fn on_pinned(&self, app_or_host: &str) -> bool {
        self.pinning.record_pinned(app_or_host).failed_open
    }

    /// Access the per-install certificate authority.
    pub fn ca(&self) -> &CaManager {
        &self.ca
    }

    fn is_request_blocked(&self, request: &Request<Body>) -> bool {
        if self.blocklist.is_empty() {
            return false;
        }
        let host = host_of_request(request);
        !host.is_empty() && self.blocklist.is_blocked(&host)
    }

    fn decide_intercept(&self, host: &str) -> bool {
        if host.is_empty() {
            return true;
        }
        if self.pinning.is_pinned(host) {
            return !self.pinning.fail_open();
        }
        if self.pinning.record_intercept_attempt(host).is_some() {
            !self.pinning.fail_open()
        } else {
            true
        }
    }

    async fn gate_buffered(
        &self,
        mut parts: ResponseParts,
        full: Vec<u8>,
        host: String,
        status: u16,
        content_type: Option<String>,
        media: Option<MediaClass>,
        html: bool,
    ) -> Response<Body> {
        let flow_id = self.next_id();
        let source = if matches!(media, Some(MediaClass::Video)) {
            FlowSource::VideoStream
        } else {
            FlowSource::Web
        };
        let receiver = if self.gate.is_armed() {
            Some(self.gate.register(flow_id).await)
        } else {
            None
        };
        let (body, image_body, video_body) = match media {
            Some(MediaClass::Image) => (peek(&full), Some(full.clone()), None),
            Some(MediaClass::Video) => (peek(&full), None, Some(full.clone())),
            Some(MediaClass::Audio) => (full.clone(), None, None),
            Some(MediaClass::UnsupportedImage) | None => (peek(&full), None, None),
        };
        let emitted = self.emit(
            flow_id,
            source,
            &host,
            "",
            &format!("status:{status}"),
            body,
            true,
            content_type,
            image_body,
            video_body,
        );

        let Some(receiver) = receiver else {
            return Response::from_parts(parts, Body::from(full));
        };
        if !emitted {
            self.gate.cancel(flow_id).await;
            return if media.is_some() {
                blocked_response()
            } else {
                Response::from_parts(parts, Body::from(full))
            };
        }

        let (window, fallback) = gate_policy(media.is_some());
        let decision = match tokio::time::timeout(window, receiver).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_)) | Err(_) => {
                self.gate.cancel(flow_id).await;
                fallback
            }
        };
        match decision {
            InterceptDecision::Forward => Response::from_parts(parts, Body::from(full)),
            InterceptDecision::Rewrite(replacement) => {
                parts
                    .headers
                    .remove(hudsucker::hyper::header::CONTENT_LENGTH);
                parts
                    .headers
                    .remove(hudsucker::hyper::header::CONTENT_ENCODING);
                Response::from_parts(parts, Body::from(replacement))
            }
            InterceptDecision::Drop if html => blocked_page_response(),
            InterceptDecision::Drop => blocked_response(),
        }
    }
}

impl HttpHandler for FlowHandler {
    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        request: &Request<Body>,
    ) -> bool {
        self.decide_intercept(&host_of_request(request))
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        if self.is_request_blocked(&request) {
            return RequestOrResponse::Response(blocked_page_response());
        }

        let host = host_of_request(&request);
        self.request_host = host.clone();
        let method = request.method().to_string();
        let uri = request.uri().to_string();
        let content_type = content_type_of(request.headers());
        let flow_id = self.next_id();

        if !should_capture_text(content_type.as_deref()) {
            self.emit(
                flow_id,
                classify_source(&uri),
                &host,
                &method,
                &uri,
                Vec::new(),
                false,
                content_type,
                None,
                None,
            );
            return RequestOrResponse::Request(request);
        }

        let request = match decode_request(request) {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(%error, %host, "request content encoding cannot be inspected");
                return RequestOrResponse::Response(unsupported_encoding_response());
            }
        };
        let content_type = content_type_of(request.headers());
        let (parts, body) = request.into_parts();
        match collect_bounded(body, BODY_PEEK_CAP).await {
            Ok(BoundedRead::Complete(full)) => {
                self.emit(
                    flow_id,
                    classify_source(&uri),
                    &host,
                    &method,
                    &uri,
                    peek(&full),
                    false,
                    content_type,
                    None,
                    None,
                );
                RequestOrResponse::Request(Request::from_parts(parts, Body::from(full)))
            }
            Ok(BoundedRead::Overflow { body, peek }) => {
                self.emit(
                    flow_id,
                    classify_source(&uri),
                    &host,
                    &method,
                    &uri,
                    peek,
                    false,
                    content_type,
                    None,
                    None,
                );
                RequestOrResponse::Request(Request::from_parts(parts, body))
            }
            Err(error) => {
                tracing::warn!(%error, %host, "request body failed during bounded inspection");
                RequestOrResponse::Response(bad_gateway_response())
            }
        }
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        let host = self.request_host.clone();
        let initial_content_type = content_type_of(response.headers());
        let initial_media = media_class(initial_content_type.as_deref());
        let inspect_text = should_capture_text(initial_content_type.as_deref());
        let encoded = has_content_encoding(response.headers());

        if matches!(initial_media, Some(MediaClass::UnsupportedImage)) {
            return blocked_response();
        }

        let response = if encoded && (initial_media.is_some() || inspect_text) {
            match decode_response(response) {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(%error, %host, "response content encoding cannot be inspected");
                    return if is_html(initial_content_type.as_deref()) {
                        blocked_page_response()
                    } else if initial_media.is_some() {
                        blocked_response()
                    } else {
                        bad_gateway_response()
                    };
                }
            }
        } else {
            response
        };

        let status = response.status().as_u16();
        let content_type = content_type_of(response.headers());
        let declared_len = content_length(response.headers());
        let media = media_class(content_type.as_deref());

        if matches!(media, Some(MediaClass::UnsupportedImage)) {
            return blocked_response();
        }

        if let Some(class) = media {
            let cap = media_cap(class);
            if declared_len.is_some_and(|length| length > cap as u64) {
                self.emit(
                    self.next_id(),
                    media_source(class),
                    &host,
                    "",
                    &format!("status:{status}"),
                    Vec::new(),
                    true,
                    content_type,
                    None,
                    None,
                );
                return blocked_response();
            }
            let (parts, body) = response.into_parts();
            return match collect_bounded(body, cap).await {
                Ok(BoundedRead::Complete(full)) if full.is_empty() => {
                    Response::from_parts(parts, Body::empty())
                }
                Ok(BoundedRead::Complete(full)) => {
                    self.gate_buffered(
                        parts,
                        full,
                        host,
                        status,
                        content_type,
                        Some(class),
                        false,
                    )
                    .await
                }
                Ok(BoundedRead::Overflow { peek, .. }) => {
                    self.emit(
                        self.next_id(),
                        media_source(class),
                        &host,
                        "",
                        &format!("status:{status}"),
                        peek,
                        true,
                        content_type,
                        None,
                        None,
                    );
                    blocked_response()
                }
                Err(error) => {
                    tracing::warn!(%error, %host, "protected media stream failed; blocking");
                    blocked_response()
                }
            };
        }

        if is_html(content_type.as_deref()) {
            if declared_len.is_some_and(|length| length > HTML_GATE_CAP as u64) {
                return blocked_page_response();
            }
            let response = if has_content_encoding(response.headers()) {
                match decode_response(response) {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::warn!(%error, %host, "HTML decoding failed; blocking");
                        return blocked_page_response();
                    }
                }
            } else {
                response
            };
            let content_type = content_type_of(response.headers());
            let (parts, body) = response.into_parts();
            return match collect_bounded(body, HTML_GATE_CAP).await {
                Ok(BoundedRead::Complete(full)) if full.is_empty() => {
                    Response::from_parts(parts, Body::empty())
                }
                Ok(BoundedRead::Complete(full)) => {
                    self.gate_buffered(parts, full, host, status, content_type, None, true)
                        .await
                }
                Ok(BoundedRead::Overflow { .. }) => blocked_page_response(),
                Err(error) => {
                    tracing::warn!(%error, %host, "HTML stream failed; blocking");
                    blocked_page_response()
                }
            };
        }

        if should_capture_text(content_type.as_deref()) {
            let response = if has_content_encoding(response.headers()) {
                match decode_response(response) {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::warn!(%error, %host, "text decoding failed");
                        return bad_gateway_response();
                    }
                }
            } else {
                response
            };
            let content_type = content_type_of(response.headers());
            let (parts, body) = response.into_parts();
            return match collect_bounded(body, BODY_PEEK_CAP).await {
                Ok(BoundedRead::Complete(full)) => {
                    self.emit(
                        self.next_id(),
                        FlowSource::Web,
                        &host,
                        "",
                        &format!("status:{status}"),
                        peek(&full),
                        true,
                        content_type,
                        None,
                        None,
                    );
                    Response::from_parts(parts, Body::from(full))
                }
                Ok(BoundedRead::Overflow { body, peek }) => {
                    self.emit(
                        self.next_id(),
                        FlowSource::Web,
                        &host,
                        "",
                        &format!("status:{status}"),
                        peek,
                        true,
                        content_type,
                        None,
                        None,
                    );
                    Response::from_parts(parts, body)
                }
                Err(error) => {
                    tracing::warn!(%error, %host, "text stream failed during bounded inspection");
                    bad_gateway_response()
                }
            };
        }

        self.emit(
            self.next_id(),
            FlowSource::Web,
            &host,
            "",
            &format!("status:{status}"),
            Vec::new(),
            true,
            content_type,
            None,
            None,
        );
        response
    }
}

impl WebSocketHandler for FlowHandler {
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        let text = match &message {
            Message::Text(text) => text.to_string(),
            Message::Ping(_) | Message::Pong(_) | Message::Close(_) => return Some(message),
            Message::Binary(_) | Message::Frame(_) => return Some(message),
        };
        if text.is_empty() {
            return Some(message);
        }
        if text.len() > BODY_PEEK_CAP {
            tracing::warn!(bytes = text.len(), "oversized WebSocket text frame blocked unscored");
            return None;
        }

        let flow_id = self.next_id();
        let is_response = matches!(ctx, WebSocketContext::ServerToClient { .. });
        let receiver = if self.gate.is_armed() {
            Some(self.gate.register(flow_id).await)
        } else {
            None
        };
        let emitted = self.emit(
            flow_id,
            FlowSource::Web,
            "",
            if is_response { "" } else { "WEBSOCKET" },
            "websocket",
            text.into_bytes(),
            is_response,
            Some("text/plain".to_string()),
            None,
            None,
        );
        let Some(receiver) = receiver else {
            return Some(message);
        };
        if !emitted {
            self.gate.cancel(flow_id).await;
            return None;
        }
        let decision = match tokio::time::timeout(WEBSOCKET_DECISION_TIMEOUT, receiver).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_)) | Err(_) => {
                self.gate.cancel(flow_id).await;
                InterceptDecision::Drop
            }
        };
        match decision {
            InterceptDecision::Forward => Some(message),
            InterceptDecision::Rewrite(_) | InterceptDecision::Drop => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MediaClass {
    Image,
    Video,
    Audio,
    UnsupportedImage,
}

enum BoundedRead {
    Complete(Vec<u8>),
    Overflow { body: Body, peek: Vec<u8> },
}

async fn collect_bounded(
    body: Body,
    cap: usize,
) -> std::result::Result<BoundedRead, HudsuckerError> {
    let mut remainder = body.into_data_stream();
    let mut chunks = Vec::<Bytes>::new();
    let mut total = 0usize;

    while let Some(item) = remainder.next().await {
        let chunk = item?;
        let next_total = total.saturating_add(chunk.len());
        if next_total > cap {
            let mut captured = Vec::with_capacity(cap);
            for buffered in &chunks {
                let remaining = cap.saturating_sub(captured.len());
                if remaining == 0 {
                    break;
                }
                captured.extend_from_slice(&buffered[..buffered.len().min(remaining)]);
            }
            let remaining = cap.saturating_sub(captured.len());
            if remaining > 0 {
                captured.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            }
            let prefix = stream::iter(
                chunks
                    .into_iter()
                    .chain(std::iter::once(chunk))
                    .map(Ok::<Bytes, HudsuckerError>),
            );
            return Ok(BoundedRead::Overflow {
                body: Body::from_stream(prefix.chain(remainder)),
                peek: captured,
            });
        }
        total = next_total;
        chunks.push(chunk);
    }

    let mut full = Vec::with_capacity(total);
    for chunk in chunks {
        full.extend_from_slice(&chunk);
    }
    Ok(BoundedRead::Complete(full))
}

fn host_of_request(request: &Request<Body>) -> String {
    if let Some(authority) = request.uri().authority() {
        return authority.host().trim().to_ascii_lowercase();
    }
    request
        .headers()
        .get(hudsucker::hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(normalize_host_header)
        .unwrap_or_default()
}

fn normalize_host_header(value: &str) -> String {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(host, _)| host.to_ascii_lowercase())
            .unwrap_or_else(|| value.to_ascii_lowercase());
    }
    value
        .split(':')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn classify_source(uri: &str) -> FlowSource {
    let lower = uri.to_ascii_lowercase();
    if lower.contains(".m3u8")
        || lower.contains(".ts?")
        || lower.ends_with(".ts")
        || lower.contains(".mpd")
        || lower.contains(".m4s")
    {
        FlowSource::VideoStream
    } else {
        FlowSource::Web
    }
}

fn peek(full: &[u8]) -> Vec<u8> {
    full[..full.len().min(BODY_PEEK_CAP)].to_vec()
}

fn content_type_of(headers: &hudsucker::hyper::HeaderMap) -> Option<String> {
    headers
        .get(hudsucker::hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .to_ascii_lowercase()
        })
}

fn content_length(headers: &hudsucker::hyper::HeaderMap) -> Option<u64> {
    headers
        .get(hudsucker::hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn has_content_encoding(headers: &hudsucker::hyper::HeaderMap) -> bool {
    headers
        .get(hudsucker::hyper::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let value = value.trim();
            !value.is_empty() && !value.eq_ignore_ascii_case("identity")
        })
}

fn media_class(content_type: Option<&str>) -> Option<MediaClass> {
    let content_type = content_type?;
    if matches!(
        content_type,
        "image/jpeg"
            | "image/jpg"
            | "image/pjpeg"
            | "image/png"
            | "image/apng"
            | "image/webp"
            | "image/gif"
            | "image/bmp"
            | "image/x-ms-bmp"
    ) {
        Some(MediaClass::Image)
    } else if content_type.starts_with("image/") {
        Some(MediaClass::UnsupportedImage)
    } else if content_type.starts_with("video/") {
        Some(MediaClass::Video)
    } else if content_type.starts_with("audio/") {
        Some(MediaClass::Audio)
    } else {
        None
    }
}

fn media_cap(class: MediaClass) -> usize {
    match class {
        MediaClass::Image => IMAGE_BODY_CAP,
        MediaClass::Video => VIDEO_SEGMENT_CAP,
        MediaClass::Audio => AUDIO_BODY_CAP,
        MediaClass::UnsupportedImage => 0,
    }
}

fn media_source(class: MediaClass) -> FlowSource {
    if class == MediaClass::Video {
        FlowSource::VideoStream
    } else {
        FlowSource::Web
    }
}

fn is_html(content_type: Option<&str>) -> bool {
    matches!(
        content_type,
        Some("text/html") | Some("application/xhtml+xml")
    )
}

fn should_capture_text(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };
    if matches!(
        content_type,
        "text/event-stream" | "application/stream+json" | "application/x-ndjson"
    ) {
        return false;
    }
    content_type.starts_with("text/")
        || matches!(
            content_type,
            "application/json"
                | "application/x-www-form-urlencoded"
                | "application/xml"
                | "application/xhtml+xml"
        )
}

fn gate_policy(media: bool) -> (Duration, InterceptDecision) {
    if media {
        (MEDIA_DECISION_TIMEOUT, InterceptDecision::Drop)
    } else {
        (HTML_DECISION_TIMEOUT, InterceptDecision::Forward)
    }
}

fn blocked_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(hudsucker::hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from("Blocked by Bulwark"))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

const BLOCK_PAGE_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Blocked by PH Bulwark</title></head><body style=\"font-family:sans-serif;text-align:center;margin-top:15vh\"><h1>Page blocked</h1><p>This page was blocked by PH Bulwark's content filter.</p><p>If you think this is a mistake, ask your parent or guardian to review it.</p></body></html>";

fn blocked_page_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(hudsucker::hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(BLOCK_PAGE_HTML))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn bad_gateway_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(hudsucker::hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from("Upstream body stream failed"))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn unsupported_encoding_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        .header(hudsucker::hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from("Unsupported content encoding"))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn overflow_reconstructs_original_stream() {
        let original = vec![7u8; BODY_PEEK_CAP + 32];
        match collect_bounded(Body::from(original.clone()), BODY_PEEK_CAP)
            .await
            .unwrap()
        {
            BoundedRead::Overflow { body, peek } => {
                assert_eq!(peek.len(), BODY_PEEK_CAP);
                assert_eq!(body.collect().await.unwrap().to_bytes().as_ref(), original.as_slice());
            }
            BoundedRead::Complete(_) => panic!("expected bounded overflow"),
        }
    }

    #[test]
    fn all_raster_audio_and_video_are_protected_classes() {
        assert_eq!(media_class(Some("image/jpeg")), Some(MediaClass::Image));
        assert_eq!(media_class(Some("image/avif")), Some(MediaClass::UnsupportedImage));
        assert_eq!(media_class(Some("video/mp4")), Some(MediaClass::Video));
        assert_eq!(media_class(Some("audio/aac")), Some(MediaClass::Audio));
    }

    #[test]
    fn streaming_text_is_not_buffered() {
        assert!(!should_capture_text(Some("text/event-stream")));
        assert!(!should_capture_text(Some("application/x-ndjson")));
        assert!(should_capture_text(Some("application/json")));
    }

    #[test]
    fn protected_decision_windows_are_short() {
        let (window, fallback) = gate_policy(true);
        assert!(window <= Duration::from_millis(1_500));
        assert!(matches!(fallback, InterceptDecision::Drop));
        assert!(WEBSOCKET_DECISION_TIMEOUT <= Duration::from_millis(250));
    }
}
