//! Low-latency TLS inspection proxy with bounded safety gates.
//!
//! Ungated traffic is never fully buffered: requests/responses either pass through
//! untouched or only a bounded textual prefix is collected for classification.
//! Protected media is bounded before analysis; oversized/failed media is blocked
//! rather than silently bypassing coverage. Response flows retain the CONNECT/
//! request host so guardian host approvals and alerts remain correctly attributed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{stream, StreamExt};
use http::response::Parts as ResponseParts;
use http_body_util::BodyExt;
use hudsucker::hyper::{Request, Response, StatusCode};
use hudsucker::{Body, Error as HudsuckerError, HttpContext, HttpHandler, RequestOrResponse};
use tokio::sync::{mpsc, oneshot, Mutex as TokioMutex};

use bulwark_core::flow::InterceptDecision;

use crate::blocklist::HostBlocklist;
use crate::ca::CaManager;
use crate::pinning::PinningRegistry;
use crate::{NetError, Result};

const MEDIA_DECISION_TIMEOUT: Duration = Duration::from_millis(1_500);
const HTML_DECISION_TIMEOUT: Duration = Duration::from_millis(350);
const HTML_GATE_CAP: usize = 2 * 1024 * 1024;
const LEAF_CACHE_SIZE: u64 = 1_000;
const BODY_PEEK_CAP: usize = 64 * 1024;
const IMAGE_BODY_CAP: usize = 8 * 1024 * 1024;
const AUDIO_BODY_CAP: usize = 8 * 1024 * 1024;
const VIDEO_SEGMENT_CAP: usize = 16 * 1024 * 1024;
const MIN_SCORABLE_IMAGE_BYTES: usize = 2 * 1024;
const HOST_CACHE_CAP: usize = 8_192;

/// Coarse source of an inspected flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowSource {
    /// Normal web traffic.
    Web,
    /// Buffered/progressive media traffic.
    VideoStream,
    /// Low-latency live media traffic.
    LiveStream,
}

/// Proxy-local decrypted flow surfaced to [`crate::interceptor::NetInterceptor`].
#[derive(Clone, Debug)]
pub struct CapturedFlow {
    /// Per-proxy monotonic flow identifier.
    pub flow_id: u64,
    /// Coarse source channel.
    pub source: FlowSource,
    /// Host/application attribution.
    pub app_or_host: String,
    /// Whether payload inspection succeeded.
    pub readable: bool,
    /// Request method, empty for response legs.
    pub method: String,
    /// Request URI or response status marker.
    pub uri: String,
    /// Bounded textual/magic-byte prefix, or full bounded audio payload.
    pub body: Vec<u8>,
    /// True for response legs.
    pub is_response: bool,
    /// Normalized content type.
    pub content_type: Option<String>,
    /// Full bounded still-image body when selected for image analysis.
    pub image_body: Option<Vec<u8>>,
    /// Full bounded video segment when selected for video analysis.
    pub video_body: Option<Vec<u8>>,
}

/// Receiver end of the bounded flow channel.
pub type FlowReceiver = mpsc::Receiver<CapturedFlow>;
/// Sender end of the bounded flow channel.
pub type FlowSender = mpsc::Sender<CapturedFlow>;

/// Per-flow decision rendezvous shared with the interceptor.
#[derive(Clone)]
pub struct DecisionGate {
    pending: Arc<TokioMutex<HashMap<u64, oneshot::Sender<InterceptDecision>>>>,
    armed: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for DecisionGate {
    fn default() -> Self {
        Self {
            pending: Arc::new(TokioMutex::new(HashMap::new())),
            armed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl DecisionGate {
    /// Enable/disable inline response gating.
    pub fn set_armed(&self, armed: bool) {
        self.armed
            .store(armed, std::sync::atomic::Ordering::Relaxed);
    }

    fn is_armed(&self) -> bool {
        self.armed.load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn register(&self, flow_id: u64) -> oneshot::Receiver<InterceptDecision> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(flow_id, tx);
        rx
    }

    async fn cancel(&self, flow_id: u64) {
        self.pending.lock().await.remove(&flow_id);
    }

    /// Deliver a response decision if the flow is still awaiting one.
    pub async fn resolve(&self, flow_id: u64, decision: InterceptDecision) -> bool {
        self.pending
            .lock()
            .await
            .remove(&flow_id)
            .map(|tx| tx.send(decision).is_ok())
            .unwrap_or(false)
    }
}

/// Running TLS-inspection proxy handle.
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

    /// Apply a decision to a live response gate.
    pub async fn apply(&self, flow_id: u64, decision: InterceptDecision) -> Result<bool> {
        Ok(self.gate.resolve(flow_id, decision).await)
    }

    /// Shared decision gate.
    pub fn decision_gate(&self) -> DecisionGate {
        self.gate.clone()
    }

    /// Arm/disarm protected response gating.
    pub fn set_gating(&self, armed: bool) {
        self.gate.set_armed(armed);
    }

    /// Stop the proxy and await its listener task.
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

/// Start the TLS-inspecting proxy.
pub async fn spawn(
    listen: SocketAddr,
    ca: Arc<CaManager>,
    pinning: Arc<PinningRegistry>,
    blocklist: Arc<HostBlocklist>,
    flow_tx: FlowSender,
) -> Result<MitmProxy> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| NetError::proxy(format!("binding TLS-inspecting listener on {listen}: {error}")))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|error| NetError::proxy(format!("resolving bound proxy address: {error}")))?;
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
        connection_hosts: Arc::new(StdMutex::new(HashMap::new())),
    };
    let fingerprint = ca.fingerprint_hex().to_owned();
    let join = tokio::spawn(async move {
        run_hudsucker(listener, authority, handler, shutdown_rx).await;
    });
    tracing::info!(%listen_addr, %fingerprint, "bounded streaming TLS-inspection proxy started");
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
        .map_err(|error| NetError::ca(format!("reparse CA key for authority: {error}")))?;
    let cert = CertificateDer::from(ca.cert_der().to_vec());
    let issuer: Issuer<'static, KeyPair> = Issuer::from_ca_cert_der(&cert, key_pair)
        .map_err(|error| NetError::ca(format!("build issuer from CA cert: {error}")))?;
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
    shutdown_rx: oneshot::Receiver<()>,
) {
    use hudsucker::rustls::crypto::aws_lc_rs;
    use hudsucker::Proxy;

    let proxy = match Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .build()
    {
        Ok(proxy) => proxy,
        Err(error) => {
            tracing::error!(%error, "failed to construct TLS-inspection proxy");
            return;
        }
    };
    if let Err(error) = proxy.start().await {
        tracing::error!(%error, "TLS-inspection proxy exited with error");
    }
}

/// Hudsucker HTTP handler with bounded capture/gating.
#[derive(Clone)]
pub struct FlowHandler {
    flow_tx: FlowSender,
    pinning: Arc<PinningRegistry>,
    ca: Arc<CaManager>,
    blocklist: Arc<HostBlocklist>,
    gate: DecisionGate,
    next_flow_id: Arc<std::sync::atomic::AtomicU64>,
    connection_hosts: Arc<StdMutex<HashMap<SocketAddr, String>>>,
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
        let sent = self.flow_tx.try_send(flow).is_ok();
        if !sent {
            tracing::warn!(host = %app_or_host, flow_id, "flow channel full; protected gate will resolve conservatively");
        }
        if !app_or_host.is_empty() {
            self.pinning.record_mitmable(app_or_host);
        }
        sent
    }

    /// Record a cert-pinned host and return the configured fail-open result.
    pub fn on_pinned(&self, app_or_host: &str) -> bool {
        self.pinning.record_pinned(app_or_host).failed_open
    }

    fn remember_host(&self, client: SocketAddr, host: &str) {
        let host = host.trim();
        if host.is_empty() {
            return;
        }
        if let Ok(mut hosts) = self.connection_hosts.lock() {
            if hosts.len() >= HOST_CACHE_CAP && !hosts.contains_key(&client) {
                hosts.clear();
            }
            hosts.insert(client, host.to_ascii_lowercase());
        }
    }

    fn response_host(&self, client: SocketAddr) -> String {
        self.connection_hosts
            .lock()
            .ok()
            .and_then(|hosts| hosts.get(&client).cloned())
            .unwrap_or_default()
    }

    fn is_request_blocked(&self, request: &Request<Body>) -> bool {
        if self.blocklist.is_empty() {
            return false;
        }
        if let Some(authority) = request.uri().authority() {
            if self.blocklist.is_blocked(authority.host()) {
                return true;
            }
        }
        request
            .headers()
            .get(hudsucker::hyper::header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(|host| self.blocklist.is_blocked(host))
            .unwrap_or(false)
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

    /// Access the per-install CA.
    pub fn ca(&self) -> &CaManager {
        &self.ca
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
        let gated = self.gate.is_armed() && (media.is_some() || html);
        let receiver = if gated {
            Some(self.gate.register(flow_id).await)
        } else {
            None
        };

        let (body, image_body, video_body) = match media {
            Some(MediaClass::Image) => (peek(&full), Some(full.clone()), None),
            Some(MediaClass::Video) => (peek(&full), None, Some(full.clone())),
            Some(MediaClass::Audio) => (full.clone(), None, None),
            Some(MediaClass::UnsupportedImage) => (Vec::new(), None, None),
            None => (peek(&full), None, None),
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
            InterceptDecision::Rewrite(new_body) => {
                parts
                    .headers
                    .remove(hudsucker::hyper::header::CONTENT_LENGTH);
                Response::from_parts(parts, Body::from(new_body))
            }
            InterceptDecision::Drop => {
                if html {
                    blocked_page_response()
                } else {
                    blocked_response()
                }
            }
        }
    }
}

impl HttpHandler for FlowHandler {
    async fn should_intercept_connect(
        &mut self,
        ctx: &HttpContext,
        request: &Request<Body>,
    ) -> bool {
        let host = host_of_request(request);
        self.remember_host(ctx.client_addr, &host);
        self.decide_intercept(&host)
    }

    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        if self.is_request_blocked(&request) {
            return RequestOrResponse::Response(blocked_page_response());
        }

        let host = host_of_request(&request);
        self.remember_host(ctx.client_addr, &host);
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
                tracing::warn!(%error, %host, "request body stream failed during bounded capture");
                RequestOrResponse::Response(bad_gateway_response())
            }
        }
    }

    async fn handle_response(
        &mut self,
        ctx: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        let status = response.status().as_u16();
        let host = self.response_host(ctx.client_addr);
        let content_type = content_type_of(response.headers());
        let declared_len = content_length(response.headers());
        let media = media_class(content_type.as_deref());

        if matches!(media, Some(MediaClass::UnsupportedImage)) {
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
            return blocked_response();
        }

        if let Some(class) = media.filter(|class| *class != MediaClass::UnsupportedImage) {
            let cap = media_cap(class);
            if declared_len.map(|length| length > cap as u64).unwrap_or(false) {
                self.emit(
                    self.next_id(),
                    if class == MediaClass::Video { FlowSource::VideoStream } else { FlowSource::Web },
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
                Ok(BoundedRead::Complete(full)) => {
                    if class == MediaClass::Image && full.len() < MIN_SCORABLE_IMAGE_BYTES {
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
                    } else if full.is_empty() {
                        Response::from_parts(parts, Body::empty())
                    } else {
                        self.gate_buffered(parts, full, host, status, content_type, Some(class), false)
                            .await
                    }
                }
                Ok(BoundedRead::Overflow { peek, .. }) => {
                    self.emit(
                        self.next_id(),
                        if class == MediaClass::Video { FlowSource::VideoStream } else { FlowSource::Web },
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
                    tracing::warn!(%error, %host, "protected media body failed while reading; blocking");
                    blocked_response()
                }
            };
        }

        let html = is_html(content_type.as_deref());
        let html_within_declared_cap = declared_len
            .map(|length| length <= HTML_GATE_CAP as u64)
            .unwrap_or(true);
        if html && html_within_declared_cap {
            let (parts, body) = response.into_parts();
            return match collect_bounded(body, HTML_GATE_CAP).await {
                Ok(BoundedRead::Complete(full)) if !full.is_empty() => {
                    self.gate_buffered(parts, full, host, status, content_type, None, true)
                        .await
                }
                Ok(BoundedRead::Complete(full)) => Response::from_parts(parts, Body::from(full)),
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
                    tracing::warn!(%error, %host, "HTML body stream failed during bounded gate");
                    bad_gateway_response()
                }
            };
        }

        if should_capture_text(content_type.as_deref()) {
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
                    tracing::warn!(%error, %host, "text response stream failed during bounded capture");
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

async fn collect_bounded(body: Body, cap: usize) -> std::result::Result<BoundedRead, HudsuckerError> {
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
        return authority.host().to_ascii_lowercase();
    }
    request
        .headers()
        .get(hudsucker::hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|host| host.split(':').next().unwrap_or(host).to_ascii_lowercase())
        .unwrap_or_default()
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
        .and_then(|value| value.parse::<u64>().ok())
}

fn is_scorable_image(content_type: &str) -> bool {
    matches!(
        content_type,
        "image/jpeg" | "image/png" | "image/webp" | "image/gif"
    )
}

fn media_class(content_type: Option<&str>) -> Option<MediaClass> {
    let content_type = content_type?;
    if is_scorable_image(content_type) {
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
        .header(
            hudsucker::hyper::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )
        .body(Body::from("Blocked by Bulwark"))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

const BLOCK_PAGE_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Blocked by PH Bulwark</title></head><body style=\"font-family:sans-serif;text-align:center;margin-top:15vh\"><h1>Page blocked</h1><p>This page was blocked by PH Bulwark's content filter.</p><p>If you think this is a mistake, ask your parent or guardian to review it.</p></body></html>";

fn blocked_page_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(
            hudsucker::hyper::header::CONTENT_TYPE,
            "text/html; charset=utf-8",
        )
        .body(Body::from(BLOCK_PAGE_HTML))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn bad_gateway_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header(
            hudsucker::hyper::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )
        .body(Body::from("Upstream body stream failed"))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_reader_reconstructs_overflow_without_collecting_the_rest() {
        let body = Body::from(vec![7u8; BODY_PEEK_CAP + 32]);
        match collect_bounded(body, BODY_PEEK_CAP).await.unwrap() {
            BoundedRead::Overflow { body, peek } => {
                assert_eq!(peek.len(), BODY_PEEK_CAP);
                let bytes = body.collect().await.unwrap().to_bytes();
                assert_eq!(bytes.len(), BODY_PEEK_CAP + 32);
            }
            BoundedRead::Complete(_) => panic!("expected overflow"),
        }
    }

    #[test]
    fn unsupported_images_and_all_audio_video_are_protected_media() {
        assert_eq!(media_class(Some("image/jpeg")), Some(MediaClass::Image));
        assert_eq!(
            media_class(Some("image/avif")),
            Some(MediaClass::UnsupportedImage)
        );
        assert_eq!(media_class(Some("video/mp4")), Some(MediaClass::Video));
        assert_eq!(media_class(Some("audio/wav")), Some(MediaClass::Audio));
    }

    #[test]
    fn streaming_text_is_not_buffered() {
        assert!(!should_capture_text(Some("text/event-stream")));
        assert!(!should_capture_text(Some("application/x-ndjson")));
        assert!(should_capture_text(Some("application/json")));
    }

    #[test]
    fn decision_windows_are_short_and_media_fails_closed() {
        let (window, fallback) = gate_policy(true);
        assert!(window <= Duration::from_millis(1_500));
        assert!(matches!(fallback, InterceptDecision::Drop));
        let (window, fallback) = gate_policy(false);
        assert!(window <= Duration::from_millis(350));
        assert!(matches!(fallback, InterceptDecision::Forward));
    }
}
