//! Streaming TLS inspection proxy.
//!
//! Ordinary HTTP bodies are forwarded frame-by-frame with bounded capture for
//! classification. Only media that must be scored/re-written and bounded HTML
//! documents are buffered. This keeps uploads, downloads, SSE and long-lived
//! responses off the whole-body buffering path.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http_body_util::{BodyExt, Limited};
use hudsucker::hyper::body::{Body as HttpBody, Bytes, SizeHint};
use hudsucker::hyper::{Request, Response, StatusCode};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use tokio::sync::{mpsc, oneshot, Mutex};

use bulwark_core::flow::InterceptDecision;

use crate::blocklist::HostBlocklist;
use crate::ca::CaManager;
use crate::pinning::PinningRegistry;
use crate::{NetError, Result};

const DECISION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const HTML_DECISION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const HTML_GATE_CAP: usize = 2 * 1024 * 1024;
const LEAF_CACHE_SIZE: u64 = 1_000;
const BODY_PEEK_CAP: usize = 64 * 1024;
const STREAM_CAPTURE_TARGET: usize = 16 * 1024;
const IMAGE_BODY_CAP: usize = 8 * 1024 * 1024;
const VIDEO_SEGMENT_CAP: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowSource {
    Web,
    VideoStream,
    LiveStream,
}

#[derive(Clone, Debug)]
pub struct CapturedFlow {
    pub flow_id: u64,
    pub source: FlowSource,
    pub app_or_host: String,
    pub readable: bool,
    pub method: String,
    pub uri: String,
    pub body: Vec<u8>,
    pub is_response: bool,
    pub content_type: Option<String>,
    pub image_body: Option<Vec<u8>>,
    pub video_body: Option<Vec<u8>>,
}

pub type FlowReceiver = mpsc::Receiver<CapturedFlow>;
pub type FlowSender = mpsc::Sender<CapturedFlow>;

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

    pub async fn resolve(&self, flow_id: u64, decision: InterceptDecision) -> bool {
        match self.pending.lock().await.remove(&flow_id) {
            Some(tx) => tx.send(decision).is_ok(),
            None => false,
        }
    }
}

pub struct MitmProxy {
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
    listen_addr: std::net::SocketAddr,
    gate: DecisionGate,
}

impl MitmProxy {
    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.listen_addr
    }

    pub async fn apply(&self, flow_id: u64, decision: InterceptDecision) -> Result<bool> {
        Ok(self.gate.resolve(flow_id, decision).await)
    }

    pub fn decision_gate(&self) -> DecisionGate {
        self.gate.clone()
    }

    pub fn set_gating(&self, armed: bool) {
        self.gate.set_armed(armed);
    }

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

pub async fn spawn(
    listen: std::net::SocketAddr,
    ca: Arc<CaManager>,
    pinning: Arc<PinningRegistry>,
    blocklist: Arc<HostBlocklist>,
    flow_tx: FlowSender,
) -> Result<MitmProxy> {
    let listener = tokio::net::TcpListener::bind(listen).await.map_err(|error| {
        NetError::proxy(format!(
            "binding TLS-inspecting listener on {listen}: {error}"
        ))
    })?;
    let listen_addr = listener
        .local_addr()
        .map_err(|error| NetError::proxy(format!("resolving bound addr: {error}")))?;
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
    };
    let ca_fp = ca.fingerprint_hex().to_owned();
    let join = tokio::spawn(async move {
        run_hudsucker(listener, authority, handler, shutdown_rx).await;
    });
    tracing::info!(%listen_addr, %ca_fp, "TLS-inspecting proxy started");
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
    let ca_cert_der = CertificateDer::from(ca.cert_der().to_vec());
    let issuer: Issuer<'static, KeyPair> = Issuer::from_ca_cert_der(&ca_cert_der, key_pair)
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
            tracing::error!(%error, "failed to build TLS-inspecting proxy");
            return;
        }
    };
    if let Err(error) = proxy.start().await {
        tracing::error!(%error, "TLS-inspecting proxy exited");
    }
}

#[derive(Clone)]
pub struct FlowHandler {
    flow_tx: FlowSender,
    pinning: Arc<PinningRegistry>,
    ca: Arc<CaManager>,
    blocklist: Arc<HostBlocklist>,
    gate: DecisionGate,
    next_flow_id: Arc<std::sync::atomic::AtomicU64>,
}

impl FlowHandler {
    fn next_id(&self) -> u64 {
        self.next_flow_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn emit(
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
    ) {
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
            tracing::warn!(host = %app_or_host, "flow channel full; capture shed");
        }
        if !app_or_host.is_empty() {
            self.pinning.record_mitmable(app_or_host);
        }
    }

    pub fn on_pinned(&self, app_or_host: &str) -> bool {
        self.pinning.record_pinned(app_or_host).failed_open
    }

    fn is_request_blocked(&self, req: &Request<Body>) -> bool {
        if self.blocklist.is_empty() {
            return false;
        }
        if let Some(authority) = req.uri().authority() {
            if self.blocklist.is_blocked(authority.host()) {
                return true;
            }
        }
        req.headers()
            .get(hudsucker::hyper::header::HOST)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|host| self.blocklist.is_blocked(host))
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

    pub fn ca(&self) -> &CaManager {
        &self.ca
    }
}

struct StreamingCaptureBody {
    inner: Body,
    handler: FlowHandler,
    flow_id: u64,
    source: FlowSource,
    app_or_host: String,
    method: String,
    uri: String,
    is_response: bool,
    content_type: Option<String>,
    capture: Vec<u8>,
    emitted: bool,
}

impl StreamingCaptureBody {
    #[allow(clippy::too_many_arguments)]
    fn new(
        inner: Body,
        handler: FlowHandler,
        flow_id: u64,
        source: FlowSource,
        app_or_host: String,
        method: String,
        uri: String,
        is_response: bool,
        content_type: Option<String>,
    ) -> Self {
        Self {
            inner,
            handler,
            flow_id,
            source,
            app_or_host,
            method,
            uri,
            is_response,
            content_type,
            capture: Vec::with_capacity(STREAM_CAPTURE_TARGET),
            emitted: false,
        }
    }

    fn emit_once(&mut self) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        self.handler.emit(
            self.flow_id,
            self.source,
            &self.app_or_host,
            &self.method,
            &self.uri,
            std::mem::take(&mut self.capture),
            self.is_response,
            self.content_type.clone(),
            None,
            None,
        );
    }
}

impl HttpBody for StreamingCaptureBody {
    type Data = Bytes;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<hudsucker::hyper::body::Frame<Self::Data>, Self::Error>>>
    {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if !this.emitted {
                    if let Some(data) = frame.data_ref() {
                        let room = STREAM_CAPTURE_TARGET.saturating_sub(this.capture.len());
                        let take = room.min(data.len());
                        if take > 0 {
                            this.capture.extend_from_slice(&data[..take]);
                        }
                        if this.capture.len() >= STREAM_CAPTURE_TARGET {
                            this.emit_once();
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.emit_once();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.emit_once();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn streaming_body(
    body: Body,
    handler: FlowHandler,
    flow_id: u64,
    source: FlowSource,
    app_or_host: String,
    method: String,
    uri: String,
    is_response: bool,
    content_type: Option<String>,
) -> Body {
    if body.is_end_stream() {
        handler.emit(
            flow_id,
            source,
            &app_or_host,
            &method,
            &uri,
            Vec::new(),
            is_response,
            content_type,
            None,
            None,
        );
        return body;
    }
    Body::from(
        StreamingCaptureBody::new(
            body,
            handler,
            flow_id,
            source,
            app_or_host,
            method,
            uri,
            is_response,
            content_type,
        )
        .boxed(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResponsePlan {
    Stream,
    Html,
    Image,
    Video,
    BlockMedia,
}

impl HttpHandler for FlowHandler {
    async fn should_intercept(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        self.decide_intercept(&host_of_request(req))
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        if self.is_request_blocked(&req) {
            return RequestOrResponse::Response(blocked_page_response());
        }

        prefer_supported_image_formats(req.headers_mut());
        let host = host_of_request(&req);
        let method = req.method().to_string();
        let uri = req.uri().to_string();
        let source = classify_source(&uri);
        let content_type = content_type_of(req.headers());
        let flow_id = self.next_id();
        let (parts, body) = req.into_parts();
        let body = streaming_body(
            body,
            self.clone(),
            flow_id,
            source,
            host,
            method,
            uri,
            false,
            content_type,
        );
        RequestOrResponse::Request(Request::from_parts(parts, body))
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        let status = res.status().as_u16();
        let content_type = content_type_of(res.headers());
        let plan = response_plan(content_type.as_deref(), res.headers());
        let source = response_source(content_type.as_deref());

        if plan == ResponsePlan::BlockMedia {
            tracing::warn!(
                content_type = content_type.as_deref().unwrap_or("unknown"),
                "unsupported or oversized visual media blocked"
            );
            return blocked_response();
        }

        let (mut parts, body) = res.into_parts();
        if plan == ResponsePlan::Stream {
            let flow_id = self.next_id();
            let body = streaming_body(
                body,
                self.clone(),
                flow_id,
                source,
                String::new(),
                String::new(),
                format!("status:{status}"),
                true,
                content_type,
            );
            return Response::from_parts(parts, body);
        }

        let cap = match plan {
            ResponsePlan::Image => IMAGE_BODY_CAP,
            ResponsePlan::Video => VIDEO_SEGMENT_CAP,
            ResponsePlan::Html => HTML_GATE_CAP,
            ResponsePlan::Stream | ResponsePlan::BlockMedia => unreachable!(),
        };
        let full = match collect_bounded(body, cap).await {
            Ok(full) => full,
            Err(()) => {
                tracing::warn!(status, cap, "bounded response body exceeded limit or failed");
                return if plan == ResponsePlan::Html {
                    blocked_page_response()
                } else {
                    blocked_response()
                };
            }
        };

        let image_body = (plan == ResponsePlan::Image && !full.is_empty()).then(|| full.clone());
        let video_body = (plan == ResponsePlan::Video && !full.is_empty()).then(|| full.clone());
        let media_gated = image_body.is_some() || video_body.is_some();
        let html_gated = plan == ResponsePlan::Html && !full.is_empty();
        let flow_id = self.next_id();
        let rx = if self.gate.is_armed() && (media_gated || html_gated) {
            Some(self.gate.register(flow_id).await)
        } else {
            None
        };

        self.emit(
            flow_id,
            source,
            "",
            "",
            &format!("status:{status}"),
            if media_gated { Vec::new() } else { peek(&full) },
            true,
            content_type,
            image_body,
            video_body,
        );

        let Some(rx) = rx else {
            return Response::from_parts(parts, Body::from(full));
        };

        let (window, fallback) = gate_policy(media_gated);
        let decision = match tokio::time::timeout(window, rx).await {
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
                if html_gated {
                    blocked_page_response()
                } else {
                    blocked_response()
                }
            }
        }
    }
}

fn host_of_request(req: &Request<Body>) -> String {
    if let Some(authority) = req.uri().authority() {
        return authority.host().to_owned();
    }
    req.headers()
        .get(hudsucker::hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|host| host.split(':').next().unwrap_or(host).to_owned())
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

fn response_source(content_type: Option<&str>) -> FlowSource {
    match content_type {
        Some("text/event-stream") => FlowSource::LiveStream,
        Some(content_type) if content_type.starts_with("video/") => FlowSource::VideoStream,
        _ => FlowSource::Web,
    }
}

async fn collect_bounded(body: Body, limit: usize) -> std::result::Result<Vec<u8>, ()> {
    Limited::new(body, limit)
        .collect()
        .await
        .map(|collected| collected.to_bytes().to_vec())
        .map_err(|_| ())
}

fn peek(full: &[u8]) -> Vec<u8> {
    full[..full.len().min(BODY_PEEK_CAP)].to_vec()
}

fn content_type_of(headers: &hudsucker::hyper::HeaderMap) -> Option<String> {
    headers
        .get(hudsucker::hyper::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|content_type| {
            content_type
                .split(';')
                .next()
                .unwrap_or(content_type)
                .trim()
                .to_ascii_lowercase()
        })
}

fn content_length(headers: &hudsucker::hyper::HeaderMap) -> Option<usize> {
    headers
        .get(hudsucker::hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
}

fn is_scorable_image_ct(content_type: &str) -> bool {
    matches!(
        content_type,
        "image/jpeg"
            | "image/jpg"
            | "image/pjpeg"
            | "image/png"
            | "image/x-png"
            | "image/apng"
            | "image/webp"
            | "image/gif"
            | "image/bmp"
            | "image/x-ms-bmp"
    )
}

fn is_passthrough_image_ct(content_type: &str) -> bool {
    matches!(
        content_type,
        "image/svg+xml" | "image/x-icon" | "image/vnd.microsoft.icon"
    )
}

fn response_plan(
    content_type: Option<&str>,
    headers: &hudsucker::hyper::HeaderMap,
) -> ResponsePlan {
    let Some(content_type) = content_type else {
        return ResponsePlan::Stream;
    };
    if is_scorable_image_ct(content_type) {
        return if content_length(headers).is_some_and(|length| length > IMAGE_BODY_CAP) {
            ResponsePlan::BlockMedia
        } else {
            ResponsePlan::Image
        };
    }
    if content_type.starts_with("image/") && !is_passthrough_image_ct(content_type) {
        return ResponsePlan::BlockMedia;
    }
    if content_type.starts_with("video/") {
        return if content_length(headers).is_some_and(|length| length > VIDEO_SEGMENT_CAP) {
            ResponsePlan::BlockMedia
        } else {
            ResponsePlan::Video
        };
    }
    if matches!(content_type, "text/html" | "application/xhtml+xml")
        && content_length(headers)
            .is_some_and(|length| length > 0 && length <= HTML_GATE_CAP)
    {
        return ResponsePlan::Html;
    }
    ResponsePlan::Stream
}

fn prefer_supported_image_formats(headers: &mut hudsucker::hyper::HeaderMap) {
    let Some(raw) = headers
        .get(hudsucker::hyper::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let filtered = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| {
            let media = entry
                .split(';')
                .next()
                .unwrap_or(entry)
                .trim()
                .to_ascii_lowercase();
            !matches!(
                media.as_str(),
                "image/avif" | "image/heic" | "image/heif" | "image/tiff"
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    if filtered.is_empty() || filtered == raw {
        return;
    }
    if let Ok(value) = hudsucker::hyper::header::HeaderValue::from_str(&filtered) {
        headers.insert(hudsucker::hyper::header::ACCEPT, value);
    }
}

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

const BLOCK_PAGE_HTML: &str = "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>Blocked by PH Bulwark</title></head><body style=\"font-family:sans-serif;\
text-align:center;margin-top:15vh\"><h1>Page blocked</h1>\
<p>This page was blocked by PH Bulwark's content filter.</p>\
<p>If you think this is a mistake, ask your parent or guardian to review it.</p>\
</body></html>";

fn blocked_page_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(
            hudsucker::hyper::header::CONTENT_TYPE,
            "text/html; charset=utf-8",
        )
        .body(Body::from(BLOCK_PAGE_HTML.as_bytes().to_vec()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn gate_policy(media_gated: bool) -> (std::time::Duration, InterceptDecision) {
    if media_gated {
        (DECISION_TIMEOUT, InterceptDecision::Drop)
    } else {
        (HTML_DECISION_TIMEOUT, InterceptDecision::Forward)
    }
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
            blocklist: Arc::new(HostBlocklist::default()),
            gate,
            next_flow_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    #[tokio::test]
    async fn proxy_binds_and_stops() {
        let (tx, _rx) = mpsc::channel(16);
        let proxy = spawn(
            "127.0.0.1:0".parse().unwrap(),
            test_ca(),
            Arc::new(PinningRegistry::new(true)),
            Arc::new(HostBlocklist::default()),
            tx,
        )
        .await
        .unwrap();
        assert!(proxy.listen_addr().port() > 0);
        proxy.stop().await.unwrap();
    }

    #[tokio::test]
    async fn streaming_body_forwards_while_emitting_bounded_capture() {
        let (tx, mut rx) = mpsc::channel(4);
        let handler = test_handler(tx, DecisionGate::default());
        let payload = vec![7u8; STREAM_CAPTURE_TARGET * 2];
        let body = streaming_body(
            Body::from(payload.clone()),
            handler,
            1,
            FlowSource::Web,
            "example.com".into(),
            "POST".into(),
            "/upload".into(),
            false,
            Some("application/octet-stream".into()),
        );
        let forwarded = body.collect().await.unwrap().to_bytes();
        assert_eq!(forwarded.as_ref(), payload.as_slice());
        let flow = rx.recv().await.unwrap();
        assert_eq!(flow.body.len(), STREAM_CAPTURE_TARGET);
        assert_eq!(flow.app_or_host, "example.com");
    }

    #[tokio::test]
    async fn decision_gate_rendezvous_delivers_decision() {
        let gate = DecisionGate::default();
        assert!(!gate.resolve(42, InterceptDecision::Drop).await);
        let rx = gate.register(7).await;
        assert!(gate.resolve(7, InterceptDecision::Drop).await);
        assert!(matches!(rx.await.unwrap(), InterceptDecision::Drop));
    }

    #[test]
    fn media_plan_is_bounded_and_unknown_binary_images_fail_closed() {
        let mut headers = hudsucker::hyper::HeaderMap::new();
        headers.insert(
            hudsucker::hyper::header::CONTENT_LENGTH,
            IMAGE_BODY_CAP.to_string().parse().unwrap(),
        );
        assert_eq!(
            response_plan(Some("image/jpeg"), &headers),
            ResponsePlan::Image
        );
        headers.insert(
            hudsucker::hyper::header::CONTENT_LENGTH,
            (IMAGE_BODY_CAP + 1).to_string().parse().unwrap(),
        );
        assert_eq!(
            response_plan(Some("image/jpeg"), &headers),
            ResponsePlan::BlockMedia
        );
        assert_eq!(
            response_plan(Some("image/avif"), &hudsucker::hyper::HeaderMap::new()),
            ResponsePlan::BlockMedia
        );
    }

    #[test]
    fn common_decodable_image_mime_types_are_scored() {
        for content_type in [
            "image/jpeg",
            "image/png",
            "image/apng",
            "image/webp",
            "image/gif",
            "image/bmp",
        ] {
            assert!(is_scorable_image_ct(content_type));
        }
    }

    #[test]
    fn html_only_buffers_when_bounded_up_front() {
        let mut headers = hudsucker::hyper::HeaderMap::new();
        assert_eq!(
            response_plan(Some("text/html"), &headers),
            ResponsePlan::Stream
        );
        headers.insert(
            hudsucker::hyper::header::CONTENT_LENGTH,
            "1024".parse().unwrap(),
        );
        assert_eq!(
            response_plan(Some("text/html"), &headers),
            ResponsePlan::Html
        );
        headers.insert(
            hudsucker::hyper::header::CONTENT_LENGTH,
            (HTML_GATE_CAP + 1).to_string().parse().unwrap(),
        );
        assert_eq!(
            response_plan(Some("text/html"), &headers),
            ResponsePlan::Stream
        );
        assert_eq!(
            response_plan(
                Some("text/event-stream"),
                &hudsucker::hyper::HeaderMap::new()
            ),
            ResponsePlan::Stream
        );
    }

    #[test]
    fn request_accept_prefers_formats_the_analyzer_can_decode() {
        let mut headers = hudsucker::hyper::HeaderMap::new();
        headers.insert(
            hudsucker::hyper::header::ACCEPT,
            "image/avif,image/webp,image/png,*/*;q=0.8"
                .parse()
                .unwrap(),
        );
        prefer_supported_image_formats(&mut headers);
        let accept = headers
            .get(hudsucker::hyper::header::ACCEPT)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(!accept.contains("image/avif"));
        assert!(accept.contains("image/webp"));
    }

    #[test]
    fn blocklist_matches_authority_and_host_header() {
        let (tx, _rx) = mpsc::channel(4);
        let mut handler = test_handler(tx, DecisionGate::default());
        handler.blocklist = Arc::new(HostBlocklist::parse("adult.example\n.tracker.example"));

        let request = Request::builder()
            .uri("http://adult.example/page")
            .body(Body::empty())
            .unwrap();
        assert!(handler.is_request_blocked(&request));

        let request = Request::builder()
            .uri("http://93.184.216.34/page")
            .header("host", "www.tracker.example:443")
            .body(Body::empty())
            .unwrap();
        assert!(handler.is_request_blocked(&request));
    }

    #[test]
    fn gate_policy_media_fails_closed_html_fails_open() {
        assert!(matches!(
            gate_policy(true).1,
            InterceptDecision::Drop
        ));
        assert!(matches!(
            gate_policy(false).1,
            InterceptDecision::Forward
        ));
    }
}
