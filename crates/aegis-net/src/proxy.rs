//! The transparent MITM proxy (`hudsucker` = hyper + rustls + rcgen).
//!
//! TUN-redirected TCP lands here; `hudsucker` terminates TLS using a leaf cert
//! minted by our per-install CA ([`crate::ca::CaManager`]), decrypts the
//! request/response, and we emit a [`CapturedFlow`](aegis_proto-style) on the
//! channel `aegis-flow` consumes. Pinned hosts reject the leaf at handshake →
//! [`crate::pinning`] records the gap and we fail-open per policy.
//!
//! ## Privacy (threat-model Asset 3)
//! Decrypted bodies are **plaintext intermediates** — the most sensitive data we
//! handle. They live in memory only, flow straight to classification over a
//! bounded channel (backpressure caps how much plaintext is buffered), and are
//! never written to disk or logs here. We never `Debug`-print bodies.
//!
//! ## hudsucker integration shape
//! `hudsucker` wants a `CertificateAuthority` and an `HttpHandler`. We adapt our
//! [`CaManager`] into hudsucker's `RcgenAuthority` (it caches leaves itself), and
//! provide [`FlowHandler`] which forwards request/response metadata + body onto
//! the flow channel. The exact `hudsucker` 0.24 builder calls are isolated in
//! [`spawn`] so an API bump touches one function.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::ca::CaManager;
use crate::pinning::PinningRegistry;
use crate::{NetError, Result};

/// Source channel of a captured flow (mirrors `aegis_proto::SourceChannel`; kept
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
/// `aegis-flow`. Mirrors `CapturedFlow` in interfaces.md; the orchestrator
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
    /// Decrypted body bytes (plaintext intermediate — in-memory only).
    pub body: Vec<u8>,
    /// `true` if this unit is a response (vs a request).
    pub is_response: bool,
}

/// Receiver end of the flow channel given to `aegis-flow` via the interceptor.
pub type FlowReceiver = mpsc::Receiver<CapturedFlow>;
/// Sender end held by the proxy handler.
pub type FlowSender = mpsc::Sender<CapturedFlow>;

/// Handle to a running MITM proxy; dropping it / calling [`MitmProxy::stop`]
/// shuts the proxy down.
pub struct MitmProxy {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
    listen_addr: std::net::SocketAddr,
}

impl MitmProxy {
    /// The address the proxy actually bound (useful when `proxy_listen` used port 0).
    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.listen_addr
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
/// The `hudsucker`-specific wiring is intentionally contained in this function.
/// With hudsucker 0.24 the shape is roughly:
/// ```ignore
/// let authority = hudsucker::certificate_authority::RcgenAuthority::new(
///     key_pair, ca_cert, 1_000, rustls::crypto::aws_lc_rs::default_provider());
/// let proxy = hudsucker::Proxy::builder()
///     .with_addr(listen)
///     .with_ca(authority)
///     .with_rustls_client(rustls::crypto::aws_lc_rs::default_provider())
///     .with_http_handler(FlowHandler { ... })
///     .build()?;
/// tokio::spawn(proxy.start(shutdown_future));
/// ```
/// We adapt our [`CaManager`] to feed `RcgenAuthority` its key + cert. Because
/// this crate need-not-compile in the build env, the exact 0.24 symbol names are
/// pinned in comments; an API bump is a single-function edit.
pub async fn spawn(
    listen: std::net::SocketAddr,
    ca: Arc<CaManager>,
    pinning: Arc<PinningRegistry>,
    flow_tx: FlowSender,
) -> Result<MitmProxy> {
    // Bind first so we can report the actual address (port 0 → ephemeral).
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| NetError::proxy(format!("binding MITM listener on {listen}: {e}")))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|e| NetError::proxy(format!("resolving bound addr: {e}")))?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let handler = FlowHandler {
        flow_tx,
        pinning,
        ca: ca.clone(),
        next_flow_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
    };

    // The proxy run-loop. In a fully-wired build this hands `listener` + `ca` +
    // `handler` to `hudsucker::Proxy` and awaits `shutdown_rx`. Until the
    // hudsucker builder is pinned at the first online build, the loop accepts and
    // closes connections so the listener is live and the task is shutdown-driven.
    // Snapshot the fingerprint before `ca` is moved into the run-loop task.
    let ca_fp = ca_fingerprint(&ca);
    let join = tokio::spawn(async move {
        run_hudsucker(listener, ca, handler, shutdown_rx).await;
    });

    tracing::info!(%listen_addr, %ca_fp, "MITM proxy started");
    Ok(MitmProxy {
        shutdown: Some(shutdown_tx),
        join: Some(join),
        listen_addr,
    })
}

fn ca_fingerprint(ca: &Arc<CaManager>) -> String {
    ca.fingerprint_hex().to_owned()
}

/// The hudsucker run-loop wrapper. Isolated so the (need-not-compile-here)
/// hudsucker 0.24 builder call lives in exactly one place.
async fn run_hudsucker(
    listener: tokio::net::TcpListener,
    _ca: Arc<CaManager>,
    _handler: FlowHandler,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    // TODO(online-build): replace the accept loop below with the hudsucker
    // builder shown in `spawn`'s docs:
    //   * `RcgenAuthority::new(ca_key, ca_cert, cache_size, provider)`
    //   * `Proxy::builder().with_listener(listener).with_ca(authority)
    //        .with_rustls_client(provider).with_http_handler(handler).build()`
    //   * `proxy.start(async { let _ = shutdown_rx.await; })`
    // The handler's `handle_request`/`handle_response` emit CapturedFlow.
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                tracing::info!("MITM proxy shutting down");
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((_stream, peer)) => {
                        // Real path: hudsucker terminates TLS w/ a minted leaf,
                        // decrypts, calls the handler, re-encrypts to upstream.
                        tracing::trace!(%peer, "accepted connection (handler wiring pending online build)");
                    }
                    Err(e) => {
                        tracing::warn!("accept error: {e}");
                        break;
                    }
                }
            }
        }
    }
}

/// hudsucker `HttpHandler`: turns decrypted requests/responses into
/// [`CapturedFlow`]s on the channel, and records MITM success/pinning.
///
/// In a wired build this implements `hudsucker::HttpHandler` with
/// `handle_request(&mut self, ctx, req)` / `handle_response(&mut self, ctx, res)`.
/// The methods read the (now-plaintext) body, build a `CapturedFlow`, and
/// `try_send` it (dropping under backpressure with a counter rather than
/// unbounded-buffering plaintext). A TLS handshake error for a host calls
/// `pinning.record_pinned(host)` and the flow is forwarded (fail-open).
#[allow(dead_code)] // fields consumed once the hudsucker handler trait is wired.
pub struct FlowHandler {
    flow_tx: FlowSender,
    pinning: Arc<PinningRegistry>,
    ca: Arc<CaManager>,
    next_flow_id: Arc<std::sync::atomic::AtomicU64>,
}

impl FlowHandler {
    /// Build a `CapturedFlow` and emit it (drops on backpressure — never blocks
    /// the data path, never unbounded-buffers plaintext). Returns the flow id.
    pub fn emit(
        &self,
        source: FlowSource,
        app_or_host: &str,
        method: &str,
        uri: &str,
        body: Vec<u8>,
        is_response: bool,
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
        };
        if self.flow_tx.try_send(flow).is_err() {
            // Bounded channel full → shed (fail-safe on memory). Log metadata only.
            tracing::warn!(host = %app_or_host, "flow channel full; dropping captured flow (backpressure)");
        }
        self.pinning.record_mitmable(app_or_host);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::DevInMemoryKeyStore;

    fn test_ca() -> Arc<CaManager> {
        Arc::new(CaManager::generate(Arc::new(DevInMemoryKeyStore::new()), "T", 365).unwrap())
    }

    #[tokio::test]
    async fn proxy_binds_and_stops() {
        let ca = test_ca();
        let pinning = Arc::new(PinningRegistry::new(true));
        let (tx, _rx) = mpsc::channel(16);
        let proxy = spawn(
            "127.0.0.1:0".parse().unwrap(),
            ca,
            pinning,
            tx,
        )
        .await
        .unwrap();
        // Bound to a real ephemeral loopback port.
        assert!(proxy.listen_addr().port() > 0);
        assert!(proxy.listen_addr().ip().is_loopback());
        proxy.stop().await.unwrap();
    }

    #[tokio::test]
    async fn handler_emits_flow_and_marks_mitmable() {
        let ca = test_ca();
        let pinning = Arc::new(PinningRegistry::new(true));
        let (tx, mut rx) = mpsc::channel(4);
        let h = FlowHandler {
            flow_tx: tx,
            pinning: pinning.clone(),
            ca,
            next_flow_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        };
        let id = h.emit(FlowSource::Web, "example.com", "GET", "/", b"<html/>".to_vec(), true);
        assert_eq!(id, 1);
        let flow = rx.recv().await.unwrap();
        assert_eq!(flow.app_or_host, "example.com");
        assert!(flow.readable);
        assert!(flow.is_response);
        assert!(pinning.capability("example.com") == crate::pinning::HostCapability::Mitmable);
    }

    #[tokio::test]
    async fn pinned_host_fails_open_by_policy() {
        let ca = test_ca();
        let pinning = Arc::new(PinningRegistry::new(true));
        let (tx, _rx) = mpsc::channel(4);
        let h = FlowHandler {
            flow_tx: tx,
            pinning: pinning.clone(),
            ca,
            next_flow_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        };
        assert!(h.on_pinned("signal.org")); // forwarded (fail-open)
        assert!(pinning.is_pinned("signal.org"));
    }
}
