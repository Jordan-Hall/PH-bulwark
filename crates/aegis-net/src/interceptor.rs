//! The [`Interceptor`] trait (interfaces.md) and the concrete [`NetInterceptor`].
//!
//! This is the public face of `aegis-net`. It wires together the TUN device, the
//! per-install CA, the MITM proxy, QUIC downgrade, and pinning detection, and
//! surfaces decrypted flows to `aegis-flow` over a channel.
//!
//! The trait signatures mirror `docs/design/interfaces.md` verbatim (names,
//! args, ownership), returning the shared [`aegis_core::Result`]. The supporting
//! types `CapturedFlow` / `InterceptDecision` / `FlowPayload` are defined here
//! because they are not in `aegis-proto` (proto has the `SourceChannel` enum,
//! which we reuse); they are the in-process boundary types interfaces.md sketches.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use aegis_core::Result as CoreResult;
use aegis_proto::SourceChannel;

use crate::ca::{select_keystore, CaManager, KeyStoreTier};
use crate::config::NetConfig;
use crate::pinning::PinningRegistry;
use crate::proxy::{self, CapturedFlow as ProxyFlow, FlowReceiver, MitmProxy};
use crate::quic::QuicDowngrade;
use crate::tun::{open_tun, TunConfig, TunDevice};
use crate::{truststore, NetError};

// The captured-flow vocabulary is now CANONICAL in `aegis-core::flow` so this
// crate and `aegis-flow` share ONE definition (no drift). Re-exported here so the
// crate's public API (`aegis_net::CapturedFlow`, …) is unchanged for callers.
pub use aegis_core::flow::{CapturedFlow, FlowPayload, HttpHead, InterceptDecision};

/// Captures and (where possible) decrypts device traffic, surfacing inspectable
/// units. Owns the per-install CA, QUIC-downgrade, and pinning detection.
/// (interfaces.md `Interceptor`.)
#[async_trait]
pub trait Interceptor: Send + Sync {
    /// Bring the TUN/VpnService + MITM proxy up; install/load the per-install CA.
    async fn start(&self) -> CoreResult<()>;

    /// Stream of decrypted (or pinning-flagged) flows for classification.
    async fn next_flow(&self) -> CoreResult<Option<CapturedFlow>>;

    /// Apply a policy decision back onto a live flow (forward/rewrite/drop).
    async fn apply(&self, flow_id: u64, decision: InterceptDecision) -> CoreResult<()>;

    /// True if a flow was rejected by cert pinning (→ OCR fallback path).
    fn is_pinned(&self, app_or_host: &str) -> bool;

    /// Graceful teardown (MUST restore routing/nftables; see platform feasibility §2).
    async fn shutdown(&self) -> CoreResult<()>;
}

/// Concrete `aegis-net` interceptor. Construct with [`NetInterceptor::new`]
/// (production keystore) or [`NetInterceptor::with_keystore`] (tests/dev).
pub struct NetInterceptor {
    config: NetConfig,
    ca: Arc<CaManager>,
    pinning: Arc<PinningRegistry>,
    quic: QuicDowngrade,
    /// TUN device (real on Windows; stub elsewhere). Created lazily in `start`
    /// (opening it can require the driver/admin), so construction stays cheap and
    /// testable. Behind a Mutex because the trait methods take `&self`.
    tun: Mutex<Option<Box<dyn TunDevice>>>,
    /// The running MITM proxy handle (None until `start`).
    proxy: Mutex<Option<MitmProxy>>,
    /// Receiver end of the flow channel; `next_flow` drains it.
    flow_rx: Mutex<FlowReceiver>,
    /// Sender retained so `start` can hand it to the proxy.
    flow_tx: Mutex<Option<proxy::FlowSender>>,
    /// Whether `shutdown` should remove our root from the trust store. For a
    /// long-lived install we keep the root across restarts; uninstall flips this
    /// via [`NetInterceptor::set_remove_root_on_shutdown`].
    remove_root_on_shutdown: std::sync::atomic::AtomicBool,
    /// Last flow id handed up (observability; used by `apply` for tracing scope).
    last_seen_flow: AtomicU64,
}

impl NetInterceptor {
    /// Production constructor: selects the platform keystore (DPAPI on Windows),
    /// loads-or-generates the per-install CA, and prepares (but does not start)
    /// the TUN + proxy. **Fail-closed** if the keystore can't provide a CA key.
    pub fn new(config: NetConfig) -> crate::Result<Self> {
        config.validate()?;
        let keystore = select_keystore(config.ca_store_dir.clone())?;
        let ca = CaManager::load_or_generate(
            keystore,
            &config.ca_common_name,
            config.ca_validity_days,
        )?;
        Self::assemble(config, ca)
    }

    /// Test/dev constructor allowing a caller-supplied keystore (e.g. the
    /// in-memory dev store). Not for production — the in-memory store provides no
    /// at-rest protection (see [`KeyStoreTier::InMemoryInsecure`]).
    pub fn with_keystore(
        config: NetConfig,
        keystore: Arc<dyn crate::ca::CaKeyStore>,
    ) -> crate::Result<Self> {
        config.validate()?;
        let ca = CaManager::load_or_generate(
            keystore,
            &config.ca_common_name,
            config.ca_validity_days,
        )?;
        Self::assemble(config, ca)
    }

    fn assemble(config: NetConfig, ca: CaManager) -> crate::Result<Self> {
        let pinning = Arc::new(PinningRegistry::new(config.pinning_fail_open));
        let quic = QuicDowngrade::new(config.quic_downgrade, config.quic_allowlist.clone());
        let (tx, rx) = tokio::sync::mpsc::channel(config.flow_channel_capacity);
        Ok(NetInterceptor {
            config,
            ca: Arc::new(ca),
            pinning,
            quic,
            tun: Mutex::new(None), // opened lazily in `start`
            proxy: Mutex::new(None),
            flow_rx: Mutex::new(rx),
            flow_tx: Mutex::new(Some(tx)),
            remove_root_on_shutdown: std::sync::atomic::AtomicBool::new(false),
            last_seen_flow: AtomicU64::new(0),
        })
    }

    /// Mark whether [`Interceptor::shutdown`] should also remove our root from
    /// the OS trust store. Set this for an UNINSTALL (orphaned-root release
    /// blocker, threat-model Asset 1); leave false for a normal stop/restart so
    /// the next start does not re-prompt.
    pub fn set_remove_root_on_shutdown(&self, remove: bool) {
        self.remove_root_on_shutdown
            .store(remove, Ordering::Relaxed);
    }

    /// SHA-256 fingerprint of the per-install root CA (audit / UI).
    pub fn ca_fingerprint(&self) -> &str {
        self.ca.fingerprint_hex()
    }

    /// The per-install root CA certificate in PEM, so a host tool can write it to
    /// disk and the user can trust it (e.g. the runnable proxy prints its path).
    /// Public cert only — never the private key.
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.cert_pem()
    }

    /// Keystore protection tier in effect (audit / UI honesty).
    pub fn keystore_tier(&self) -> KeyStoreTier {
        self.ca.tier()
    }

    /// Install the per-install root into the current-user Trusted Root store.
    /// Called once at setup; idempotent. Logs the fingerprint (audit event).
    pub fn install_ca(&self) -> crate::Result<()> {
        truststore::install_root(self.ca.cert_der(), truststore::StoreScope::CurrentUser)
    }

    /// Uninstall path: remove our root from the trust store. MUST be called on
    /// uninstall (orphaned-root release-blocker, threat-model Asset 1).
    pub fn uninstall_ca(&self) -> crate::Result<()> {
        truststore::uninstall_root(self.ca.cert_der(), truststore::StoreScope::CurrentUser)
    }

    /// Map our proxy-local flow source onto the proto `SourceChannel`.
    fn map_source(src: proxy::FlowSource) -> SourceChannel {
        match src {
            proxy::FlowSource::Web => SourceChannel::Web,
            proxy::FlowSource::VideoStream => SourceChannel::VideoStream,
            proxy::FlowSource::LiveStream => SourceChannel::LiveStream,
        }
    }

    fn convert(flow: ProxyFlow) -> CapturedFlow {
        // Map net's flat request/response onto the canonical `FlowPayload::Http`
        // head. The proxy now surfaces the response Content-Type, so we populate
        // the `content-type` header and aegis-flow's content-type fast-path
        // engages (instead of relying solely on magic-byte sniffing).
        let mut headers = Vec::new();
        if let Some(ct) = &flow.content_type {
            headers.push(aegis_core::flow::Header {
                name: "content-type".to_owned(),
                value: ct.clone(),
            });
        }

        // When the proxy captured a WHOLE still-image body for NSFW scoring, that
        // becomes the classifier's body so the (image) magic bytes AND the full
        // pixels reach the analyzer. Otherwise we carry the bounded peek as before.
        let body = match flow.image_body {
            Some(img) => bytes::Bytes::from(img),
            None => bytes::Bytes::from(flow.body),
        };

        CapturedFlow {
            flow_id: flow.flow_id,
            source_channel: Self::map_source(flow.source),
            app_or_host: flow.app_or_host,
            readable: flow.readable,
            payload: FlowPayload::Http(HttpHead {
                method: (!flow.method.is_empty()).then_some(flow.method),
                path: (!flow.uri.is_empty()).then_some(flow.uri),
                status: None,
                headers,
                body_peek: body,
            }),
        }
    }
}

impl NetInterceptor {
    /// Start ONLY the MITM proxy (install CA + spawn hudsucker), skipping the TUN
    /// device and the QUIC firewall rule. This is the **explicit-proxy** path: the
    /// user points their browser's HTTP/HTTPS proxy at `proxy_listen` directly, so
    /// no transparent TUN redirect (which needs admin / the wintun driver) is
    /// required. Decision-gating is armed exactly as in [`Interceptor::start`].
    pub async fn start_proxy_only(&self) -> crate::Result<()> {
        // Best-effort CA trust: installing a root into the user store requires the
        // user's consent (a Windows dialog), and the proxy can serve even if that is
        // declined or deferred — the browser simply won't accept the MITM leaf certs
        // until the printed root CA is trusted. So a trust-store failure here is a
        // WARNING, not fatal: the proxy still comes up, and the user can trust the CA
        // (the entrypoint prints the exact `certutil` command) and then browse.
        if let Err(e) = self.install_ca() {
            tracing::warn!(
                error = %e,
                "could not auto-trust the root CA (needs your consent / may have been declined); \
                 the proxy is still serving — trust the printed CA cert to enable HTTPS interception"
            );
        }
        self.spawn_proxy().await
    }

    /// Spawn the MITM proxy listener + arm decision-gating. Shared by
    /// [`Interceptor::start`] and [`NetInterceptor::start_proxy_only`].
    async fn spawn_proxy(&self) -> crate::Result<()> {
        let listen: std::net::SocketAddr = self
            .config
            .proxy_listen
            .parse()
            .map_err(|e| NetError::proxy(format!("bad proxy_listen: {e}")))?;

        let tx = self
            .flow_tx
            .lock()
            .await
            .take()
            .ok_or_else(|| NetError::proxy("proxy already started"))?;

        let proxy = proxy::spawn(listen, self.ca.clone(), self.pinning.clone(), tx).await?;
        proxy.set_gating(true);
        tracing::info!(
            ca_fp = %self.ca.fingerprint_hex(),
            tier = ?self.ca.tier(),
            listen = %proxy.listen_addr(),
            "MITM proxy started (decision-gating armed)"
        );
        *self.proxy.lock().await = Some(proxy);
        Ok(())
    }
}

#[async_trait]
impl Interceptor for NetInterceptor {
    async fn start(&self) -> CoreResult<()> {
        // 1. Open + bring the TUN device up (lazily — opening may need the driver).
        {
            let mut slot = self.tun.lock().await;
            let mut tun = open_tun().map_err(aegis_core::Error::from)?;
            let tun_cfg = TunConfig::default();
            tun.up(&tun_cfg).map_err(aegis_core::Error::from)?;
            tracing::info!(backend = tun.backend(), "TUN up");
            *slot = Some(tun);
        }

        // 2. Apply the QUIC downgrade firewall rule (block UDP/443 → TCP).
        self.quic.apply_rule().map_err(aegis_core::Error::from)?;

        // 3. Install / confirm the per-install root CA in the trust store, then
        //    start the MITM proxy. CA was already loaded/generated in `new`
        //    (fail-closed there); installing the public root is safe to repeat.
        self.install_ca().map_err(aegis_core::Error::from)?;

        let listen: std::net::SocketAddr = self
            .config
            .proxy_listen
            .parse()
            .map_err(|e| aegis_core::Error::Config(format!("bad proxy_listen: {e}")))?;

        let tx = self
            .flow_tx
            .lock()
            .await
            .take()
            .ok_or_else(|| aegis_core::Error::from(NetError::proxy("proxy already started")))?;

        let proxy = proxy::spawn(listen, self.ca.clone(), self.pinning.clone(), tx)
            .await
            .map_err(aegis_core::Error::from)?;
        // Arm inline decision-gating: the orchestrator now wires `apply` (below)
        // to the proxy's per-flow decision sink, so the response handler awaits a
        // Forward/Drop/Rewrite for each emitted flow (bounded, fail-OPEN on
        // timeout). This is what makes a BLOCK actually drop the live response.
        proxy.set_gating(true);
        tracing::info!(
            ca_fp = %self.ca.fingerprint_hex(),
            tier = ?self.ca.tier(),
            listen = %proxy.listen_addr(),
            "interceptor started (decision-gating armed)"
        );
        *self.proxy.lock().await = Some(proxy);
        Ok(())
    }

    async fn next_flow(&self) -> CoreResult<Option<CapturedFlow>> {
        let mut rx = self.flow_rx.lock().await;
        match rx.recv().await {
            Some(flow) => {
                self.last_seen_flow.store(flow.flow_id, Ordering::Relaxed);
                Ok(Some(Self::convert(flow)))
            }
            None => Ok(None), // channel closed → no more flows
        }
    }

    async fn apply(&self, flow_id: u64, decision: InterceptDecision) -> CoreResult<()> {
        // The proxy holds live flows; with gating armed (see `start`), `apply`
        // signals the hudsucker response handler (keyed by flow_id) to
        // forward/rewrite/drop the in-flight response.
        match &decision {
            InterceptDecision::Forward => {
                tracing::trace!(flow_id, "decision: forward");
            }
            InterceptDecision::Rewrite(bytes) => {
                tracing::debug!(flow_id, len = bytes.len(), "decision: rewrite payload");
            }
            InterceptDecision::Drop => {
                tracing::debug!(flow_id, "decision: drop/block");
            }
        }
        // Route the decision to the per-flow_id response sink in the running
        // proxy. If the proxy isn't up yet (or the flow already forwarded/timed
        // out), this resolves to `false` — a no-op, never an error.
        if let Some(proxy) = self.proxy.lock().await.as_ref() {
            let _ = proxy.apply(flow_id, decision).await.map_err(aegis_core::Error::from)?;
        }
        Ok(())
    }

    fn is_pinned(&self, app_or_host: &str) -> bool {
        self.pinning.is_pinned(app_or_host)
    }

    async fn shutdown(&self) -> CoreResult<()> {
        // 1. Stop the MITM proxy.
        if let Some(proxy) = self.proxy.lock().await.take() {
            proxy.stop().await.map_err(aegis_core::Error::from)?;
        }
        // 2. Remove the QUIC downgrade rule (don't leave UDP/443 blocked).
        self.quic.remove_rule().map_err(aegis_core::Error::from)?;
        // 3. Tear down the TUN device — MUST restore host routing (no blackhole).
        {
            let mut tun = self.tun.lock().await;
            if let Some(dev) = tun.as_mut() {
                dev.close().map_err(aegis_core::Error::from)?;
            }
            *tun = None;
        }
        // 4. Trust-store hygiene: on a true uninstall, remove the root (orphaned
        //    root = latent MITM backdoor). On a normal stop we keep it so the
        //    next start doesn't re-prompt; uninstall sets `remove_root_on_shutdown`.
        if self.remove_root_on_shutdown.load(Ordering::Relaxed) {
            self.uninstall_ca().map_err(aegis_core::Error::from)?;
        }
        tracing::info!("interceptor shut down; routing restored");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::DevInMemoryKeyStore;

    fn dev_interceptor() -> NetInterceptor {
        // Use a loopback proxy port and the in-memory dev keystore (tests only).
        let cfg = NetConfig {
            proxy_listen: "127.0.0.1:0".to_owned(),
            ..NetConfig::default()
        };
        NetInterceptor::with_keystore(cfg, Arc::new(DevInMemoryKeyStore::new()))
            .expect("dev interceptor builds")
    }

    #[test]
    fn builds_with_dev_keystore_and_generates_unique_ca() {
        let i = dev_interceptor();
        assert_eq!(i.ca_fingerprint().len(), 64);
        assert_eq!(i.keystore_tier(), KeyStoreTier::InMemoryInsecure);
    }

    #[test]
    fn is_pinned_reflects_registry() {
        let i = dev_interceptor();
        assert!(!i.is_pinned("example.com"));
        i.pinning.record_pinned("signal.org");
        assert!(i.is_pinned("signal.org"));
    }

    #[test]
    fn proxy_flow_converts_to_captured_flow_with_proto_source() {
        let pf = ProxyFlow {
            flow_id: 7,
            source: proxy::FlowSource::VideoStream,
            app_or_host: "video.example".to_owned(),
            readable: true,
            method: "GET".to_owned(),
            uri: "/seg1.ts".to_owned(),
            body: b"abc".to_vec(),
            is_response: true,
            content_type: Some("video/mp2t".to_owned()),
            image_body: None,
        };
        let cf = NetInterceptor::convert(pf);
        assert_eq!(cf.flow_id, 7);
        assert_eq!(cf.source_channel, SourceChannel::VideoStream);
        assert!(cf.readable);
        match cf.payload {
            FlowPayload::Http(h) => {
                assert_eq!(h.path.as_deref(), Some("/seg1.ts"));
                assert_eq!(h.body_peek.as_ref(), b"abc");
                assert_eq!(h.content_type().as_deref(), Some("video/mp2t"));
            }
            _ => panic!("expected Http payload"),
        }
    }

    #[test]
    fn convert_surfaces_full_image_body_and_content_type() {
        // An image response: the WHOLE image body (not just a peek) becomes the
        // classifier's body, and the content-type header is populated so the
        // content-type fast-path classifies it as IMAGE.
        let jpeg = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 9, 9, 9, 9];
        let pf = ProxyFlow {
            flow_id: 12,
            source: proxy::FlowSource::Web,
            app_or_host: String::new(),
            readable: true,
            method: String::new(),
            uri: "status:200".to_owned(),
            body: vec![0xFF, 0xD8, 0xFF], // peek only
            is_response: true,
            content_type: Some("image/jpeg".to_owned()),
            image_body: Some(jpeg.clone()),
        };
        let cf = NetInterceptor::convert(pf);
        match cf.payload {
            FlowPayload::Http(h) => {
                assert_eq!(h.content_type().as_deref(), Some("image/jpeg"));
                assert_eq!(h.body_peek.as_ref(), jpeg.as_slice(), "full image surfaced");
            }
            _ => panic!("expected Http payload"),
        }
    }

    #[tokio::test]
    async fn next_flow_yields_then_ends_when_channel_closes() {
        let i = dev_interceptor();
        // Grab the retained sender, push a flow, then drop it to close the channel.
        let tx = i.flow_tx.lock().await.take().expect("sender present");
        tx.send(ProxyFlow {
            flow_id: 1,
            source: proxy::FlowSource::Web,
            app_or_host: "example.com".to_owned(),
            readable: true,
            method: "GET".to_owned(),
            uri: "/".to_owned(),
            body: Vec::new(),
            is_response: false,
            content_type: None,
            image_body: None,
        })
        .await
        .unwrap();
        drop(tx);

        let first = i.next_flow().await.unwrap();
        assert!(first.is_some());
        assert_eq!(first.unwrap().app_or_host, "example.com");
        // Channel now closed → None.
        let end = i.next_flow().await.unwrap();
        assert!(end.is_none());
    }
}
