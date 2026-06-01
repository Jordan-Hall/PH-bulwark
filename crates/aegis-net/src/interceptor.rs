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

/// Protocol metadata + bytes for a captured flow (interfaces.md `FlowPayload`).
#[derive(Clone, Debug)]
pub struct FlowPayload {
    /// HTTP method for a request, empty for a response.
    pub method: String,
    /// Request URI / path.
    pub uri: String,
    /// Decrypted body bytes (plaintext intermediate — in-memory only).
    pub bytes: Vec<u8>,
    /// True if this unit is a response.
    pub is_response: bool,
}

/// A captured, MITM-decrypted (or marked-unreadable) network unit handed up to
/// the flow layer. Carries no verdict yet. (interfaces.md `CapturedFlow`.)
#[derive(Clone, Debug)]
pub struct CapturedFlow {
    /// Per-session flow id.
    pub flow_id: u64,
    /// WEB / VIDEO_STREAM / LIVE_STREAM (reuses the proto enum).
    pub source_channel: SourceChannel,
    /// Host / app the flow is for.
    pub app_or_host: String,
    /// `false` = pinned/E2E → route to OcrSource.
    pub readable: bool,
    /// Bytes + protocol metadata.
    pub payload: FlowPayload,
}

/// A policy decision applied back onto a live flow (interfaces.md
/// `InterceptDecision`).
#[derive(Clone, Debug)]
pub enum InterceptDecision {
    /// Pass through unchanged.
    Forward,
    /// Replace payload (blur image / interstitial).
    Rewrite(Vec<u8>),
    /// Block / drop the flow.
    Drop,
}

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
        CapturedFlow {
            flow_id: flow.flow_id,
            source_channel: Self::map_source(flow.source),
            app_or_host: flow.app_or_host,
            readable: flow.readable,
            payload: FlowPayload {
                method: flow.method,
                uri: flow.uri,
                bytes: flow.body,
                is_response: flow.is_response,
            },
        }
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
        tracing::info!(
            ca_fp = %self.ca.fingerprint_hex(),
            tier = ?self.ca.tier(),
            listen = %proxy.listen_addr(),
            "interceptor started"
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
        // The proxy holds live flows; in the wired build `apply` signals the
        // hudsucker handler (keyed by flow_id) to forward/rewrite/drop the
        // in-flight response. Here we log the decision and accept it; the actual
        // response mutation is wired with the hudsucker handler (online build).
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
        // TODO(online-build): route `decision` to the per-flow_id response sink
        // in the hudsucker handler. Documented; no-op-with-log until then.
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
        };
        let cf = NetInterceptor::convert(pf);
        assert_eq!(cf.flow_id, 7);
        assert_eq!(cf.source_channel, SourceChannel::VideoStream);
        assert!(cf.readable);
        assert_eq!(cf.payload.uri, "/seg1.ts");
        assert!(cf.payload.is_response);
        assert_eq!(cf.payload.bytes, b"abc");
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
