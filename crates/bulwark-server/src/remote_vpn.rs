//! In-process, peer-attributed filtering for authenticated Remote VPN traffic.

use std::path::PathBuf;
#[cfg(target_os = "linux")]
use {
    crate::{
        accounts::AccountStore, child_control::ChildConfigStore, relay::AlertHub,
        review_security::ReviewLedger, AnalyzerRegistry,
    },
    bulwark_alert::AlertSink,
    std::sync::Arc,
};

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct RemoteVpnContext {
    pub registry: AnalyzerRegistry,
    pub accounts: AccountStore,
    pub child_config: ChildConfigStore,
    pub hub: AlertHub,
    pub review_ledger: ReviewLedger,
    pub alert_sink: Option<Arc<dyn AlertSink>>,
    pub state_dir: PathBuf,
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

#[cfg(target_os = "linux")]
pub use linux::start;

#[cfg(target_os = "linux")]
#[path = "remote_vpn_linux.rs"]
mod linux;

#[cfg(not(target_os = "linux"))]
pub async fn start(_state_dir: PathBuf) -> anyhow::Result<()> {
    if env_flag("BULWARK_WG_FILTER_ACTIVE") {
        anyhow::bail!("Remote VPN server filtering is supported only on Linux regions");
    }
    Ok(())
}
