//! In-process, peer-attributed filtering for authenticated Remote VPN traffic.

use crate::accounts::AccountStore;
use crate::child_control::ChildConfigStore;
use crate::relay::AlertHub;
use crate::review_security::ReviewLedger;
use crate::AnalyzerRegistry;
use bulwark_alert::AlertSink;
use std::path::PathBuf;
use std::sync::Arc;

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
pub async fn start(_context: RemoteVpnContext) -> anyhow::Result<()> {
    if env_flag("BULWARK_WG_FILTER_ACTIVE") {
        anyhow::bail!("Remote VPN server filtering is supported only on Linux regions");
    }
    Ok(())
}
