//! DEV-ONLY visual demo (NOT for production): runs the real `AlertRelay` +
//! `Review` gRPC services on `127.0.0.1:8443` over **plaintext** (no TLS) and
//! injects synthetic, fully-redacted guardian alerts on a loop. Point the Dioxus
//! parent console at it to watch alerts stream in and Approve / Keep-blocked them:
//!
//! ```text
//!   cargo run -p aegis-server --example dev_demo          # this server
//!   # then, in apps/parent (AEGIS_CLUSTER_ENDPOINT=http://127.0.0.1:8443):
//!   cargo run                                             # the parent GUI
//! ```
//!
//! Privacy: every injected alert carries ONLY the no-media fields the invariant
//! permits (a hash, a redacted context line) — never a thumbnail or message body.
//! The CSAM-category sample exists so you can SEE that approving it is refused
//! (CSAM is never allowlistable).

use std::time::Duration;

use aegis_proto::v1::alert_relay_server::AlertRelayServer;
use aegis_proto::v1::review_server::ReviewServer;
use aegis_proto::v1::{AlertEvent, AlertKind, Category, Evidence, Severity};

use aegis_server::relay::{AlertHub, ReviewService};
use aegis_server::service::AlertRelayService;

use tonic::transport::Server;

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Build the `n`-th synthetic alert, rotating through a few realistic templates.
fn demo_alert(n: u64) -> AlertEvent {
    let templates: &[(Category, AlertKind, &str, &str)] = &[
        (
            Category::AdultImage,
            AlertKind::Intervention,
            "example.com",
            "[redacted] adult image blocked on a web page",
        ),
        (
            Category::Grooming,
            AlertKind::GroomingSuspected,
            "messenger",
            "[redacted] secrecy + \u{201c}move to another app\u{201d} patterns in a chat",
        ),
        (
            Category::AdultAudio,
            AlertKind::Intervention,
            "a-video-site",
            "[redacted] adult audio muted in a video",
        ),
        (
            Category::CsamSuspected,
            AlertKind::Intervention,
            "unknown-host",
            "[redacted] suspected illegal content blocked + reported",
        ),
    ];
    let (cat, kind, app, ctx) = templates[(n as usize) % templates.len()];
    AlertEvent {
        alert_id: format!("demo-{n}"),
        kind: kind as i32,
        category: cat as i32,
        severity: Severity::High as i32,
        app: app.to_string(),
        device_id: "kids-tablet".to_string(),
        ts: now_ms(),
        redacted_context: ctx.to_string(),
        evidence: Some(Evidence {
            sha256: vec![(n & 0xff) as u8, 0xde, 0xad, 0xbe, 0xef],
            perceptual_hash: Vec::new(),
            safe_thumbnail: Vec::new(), // NEVER any media
            text_snippet: String::new(),
            model_id: "demo".to_string(),
            model_version: "0".to_string(),
        }),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8443".parse()?;

    // One shared hub backs both services, exactly as an all-in-one node wires it.
    let hub = AlertHub::new();
    let relay = AlertRelayService::new(hub.clone(), None); // no SMTP sink in the demo
    let review = ReviewService::new(hub.clone());

    // Inject a fresh redacted alert every few seconds so the parent always has
    // something live to act on. publish() both fans out to subscribers and records
    // the alert's content-free facts so a later APPROVE/DENY can resolve it.
    let inject_hub = hub.clone();
    tokio::spawn(async move {
        // Small head start so the parent has time to connect & subscribe.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut n: u64 = 1;
        loop {
            let ev = demo_alert(n);
            let reached = inject_hub.publish(ev.clone());
            eprintln!(
                "[demo] published {} (category={}) -> {reached} live guardian stream(s)",
                ev.alert_id, ev.category
            );
            n += 1;
            tokio::time::sleep(Duration::from_secs(4)).await;
        }
    });

    eprintln!("[demo] AlertRelay + Review serving PLAINTEXT on http://{addr}");
    eprintln!("[demo] run the parent with AEGIS_CLUSTER_ENDPOINT=http://127.0.0.1:8443");
    eprintln!("[demo] Ctrl-C to stop.");

    Server::builder()
        .add_service(AlertRelayServer::new(relay))
        .add_service(ReviewServer::new(review))
        .serve(addr)
        .await?;

    Ok(())
}
