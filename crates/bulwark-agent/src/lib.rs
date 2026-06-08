//! bulwark-agent — on-device conventional OCR + accessibility capture.
//!
//! This is the answer for **end-to-end-encrypted / cert-pinned apps** the network
//! can't read (Messenger secret chats, WhatsApp, Signal, iMessage): read the text
//! the app has already decrypted and rendered on screen, then feed it into the
//! same grooming pipeline as network chat.
//!
//! Uses **conventional OCR only — never a vision-LLM** (`Windows.Media.Ocr`,
//! Tesseract, Android ML Kit, macOS Vision) plus the accessibility tree and
//! notification text. Emits `TextSpan`s with `SourceChannel::OCR_ONSCREEN` /
//! `NOTIFICATION`. Implements the `OcrSource` contract (interfaces.md).
//!
//! Capture requires explicit user consent (accessibility grant) — see
//! docs/security/legal-consent.md. `#![forbid(unsafe_code)]` (FFI lives behind
//! the platform features in isolated modules when enabled).
#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use bulwark_core::ids::DeviceId;
use bulwark_core::Result;
use bulwark_proto::v1::{Action, Category, SourceChannel, TextSpan};
use tokio::sync::Mutex;

/// On-device OCR / accessibility source. Conventional OCR → `TextSpan`.
#[async_trait]
pub trait OcrSource: Send + Sync {
    async fn start(&self, device: &DeviceId) -> Result<()>;
    async fn next_text(&self) -> Result<Option<TextSpan>>;
    fn engines(&self) -> &[&'static str];
    async fn shutdown(&self) -> Result<()>;
}

/// Which OCR backend a build uses (best-first; OS-native preferred).
pub fn available_engines() -> &'static [&'static str] {
    // Reflects the enabled features; the platform impls register here.
    &[
        #[cfg(feature = "winocr")]
        "windows.media.ocr",
        #[cfg(feature = "tesseract")]
        "tesseract",
        "stub",
    ]
}

/// Captured screen/notification text awaiting analysis. The platform capture
/// task pushes `TextSpan`s into the queue; `next_text` drains it.
#[derive(Clone, Default)]
pub struct OcrAgent {
    queue: Arc<Mutex<std::collections::VecDeque<TextSpan>>>,
}

impl OcrAgent {
    pub fn new() -> Self {
        Self::default()
    }

    /// Push an OCR'd span (called by the platform capture task / accessibility
    /// callback). `app` and `thread_id` tag it for the grooming state machine.
    pub async fn push(&self, app: &str, thread_id: &str, text: String, channel: SourceChannel) {
        let span = TextSpan {
            text,
            lang: String::new(),
            app: app.to_string(),
            thread_id: thread_id.to_string(),
            from_minor: false,
            prior_excerpts: Vec::new(),
        };
        let _ = channel; // SourceChannel travels on the AnalysisRequest, set by the router
        self.queue.lock().await.push_back(span);
    }
}

#[async_trait]
impl OcrSource for OcrAgent {
    async fn start(&self, device: &DeviceId) -> Result<()> {
        tracing::info!(%device, engines = ?available_engines(),
            "ocr agent started (requires accessibility consent)");
        // Platform capture loop (Windows UIA + Windows.Media.Ocr / Android
        // AccessibilityService + ML Kit) is started here behind the platform
        // features; each pushes spans via `push`. SEAM: wire platform module.
        Ok(())
    }

    async fn next_text(&self) -> Result<Option<TextSpan>> {
        Ok(self.queue.lock().await.pop_front())
    }

    fn engines(&self) -> &[&'static str] {
        available_engines()
    }

    async fn shutdown(&self) -> Result<()> {
        self.queue.lock().await.clear();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// On-device screen guard: classify captured content → ALERT + OVERLAY.
//
// This is how the child app handles E2E / cert-pinned apps (WhatsApp, Signal,
// WebRTC) the network filter can't read: the OS renders the decrypted content,
// the [`OcrAgent`] captures it (accessibility text / OCR'd screenshots), we
// classify it on-device, and on a flag we (a) raise a guardian alert and (b)
// drive an on-screen [`Overlay`] to COVER or WARN over the offending app.
//
// TRANSPARENT + CONSENTED only: the child's device shows Bulwark is active and the
// capture permissions are granted visibly. Safety classification only — no raw
// content is exfiltrated, and suspected CSAM is covered + alerted (redacted) but
// NEVER screenshotted, stored, or sent.
// ---------------------------------------------------------------------------

/// What to render over flagged on-screen content — the "place something over it".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intervention {
    /// Opaque cover that blocks the flagged content from view, with a notice.
    Cover { reason: String },
    /// Non-blocking warning banner (content stays visible).
    Warn { reason: String },
    /// No on-screen surface — raise the guardian alert only.
    AlertOnly,
}

/// A platform surface that can draw an [`Intervention`] over other apps.
///
/// Feasible: **Android** (`SYSTEM_ALERT_WINDOW` + `AccessibilityService`),
/// **Windows / macOS / Linux-X11** (a top-most always-on-top window). **iOS and
/// ChromeOS forbid third-party system overlays** — they use [`StubOverlay`]
/// (alert-only). The real impls live in the platform shells; this trait keeps the
/// guard cross-platform.
#[async_trait]
pub trait Overlay: Send + Sync {
    /// Show the intervention over the current foreground content.
    async fn show(&self, intervention: &Intervention) -> Result<()>;
    /// Remove any active overlay (content approved / no longer on screen).
    async fn clear(&self) -> Result<()>;
    /// Platform/mechanism label (diagnostics + the coverage matrix).
    fn platform(&self) -> &'static str;
}

/// Overlay for platforms that forbid third-party overlays (iOS/ChromeOS) or for
/// headless use: logs the intervention; the guardian alert still fires.
pub struct StubOverlay;

#[async_trait]
impl Overlay for StubOverlay {
    async fn show(&self, intervention: &Intervention) -> Result<()> {
        tracing::info!(
            ?intervention,
            "overlay not available on this platform; alert-only"
        );
        Ok(())
    }
    async fn clear(&self) -> Result<()> {
        Ok(())
    }
    fn platform(&self) -> &'static str {
        "stub (alert-only)"
    }
}

/// Safety verdict for a piece of captured on-screen content.
#[derive(Debug, Clone)]
pub struct ScreenVerdict {
    pub category: Category,
    pub action: Action,
    /// Redacted reason for the alert/overlay — NEVER raw suspected-CSAM content.
    pub redacted: String,
    /// Raise a guardian alert (vs log-only / overlay-only).
    pub raise_alert: bool,
}

/// Classifies captured on-screen content. Injected by the composition root so
/// `bulwark-agent` stays decoupled from the model crates — `bulwark-client` wires
/// `bulwark-text` (OCR'd / accessibility text) and `bulwark-vision` (screenshots).
#[async_trait]
pub trait OnScreenClassifier: Send + Sync {
    /// Classify captured text. `None` = safe / no action.
    async fn classify_text(&self, span: &TextSpan) -> Option<ScreenVerdict>;
    /// Classify a captured screenshot/frame (JPEG/PNG). `None` = safe.
    async fn classify_image(&self, _bytes: &[u8]) -> Option<ScreenVerdict> {
        None
    }
}

/// Sink for an on-screen flag → the guardian relay (redacted; no raw content).
#[async_trait]
pub trait ScreenAlertSink: Send + Sync {
    async fn on_flagged(&self, device_id: &str, app: &str, verdict: &ScreenVerdict);
}

/// The on-device screen guard. Pulls captured content from the [`OcrAgent`],
/// classifies it, and on a flag drives the [`Overlay`] + raises a guardian alert.
pub struct ScreenGuard<C: OnScreenClassifier> {
    device_id: DeviceId,
    ocr: OcrAgent,
    classifier: C,
    overlay: Arc<dyn Overlay>,
    alert: Option<Arc<dyn ScreenAlertSink>>,
}

impl<C: OnScreenClassifier> ScreenGuard<C> {
    pub fn new(
        device_id: DeviceId,
        ocr: OcrAgent,
        classifier: C,
        overlay: Arc<dyn Overlay>,
    ) -> Self {
        Self {
            device_id,
            ocr,
            classifier,
            overlay,
            alert: None,
        }
    }

    /// Attach a guardian alert sink (a flagged item also raises an alert).
    pub fn with_alert(mut self, sink: Arc<dyn ScreenAlertSink>) -> Self {
        self.alert = Some(sink);
        self
    }

    /// Map a verdict to the on-screen intervention. BLOCK/BLUR (incl. CSAM) →
    /// cover; WARN → warn banner; otherwise alert-only.
    fn intervention_for(v: &ScreenVerdict) -> Intervention {
        match v.action {
            Action::Block | Action::Blur => Intervention::Cover {
                reason: v.redacted.clone(),
            },
            Action::Warn => Intervention::Warn {
                reason: v.redacted.clone(),
            },
            _ => Intervention::AlertOnly,
        }
    }

    /// Process one captured text span (if any): classify → cover/warn + alert on a
    /// flag. Returns the verdict it acted on (for the run loop / tests).
    ///
    /// IMPORTANT: when the captured content is no longer flagged (safe verdict, or
    /// nothing to act on), any active cover/banner is CLEARED — otherwise an
    /// overlay shown for earlier content would stay stuck over benign screens. A
    /// scan with no new capture leaves the current overlay untouched.
    pub async fn scan_once(&self) -> Result<Option<ScreenVerdict>> {
        let Some(span) = self.ocr.next_text().await? else {
            // No new capture this tick → don't change the current overlay state.
            return Ok(None);
        };
        let app = span.app.clone();
        let Some(verdict) = self.classifier.classify_text(&span).await else {
            // Captured content classified SAFE → clear any active intervention.
            self.clear_overlay().await;
            return Ok(None);
        };
        match Self::intervention_for(&verdict) {
            // Not flagged for a surface (ALLOW/LOG) → the screen is benign now;
            // clear any cover/banner left from earlier flagged content.
            Intervention::AlertOnly => self.clear_overlay().await,
            action => {
                if let Err(e) = self.overlay.show(&action).await {
                    tracing::warn!(error = %e, "on-screen overlay failed");
                }
            }
        }
        if verdict.raise_alert {
            if let Some(sink) = &self.alert {
                sink.on_flagged(&self.device_id.to_string(), &app, &verdict)
                    .await;
            }
        }
        Ok(Some(verdict))
    }

    /// Remove any active overlay, logging (never failing the scan) on error.
    async fn clear_overlay(&self) {
        if let Err(e) = self.overlay.clear().await {
            tracing::warn!(error = %e, "on-screen overlay clear failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pushed_text_is_drained_in_order() {
        let a = OcrAgent::new();
        a.start(&DeviceId::from("dev1")).await.unwrap();
        a.push(
            "messenger",
            "t1",
            "our little secret".into(),
            SourceChannel::OcrOnscreen,
        )
        .await;
        a.push(
            "messenger",
            "t1",
            "dont tell your parents".into(),
            SourceChannel::Notification,
        )
        .await;
        let first = a.next_text().await.unwrap().unwrap();
        assert_eq!(first.app, "messenger");
        assert_eq!(first.thread_id, "t1");
        assert!(a.next_text().await.unwrap().is_some());
        assert!(a.next_text().await.unwrap().is_none());
    }

    struct AlwaysGrooming;
    #[async_trait]
    impl OnScreenClassifier for AlwaysGrooming {
        async fn classify_text(&self, _s: &TextSpan) -> Option<ScreenVerdict> {
            Some(ScreenVerdict {
                category: Category::Grooming,
                action: Action::Warn,
                redacted: "[redacted] grooming-suspicion".into(),
                raise_alert: true,
            })
        }
    }

    struct RecOverlay {
        shown: Arc<Mutex<Vec<Intervention>>>,
        cleared: Arc<Mutex<u32>>,
    }
    #[async_trait]
    impl Overlay for RecOverlay {
        async fn show(&self, i: &Intervention) -> Result<()> {
            self.shown.lock().await.push(i.clone());
            Ok(())
        }
        async fn clear(&self) -> Result<()> {
            *self.cleared.lock().await += 1;
            Ok(())
        }
        fn platform(&self) -> &'static str {
            "test"
        }
    }

    /// Flags the 1st span (WARN), returns a safe ALLOW verdict for the 2nd, and
    /// `None` (safe, no verdict) for the 3rd — to exercise both safe paths.
    struct FlagThenSafe(Arc<Mutex<u32>>);
    #[async_trait]
    impl OnScreenClassifier for FlagThenSafe {
        async fn classify_text(&self, _s: &TextSpan) -> Option<ScreenVerdict> {
            let mut n = self.0.lock().await;
            *n += 1;
            match *n {
                1 => Some(ScreenVerdict {
                    category: Category::Grooming,
                    action: Action::Warn,
                    redacted: "[redacted] grooming-suspicion".into(),
                    raise_alert: true,
                }),
                2 => Some(ScreenVerdict {
                    category: Category::Safe,
                    action: Action::Allow,
                    redacted: String::new(),
                    raise_alert: false,
                }),
                _ => None,
            }
        }
    }

    struct RecAlert(Arc<Mutex<u32>>);
    #[async_trait]
    impl ScreenAlertSink for RecAlert {
        async fn on_flagged(&self, _device: &str, _app: &str, _v: &ScreenVerdict) {
            *self.0.lock().await += 1;
        }
    }

    #[tokio::test]
    async fn screen_guard_covers_and_alerts_on_flagged_text() {
        let shown = Arc::new(Mutex::new(Vec::new()));
        let alerts = Arc::new(Mutex::new(0u32));
        let ocr = OcrAgent::new();
        ocr.push(
            "whatsapp",
            "t1",
            "send me a pic of you".into(),
            SourceChannel::OcrOnscreen,
        )
        .await;

        let guard = ScreenGuard::new(
            DeviceId::from("kids-phone"),
            ocr,
            AlwaysGrooming,
            Arc::new(RecOverlay {
                shown: shown.clone(),
                cleared: Arc::new(Mutex::new(0)),
            }),
        )
        .with_alert(Arc::new(RecAlert(alerts.clone())));

        let v = guard.scan_once().await.unwrap().expect("flagged span");
        assert_eq!(v.category, Category::Grooming);
        // A WARN verdict → an on-screen overlay is shown AND the guardian alerted.
        {
            let s = shown.lock().await;
            assert_eq!(s.len(), 1);
            assert!(matches!(s[0], Intervention::Warn { .. }));
        }
        assert_eq!(*alerts.lock().await, 1);
        // Queue drained → next scan is a no-op.
        assert!(guard.scan_once().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn safe_scan_clears_a_previously_shown_overlay() {
        let shown = Arc::new(Mutex::new(Vec::new()));
        let cleared = Arc::new(Mutex::new(0u32));
        let ocr = OcrAgent::new();
        for t in [
            "our little secret",
            "what time is football",
            "see you at school",
        ] {
            ocr.push("whatsapp", "t1", t.into(), SourceChannel::OcrOnscreen)
                .await;
        }

        let guard = ScreenGuard::new(
            DeviceId::from("kids-phone"),
            ocr,
            FlagThenSafe(Arc::new(Mutex::new(0))),
            Arc::new(RecOverlay {
                shown: shown.clone(),
                cleared: cleared.clone(),
            }),
        );

        // 1) flagged → overlay shown, nothing cleared yet.
        guard.scan_once().await.unwrap().expect("flagged");
        assert_eq!(shown.lock().await.len(), 1);
        assert_eq!(*cleared.lock().await, 0);

        // 2) safe ALLOW verdict (AlertOnly) → the stuck overlay is cleared.
        guard.scan_once().await.unwrap().expect("safe verdict");
        assert_eq!(*cleared.lock().await, 1);

        // 3) safe with no verdict (None) → also clears.
        assert!(guard.scan_once().await.unwrap().is_none());
        assert_eq!(*cleared.lock().await, 2);

        // No further overlays were shown for the benign content.
        assert_eq!(shown.lock().await.len(), 1);
    }
}
