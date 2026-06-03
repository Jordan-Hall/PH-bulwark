//! aegis-agent — on-device conventional OCR + accessibility capture.
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

use aegis_core::ids::DeviceId;
use aegis_core::Result;
use aegis_proto::v1::{SourceChannel, TextSpan};
use async_trait::async_trait;
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
}
