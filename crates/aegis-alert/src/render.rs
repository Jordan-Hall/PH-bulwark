//! Email rendering — the privacy-critical heart of the crate.
//!
//! This module turns an [`AlertEvent`] into a human-readable guardian email.
//! It is the single place where the **hard invariant** from
//! `docs/security/data-handling.md` is enforced in code:
//!
//! > NEVER put explicit media or unredacted content in the email. Only the
//! > `redacted_context` string + SAFE (hash / blurred-thumbnail) evidence.
//!
//! Concretely, the renderer:
//! - emits **only** the safe scalar fields (kind, category, severity, app,
//!   device, timestamp) and the `redacted_context` summary string;
//! - emits, from [`Evidence`], **only** the hashes (hex), the model id/version,
//!   and the redacted text snippet — it **never** writes `safe_thumbnail` bytes
//!   into the body, and it asserts the snippet is non-empty-of-control-bytes;
//! - runs [`assert_no_media`] up front, which rejects the event if any field
//!   smells like raw bytes (NUL/control runs, base64/data-URI blobs, oversized
//!   binary). A rejection is a hard error, not a best-effort scrub.
//!
//! The `safe_thumbnail` is *deliberately not inlined*. Even though the proto
//! guarantees it is blurred/cropped, the email channel renders it only as a
//! note that a safe thumbnail exists in the review UI — keeping raw image bytes
//! out of guardian inboxes entirely.

use aegis_proto::v1::{AlertEvent, AlertKind, Category, Evidence, Severity};

use crate::error::{AlertError, Result};

/// Maximum length we will ever echo for the redacted context / snippet. Longer
/// inputs are truncated; this bounds an accidental transcript dump.
const MAX_CONTEXT_CHARS: usize = 1_000;

/// A redacted text field with more than this fraction of non-printable bytes is
/// treated as binary and rejected (it should be human-readable redacted text).
const MAX_CONTROL_RATIO: f32 = 0.10;

/// A rendered email ready to hand to a transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedEmail {
    pub subject: String,
    /// Plain-text body. (HTML can be layered later; plain text keeps the safety
    /// surface minimal and is trivially auditable in tests.)
    pub body: String,
}

/// Guard the hard invariant: reject anything that looks like raw/explicit media
/// or unredacted binary content before it can be rendered.
///
/// This intentionally errs on the side of rejecting. The contract is that the
/// `redacted_context` and `Evidence.text_snippet` are short, human-readable,
/// already-redacted strings, and that `Evidence` carries only derived
/// artifacts (hashes + an optional SAFE thumbnail). Anything else is a bug
/// upstream and MUST NOT be emailed.
pub fn assert_no_media(event: &AlertEvent) -> Result<()> {
    check_redacted_text("redacted_context", &event.redacted_context)?;

    if let Some(ev) = &event.evidence {
        check_redacted_text("evidence.text_snippet", &ev.text_snippet)?;
        // sha256 / perceptual_hash are derived hashes — fine, but sanity-bound
        // their size so a raw frame can't masquerade as a "hash".
        if ev.sha256.len() > 64 {
            return Err(AlertError::UnsafeContent(format!(
                "evidence.sha256 is {} bytes; a content hash is <= 64 bytes — \
                 refusing to email possible raw media",
                ev.sha256.len()
            )));
        }
        if ev.perceptual_hash.len() > 64 {
            return Err(AlertError::UnsafeContent(format!(
                "evidence.perceptual_hash is {} bytes; refusing to email \
                 possible raw media",
                ev.perceptual_hash.len()
            )));
        }
        // NOTE: we never inspect `safe_thumbnail` *for inclusion* — the renderer
        // never emits its bytes. We do not even look at them here.
    }
    Ok(())
}

/// Verify a field is human-readable redacted text, not smuggled binary/media.
fn check_redacted_text(field: &str, text: &str) -> Result<()> {
    if text.is_empty() {
        return Ok(());
    }
    // Reject obvious embedded-binary markers (data URIs, base64 image blobs).
    let lowered = text.to_ascii_lowercase();
    if lowered.contains("data:image/")
        || lowered.contains("data:video/")
        || lowered.contains("data:audio/")
        || lowered.contains("base64,")
    {
        return Err(AlertError::UnsafeContent(format!(
            "{field} contains an embedded media/data-URI blob"
        )));
    }
    // Reject a NUL byte outright (text never legitimately contains it).
    if text.contains('\u{0}') {
        return Err(AlertError::UnsafeContent(format!(
            "{field} contains a NUL byte (looks like raw bytes)"
        )));
    }
    // Reject a high ratio of control characters (raw bytes rendered as a str).
    let total = text.chars().count().max(1);
    let control = text
        .chars()
        .filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t')
        .count();
    if (control as f32) / (total as f32) > MAX_CONTROL_RATIO {
        return Err(AlertError::UnsafeContent(format!(
            "{field} is mostly non-printable bytes; not redacted text"
        )));
    }
    Ok(())
}

/// Render a single alert event into an email. Runs [`assert_no_media`] first.
pub fn render_event(event: &AlertEvent, subject_prefix: &str) -> Result<RenderedEmail> {
    assert_no_media(event)?;

    let kind = AlertKind::try_from(event.kind).unwrap_or(AlertKind::Unspecified);
    let category = Category::try_from(event.category).unwrap_or(Category::Unspecified);
    let severity = Severity::try_from(event.severity).unwrap_or(Severity::Unspecified);

    let headline = headline_for(kind);
    let subject = format!(
        "{prefix} {headline} — {cat} ({sev})",
        prefix = subject_prefix.trim(),
        cat = category_label(category),
        sev = severity_label(severity),
    );

    let mut body = String::new();
    body.push_str(intro_for(kind));
    body.push_str("\n\n");

    push_field(&mut body, "Alert type", headline);
    push_field(&mut body, "Category", category_label(category));
    push_field(&mut body, "Severity", severity_label(severity));
    push_field(&mut body, "App / site", non_empty(&event.app, "(unknown)"));
    push_field(
        &mut body,
        "Device",
        non_empty(&event.device_id, "(unknown)"),
    );
    push_field(&mut body, "When", &format_ts(event.ts));

    body.push_str("\nWhat we saw (redacted):\n");
    body.push_str("  ");
    body.push_str(&clamp(&event.redacted_context, "(no context provided)"));
    body.push('\n');

    if kind == AlertKind::GroomingSuspected {
        body.push_str(
            "\nThis is a grooming-suspicion alert. The full conversation has \
             NOT been copied here. Review the flagged thread in the Aegis \
             dashboard and decide how you want to handle it.\n",
        );
    }

    render_evidence(&mut body, event.evidence.as_ref());

    body.push_str(
        "\n— Aegis. This message contains redacted summaries only; no images, \
         video, audio, or full message text is included by design.\n",
    );

    Ok(RenderedEmail { subject, body })
}

/// Render a coalesced digest of several events into a single email.
pub fn render_digest(events: &[AlertEvent], subject_prefix: &str) -> Result<RenderedEmail> {
    for e in events {
        assert_no_media(e)?;
    }

    let subject = format!(
        "{prefix} Activity digest — {n} alert(s)",
        prefix = subject_prefix.trim(),
        n = events.len(),
    );

    let mut body = String::new();
    body.push_str(
        "Several Aegis alerts were grouped to avoid flooding your inbox. \
         Summaries only — no media or full message text is included.\n\n",
    );

    for (i, event) in events.iter().enumerate() {
        let kind = AlertKind::try_from(event.kind).unwrap_or(AlertKind::Unspecified);
        let category = Category::try_from(event.category).unwrap_or(Category::Unspecified);
        let severity = Severity::try_from(event.severity).unwrap_or(Severity::Unspecified);

        body.push_str(&format!(
            "{}. {} — {} [{}] on {} via {} @ {}\n",
            i + 1,
            headline_for(kind),
            category_label(category),
            severity_label(severity),
            non_empty(&event.device_id, "(unknown device)"),
            non_empty(&event.app, "(unknown app)"),
            format_ts(event.ts),
        ));
        body.push_str("   ");
        body.push_str(&clamp(&event.redacted_context, "(no context)"));
        body.push('\n');
        if let Some(ev) = &event.evidence {
            if !ev.sha256.is_empty() {
                body.push_str(&format!("   evidence sha256: {}\n", hex(&ev.sha256)));
            }
        }
        body.push('\n');
    }

    body.push_str(
        "Open the Aegis dashboard for the full (still redacted) detail and any \
         safe thumbnails.\n",
    );

    Ok(RenderedEmail { subject, body })
}

fn render_evidence(body: &mut String, evidence: Option<&Evidence>) {
    let Some(ev) = evidence else {
        return;
    };
    let has_any = !ev.sha256.is_empty()
        || !ev.perceptual_hash.is_empty()
        || !ev.safe_thumbnail.is_empty()
        || !ev.text_snippet.is_empty()
        || !ev.model_id.is_empty();
    if !has_any {
        return;
    }

    body.push_str("\nSafe evidence (derived artifacts only):\n");
    if !ev.text_snippet.is_empty() {
        body.push_str("  Redacted excerpt: ");
        body.push_str(&clamp(&ev.text_snippet, ""));
        body.push('\n');
    }
    if !ev.sha256.is_empty() {
        body.push_str(&format!("  Content hash (sha256): {}\n", hex(&ev.sha256)));
    }
    if !ev.perceptual_hash.is_empty() {
        body.push_str(&format!("  Perceptual hash: {}\n", hex(&ev.perceptual_hash)));
    }
    if !ev.safe_thumbnail.is_empty() {
        // We intentionally do NOT inline the bytes — only note availability.
        body.push_str(
            "  A safe (blurred/cropped) thumbnail is available in the Aegis \
             dashboard. It is not attached to this email.\n",
        );
    }
    if !ev.model_id.is_empty() {
        let ver = if ev.model_version.is_empty() {
            String::new()
        } else {
            format!(" v{}", ev.model_version)
        };
        body.push_str(&format!("  Detected by: {}{}\n", ev.model_id, ver));
    }
}

fn headline_for(kind: AlertKind) -> &'static str {
    match kind {
        AlertKind::Intervention => "Aegis blocked something",
        AlertKind::GroomingSuspected => "Possible grooming detected",
        AlertKind::Unspecified => "Aegis alert",
    }
}

fn intro_for(kind: AlertKind) -> &'static str {
    match kind {
        AlertKind::Intervention => {
            "Aegis stepped in and acted on content on a supervised device \
             (blocked, blurred, or muted it). Here is a redacted summary of \
             what happened."
        }
        AlertKind::GroomingSuspected => {
            "Aegis detected conversation patterns that may indicate grooming \
             on a supervised device. Please review this carefully."
        }
        AlertKind::Unspecified => "Aegis raised an alert on a supervised device.",
    }
}

fn category_label(c: Category) -> &'static str {
    match c {
        Category::Unspecified => "Unspecified",
        Category::Safe => "Safe",
        Category::AdultImage => "Adult image",
        Category::AdultAudio => "Adult audio",
        Category::AdultText => "Adult text",
        Category::Grooming => "Grooming",
        Category::CsamSuspected => "Suspected CSAM",
        Category::Violence => "Violence",
        Category::SelfHarm => "Self-harm",
        Category::Hate => "Hate",
    }
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Unspecified => "Unspecified",
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

fn push_field(body: &mut String, label: &str, value: &str) {
    body.push_str(label);
    body.push_str(": ");
    body.push_str(value);
    body.push('\n');
}

fn non_empty<'a>(s: &'a str, fallback: &'a str) -> &'a str {
    if s.trim().is_empty() {
        fallback
    } else {
        s
    }
}

/// Clamp redacted text to a bounded length so we never dump a full transcript,
/// and substitute a fallback when empty.
fn clamp(s: &str, empty_fallback: &str) -> String {
    if s.trim().is_empty() {
        return empty_fallback.to_string();
    }
    if s.chars().count() <= MAX_CONTEXT_CHARS {
        return s.to_string();
    }
    let truncated: String = s.chars().take(MAX_CONTEXT_CHARS).collect();
    format!("{truncated}… (truncated)")
}

/// Format a unix-epoch-millis timestamp without pulling in a date crate.
/// Renders as ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
fn format_ts(ts_millis: i64) -> String {
    if ts_millis <= 0 {
        return "(unknown time)".to_string();
    }
    let secs = ts_millis / 1000;
    let (year, month, day, hour, min, sec) = civil_from_unix(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert unix seconds (UTC) to civil date/time. Algorithm from Howard
/// Hinnant's `civil_from_days` (public domain), avoiding a date dependency.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3600) as u32;
    let min = ((rem % 3600) / 60) as u32;
    let sec = (rem % 60) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

/// Lowercase hex encoding for hash bytes (no external dep).
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
