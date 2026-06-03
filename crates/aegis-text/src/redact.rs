//! Excerpt helpers (guardian-transparency model).
//!
//! GUARDIAN-TRANSPARENCY MODEL: this is a consented parental-control product, so
//! for non-CSAM categories the guardian sees the ACTUAL matched text — a short,
//! length-capped span of the real message — via [`full_excerpt`]. That is what
//! lets a parent understand and (in the parent app) approve/deny what fired.
//!
//! HARD LEGAL EXCEPTION (PLAN §0c): suspected CSAM (an `image_request` →
//! `Category::CsamSuspected`) is NEVER shown verbatim. For that branch the
//! analyzer keeps the *redacted* form below ([`redacted_excerpt`]): a category-
//! named placeholder plus a coarse, digit-masked, truncated fragment — enough to
//! triage, never enough to reconstruct the request. The redaction helpers remain
//! solely for that CSAM path.

use aegis_proto::GroomingRule;

/// Max characters of any (masked) fragment we are willing to surface.
const MAX_FRAGMENT: usize = 48;

/// Max characters of the REAL message text surfaced to the guardian for a
/// non-CSAM hit. Bounded so a huge message can't bloat a verdict/alert/store row,
/// while still showing the parent enough actual context to act on.
const MAX_FULL_EXCERPT: usize = 200;

/// Collapse whitespace and hard-truncate to `max` chars on a char boundary,
/// appending an ellipsis when cut. Shared by the redacted and full excerpts.
fn squeeze_truncate_to(s: &str, max: usize) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max {
        collapsed
    } else {
        let mut out: String = collapsed.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Build the guardian-facing excerpt of the ACTUAL matched text (non-CSAM only).
///
/// Returns the real message span, whitespace-collapsed and bounded to
/// [`MAX_FULL_EXCERPT`] chars. Unlike [`redacted_excerpt`], digits are NOT masked
/// and there is no `[redacted]` marker — the guardian sees what actually fired so
/// they can understand and approve/deny it. MUST NOT be used for the CSAM-
/// suspected branch (use [`redacted_excerpt`] there).
pub fn full_excerpt(text: &str, fired: &[GroomingRule]) -> String {
    let cats = fired
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let fragment = squeeze_truncate_to(text, MAX_FULL_EXCERPT);
    if fired.is_empty() {
        fragment
    } else {
        format!("[{cats}] {fragment}")
    }
}

/// Replace every ASCII digit with `#` so ages, phone numbers, addresses and
/// dollar amounts never appear in evidence.
fn mask_digits(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .collect()
}

/// Collapse whitespace and hard-truncate to `MAX_FRAGMENT` chars on a char
/// boundary, appending an ellipsis when cut.
fn squeeze_truncate(s: &str) -> String {
    squeeze_truncate_to(s, MAX_FRAGMENT)
}

/// Build a redacted excerpt for the CSAM-suspected branch. Used ONLY there
/// (non-CSAM hits use [`full_excerpt`], which shows the real text).
///
/// The suspected-CSAM message is **NEVER surfaced verbatim** — not even
/// digit-masked. We return only a `[redacted]` marker naming the fired
/// categories, so evidence/logs/alerts carry reviewer context (e.g. that an
/// `image_request` fired) without ever reproducing the message content. This is
/// the "CSAM is blocked and never shown or stored" invariant at the text layer.
pub fn redacted_excerpt(text: &str, fired: &[GroomingRule]) -> String {
    // The message text is intentionally NOT included in the output.
    let _ = text;
    let cats = fired
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if fired.is_empty() {
        "[redacted · content withheld]".to_string()
    } else {
        format!("[redacted · {cats} · content withheld]")
    }
}

/// Redacted excerpt for an adult-text verdict (no grooming categories).
pub fn redacted_adult_excerpt(text: &str) -> String {
    let fragment = squeeze_truncate(&mask_digits(text));
    format!("[redacted · adult_text] \"{fragment}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_are_masked() {
        let out = redacted_excerpt(
            "im 13 call me on 0123456789",
            &[GroomingRule::Sexualization],
        );
        assert!(
            !out.chars().any(|c| c.is_ascii_digit()),
            "no raw digits: {out}"
        );
        assert!(out.contains("sexualization"));
    }

    #[test]
    fn redacted_excerpt_withholds_message_text() {
        // CSAM branch: the verbatim message is NEVER reproduced, regardless of
        // length — only the marker + fired categories.
        let long = "secretphrase ".repeat(50);
        let out = redacted_excerpt(&long, &[GroomingRule::Sexualization]);
        assert!(out.starts_with("[redacted"));
        assert!(
            !out.contains("secretphrase"),
            "verbatim text withheld: {out}"
        );
        assert!(out.contains("sexualization"));
        assert!(out.chars().count() < 80, "stays short: {out}");
    }

    #[test]
    fn full_excerpt_shows_real_text_with_digits() {
        // Guardian transparency: the actual matched text, digits intact, no
        // [redacted] marker — just the fired category tag + real span.
        let raw = "im 13 call me on 0123456789";
        let out = full_excerpt(raw, &[GroomingRule::Sexualization]);
        assert!(out.contains("13"), "real digits preserved: {out}");
        assert!(out.contains("0123456789"), "real number preserved: {out}");
        assert!(out.contains("sexualization"));
        assert!(!out.contains("[redacted"), "not redacted: {out}");
    }

    #[test]
    fn full_excerpt_is_bounded() {
        let long = "word ".repeat(200);
        let out = full_excerpt(&long, &[]);
        // Bounded to ~MAX_FULL_EXCERPT chars (+ category tag), and cut-marked.
        assert!(
            out.chars().count() <= MAX_FULL_EXCERPT + 2,
            "bounded: {}",
            out.chars().count()
        );
        assert!(out.contains('…'));
    }
}
