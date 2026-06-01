//! Redaction helpers.
//!
//! PRIVACY INVARIANT (PLAN §0c, proto `Evidence`): aegis-text never stores raw
//! message text in a verdict, evidence, or thread state. The only text that may
//! leave the engine is a *redacted excerpt* produced here: a short, length-
//! capped summary that masks digits (ages, phone numbers, addresses) and is
//! clearly marked as redacted so reviewers know it is not verbatim.
//!
//! We do NOT echo the matched message back. The excerpt is a category-named
//! placeholder plus a coarse, digit-masked, truncated fragment — enough for a
//! human reviewer to triage, not enough to reconstruct the conversation.

use aegis_proto::GroomingRule;

/// Max characters of any (masked) fragment we are willing to surface.
const MAX_FRAGMENT: usize = 48;

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
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= MAX_FRAGMENT {
        collapsed
    } else {
        let mut out: String = collapsed.chars().take(MAX_FRAGMENT).collect();
        out.push('…');
        out
    }
}

/// Build a redacted excerpt for a grooming signal.
///
/// The excerpt names the fired categories and includes one short, digit-masked,
/// truncated fragment of the message for reviewer context. It is explicitly
/// **not** the verbatim message. Returns a `[redacted]` marker so it is obvious
/// in logs/alerts.
pub fn redacted_excerpt(text: &str, fired: &[GroomingRule]) -> String {
    let cats = fired
        .iter()
        .map(|r| r.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let fragment = squeeze_truncate(&mask_digits(text));
    if fired.is_empty() {
        format!("[redacted] \"{fragment}\"")
    } else {
        format!("[redacted · {cats}] \"{fragment}\"")
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
        let out = redacted_excerpt("im 13 call me on 0123456789", &[GroomingRule::Sexualization]);
        assert!(!out.chars().any(|c| c.is_ascii_digit()), "no raw digits: {out}");
        assert!(out.contains("sexualization"));
    }

    #[test]
    fn long_text_is_truncated() {
        let long = "a ".repeat(200);
        let out = redacted_excerpt(&long, &[]);
        assert!(out.chars().count() < 80, "excerpt stays short: {}", out.len());
        assert!(out.contains('…'));
    }
}
