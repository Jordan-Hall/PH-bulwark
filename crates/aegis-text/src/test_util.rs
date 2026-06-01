//! Test-only helpers for building `TextSpan`s succinctly.

use aegis_proto::TextSpan;

/// A `TextSpan` for `thread_id` carrying `text`, English, minimal context.
pub fn text_span(thread_id: &str, text: &str) -> TextSpan {
    TextSpan {
        text: text.to_string(),
        lang: "en".to_string(),
        app: "testchat".to_string(),
        thread_id: thread_id.to_string(),
        from_minor: false,
        prior_excerpts: Vec::new(),
    }
}
