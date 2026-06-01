//! The `Analyzer` implementation for text (interfaces.md §`Analyzer`).
//!
//! Pipeline for one `TextSpan`:
//!   1. Resolve the language lexicon (BCP-47 hint → English fallback).
//!   2. Load prior [`ThreadState`] for `thread_id` (cross-message memory).
//!   3. Run the deterministic [`GroomingRuleEngine`] — the PRIMARY detector.
//!   4. Optionally let the backstop [`TextClassifier`] *confirm* (sets
//!      `classifier_backed`); it never changes the category/score/action.
//!   5. Run adult-text detection (independent of grooming state).
//!   6. Record the fired categories back into thread state.
//!   7. Emit an explainable [`Verdict`] with a populated [`GroomingSignal`] and
//!      a redacted excerpt (never raw message text).
//!
//! Thread state lives in an in-process map here for the local first-pass; the
//! server wires the same `ThreadState` through `aegis-store`
//! (`thread_state`/`put_thread_state`) so memory survives restarts. State and
//! evidence carry category names + redacted excerpts only — no message text, no
//! telemetry.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use futures_core::stream::BoxStream;
use futures_util::StreamExt;

use aegis_proto::{
    Action, AnalysisRequest, Category, Evidence, GroomingSignal, MediaKind, Severity, TextSpan,
    Verdict,
};

use crate::classifier::{NoClassifier, TextClassifier};
use crate::engine::{GroomingRuleEngine, RuleOutcome};
use crate::error::TextError;
use crate::lexicon::Lexicon;
use crate::redact::{redacted_adult_excerpt, redacted_excerpt};
use crate::state::ThreadState;
use crate::traits::{Analyzer, GroomingRules};

/// Stable model id reported in `Evidence.model_id` for the deterministic engine.
const RULE_ENGINE_ID: &str = "aegis-grooming-rules";
const RULE_ENGINE_VERSION: &str = "1";

/// The text analyzer: deterministic rules FIRST, optional classifier SECOND.
///
/// Generic over the [`TextClassifier`] backstop so the `classifier` feature can
/// swap in an `ort` model without touching this type; the default is
/// [`NoClassifier`] (no model, hot path is pure rules).
pub struct TextAnalyzer<C: TextClassifier = NoClassifier> {
    engine: GroomingRuleEngine,
    lexicon: Lexicon,
    classifier: C,
    /// Per-thread grooming memory, keyed by `TextSpan.thread_id`.
    threads: Mutex<HashMap<String, ThreadState>>,
}

impl TextAnalyzer<NoClassifier> {
    /// Build the analyzer with the built-in lexicon and no classifier backstop
    /// (the default, minimal-AI configuration).
    pub fn new() -> Result<Self, TextError> {
        Ok(TextAnalyzer {
            engine: GroomingRuleEngine::new(),
            lexicon: Lexicon::load_builtin()?,
            classifier: NoClassifier,
            threads: Mutex::new(HashMap::new()),
        })
    }
}

impl<C: TextClassifier> TextAnalyzer<C> {
    /// Build with a specific classifier backstop (used under the `classifier`
    /// feature). The classifier only ever sets `classifier_backed`.
    pub fn with_classifier(classifier: C) -> Result<Self, TextError> {
        Ok(TextAnalyzer {
            engine: GroomingRuleEngine::new(),
            lexicon: Lexicon::load_builtin()?,
            classifier,
            threads: Mutex::new(HashMap::new()),
        })
    }

    /// Languages the loaded lexicon covers (diagnostics).
    pub fn languages(&self) -> Vec<&str> {
        self.lexicon.languages()
    }

    /// Snapshot of a thread's current state (testing / store hand-off).
    pub fn thread_snapshot(&self, thread_id: &str) -> Option<ThreadState> {
        self.threads.lock().unwrap().get(thread_id).cloned()
    }

    /// Seed thread state (e.g. rehydrated from `aegis-store`).
    pub fn load_thread_state(&self, state: ThreadState) {
        self.threads
            .lock()
            .unwrap()
            .insert(state.thread_id.clone(), state);
    }

    /// Core synchronous analysis of a `TextSpan` → `Verdict`. This is the real
    /// work; `analyze` just adapts it to the async trait. Pure CPU/in-memory.
    pub fn analyze_span(&self, request_id: &str, span: &TextSpan, ts_ms: i64) -> Verdict {
        let lex = self.lexicon.resolve(&span.lang);

        // --- read prior thread state (clone out; don't hold the lock long) ---
        let prior = {
            let map = self.threads.lock().unwrap();
            map.get(&span.thread_id)
                .cloned()
                .unwrap_or_else(|| ThreadState::new(span.thread_id.clone()))
        };

        // --- 1. PRIMARY: deterministic grooming rules ---
        let outcome: RuleOutcome = self.engine.evaluate(&span.text, lex, &prior, ts_ms);

        // --- 2. adult-text detection (independent of grooming state) ---
        let adult = lex.is_adult_text(&span.text);

        // --- 3. record fired categories back into thread memory ---
        // Only create/touch thread state when something actually fired, so a
        // clean conversation leaves no trace (and no spurious memory growth).
        if !outcome.fired.is_empty() {
            let mut map = self.threads.lock().unwrap();
            let st = map
                .entry(span.thread_id.clone())
                .or_insert_with(|| ThreadState::new(span.thread_id.clone()));
            st.record(&outcome.fired, ts_ms);
        }

        // Privacy-safe trace: category counts + score only, never message text.
        tracing::trace!(
            thread_id = %span.thread_id,
            app = %span.app,
            fired = outcome.fired.len(),
            score = outcome.score,
            image_request = outcome.image_request,
            adult,
            "aegis-text rule evaluation",
        );

        // --- 4. assemble the verdict ---
        if !outcome.is_silent() {
            self.grooming_verdict(request_id, span, outcome)
        } else if adult {
            adult_text_verdict(request_id, span)
        } else {
            safe_verdict(request_id)
        }
    }

    /// Build a GROOMING / CSAM_SUSPECTED verdict from a rule outcome.
    fn grooming_verdict(&self, request_id: &str, span: &TextSpan, outcome: RuleOutcome) -> Verdict {
        // Backstop confirmation only — never alters category/score/action.
        let classifier_backed = self.classifier.agrees_grooming(span);

        let fired_names: Vec<String> =
            outcome.fired.iter().map(|r| r.as_str().to_string()).collect();
        let excerpt = redacted_excerpt(&span.text, &outcome.fired);

        // Image request → CSAM-suspected (report-never-archive path, PLAN §0c).
        let category = if outcome.image_request {
            Category::CsamSuspected
        } else {
            Category::Grooming
        };

        let action = action_for(outcome.severity);

        let mut rationale = outcome.rationale.clone();
        if classifier_backed {
            rationale.push_str("; backstop classifier agreed");
        } else {
            rationale.push_str("; rule-only (classifier did not back)");
        }

        let grooming = GroomingSignal {
            fired_categories: fired_names,
            score: outcome.score,
            excerpt: excerpt.clone(),
            classifier_backed,
        };

        Verdict {
            request_id: request_id.to_string(),
            category: category as i32,
            action: action as i32,
            severity: outcome.severity as i32,
            score: outcome.score,
            rationale,
            evidence: Some(Evidence {
                sha256: Vec::new(),
                perceptual_hash: Vec::new(),
                safe_thumbnail: Vec::new(),
                // Redacted excerpt ONLY — never raw message text.
                text_snippet: excerpt,
                model_id: RULE_ENGINE_ID.to_string(),
                model_version: RULE_ENGINE_VERSION.to_string(),
            }),
            grooming: Some(grooming),
            worker_id: String::new(),
            latency_ms: 0,
        }
    }
}

/// Expose the deterministic rule layer (interfaces.md §`GroomingRules`) so the
/// verdict is explainable independently of the full `Analyzer` pipeline. Uses
/// the span's own thread id timestamp-less (now=0) when called directly; the
/// full pipeline in `analyze_span` supplies the real timestamp for the
/// rapid-escalation window.
impl<C: TextClassifier> GroomingRules for TextAnalyzer<C> {
    fn evaluate(&self, span: &TextSpan, thread: &ThreadState) -> GroomingSignal {
        let lex = self.lexicon.resolve(&span.lang);
        let outcome = self.engine.evaluate(&span.text, lex, thread, 0);
        let classifier_backed = !outcome.is_silent() && self.classifier.agrees_grooming(span);
        GroomingSignal {
            fired_categories: outcome.fired.iter().map(|r| r.as_str().to_string()).collect(),
            score: outcome.score,
            excerpt: redacted_excerpt(&span.text, &outcome.fired),
            classifier_backed,
        }
    }
}

/// Map a severity band to the recommended `Action` (policy may override; this is
/// the sensible default from the thresholds). aegis-policy is the authority.
fn action_for(sev: Severity) -> Action {
    match sev {
        // CSAM risk / image request — block and escalate immediately.
        Severity::Critical => Action::Block,
        // ≥0.7 — immediate alert + human review; warn the flow meanwhile.
        Severity::High => Action::Warn,
        // ≥0.5 — flag + log.
        Severity::Medium => Action::Log,
        // ≥0.3 — log.
        Severity::Low => Action::Log,
        // <0.3 — pass.
        Severity::Info | Severity::Unspecified => Action::Allow,
    }
}

/// Verdict for explicit adult text with no grooming signal.
fn adult_text_verdict(request_id: &str, span: &TextSpan) -> Verdict {
    let excerpt = redacted_adult_excerpt(&span.text);
    Verdict {
        request_id: request_id.to_string(),
        category: Category::AdultText as i32,
        action: Action::Warn as i32,
        severity: Severity::Medium as i32,
        score: 0.6,
        rationale: "adult-text lexicon matched explicit sexual content".to_string(),
        evidence: Some(Evidence {
            sha256: Vec::new(),
            perceptual_hash: Vec::new(),
            safe_thumbnail: Vec::new(),
            text_snippet: excerpt,
            model_id: RULE_ENGINE_ID.to_string(),
            model_version: RULE_ENGINE_VERSION.to_string(),
        }),
        grooming: None,
        worker_id: String::new(),
        latency_ms: 0,
    }
}

/// The explicit SAFE negative verdict (so a verdict is always conclusive).
fn safe_verdict(request_id: &str) -> Verdict {
    Verdict {
        request_id: request_id.to_string(),
        category: Category::Safe as i32,
        action: Action::Allow as i32,
        severity: Severity::Info as i32,
        score: 0.0,
        rationale: "no grooming or adult-text indicators fired".to_string(),
        evidence: None,
        grooming: None,
        worker_id: String::new(),
        latency_ms: 0,
    }
}

/// Extract the `TextSpan` from a request, erroring if absent / wrong kind.
fn require_text_span(req: &AnalysisRequest) -> Result<&TextSpan, TextError> {
    req.text_span.as_ref().ok_or(TextError::MissingTextSpan)
}

#[async_trait]
impl<C: TextClassifier + 'static> Analyzer for TextAnalyzer<C> {
    fn handles(&self) -> &[MediaKind] {
        &[MediaKind::Text]
    }

    async fn analyze(&self, req: AnalysisRequest) -> anyhow::Result<Verdict> {
        let span = require_text_span(&req)?;
        // ts is unix epoch millis on the request; default to 0 if unset.
        Ok(self.analyze_span(&req.request_id, span, req.ts))
    }

    async fn analyze_stream(
        &self,
        requests: BoxStream<'static, AnalysisRequest>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<Verdict>>> {
        // The text analyzer is cheap and synchronous per message; we map the
        // request stream straight to a verdict stream. Thread state is shared
        // via the analyzer's internal map, so ordering within a thread is
        // preserved as long as the producer feeds messages in order.
        //
        // We must produce a 'static stream, so collect verdicts eagerly per
        // item using the analyzer behind an Arc would be ideal; for the
        // first-pass local path we buffer the (already in-memory) requests.
        let mut verdicts: Vec<anyhow::Result<Verdict>> = Vec::new();
        // `BoxStream` (Pin<Box<dyn Stream + Send>>) is `Unpin`, so we can poll it
        // directly via `StreamExt::next`.
        let mut requests = requests;
        while let Some(req) = requests.next().await {
            match require_text_span(&req) {
                Ok(span) => verdicts.push(Ok(self.analyze_span(&req.request_id, span, req.ts))),
                Err(e) => verdicts.push(Err(e.into())),
            }
        }
        Ok(futures_util::stream::iter(verdicts).boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::text_span;

    #[test]
    fn benign_message_is_safe() {
        let a = TextAnalyzer::new().unwrap();
        let span = text_span("benign", "are you coming to football practice tonight?");
        let v = a.analyze_span("r1", &span, 0);
        assert_eq!(v.category, Category::Safe as i32);
        assert_eq!(v.action, Action::Allow as i32);
        assert!(v.grooming.is_none());
    }

    #[test]
    fn image_request_is_csam_suspected_and_blocked() {
        let a = TextAnalyzer::new().unwrap();
        let span = text_span("t", "can you send me a pic of you");
        let v = a.analyze_span("r1", &span, 0);
        assert_eq!(v.category, Category::CsamSuspected as i32);
        assert_eq!(v.severity, Severity::Critical as i32);
        assert_eq!(v.action, Action::Block as i32);
        let g = v.grooming.unwrap();
        assert!(g.fired_categories.iter().any(|c| c == "image_request"));
        assert!(g.excerpt.starts_with("[redacted"));
        // classifier_backed is false without the feature.
        assert!(!g.classifier_backed);
    }

    #[test]
    fn evidence_never_contains_raw_text() {
        let a = TextAnalyzer::new().unwrap();
        let raw = "our little secret, dont tell your parents";
        let span = text_span("t", raw);
        let v = a.analyze_span("r1", &span, 0);
        let ev = v.evidence.unwrap();
        // The redacted snippet is marked and must not be the verbatim message.
        assert!(ev.text_snippet.starts_with("[redacted"));
        assert_ne!(ev.text_snippet, raw);
    }
}
