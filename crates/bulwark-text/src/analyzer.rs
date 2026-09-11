//! Deterministic text analysis with bounded, per-conversation state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_core::stream::BoxStream;
use futures_util::StreamExt;

use bulwark_proto::{
    Action, AnalysisRequest, Category, Evidence, GroomingSignal, MediaKind, Severity, TextSpan,
    Verdict,
};

use crate::classifier::{NoClassifier, TextClassifier};
use crate::engine::{GroomingRuleEngine, RuleOutcome};
use crate::error::TextError;
use crate::lexicon::Lexicon;
use crate::redact::redacted_excerpt;
use crate::state::ThreadState;
use crate::traits::GroomingRules;
use bulwark_core::Analyzer;

const RULE_ENGINE_ID: &str = "bulwark-grooming-rules";
const RULE_ENGINE_VERSION: &str = "2";
const DEFAULT_THREAD_TTL_MS: i64 = 24 * 60 * 60 * 1000;
const DEFAULT_MAX_THREADS: usize = 4096;

struct ThreadCell {
    state: Mutex<ThreadState>,
    last_seen_ms: AtomicI64,
}

impl ThreadCell {
    fn new(state: ThreadState, ts_ms: i64) -> Self {
        Self {
            state: Mutex::new(state),
            last_seen_ms: AtomicI64::new(ts_ms.max(0)),
        }
    }
}

pub struct TextAnalyzer<C: TextClassifier = NoClassifier> {
    engine: GroomingRuleEngine,
    lexicon: Lexicon,
    classifier: C,
    threads: Mutex<HashMap<String, Arc<ThreadCell>>>,
    thread_ttl_ms: i64,
    max_threads: usize,
}

impl TextAnalyzer<NoClassifier> {
    pub fn new() -> Result<Self, TextError> {
        Self::with_components(NoClassifier)
    }
}

#[cfg(feature = "classifier")]
impl TextAnalyzer<crate::classifier::SklearnTfidfClassifier> {
    pub fn with_builtin_grooming_model() -> Result<Self, TextError> {
        Self::with_classifier(crate::classifier::SklearnTfidfClassifier::load_builtin()?)
    }
}

#[cfg(feature = "classifier")]
impl TextAnalyzer<crate::classifier::DistilbertGroomingClassifier> {
    pub fn with_distilbert_grooming_model(
        model_path: impl AsRef<std::path::Path>,
        tokenizer_json: impl AsRef<std::path::Path>,
    ) -> Result<Self, TextError> {
        Self::with_classifier(crate::classifier::DistilbertGroomingClassifier::load(
            model_path,
            tokenizer_json,
            "distilbert-grooming-fullcorpus-v2",
        )?)
    }
}

impl<C: TextClassifier> TextAnalyzer<C> {
    fn with_components(classifier: C) -> Result<Self, TextError> {
        let thread_ttl_ms = std::env::var("BULWARK_TEXT_THREAD_TTL_MS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_THREAD_TTL_MS);
        let max_threads = std::env::var("BULWARK_TEXT_MAX_THREADS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_MAX_THREADS);
        Ok(Self {
            engine: GroomingRuleEngine::new(),
            lexicon: Lexicon::load_builtin()?,
            classifier,
            threads: Mutex::new(HashMap::new()),
            thread_ttl_ms,
            max_threads,
        })
    }

    pub fn with_classifier(classifier: C) -> Result<Self, TextError> {
        Self::with_components(classifier)
    }

    pub fn languages(&self) -> Vec<&str> {
        self.lexicon.languages()
    }

    pub fn thread_snapshot(&self, thread_id: &str) -> Option<ThreadState> {
        let cell = self.threads.lock().ok()?.get(thread_id).cloned()?;
        cell.state.lock().ok().map(|state| state.clone())
    }

    pub fn load_thread_state(&self, state: ThreadState) {
        let now = now_ms();
        if let Ok(mut threads) = self.threads.lock() {
            self.prune_locked(&mut threads, now);
            threads.insert(
                state.thread_id.clone(),
                Arc::new(ThreadCell::new(state, now)),
            );
        }
    }

    fn thread_cell(&self, thread_id: &str, ts_ms: i64) -> Arc<ThreadCell> {
        let timestamp = if ts_ms > 0 { ts_ms } else { now_ms() };
        let mut threads = self.threads.lock().expect("text thread map mutex poisoned");
        self.prune_locked(&mut threads, timestamp);
        threads
            .entry(thread_id.to_string())
            .or_insert_with(|| {
                Arc::new(ThreadCell::new(
                    ThreadState::new(thread_id.to_string()),
                    timestamp,
                ))
            })
            .clone()
    }

    fn prune_locked(&self, threads: &mut HashMap<String, Arc<ThreadCell>>, now: i64) {
        let cutoff = now.saturating_sub(self.thread_ttl_ms);
        threads.retain(|_, cell| cell.last_seen_ms.load(Ordering::Relaxed) >= cutoff);
        while threads.len() >= self.max_threads {
            let oldest = threads
                .iter()
                .min_by_key(|(_, cell)| cell.last_seen_ms.load(Ordering::Relaxed))
                .map(|(key, _)| key.clone());
            match oldest {
                Some(key) => {
                    threads.remove(&key);
                }
                None => break,
            }
        }
    }

    pub fn analyze_span(&self, request_id: &str, span: &TextSpan, ts_ms: i64) -> Verdict {
        let timestamp = if ts_ms > 0 { ts_ms } else { now_ms() };
        let lexicon = self.lexicon.resolve(&span.lang);
        let cell = self.thread_cell(&span.thread_id, timestamp);
        let mut state = cell.state.lock().expect("text thread mutex poisoned");
        let outcome: RuleOutcome = self.engine.evaluate(&span.text, lexicon, &state, timestamp);
        let adult = lexicon.is_adult_text(&span.text);
        if !outcome.fired.is_empty() {
            state.record(&outcome.fired, timestamp);
        }
        cell.last_seen_ms.store(timestamp, Ordering::Relaxed);
        drop(state);

        tracing::trace!(
            thread_id = %span.thread_id,
            app = %span.app,
            fired = outcome.fired.len(),
            score = outcome.score,
            image_request = outcome.image_request,
            adult,
            "text rule evaluation"
        );

        if !outcome.is_silent() {
            self.grooming_verdict(request_id, span, outcome)
        } else if adult {
            adult_text_verdict(request_id, span)
        } else {
            safe_verdict(request_id)
        }
    }

    fn grooming_verdict(&self, request_id: &str, span: &TextSpan, outcome: RuleOutcome) -> Verdict {
        let classifier_backed = self.classifier.agrees_grooming(span);
        let fired_names = outcome
            .fired
            .iter()
            .map(|rule| rule.as_str().to_string())
            .collect::<Vec<_>>();
        let excerpt = redacted_excerpt(&span.text, &outcome.fired);
        let action = action_for(outcome.severity);
        let mut rationale = outcome.rationale.clone();
        if outcome.image_request {
            rationale.push_str("; sexual-image solicitation risk");
        }
        if classifier_backed {
            rationale.push_str("; backstop classifier agreed");
        } else {
            rationale.push_str("; deterministic-rule signal");
        }

        Verdict {
            request_id: request_id.to_string(),
            category: Category::Grooming as i32,
            action: action as i32,
            severity: outcome.severity as i32,
            score: outcome.score,
            rationale,
            evidence: Some(Evidence {
                text_snippet: excerpt.clone(),
                model_id: RULE_ENGINE_ID.to_string(),
                model_version: RULE_ENGINE_VERSION.to_string(),
                ..Default::default()
            }),
            grooming: Some(GroomingSignal {
                fired_categories: fired_names,
                score: outcome.score,
                excerpt,
                classifier_backed,
            }),
            ..Default::default()
        }
    }
}

impl<C: TextClassifier> GroomingRules for TextAnalyzer<C> {
    fn evaluate(&self, span: &TextSpan, thread: &ThreadState) -> GroomingSignal {
        let lexicon = self.lexicon.resolve(&span.lang);
        let outcome = self.engine.evaluate(&span.text, lexicon, thread, now_ms());
        let classifier_backed = !outcome.is_silent() && self.classifier.agrees_grooming(span);
        GroomingSignal {
            fired_categories: outcome
                .fired
                .iter()
                .map(|rule| rule.as_str().to_string())
                .collect(),
            score: outcome.score,
            excerpt: redacted_excerpt(&span.text, &outcome.fired),
            classifier_backed,
        }
    }
}

fn action_for(severity: Severity) -> Action {
    match severity {
        Severity::Critical => Action::Block,
        Severity::High => Action::Warn,
        Severity::Medium | Severity::Low => Action::Log,
        Severity::Info | Severity::Unspecified => Action::Allow,
    }
}

fn adult_text_verdict(request_id: &str, span: &TextSpan) -> Verdict {
    Verdict {
        request_id: request_id.to_string(),
        category: Category::AdultText as i32,
        action: Action::Warn as i32,
        severity: Severity::Medium as i32,
        score: 0.6,
        rationale: "adult-text lexicon matched explicit sexual content".to_string(),
        evidence: Some(Evidence {
            text_snippet: redacted_excerpt(&span.text, &[]),
            model_id: RULE_ENGINE_ID.to_string(),
            model_version: RULE_ENGINE_VERSION.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn safe_verdict(request_id: &str) -> Verdict {
    Verdict {
        request_id: request_id.to_string(),
        category: Category::Safe as i32,
        action: Action::Allow as i32,
        severity: Severity::Info as i32,
        score: 0.0,
        rationale: "no grooming or adult-text indicators fired".to_string(),
        ..Default::default()
    }
}

fn require_text_span(req: &AnalysisRequest) -> Result<&TextSpan, TextError> {
    req.text_span.as_ref().ok_or(TextError::MissingTextSpan)
}

#[async_trait]
impl<C: TextClassifier + 'static> Analyzer for TextAnalyzer<C> {
    fn handles(&self) -> &[MediaKind] {
        const KINDS: [MediaKind; 1] = [MediaKind::Text];
        &KINDS
    }

    async fn analyze(&self, req: AnalysisRequest) -> bulwark_core::Result<Verdict> {
        let span = require_text_span(&req).map_err(|error| bulwark_core::Error::Other(error.into()))?;
        Ok(self.analyze_span(&req.request_id, span, req.ts))
    }
}

impl<C: TextClassifier> TextAnalyzer<C> {
    pub async fn analyze_stream(
        &self,
        requests: BoxStream<'static, AnalysisRequest>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<Verdict>>> {
        let mut output = Vec::new();
        let mut requests = requests;
        while let Some(req) = requests.next().await {
            match require_text_span(&req) {
                Ok(span) => output.push(Ok(self.analyze_span(&req.request_id, span, req.ts))),
                Err(error) => output.push(Err(error.into())),
            }
        }
        Ok(futures_util::stream::iter(output).boxed())
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_memory_is_bounded() {
        let analyzer = TextAnalyzer::new().unwrap();
        for n in 0..(DEFAULT_MAX_THREADS + 8) {
            let span = TextSpan {
                text: "hello".into(),
                thread_id: format!("t-{n}"),
                ..Default::default()
            };
            let _ = analyzer.analyze_span("r", &span, now_ms());
        }
        assert!(analyzer.threads.lock().unwrap().len() <= DEFAULT_MAX_THREADS);
    }

    #[test]
    fn safe_is_explicit_only_after_successful_rules() {
        let analyzer = TextAnalyzer::new().unwrap();
        let span = TextSpan {
            text: "hello there".into(),
            thread_id: "d\u{1f}app\u{1f}thread".into(),
            ..Default::default()
        };
        let verdict = analyzer.analyze_span("r", &span, now_ms());
        assert_eq!(verdict.category(), Category::Safe);
    }
}
