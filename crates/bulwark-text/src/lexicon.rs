//! Embedded grooming + adult-text lexicon, keyed by category and language.
//!
//! The lexicon is *data only* (TOML compiled in via `include_str!`); all
//! weights, multipliers and thresholds live in [`crate::engine`]. This keeps the
//! detector multilingual-extensible: a translator drops in a new `<lang>.toml`
//! with localized phrases for the same eight categories and the engine works
//! unchanged.
//!
//! Matching uses two complementary deterministic strategies:
//!   * **aho-corasick** — scans every literal phrase for a language in a single
//!     pass over the message (case-insensitive), cheap even with large lexicons.
//!   * **regex** — templated triggers (age-conditioned compliments, "send me a
//!     pic", platform names) that literals cannot capture compactly.
//!
//! No raw message text is ever retained here; matchers return only which
//! [`GroomingRule`] / adult-text category fired.

use std::collections::BTreeMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::RegexSet;
use serde::Deserialize;

use bulwark_proto::GroomingRule;

use crate::error::TextError;

/// English lexicon, embedded at compile time. Additional languages register the
/// same way (see [`Lexicon::load_builtin`]).
const EN_TOML: &str = include_str!("lexicon/en.toml");

/// Raw shape of a `<lang>.toml` file. Deserialized then compiled into matchers.
#[derive(Debug, Deserialize)]
struct RawLexicon {
    lang: String,
    grooming: RawGrooming,
    adult_text: RawCategory,
}

#[derive(Debug, Deserialize)]
struct RawGrooming {
    secrecy: RawCategory,
    // #[serde(default)] so existing per-language files without the (newer)
    // guardian-isolation split still load (empty = no hard-secrecy phrases).
    #[serde(default)]
    secrecy_isolation: RawCategory,
    platform_switching: RawCategory,
    personal_info_age_probing: RawCategory,
    sexualization: RawCategory,
    gifts_bribery: RawCategory,
    emotional_manipulation: RawCategory,
    boundary_testing: RawCategory,
    image_request: RawCategory,
}

#[derive(Debug, Default, Deserialize)]
struct RawCategory {
    #[serde(default)]
    phrases: Vec<String>,
    #[serde(default)]
    patterns: Vec<String>,
}

impl RawGrooming {
    /// Pair each typed rule with its raw category, in spec order.
    fn by_rule(&self) -> [(GroomingRule, &RawCategory); 9] {
        [
            (GroomingRule::Secrecy, &self.secrecy),
            (GroomingRule::SecrecyIsolation, &self.secrecy_isolation),
            (GroomingRule::PlatformSwitching, &self.platform_switching),
            (
                GroomingRule::PersonalInfoAgeProbing,
                &self.personal_info_age_probing,
            ),
            (GroomingRule::Sexualization, &self.sexualization),
            (GroomingRule::GiftsBribery, &self.gifts_bribery),
            (
                GroomingRule::EmotionalManipulation,
                &self.emotional_manipulation,
            ),
            (GroomingRule::BoundaryTesting, &self.boundary_testing),
            (GroomingRule::ImageRequest, &self.image_request),
        ]
    }
}

/// Compiled matchers for one grooming category: a literal-phrase scanner plus a
/// patterned-trigger set. Either may be empty.
#[derive(Debug)]
struct CategoryMatcher {
    /// `None` when the category defines no literal phrases.
    phrases: Option<AhoCorasick>,
    /// `None` when the category defines no regex patterns.
    patterns: Option<RegexSet>,
}

impl CategoryMatcher {
    fn build(cat: &RawCategory) -> Result<Self, TextError> {
        let phrases = if cat.phrases.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    // Leftmost-longest so overlapping phrases collapse to one hit.
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&cat.phrases)
                    .map_err(|e| TextError::Lexicon(e.to_string()))?,
            )
        };
        let patterns = if cat.patterns.is_empty() {
            None
        } else {
            // Case-insensitive set; build once, query many.
            let set = RegexSet::new(cat.patterns.iter().map(|p| format!("(?i){p}")))
                .map_err(|e| TextError::Lexicon(e.to_string()))?;
            Some(set)
        };
        Ok(CategoryMatcher { phrases, patterns })
    }

    /// True if any phrase or pattern matches the (lower-cased) haystack.
    fn matches(&self, haystack: &str) -> bool {
        if let Some(ac) = &self.phrases {
            if ac.is_match(haystack) {
                return true;
            }
        }
        if let Some(rs) = &self.patterns {
            if rs.is_match(haystack) {
                return true;
            }
        }
        false
    }
}

/// A fully compiled lexicon for a single language: the eight grooming category
/// matchers plus the adult-text matcher.
#[derive(Debug)]
pub struct LanguageLexicon {
    lang: String,
    grooming: BTreeMap<&'static str, CategoryMatcher>,
    adult_text: CategoryMatcher,
}

impl LanguageLexicon {
    fn build(raw: RawLexicon) -> Result<Self, TextError> {
        let mut grooming = BTreeMap::new();
        for (rule, cat) in raw.grooming.by_rule() {
            grooming.insert(rule.as_str(), CategoryMatcher::build(cat)?);
        }
        Ok(LanguageLexicon {
            lang: raw.lang,
            grooming,
            adult_text: CategoryMatcher::build(&raw.adult_text)?,
        })
    }

    /// BCP-47 language tag this lexicon covers.
    pub fn lang(&self) -> &str {
        &self.lang
    }

    /// Which of the eight grooming rules fire on `text`, in stable spec order.
    pub fn fired_rules(&self, text: &str) -> Vec<GroomingRule> {
        let hay = text.to_lowercase();
        GroomingRule::ALL
            .into_iter()
            .filter(|rule| {
                self.grooming
                    .get(rule.as_str())
                    .map(|m| m.matches(&hay))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// True if the message contains explicit adult text (Category::ADULT_TEXT).
    pub fn is_adult_text(&self, text: &str) -> bool {
        self.adult_text.matches(&text.to_lowercase())
    }
}

/// All loaded languages. The English lexicon is always present; callers select a
/// language per [`bulwark_proto::TextSpan::lang`], falling back to English.
#[derive(Debug)]
pub struct Lexicon {
    by_lang: BTreeMap<String, LanguageLexicon>,
}

impl Lexicon {
    /// Load every built-in language lexicon (currently English). Adding a
    /// language is: embed `<lang>.toml`, parse it here, insert it.
    pub fn load_builtin() -> Result<Self, TextError> {
        let mut by_lang = BTreeMap::new();
        let en = Self::parse(EN_TOML)?;
        by_lang.insert(en.lang.clone(), en);
        Ok(Lexicon { by_lang })
    }

    fn parse(toml_src: &str) -> Result<LanguageLexicon, TextError> {
        let raw: RawLexicon =
            toml::from_str(toml_src).map_err(|e| TextError::Lexicon(e.to_string()))?;
        LanguageLexicon::build(raw)
    }

    /// Resolve a BCP-47 hint to a loaded lexicon. Matches the primary subtag
    /// (`en-GB` → `en`); empty/unknown hints fall back to English so the
    /// detector always runs.
    pub fn resolve(&self, lang_hint: &str) -> &LanguageLexicon {
        let primary = lang_hint
            .split(['-', '_'])
            .next()
            .unwrap_or("")
            .to_lowercase();
        self.by_lang
            .get(&primary)
            .or_else(|| self.by_lang.get("en"))
            .expect("English lexicon is always loaded")
    }

    /// Languages currently available (for diagnostics / coverage reporting).
    pub fn languages(&self) -> Vec<&str> {
        self.by_lang.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_lexicon_loads_and_has_all_nine_categories() {
        let lex = Lexicon::load_builtin().expect("lexicon compiles");
        let en = lex.resolve("en");
        assert_eq!(en.grooming.len(), 9);
        assert_eq!(lex.languages(), vec!["en"]);
    }

    #[test]
    fn resolve_falls_back_to_english() {
        let lex = Lexicon::load_builtin().unwrap();
        assert_eq!(lex.resolve("").lang(), "en");
        assert_eq!(lex.resolve("fr").lang(), "en");
        assert_eq!(lex.resolve("en-GB").lang(), "en");
    }

    #[test]
    fn literal_and_regex_triggers_fire_expected_categories() {
        let lex = Lexicon::load_builtin().unwrap();
        let en = lex.resolve("en");

        let fired = en.fired_rules("This is our little secret, ok?");
        assert!(fired.contains(&GroomingRule::Secrecy));

        // Regex-only platform switch.
        let fired = en.fired_rules("hey lets hop over to telegram");
        assert!(fired.contains(&GroomingRule::PlatformSwitching));

        // Age-conditioned compliment via regex template.
        let fired = en.fired_rules("you're really sexy for 13 honestly");
        assert!(fired.contains(&GroomingRule::Sexualization));

        // Image request via regex.
        let fired = en.fired_rules("can you send me a pic");
        assert!(fired.contains(&GroomingRule::ImageRequest));
    }

    #[test]
    fn benign_text_fires_nothing() {
        let lex = Lexicon::load_builtin().unwrap();
        let en = lex.resolve("en");
        assert!(en
            .fired_rules("did you finish the maths homework yet?")
            .is_empty());
        assert!(!en.is_adult_text("did you finish the maths homework yet?"));
    }
}
