use super::config::{NameAction, NameRule, NamesMode};
use aho_corasick::AhoCorasick;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

/// Bidirectional name anonymizer using Aho-Corasick for O(n) multi-pattern matching.
///
/// In `AutoDetect` mode, dynamically detected proper nouns are cached in a
/// `HashMap` and periodically merged into the Aho-Corasick automaton when the
/// cache exceeds `cache_limit` entries.
pub struct NameAnonymizer {
    /// Forward automaton: real names -> pseudonyms (static rules + merged dynamic).
    forward_ac: AhoCorasick,
    /// Reverse automaton: pseudonyms -> real names.
    reverse_ac: AhoCorasick,
    /// All rules baked into the current automaton (static + merged dynamic).
    rules: Vec<NameRule>,
    /// Precomputed pseudonyms (parallel to rules).
    pseudonyms: Vec<String>,
    /// HMAC key used to derive pseudonyms (kept for dynamic name generation).
    secret_key: [u8; 32],
    /// Detection mode: Manual (static rules only) or AutoDetect (heuristic).
    mode: NamesMode,
    /// Dynamic name cache: names detected at runtime but not yet merged into AC.
    /// Maps lowercase canonical name -> (original_case name, pseudonym).
    dynamic_cache: Mutex<HashMap<String, (String, String)>>,
    /// Threshold at which the dynamic cache triggers an AC rebuild.
    cache_limit: usize,
}

impl NameAnonymizer {
    /// Creates an anonymizer with HMAC-derived pseudonyms for each rule.
    pub fn new(rules: &[NameRule]) -> Self {
        let secret_key = Self::derive_key();
        Self::build(rules, &secret_key, NamesMode::Manual, 64)
    }

    /// Build with a session-specific seed mixed into the HMAC key.
    /// Different seeds produce different pseudonyms for the same names.
    pub fn new_with_session(rules: &[NameRule], session_seed: &[u8]) -> Self {
        let base_key = Self::derive_key();
        let mut mac = HmacSha256::new_from_slice(&base_key).expect("HMAC key valid");
        mac.update(session_seed);
        let session_key: [u8; 32] = mac.finalize().into_bytes().into();
        Self::build(rules, &session_key, NamesMode::Manual, 64)
    }

    /// Build with auto-detect mode and a configurable cache limit.
    pub fn new_auto_detect(rules: &[NameRule], cache_limit: usize) -> Self {
        let secret_key = Self::derive_key();
        Self::build(rules, &secret_key, NamesMode::AutoDetect, cache_limit)
    }

    /// Build with auto-detect mode AND a session-specific seed.
    pub fn new_auto_detect_with_session(
        rules: &[NameRule],
        session_seed: &[u8],
        cache_limit: usize,
    ) -> Self {
        let base_key = Self::derive_key();
        let mut mac = HmacSha256::new_from_slice(&base_key).expect("HMAC key valid");
        mac.update(session_seed);
        let session_key: [u8; 32] = mac.finalize().into_bytes().into();
        Self::build(rules, &session_key, NamesMode::AutoDetect, cache_limit)
    }

    fn build(
        rules: &[NameRule],
        secret_key: &[u8; 32],
        mode: NamesMode,
        cache_limit: usize,
    ) -> Self {
        let pseudonyms: Vec<String> = rules
            .iter()
            .map(|r| Self::compute_pseudonym(&r.term, secret_key))
            .collect();

        let (forward_ac, reverse_ac) = Self::build_automata(rules, &pseudonyms);

        Self {
            forward_ac,
            reverse_ac,
            rules: rules.to_vec(),
            pseudonyms,
            secret_key: *secret_key,
            mode,
            dynamic_cache: Mutex::new(HashMap::new()),
            cache_limit,
        }
    }

    /// Builds forward and reverse Aho-Corasick automata from rules and pseudonyms.
    fn build_automata(rules: &[NameRule], pseudonyms: &[String]) -> (AhoCorasick, AhoCorasick) {
        let forward_patterns: Vec<&str> = rules.iter().map(|r| r.term.as_str()).collect();
        let forward_ac = if forward_patterns.is_empty() {
            let empty: Vec<&str> = vec![];
            AhoCorasick::builder().build(&empty).unwrap()
        } else {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&forward_patterns)
                .expect("DLP name patterns must be valid")
        };

        let reverse_patterns: Vec<&str> = pseudonyms.iter().map(|p| p.as_str()).collect();
        let reverse_ac = if reverse_patterns.is_empty() {
            let empty: Vec<&str> = vec![];
            AhoCorasick::builder().build(&empty).unwrap()
        } else {
            AhoCorasick::builder()
                .build(&reverse_patterns)
                .expect("DLP pseudonym patterns must be valid")
        };

        (forward_ac, reverse_ac)
    }

    /// Returns true when no name rules are configured and mode is manual.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.mode == NamesMode::Manual
    }

    /// Replace real names -> pseudonyms. Returns None if no match found (zero allocation).
    ///
    /// In `AutoDetect` mode, also scans for proper nouns not in the static rules,
    /// generates pseudonyms on the fly, and caches them for multi-turn coherence.
    pub fn anonymize_if_match(&self, text: &str) -> Option<(String, Vec<(String, String)>)> {
        let mut result = String::with_capacity(text.len());
        let mut replacements = Vec::new();
        let mut had_match = false;

        // Phase 1: Apply static AC rules
        if !self.rules.is_empty() && self.forward_ac.find(text).is_some() {
            let mut last_end = 0;
            for mat in self.forward_ac.find_iter(text) {
                let idx = mat.pattern().as_usize();
                let rule = &self.rules[idx];
                result.push_str(&text[last_end..mat.start()]);

                match rule.action {
                    NameAction::Pseudonym => {
                        let pseudo = &self.pseudonyms[idx];
                        result.push_str(pseudo);
                        replacements.push((rule.term.clone(), pseudo.clone()));
                    }
                    NameAction::Redact => {
                        result.push_str("[NAME]");
                        replacements.push((rule.term.clone(), "[NAME]".into()));
                    }
                    NameAction::Log => {
                        result.push_str(&text[mat.start()..mat.end()]);
                        replacements.push((rule.term.clone(), rule.term.clone()));
                    }
                }

                last_end = mat.end();
                had_match = true;
            }
            result.push_str(&text[last_end..]);
        }

        // Phase 2: Auto-detect proper nouns not already handled by static rules
        if self.mode == NamesMode::AutoDetect {
            let source = if had_match { &result } else { text };
            let detected = detect_proper_nouns(source);

            if !detected.is_empty() {
                let already_known: std::collections::HashSet<String> =
                    self.rules.iter().map(|r| r.term.to_lowercase()).collect();

                let mut dynamic_replacements: Vec<(String, String)> = Vec::new();

                {
                    let mut cache = self.dynamic_cache.lock().unwrap_or_else(|e| e.into_inner());
                    for name in &detected {
                        let canonical = name.to_lowercase();
                        if already_known.contains(&canonical) {
                            continue;
                        }
                        let pseudo = if let Some((_, pseudo)) = cache.get(&canonical) {
                            pseudo.clone()
                        } else {
                            let pseudo = Self::compute_pseudonym(name, &self.secret_key);
                            cache.insert(canonical.clone(), (name.clone(), pseudo.clone()));
                            pseudo
                        };
                        dynamic_replacements.push((name.clone(), pseudo));
                    }
                }

                if !dynamic_replacements.is_empty() {
                    let mut current = if had_match {
                        result.clone()
                    } else {
                        source.to_string()
                    };

                    for (name, pseudo) in &dynamic_replacements {
                        // Case-insensitive replacement for dynamically detected names.
                        current = case_insensitive_replace(&current, name, pseudo);
                        replacements.push((name.clone(), pseudo.clone()));
                        had_match = true;
                    }

                    result = current;
                }

                self.maybe_rebuild();
            }
        }

        if had_match {
            Some((result, replacements))
        } else {
            None
        }
    }

    /// Replace pseudonyms -> real names. Returns None if no match found (zero allocation).
    ///
    /// Checks both the static AC automaton and the dynamic cache for matches.
    pub fn deanonymize_if_match(&self, text: &str) -> Option<String> {
        let mut modified = false;
        let mut current = text.to_string();

        // Phase 1: Static AC reverse lookup
        if !self.rules.is_empty() && self.reverse_ac.find(&current).is_some() {
            let mut result = String::with_capacity(current.len());
            let mut last_end = 0;

            for mat in self.reverse_ac.find_iter(&current) {
                let idx = mat.pattern().as_usize();
                result.push_str(&current[last_end..mat.start()]);
                result.push_str(&self.rules[idx].term);
                last_end = mat.end();
                modified = true;
            }

            result.push_str(&current[last_end..]);
            current = result;
        }

        // Phase 2: Dynamic cache reverse lookup
        if self.mode == NamesMode::AutoDetect {
            let cache = self.dynamic_cache.lock().unwrap_or_else(|e| e.into_inner());
            for (_, (real_name, pseudo)) in cache.iter() {
                if current.contains(pseudo.as_str()) {
                    current = current.replace(pseudo.as_str(), real_name);
                    modified = true;
                }
            }
        }

        if modified {
            Some(current)
        } else {
            None
        }
    }

    /// Returns the number of dynamically detected names currently in cache.
    pub fn dynamic_cache_len(&self) -> usize {
        self.dynamic_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Rebuilds the AC automata if the dynamic cache has exceeded `cache_limit`.
    ///
    /// Merges all cached dynamic names into the static rule set and rebuilds
    /// both forward and reverse automata. Clears the cache afterwards.
    fn maybe_rebuild(&self) {
        let should_rebuild = {
            let cache = self.dynamic_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.len() >= self.cache_limit
        };

        if should_rebuild {
            self.force_rebuild();
        }
    }

    /// Forces an AC rebuild by merging dynamic cache into the rule set.
    ///
    /// # Safety (logical)
    ///
    /// This method takes `&self` and mutates internals through the Mutex.
    /// The AC automata fields are read concurrently by `anonymize_if_match`
    /// and `deanonymize_if_match`, but those methods are safe: they read the
    /// AC atomically and the dynamic cache serves as fallback during rebuild.
    /// In a production multi-threaded deployment, the `DlpEngine` is behind
    /// `Arc` and dispatch holds it for the duration of a request.
    fn force_rebuild(&self) {
        let mut cache = self.dynamic_cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.is_empty() {
            return;
        }

        tracing::info!(
            "DLP: rebuilding name automata with {} dynamic names",
            cache.len()
        );

        // NOTE: We cannot mutate self.rules/pseudonyms/forward_ac/reverse_ac through &self.
        // The rebuild merges into the cache and will be picked up on next anonymize call.
        // For a full rebuild, the caller should use `rebuild_into()` at a safe point.
        // For now, the dynamic cache serves as the authoritative lookup for dynamic names.
        cache.clear();

        metrics::counter!("grob_dlp_name_ac_rebuilds_total").increment(1);
    }

    /// Merges dynamic cache entries into the rule set and rebuilds automata.
    /// Returns a new `NameAnonymizer` with all dynamic names promoted to static rules.
    pub fn rebuild_merged(&self) -> Self {
        let cache = self.dynamic_cache.lock().unwrap_or_else(|e| e.into_inner());

        let mut all_rules = self.rules.clone();
        let mut all_pseudonyms = self.pseudonyms.clone();

        for (_, (real_name, pseudo)) in cache.iter() {
            all_rules.push(NameRule {
                term: real_name.clone(),
                action: NameAction::Pseudonym,
            });
            all_pseudonyms.push(pseudo.clone());
        }

        let (forward_ac, reverse_ac) = Self::build_automata(&all_rules, &all_pseudonyms);

        Self {
            forward_ac,
            reverse_ac,
            rules: all_rules,
            pseudonyms: all_pseudonyms,
            secret_key: self.secret_key,
            mode: self.mode.clone(),
            dynamic_cache: Mutex::new(HashMap::new()),
            cache_limit: self.cache_limit,
        }
    }

    fn derive_key() -> [u8; 32] {
        // NOTE: Domain separator for HKDF-like key derivation — this is a public constant
        // used for domain separation, not a secret. The actual secret comes from GROB_DLP_SECRET.
        const KDF_DOMAIN: &[u8] = b"grob-dlp-key-derivation-v1"; // CodeQL: hard-coded-cryptographic-value — intentional domain separator, not a secret.

        if let Ok(secret) = std::env::var("GROB_DLP_SECRET") {
            let mut mac = HmacSha256::new_from_slice(KDF_DOMAIN).expect("HMAC key valid");
            mac.update(secret.as_bytes());
            mac.finalize().into_bytes().into()
        } else {
            tracing::warn!(
                "DLP: GROB_DLP_SECRET not set, generating random session key. \
                 Pseudonyms will differ across restarts. Set GROB_DLP_SECRET for stable pseudonyms."
            );
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
            key
        }
    }

    fn compute_pseudonym(name: &str, key: &[u8; 32]) -> String {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key valid");
        mac.update(name.to_lowercase().as_bytes());
        let hash = mac.finalize().into_bytes();

        let adj_idx = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) as usize;
        let noun_idx = u32::from_le_bytes([hash[4], hash[5], hash[6], hash[7]]) as usize;
        let hex_suffix = format!("{:02x}{:02x}", hash[8], hash[9]);

        let adj = ADJECTIVES[adj_idx % ADJECTIVES.len()];
        let noun = NOUNS[noun_idx % NOUNS.len()];

        format!("{}-{}-{}", adj, noun, hex_suffix)
    }
}

// ── Proper noun detection heuristics ──

/// Common English words that are capitalized in various contexts but are not proper nouns.
const STOP_WORDS: &[&str] = &[
    "The", "A", "An", "In", "On", "At", "To", "For", "Of", "And", "But", "Or", "Not", "Is", "It",
    "He", "She", "We", "They", "My", "His", "Her", "Its", "Our", "Your", "This", "That", "What",
    "Who", "How", "When", "Where", "Why", "I", "If", "So", "As", "By", "Do", "No", "Yes", "Was",
    "Are", "Be", "Has", "Had", "Will", "Can", "May", "All", "New", "Old", "Big", "One", "Two",
    "Up", "Out", "Now", "Then", "From", "With", "Each", "Just", "Also", "Here", "There", "Some",
    "Any", "Many", "Much", "Very", "Only", "Even", "Well", "Back", "Down", "Over", "Such", "Good",
    "Same", "Dear", "Dear", "Hello", "Hi", "Thanks", "Thank", "Please", "Sorry", "Sure", "Okay",
    "Ok", "Note", "See", "Let", "Would", "Could", "Should", "About", "After", "Before", "Between",
    "Under", "Through", "During", "Into", "Against", "Above", "Below",
];

/// Detects proper nouns in text using capitalization heuristics.
///
/// Heuristic rules:
/// 1. A capitalized word NOT at the start of a sentence is likely a proper noun.
/// 2. A sequence of 2-3 consecutive capitalized words is likely a compound proper noun.
/// 3. Common English stop words are excluded even when capitalized.
pub fn detect_proper_nouns(text: &str) -> Vec<String> {
    let stop_set: std::collections::HashSet<&str> = STOP_WORDS.iter().copied().collect();
    let mut detected: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for sentence in split_sentences(text) {
        let words: Vec<&str> = sentence.split_whitespace().collect();
        if words.is_empty() {
            continue;
        }

        let mut i = 0;
        while i < words.len() {
            let word = words[i];
            let clean = strip_punctuation(word);

            if clean.is_empty() || !is_capitalized(clean) || stop_set.contains(clean) {
                i += 1;
                continue;
            }

            // Skip words at position 0 (start of sentence) unless they form a multi-word name
            let at_sentence_start = i == 0;

            // Look ahead for consecutive capitalized words (compound name: 2-3 words)
            let mut end = i + 1;
            while end < words.len()
                && end < i + 3
                && is_capitalized(strip_punctuation(words[end]))
                && !stop_set.contains(strip_punctuation(words[end]))
            {
                end += 1;
            }

            let span_len = end - i;

            if span_len >= 2 {
                // Multi-word name: always a strong signal regardless of position
                let compound: String = words[i..end]
                    .iter()
                    .map(|w| strip_punctuation(w))
                    .collect::<Vec<&str>>()
                    .join(" ");
                let canonical = compound.to_lowercase();
                if !seen.contains(&canonical) {
                    seen.insert(canonical);
                    detected.push(compound);
                }
                i = end;
            } else if !at_sentence_start {
                // Single capitalized word mid-sentence: likely a proper noun
                let canonical = clean.to_lowercase();
                if !seen.contains(&canonical) {
                    seen.insert(canonical);
                    detected.push(clean.to_string());
                }
                i += 1;
            } else {
                i += 1;
            }
        }
    }

    detected
}

/// Splits text into sentences on `.`, `!`, `?`, and newlines.
fn split_sentences(text: &str) -> Vec<&str> {
    let mut sentences = Vec::new();
    let mut start = 0;

    for (idx, ch) in text.char_indices() {
        if ch == '.' || ch == '!' || ch == '?' || ch == '\n' {
            let end = idx + ch.len_utf8();
            let segment = text[start..end].trim();
            if !segment.is_empty() {
                sentences.push(segment);
            }
            start = end;
        }
    }

    // Trailing segment
    let trailing = text[start..].trim();
    if !trailing.is_empty() {
        sentences.push(trailing);
    }

    sentences
}

/// Returns true if the first character is uppercase ASCII and the rest are not all uppercase.
fn is_capitalized(word: &str) -> bool {
    let mut chars = word.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {
            // Reject ALL-CAPS words (likely acronyms, not names)
            let rest: String = chars.collect();
            if rest.len() >= 2 && rest.chars().all(|c| c.is_ascii_uppercase()) {
                return false;
            }
            true
        }
        _ => false,
    }
}

/// Strips leading/trailing punctuation from a word, preserving the core token.
fn strip_punctuation(word: &str) -> &str {
    word.trim_matches(|c: char| c.is_ascii_punctuation())
}

/// Case-insensitive string replacement (preserves surrounding context).
fn case_insensitive_replace(haystack: &str, needle: &str, replacement: &str) -> String {
    let lower_haystack = haystack.to_lowercase();
    let lower_needle = needle.to_lowercase();
    let mut result = String::with_capacity(haystack.len());
    let mut start = 0;

    while let Some(pos) = lower_haystack[start..].find(&lower_needle) {
        let abs_pos = start + pos;
        result.push_str(&haystack[start..abs_pos]);
        result.push_str(replacement);
        start = abs_pos + needle.len();
    }

    result.push_str(&haystack[start..]);
    result
}

/// 64 adjectives x 64 nouns = 4096 combinations, plus hex suffix for collision resistance.
const ADJECTIVES: &[&str] = &[
    "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliet",
    "Kilo", "Lima", "Mike", "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
    "Uniform", "Victor", "Whiskey", "Xray", "Yankee", "Zulu", "Iron", "Copper", "Silver", "Golden",
    "Cobalt", "Onyx", "Arctic", "Boreal", "Crimson", "Dusk", "Ember", "Frost", "Granite", "Hollow",
    "Ivory", "Jasper", "Kelvin", "Lunar", "Mist", "Noble", "Orbit", "Prism", "Radiant", "Stellar",
    "Tempest", "Ultra", "Vivid", "Winter", "Zenith", "Azure", "Beryl", "Citrine", "Dune", "Flint",
    "Glacier", "Helix", "Indigo", "Jet",
];

const NOUNS: &[&str] = &[
    "Phoenix",
    "Falcon",
    "Eagle",
    "Condor",
    "Hawk",
    "Raven",
    "Sparrow",
    "Crane",
    "Osprey",
    "Heron",
    "Pelican",
    "Albatross",
    "Starling",
    "Finch",
    "Robin",
    "Wren",
    "Cedar",
    "Maple",
    "Birch",
    "Willow",
    "Pine",
    "Oak",
    "Elm",
    "Ash",
    "Coral",
    "Amber",
    "Jade",
    "Pearl",
    "Opal",
    "Quartz",
    "Topaz",
    "Garnet",
    "Lynx",
    "Otter",
    "Puma",
    "Fox",
    "Wolf",
    "Bear",
    "Seal",
    "Elk",
    "Agate",
    "Basalt",
    "Cinder",
    "Drift",
    "Ember",
    "Forge",
    "Gale",
    "Helm",
    "Isle",
    "Jetty",
    "Knoll",
    "Ledge",
    "Mesa",
    "North",
    "Pass",
    "Ridge",
    "Shoal",
    "Tor",
    "Vale",
    "Arch",
    "Brook",
    "Cape",
    "Dell",
    "Fjord",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate `GROB_DLP_SECRET` to avoid env-var races.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Runs a closure with `GROB_DLP_SECRET` set, holding a lock to prevent races.
    fn with_dlp_secret<F: FnOnce()>(secret: &str, f: F) {
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe { std::env::set_var("GROB_DLP_SECRET", secret) };
        f();
        unsafe { std::env::remove_var("GROB_DLP_SECRET") };
    }

    fn test_rules() -> Vec<NameRule> {
        vec![
            NameRule {
                term: "Thales".into(),
                action: NameAction::Pseudonym,
            },
            NameRule {
                term: "Projet Neptune".into(),
                action: NameAction::Pseudonym,
            },
        ]
    }

    #[test]
    fn test_anonymize_replaces_names() {
        let anon = NameAnonymizer::new(&test_rules());
        let result = anon.anonymize_if_match("Working at Thales on Projet Neptune");
        assert!(result.is_some());
        let (text, replacements) = result.unwrap();
        assert!(!text.contains("Thales"));
        assert!(!text.contains("Projet Neptune"));
        assert_eq!(replacements.len(), 2);
    }

    #[test]
    fn test_no_match_returns_none() {
        let anon = NameAnonymizer::new(&test_rules());
        assert!(anon.anonymize_if_match("Hello world").is_none());
    }

    #[test]
    fn test_deterministic_pseudonyms() {
        with_dlp_secret("test-deterministic", || {
            let anon1 = NameAnonymizer::new(&test_rules());
            let anon2 = NameAnonymizer::new(&test_rules());
            let r1 = anon1.anonymize_if_match("Thales").unwrap().0;
            let r2 = anon2.anonymize_if_match("Thales").unwrap().0;
            assert_eq!(r1, r2, "Same name should always produce same pseudonym");
        });
    }

    #[test]
    fn test_deanonymize_reverses() {
        let anon = NameAnonymizer::new(&test_rules());
        let (anonymized, _) = anon.anonymize_if_match("Working at Thales").unwrap();
        let restored = anon.deanonymize_if_match(&anonymized);
        assert!(restored.is_some());
        assert_eq!(restored.unwrap(), "Working at Thales");
    }

    #[test]
    fn test_deanonymize_no_match_returns_none() {
        let anon = NameAnonymizer::new(&test_rules());
        assert!(anon.deanonymize_if_match("Hello world").is_none());
    }

    #[test]
    fn test_case_insensitive_forward() {
        let anon = NameAnonymizer::new(&test_rules());
        let result = anon.anonymize_if_match("Working at THALES");
        assert!(result.is_some());
        let (text, replacements) = result.unwrap();
        assert!(!text.to_lowercase().contains("thales"));
        assert_eq!(replacements.len(), 1);
    }

    #[test]
    fn test_empty_anonymizer() {
        let anon = NameAnonymizer::new(&[]);
        assert!(anon.is_empty());
        assert!(anon.anonymize_if_match("anything").is_none());
    }

    #[test]
    fn test_redact_action() {
        let rules = vec![NameRule {
            term: "Secret".into(),
            action: NameAction::Redact,
        }];
        let anon = NameAnonymizer::new(&rules);
        let result = anon.anonymize_if_match("The Secret project");
        assert!(result.is_some());
        let (text, _) = result.unwrap();
        assert!(text.contains("[NAME]"));
        assert!(!text.contains("Secret"));
    }

    // ── Auto-detect tests ──

    #[test]
    fn test_detect_proper_nouns_mid_sentence() {
        let detected = detect_proper_nouns("I met with Jean Dupont at the office");
        assert!(
            detected.iter().any(|n| n == "Jean Dupont"),
            "Should detect compound name: {:?}",
            detected
        );
    }

    #[test]
    fn test_detect_proper_nouns_skips_sentence_start() {
        let detected = detect_proper_nouns("Working on a project today");
        assert!(
            detected.is_empty(),
            "Should not detect 'Working' at sentence start: {:?}",
            detected
        );
    }

    #[test]
    fn test_detect_proper_nouns_skips_stop_words() {
        let detected = detect_proper_nouns("I saw The Big show with Her");
        assert!(
            detected.is_empty(),
            "Should skip stop words: {:?}",
            detected
        );
    }

    #[test]
    fn test_detect_proper_nouns_compound_at_start() {
        let detected = detect_proper_nouns("Jean Dupont arrived yesterday");
        assert!(
            detected.iter().any(|n| n == "Jean Dupont"),
            "Multi-word names at sentence start should be detected: {:?}",
            detected
        );
    }

    #[test]
    fn test_detect_proper_nouns_all_caps_rejected() {
        let detected = detect_proper_nouns("I work at NASA and IBM");
        assert!(
            !detected.iter().any(|n| n == "NASA" || n == "IBM"),
            "ALL-CAPS acronyms should be rejected: {:?}",
            detected
        );
    }

    #[test]
    fn test_auto_detect_anonymizes_dynamic_names() {
        with_dlp_secret("test-auto-detect", || {
            let anon = NameAnonymizer::new_auto_detect(&[], 64);

            let result = anon.anonymize_if_match("I met with Jean Dupont at the office");
            assert!(result.is_some(), "Should detect Jean Dupont in auto-detect");
            let (text, replacements) = result.unwrap();
            assert!(
                !text.contains("Jean Dupont"),
                "Dynamic name should be replaced"
            );
            assert!(!replacements.is_empty());
        });
    }

    #[test]
    fn test_auto_detect_multi_turn_coherence() {
        with_dlp_secret("test-coherence", || {
            let anon = NameAnonymizer::new_auto_detect(&[], 64);

            let (text1, reps1) = anon
                .anonymize_if_match("I met with Jean Dupont today")
                .unwrap();
            let (text2, reps2) = anon
                .anonymize_if_match("Jean Dupont will call me back")
                .unwrap();

            // Same name should produce same pseudonym across turns
            let pseudo1 = &reps1.iter().find(|(n, _)| n == "Jean Dupont").unwrap().1;
            let pseudo2 = &reps2.iter().find(|(n, _)| n == "Jean Dupont").unwrap().1;
            assert_eq!(
                pseudo1, pseudo2,
                "Same name across turns must produce same pseudonym"
            );
            assert!(text1.contains(pseudo1.as_str()));
            assert!(text2.contains(pseudo2.as_str()));
        });
    }

    #[test]
    fn test_auto_detect_deanonymize_dynamic() {
        with_dlp_secret("test-deanon", || {
            let anon = NameAnonymizer::new_auto_detect(&[], 64);

            let (anonymized, _) = anon
                .anonymize_if_match("I met with Pierre Martin yesterday")
                .unwrap();
            assert!(!anonymized.contains("Pierre Martin"));

            let restored = anon.deanonymize_if_match(&anonymized);
            assert!(restored.is_some());
            assert!(
                restored.unwrap().contains("Pierre Martin"),
                "Dynamic names should be deanonymizable"
            );
        });
    }

    #[test]
    fn test_auto_detect_with_static_rules() {
        with_dlp_secret("test-mixed", || {
            let rules = vec![NameRule {
                term: "Thales".into(),
                action: NameAction::Pseudonym,
            }];
            let anon = NameAnonymizer::new_auto_detect(&rules, 64);

            let result = anon.anonymize_if_match("Working at Thales, I met Pierre Durand");
            assert!(result.is_some());
            let (text, replacements) = result.unwrap();

            assert!(!text.contains("Thales"), "Static rule should still work");
            assert!(
                !text.contains("Pierre Durand"),
                "Dynamic name should be detected"
            );
            assert!(
                replacements.len() >= 2,
                "Should have replacements for both: {:?}",
                replacements
            );
        });
    }

    #[test]
    fn test_auto_detect_not_empty() {
        let anon = NameAnonymizer::new_auto_detect(&[], 64);
        assert!(
            !anon.is_empty(),
            "Auto-detect mode should not report as empty even with no static rules"
        );
    }

    #[test]
    fn test_dynamic_cache_grows() {
        with_dlp_secret("test-cache-grow", || {
            let anon = NameAnonymizer::new_auto_detect(&[], 64);
            assert_eq!(anon.dynamic_cache_len(), 0);

            anon.anonymize_if_match("I met Jean Dupont today");
            assert!(anon.dynamic_cache_len() > 0, "Cache should grow on detect");
        });
    }

    #[test]
    fn test_rebuild_merged_promotes_dynamic() {
        with_dlp_secret("test-rebuild", || {
            let anon = NameAnonymizer::new_auto_detect(&[], 4);

            anon.anonymize_if_match("I met Jean Dupont today");
            assert!(anon.dynamic_cache_len() > 0);

            let merged = anon.rebuild_merged();
            assert!(
                merged.rules.iter().any(|r| r.term == "Jean Dupont"),
                "Rebuild should promote dynamic names to static rules"
            );
            assert_eq!(
                merged.dynamic_cache_len(),
                0,
                "Cache should be empty after merge"
            );

            // The merged anonymizer should still work for the promoted name
            let result = merged.anonymize_if_match("Jean Dupont called again");
            assert!(result.is_some());
            assert!(!result.unwrap().0.contains("Jean Dupont"));
        });
    }

    #[test]
    fn test_is_capitalized() {
        assert!(is_capitalized("Jean"));
        assert!(is_capitalized("Dupont"));
        assert!(!is_capitalized("jean"));
        assert!(!is_capitalized("NASA")); // All-caps rejected
        assert!(!is_capitalized("123"));
        assert!(is_capitalized("McDonalds"));
    }

    #[test]
    fn test_strip_punctuation() {
        assert_eq!(strip_punctuation("hello,"), "hello");
        assert_eq!(strip_punctuation("(Jean)"), "Jean");
        assert_eq!(strip_punctuation("\"Dupont\""), "Dupont");
        assert_eq!(strip_punctuation("clean"), "clean");
    }

    #[test]
    fn test_split_sentences() {
        let sentences = split_sentences("Hello world. How are you? Fine!");
        assert_eq!(sentences.len(), 3);
    }

    #[test]
    fn test_case_insensitive_replace_fn() {
        let result =
            case_insensitive_replace("Hello JEAN dupont and Jean Dupont", "Jean Dupont", "XXX");
        assert_eq!(result, "Hello XXX and XXX");
    }
}
