use super::canary::CanaryGenerator;
use super::config::{CustomPrefixRule, SecretAction, SecretRule};
use aho_corasick::AhoCorasick;
use std::sync::OnceLock;

/// A match found by the DFA scanner.
#[derive(Debug, Clone)]
pub struct SecretMatch {
    /// Byte offset where the match begins.
    pub start: usize,
    /// Byte offset where the match ends (exclusive).
    pub end: usize,
    /// Index into the scanner's rule list (avoids String clone on hot path).
    pub rule_idx: usize,
    /// Original matched text length.
    pub matched_len: usize,
}

/// DLP event emitted on detection.
#[derive(Debug, Clone)]
pub struct DlpEvent {
    /// Name of the secret rule that triggered the event.
    pub rule_name: String,
    /// Action taken (canary, redact, or log).
    pub action: String,
}

/// Internal rule representation (unified from SecretRule + CustomPrefixRule).
#[derive(Debug, Clone)]
pub(crate) struct ScannerRule {
    pub name: String,
    pub action: SecretAction,
    pub family: &'static str,
}

/// Compiled regex-based secret scanner with two-level prefix pre-filter.
///
/// Construction validates pattern syntax cheaply via `regex_syntax::parse`
/// and defers full DFA compilation to the first `scan()` call (via `OnceLock`).
///
/// Pre-filter uses two levels for high selectivity:
/// 1. **Byte filter** — O(n) scan for first bytes of known prefixes (rejects ~90%)
/// 2. **AC prefix filter** — Aho-Corasick automaton on full prefix strings (rejects ~99%)
///
/// Only when both levels pass does the scanner invoke regex matching.
pub struct SecretScanner {
    /// Pattern strings for lazy individual regex compilation.
    patterns: Vec<String>,
    /// Lazily compiled individual regexes for match position extraction.
    regexes: Vec<OnceLock<regex::Regex>>,
    pub(crate) rules: Vec<ScannerRule>,
    /// Unique first bytes of all known prefixes — used as O(1) pre-filter.
    /// If text contains none of these bytes, no regex scan is needed.
    prefix_bytes: [bool; 256],
    /// Full prefix strings for Aho-Corasick confirmation filter.
    prefix_strings: Vec<String>,
    /// Lazily compiled Aho-Corasick automaton on prefix strings.
    prefix_ac: OnceLock<AhoCorasick>,
}

impl SecretScanner {
    /// Constructs a scanner by validating pattern syntax (no DFA compilation).
    ///
    /// Uses `regex_syntax::parse` for fast AST-only validation. Full DFA
    /// compilation is deferred to the first `scan()` call via `OnceLock`.
    pub fn new(secrets: &[SecretRule], custom_prefixes: &[CustomPrefixRule]) -> Self {
        let mut patterns = Vec::new();
        let mut rules = Vec::new();
        let mut prefix_bytes = [false; 256];
        let mut prefix_strings = Vec::new();

        for rule in secrets {
            if regex_syntax::parse(&rule.pattern).is_ok() {
                patterns.push(rule.pattern.clone());
                if let Some(&b) = rule.prefix.as_bytes().first() {
                    prefix_bytes[b as usize] = true;
                }
                prefix_strings.push(rule.prefix.clone());
                rules.push(ScannerRule {
                    name: rule.name.clone(),
                    action: rule.action.clone(),
                    family: guess_family(&rule.prefix),
                });
            } else {
                tracing::warn!(
                    "DLP: skipping secret rule '{}' — invalid regex '{}'",
                    rule.name,
                    rule.pattern,
                );
            }
        }

        for cp in custom_prefixes {
            let remaining = cp.length.saturating_sub(cp.prefix.len());
            let pattern = format!("{}[A-Za-z0-9]{{{}}}", regex::escape(&cp.prefix), remaining);
            if regex_syntax::parse(&pattern).is_ok() {
                patterns.push(pattern);
                if let Some(&b) = cp.prefix.as_bytes().first() {
                    prefix_bytes[b as usize] = true;
                }
                prefix_strings.push(cp.prefix.clone());
                rules.push(ScannerRule {
                    name: cp.name.clone(),
                    action: cp.action.clone(),
                    family: "generic",
                });
            } else {
                tracing::warn!(
                    "DLP: skipping custom prefix rule '{}' — invalid pattern '{}'",
                    cp.name,
                    pattern,
                );
            }
        }

        let regexes = (0..patterns.len()).map(|_| OnceLock::new()).collect();

        Self {
            patterns,
            regexes,
            rules,
            prefix_bytes,
            prefix_strings,
            prefix_ac: OnceLock::new(),
        }
    }

    /// Returns true if there are no rules loaded.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Two-level O(n) pre-filter for secret detection.
    ///
    /// Level 1: single-byte lookup rejects text without any prefix start byte.
    /// Level 2 (short texts only): Aho-Corasick confirms a full prefix string
    /// exists. This avoids running 24+ regexes on clean text where a common
    /// letter (e, s, p) happened to match a prefix start byte.
    ///
    /// For long texts (>512 bytes), the AC scan cost approaches the regex scan
    /// cost, so we skip level 2 and let `scan()` run directly.
    #[inline]
    pub fn might_contain_secret(&self, text: &str) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        // Level 1: fast byte-level reject
        if !text
            .as_bytes()
            .iter()
            .any(|&b| self.prefix_bytes[b as usize])
        {
            return false;
        }
        // Level 2: AC confirmation for short texts (avoids 24+ regex scans)
        if text.len() <= 512 {
            let ac = self.prefix_ac.get_or_init(|| {
                AhoCorasick::builder()
                    .build(&self.prefix_strings)
                    .expect("prefix strings are valid AC patterns")
            });
            return ac.find(text).is_some();
        }
        true
    }

    /// Returns the length of the longest pattern *string* (not max match length).
    pub fn max_pattern_str_len(&self) -> usize {
        self.patterns.iter().map(|p| p.len()).max().unwrap_or(0)
    }

    /// Returns the compiled regex for a given rule index, compiling it lazily.
    #[inline]
    fn get_regex(&self, idx: usize) -> &regex::Regex {
        self.regexes[idx]
            .get_or_init(|| regex::Regex::new(&self.patterns[idx]).expect("pre-validated regex"))
    }

    /// Scan text and return all matches with positions.
    /// Caller should check `might_contain_secret()` first for fast rejection.
    pub fn scan(&self, text: &str) -> Vec<SecretMatch> {
        if self.rules.is_empty() {
            return Vec::new();
        }

        let mut matches = Vec::new();

        for idx in 0..self.rules.len() {
            let regex = self.get_regex(idx);
            for mat in regex.find_iter(text) {
                matches.push(SecretMatch {
                    start: mat.start(),
                    end: mat.end(),
                    rule_idx: idx,
                    matched_len: mat.end() - mat.start(),
                });
            }
        }

        // Sort by position so replacements can be applied left-to-right
        if matches.len() > 1 {
            matches.sort_unstable_by_key(|m| m.start);
        }
        matches
    }

    /// Replace matches in text with canary/redacted tokens.
    /// Returns None if no matches found (caller can reuse original text).
    pub fn redact(
        &self,
        text: &str,
        canary_gen: &CanaryGenerator,
    ) -> Option<(String, Vec<DlpEvent>)> {
        let matches = self.scan(text);
        if matches.is_empty() {
            return None;
        }

        let mut result = String::with_capacity(text.len());
        let mut events = Vec::with_capacity(matches.len());
        let mut last_end = 0;

        for m in &matches {
            // Skip overlapping matches
            if m.start < last_end {
                continue;
            }

            let rule = &self.rules[m.rule_idx];
            result.push_str(&text[last_end..m.start]);

            match rule.action {
                SecretAction::Canary => {
                    let canary = canary_gen.generate_for(rule.family, m.matched_len);
                    result.push_str(&canary.fake);
                }
                SecretAction::Redact => {
                    let canary = canary_gen.generate_for(rule.family, m.matched_len);
                    result.push_str(&canary.fake);
                }
                SecretAction::Log => {
                    result.push_str(&text[m.start..m.end]);
                }
            }

            events.push(DlpEvent {
                rule_name: rule.name.clone(),
                action: rule.action.to_string(),
            });

            last_end = m.end;
        }

        result.push_str(&text[last_end..]);
        Some((result, events))
    }
}

/// Guess the token family from its prefix for canary generation.
fn guess_family(prefix: &str) -> &'static str {
    if prefix.starts_with("ghp_")
        || prefix.starts_with("gho_")
        || prefix.starts_with("ghs_")
        || prefix.starts_with("github_pat_")
    {
        "github"
    } else if prefix.starts_with("AKIA") {
        "aws"
    } else if prefix.starts_with("eyJ") {
        "jwt"
    } else if prefix.starts_with("sk-proj-")
        || prefix.starts_with("sk-ant-api03-")
        || prefix.starts_with("hf_")
        || prefix.starts_with("pplx-")
    {
        "llm"
    } else if prefix.starts_with("sk_live_")
        || prefix.starts_with("rk_live_")
        || prefix.starts_with("SG.")
    {
        "stripe"
    } else if prefix.starts_with("glpat-") {
        "gitlab"
    } else if prefix.starts_with("-----BEGIN") {
        "pem"
    } else if prefix.starts_with("postgres://") || prefix.starts_with("mongodb") {
        "database"
    } else {
        "generic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rules() -> Vec<SecretRule> {
        vec![
            SecretRule {
                name: "github_token".into(),
                prefix: "ghp_".into(),
                pattern: "ghp_[A-Za-z0-9]{36}".into(),
                action: SecretAction::Canary,
            },
            SecretRule {
                name: "aws_access_key".into(),
                prefix: "AKIA".into(),
                pattern: "AKIA[0-9A-Z]{16}".into(),
                action: SecretAction::Redact,
            },
        ]
    }

    #[test]
    fn test_scan_finds_github_token() {
        let scanner = SecretScanner::new(&test_rules(), &[]);
        let text = "my token is ghp_abcdefghijklmnopqrstuvwxyz1234567890 here";
        let matches = scanner.scan(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(scanner.rules[matches[0].rule_idx].name, "github_token");
        assert_eq!(scanner.rules[matches[0].rule_idx].family, "github");
    }

    #[test]
    fn test_scan_finds_aws_key() {
        let scanner = SecretScanner::new(&test_rules(), &[]);
        let text = "key=AKIAIOSFODNN7EXAMPLE";
        let matches = scanner.scan(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(scanner.rules[matches[0].rule_idx].name, "aws_access_key");
    }

    #[test]
    fn test_redact_replaces_aws() {
        let scanner = SecretScanner::new(&test_rules(), &[]);
        let canary_gen = CanaryGenerator::new();
        let text = "key=AKIAIOSFODNN7EXAMPLE done";
        let result = scanner.redact(text, &canary_gen);
        assert!(result.is_some());
        let (redacted, events) = result.unwrap();
        // Redact action now uses canary tokens for traceability.
        assert!(
            redacted.contains("AKIA~CANARY"),
            "redact should produce a canary token, got: {}",
            redacted
        );
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_empty_scanner() {
        let scanner = SecretScanner::new(&[], &[]);
        assert!(scanner.is_empty());
        assert!(scanner.scan("anything").is_empty());
    }

    #[test]
    fn test_custom_prefix() {
        let custom = vec![CustomPrefixRule {
            name: "vault_token".into(),
            prefix: "v1.AA".into(),
            length: 32,
            action: SecretAction::Canary,
        }];
        let scanner = SecretScanner::new(&[], &custom);
        // prefix "v1.AA" (5 chars) + 27 alnum chars = 32 total
        let text = "token=v1.AAabcdefghijklmnopqrstuvwxyz0 done";
        let matches = scanner.scan(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(scanner.rules[matches[0].rule_idx].name, "vault_token");
    }

    #[test]
    fn test_might_contain_secret_fast_reject() {
        let scanner = SecretScanner::new(&test_rules(), &[]);
        // No 'g' or 'A' → fast reject
        assert!(!scanner.might_contain_secret("hello world"));
        // Has 'g' → might contain
        assert!(scanner.might_contain_secret("ghp_test"));
        // Has 'A' → might contain
        assert!(scanner.might_contain_secret("AKIA"));
    }

    #[test]
    fn test_redact_returns_none_on_no_match() {
        let scanner = SecretScanner::new(&test_rules(), &[]);
        let canary_gen = CanaryGenerator::new();
        assert!(scanner.redact("hello world", &canary_gen).is_none());
    }

    #[test]
    fn test_invalid_regex_graceful() {
        // Invalid regex pattern — should be skipped gracefully, not panic
        let rules = vec![
            SecretRule {
                name: "bad_rule".into(),
                prefix: "bad_".into(),
                pattern: "bad_[unclosed".into(), // invalid regex
                action: SecretAction::Canary,
            },
            SecretRule {
                name: "good_rule".into(),
                prefix: "ghp_".into(),
                pattern: "ghp_[A-Za-z0-9]{36}".into(),
                action: SecretAction::Canary,
            },
        ];
        let scanner = SecretScanner::new(&rules, &[]);
        // Bad rule skipped, good rule loaded
        assert_eq!(scanner.rules.len(), 1);
        assert_eq!(scanner.rules[0].name, "good_rule");
    }

    #[test]
    fn test_max_pattern_str_len() {
        let scanner = SecretScanner::new(&test_rules(), &[]);
        assert!(
            scanner.max_pattern_str_len() > 0,
            "max_pattern_str_len should be > 0 with rules loaded"
        );
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Generates a valid 40-character GitHub PAT (ghp_ + 36 alnum).
        fn github_pat_strategy() -> impl Strategy<Value = String> {
            prop::collection::vec(
                prop::sample::select(
                    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_vec(),
                ),
                36..=36,
            )
            .prop_map(|chars| {
                let suffix: String = chars.into_iter().map(|b| b as char).collect();
                format!("ghp_{}", suffix)
            })
        }

        /// Generates a valid 20-character AWS access key (AKIA + 16 uppercase alnum).
        fn aws_key_strategy() -> impl Strategy<Value = String> {
            prop::collection::vec(
                prop::sample::select(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_vec()),
                16..=16,
            )
            .prop_map(|chars| {
                let suffix: String = chars.into_iter().map(|b| b as char).collect();
                format!("AKIA{}", suffix)
            })
        }

        /// Generates arbitrary lowercase ASCII text without secret prefixes.
        fn safe_text_strategy() -> impl Strategy<Value = String> {
            "[a-z ]{0,200}"
        }

        proptest! {
            #[test]
            fn any_github_pat_is_detected(token in github_pat_strategy()) {
                let scanner = SecretScanner::new(&test_rules(), &[]);
                let text = format!("token: {} end", token);
                let matches = scanner.scan(&text);
                prop_assert!(
                    !matches.is_empty(),
                    "GitHub PAT '{}' should be detected", token
                );
                prop_assert_eq!(
                    &scanner.rules[matches[0].rule_idx].name,
                    "github_token"
                );
            }

            #[test]
            fn any_aws_key_is_detected(key in aws_key_strategy()) {
                let scanner = SecretScanner::new(&test_rules(), &[]);
                let text = format!("key={} done", key);
                let matches = scanner.scan(&text);
                prop_assert!(
                    !matches.is_empty(),
                    "AWS key '{}' should be detected", key
                );
                prop_assert_eq!(
                    &scanner.rules[matches[0].rule_idx].name,
                    "aws_access_key"
                );
            }

            #[test]
            fn safe_text_never_matches(text in safe_text_strategy()) {
                let scanner = SecretScanner::new(&test_rules(), &[]);
                let matches = scanner.scan(&text);
                prop_assert!(
                    matches.is_empty(),
                    "Safe text '{}' should not trigger any rule", text
                );
            }

            #[test]
            fn redact_never_leaks_original_secret(token in github_pat_strategy()) {
                let scanner = SecretScanner::new(&test_rules(), &[]);
                let canary_gen = CanaryGenerator::new();
                let text = format!("secret: {} end", token);
                if let Some((redacted, _)) = scanner.redact(&text, &canary_gen) {
                    prop_assert!(
                        !redacted.contains(&token),
                        "Redacted output must not contain original token"
                    );
                    prop_assert!(
                        redacted.contains("~CANARY"),
                        "Redacted output must contain canary marker"
                    );
                }
            }

            #[test]
            fn scan_is_idempotent(token in github_pat_strategy()) {
                let scanner = SecretScanner::new(&test_rules(), &[]);
                let text = format!("x {} y", token);
                let m1 = scanner.scan(&text);
                let m2 = scanner.scan(&text);
                prop_assert_eq!(m1.len(), m2.len());
                for (a, b) in m1.iter().zip(m2.iter()) {
                    prop_assert_eq!(a.start, b.start);
                    prop_assert_eq!(a.end, b.end);
                    prop_assert_eq!(a.rule_idx, b.rule_idx);
                }
            }
        }
    }
}
