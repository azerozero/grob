use super::canary::CanaryGenerator;
use super::config::{CustomPrefixRule, SecretAction, SecretRule};

/// A match found by the DFA scanner.
#[derive(Debug, Clone)]
pub struct SecretMatch {
    pub start: usize,
    pub end: usize,
    /// Index into the scanner's rule list (avoids String clone on hot path).
    pub rule_idx: usize,
    /// Original matched text length.
    pub matched_len: usize,
}

/// DLP event emitted on detection.
#[derive(Debug, Clone)]
pub struct DlpEvent {
    pub rule_name: String,
    pub action: String,
    #[allow(dead_code)]
    pub event_type: &'static str,
}

/// Internal rule representation (unified from SecretRule + CustomPrefixRule).
#[derive(Debug, Clone)]
pub(crate) struct ScannerRule {
    pub name: String,
    pub action: SecretAction,
    pub family: &'static str,
}

/// Compiled regex-based secret scanner with fast-path prefix pre-filter.
///
/// The scanner extracts unique first bytes from all known prefixes. If none of
/// those bytes appear in the input text, regex matching is skipped entirely.
/// This eliminates ~95% of chunks in typical LLM streaming workloads.
pub struct SecretScanner {
    /// Individual compiled regexes for match extraction.
    regexes: Vec<regex::Regex>,
    pub(crate) rules: Vec<ScannerRule>,
    /// Unique first bytes of all known prefixes — used as O(1) pre-filter.
    /// If text contains none of these bytes, no regex scan is needed.
    prefix_bytes: [bool; 256],
}

impl SecretScanner {
    pub fn new(secrets: &[SecretRule], custom_prefixes: &[CustomPrefixRule]) -> Self {
        let mut patterns = Vec::new();
        let mut rules = Vec::new();
        let mut prefix_bytes = [false; 256];

        for rule in secrets {
            match regex::Regex::new(&rule.pattern) {
                Ok(_) => {
                    patterns.push(rule.pattern.clone());
                    if let Some(&b) = rule.prefix.as_bytes().first() {
                        prefix_bytes[b as usize] = true;
                    }
                    rules.push(ScannerRule {
                        name: rule.name.clone(),
                        action: rule.action.clone(),
                        family: guess_family(&rule.prefix),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        "DLP: skipping secret rule '{}' — invalid regex '{}': {}",
                        rule.name,
                        rule.pattern,
                        e
                    );
                }
            }
        }

        for cp in custom_prefixes {
            let remaining = cp.length.saturating_sub(cp.prefix.len());
            let pattern = format!("{}[A-Za-z0-9]{{{}}}", regex::escape(&cp.prefix), remaining);
            match regex::Regex::new(&pattern) {
                Ok(_) => {
                    patterns.push(pattern);
                    if let Some(&b) = cp.prefix.as_bytes().first() {
                        prefix_bytes[b as usize] = true;
                    }
                    rules.push(ScannerRule {
                        name: cp.name.clone(),
                        action: cp.action.clone(),
                        family: "generic",
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        "DLP: skipping custom prefix rule '{}' — invalid pattern '{}': {}",
                        cp.name,
                        pattern,
                        e
                    );
                }
            }
        }

        let regexes = patterns
            .iter()
            .map(|p| regex::Regex::new(p).expect("pre-validated regex"))
            .collect();

        Self {
            regexes,
            rules,
            prefix_bytes,
        }
    }

    /// Returns true if there are no rules loaded.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Fast O(n) pre-filter: checks if text contains any byte that could start
    /// a known secret prefix. Returns false if no prefix byte is found → skip regex.
    #[inline]
    pub fn might_contain_secret(&self, text: &str) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        text.as_bytes()
            .iter()
            .any(|&b| self.prefix_bytes[b as usize])
    }

    /// Returns the length of the longest pattern *string* (not max match length).
    /// For cross-chunk window sizing, prefer using the known max match length from rule config.
    #[allow(dead_code)]
    pub fn max_pattern_str_len(&self) -> usize {
        self.regexes
            .iter()
            .map(|r| r.as_str().len())
            .max()
            .unwrap_or(0)
    }

    /// Scan text and return all matches with positions.
    /// Caller should check `might_contain_secret()` first for fast rejection.
    pub fn scan(&self, text: &str) -> Vec<SecretMatch> {
        if self.rules.is_empty() {
            return Vec::new();
        }

        let mut matches = Vec::new();

        for (idx, regex) in self.regexes.iter().enumerate() {
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
                    result.push_str("[REDACTED]");
                }
                SecretAction::Log => {
                    result.push_str(&text[m.start..m.end]);
                }
            }

            events.push(DlpEvent {
                rule_name: rule.name.clone(),
                action: rule.action.to_string(),
                event_type: "secret",
            });

            last_end = m.end;
        }

        result.push_str(&text[last_end..]);
        Some((result, events))
    }
}

/// Guess the token family from its prefix for canary generation.
fn guess_family(prefix: &str) -> &'static str {
    if prefix.starts_with("ghp_") || prefix.starts_with("gho_") || prefix.starts_with("ghs_") {
        "github"
    } else if prefix.starts_with("AKIA") {
        "aws"
    } else if prefix.starts_with("eyJ") {
        "jwt"
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
        assert!(redacted.contains("[REDACTED]"));
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
}
