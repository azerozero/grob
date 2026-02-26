use super::config::DomainMatchMode;
use chrono::{DateTime, Utc};
use regex::Regex;
use std::sync::{Arc, RwLock};

/// Thread-safe shared hot config, updated by the background reload task.
pub type SharedHotConfig = Arc<RwLock<HotConfig>>;

/// Live-reloadable DLP configuration (domain lists + injection patterns).
pub struct HotConfig {
    pub url_whitelist: Vec<DomainMatcher>,
    pub url_blacklist: Vec<DomainMatcher>,
    pub injection_custom_patterns: Vec<Regex>,
    pub last_loaded: DateTime<Utc>,
    /// SHA-256 of the source content; skip reload if unchanged.
    pub source_hash: String,
}

impl Default for HotConfig {
    fn default() -> Self {
        Self {
            url_whitelist: Vec::new(),
            url_blacklist: Vec::new(),
            injection_custom_patterns: Vec::new(),
            last_loaded: Utc::now(),
            source_hash: String::new(),
        }
    }
}

/// Matches a hostname against a domain pattern.
pub struct DomainMatcher {
    pub raw: String,
    pub mode: DomainMatchMode,
    /// Pre-compiled regex for glob mode.
    glob_re: Option<Regex>,
}

impl DomainMatcher {
    pub fn new(pattern: &str, mode: &DomainMatchMode) -> Self {
        let glob_re = if *mode == DomainMatchMode::Glob {
            // Convert glob pattern to regex: *.example.com → ^.*\.example\.com$
            let escaped = regex::escape(pattern).replace(r"\*", ".*");
            Regex::new(&format!("^{}$", escaped)).ok()
        } else {
            None
        };
        Self {
            raw: pattern.to_string(),
            mode: mode.clone(),
            glob_re,
        }
    }

    /// Check if a hostname matches this domain pattern.
    pub fn matches(&self, hostname: &str) -> bool {
        let hostname = hostname.to_lowercase();
        let pattern = self.raw.to_lowercase();
        match self.mode {
            DomainMatchMode::Exact => hostname == pattern,
            DomainMatchMode::Suffix => {
                hostname == pattern
                    || hostname.ends_with(&format!(".{}", pattern))
            }
            DomainMatchMode::Glob => {
                self.glob_re
                    .as_ref()
                    .map(|re| re.is_match(&hostname))
                    .unwrap_or(false)
            }
        }
    }
}

/// Check if a hostname is suspicious based on whitelist/blacklist.
///
/// - If whitelist is non-empty, the domain MUST be in it (anything else is suspicious).
/// - If whitelist is empty, check blacklist (domain in blacklist is suspicious).
/// - If both are empty, nothing is suspicious.
pub fn is_domain_suspicious(
    hostname: &str,
    whitelist: &[DomainMatcher],
    blacklist: &[DomainMatcher],
) -> bool {
    if !whitelist.is_empty() {
        // Whitelist mode: domain must match at least one entry
        return !whitelist.iter().any(|m| m.matches(hostname));
    }
    if !blacklist.is_empty() {
        return blacklist.iter().any(|m| m.matches(hostname));
    }
    false
}

/// Build the initial hot config from inline config domain lists.
pub fn build_initial_hot_config(
    whitelist_domains: &[String],
    blacklist_domains: &[String],
    domain_mode: &DomainMatchMode,
    custom_injection_patterns: &[String],
) -> SharedHotConfig {
    let url_whitelist = whitelist_domains
        .iter()
        .map(|d| DomainMatcher::new(d, domain_mode))
        .collect();
    let url_blacklist = blacklist_domains
        .iter()
        .map(|d| DomainMatcher::new(d, domain_mode))
        .collect();
    let injection_custom_patterns = custom_injection_patterns
        .iter()
        .filter_map(|p| match Regex::new(p) {
            Ok(re) => Some(re),
            Err(e) => {
                tracing::warn!("Invalid custom injection pattern '{}': {}", p, e);
                None
            }
        })
        .collect();

    Arc::new(RwLock::new(HotConfig {
        url_whitelist,
        url_blacklist,
        injection_custom_patterns,
        last_loaded: Utc::now(),
        source_hash: String::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let m = DomainMatcher::new("github.com", &DomainMatchMode::Exact);
        assert!(m.matches("github.com"));
        assert!(m.matches("GitHub.com"));
        assert!(!m.matches("api.github.com"));
    }

    #[test]
    fn test_suffix_match() {
        let m = DomainMatcher::new("github.com", &DomainMatchMode::Suffix);
        assert!(m.matches("github.com"));
        assert!(m.matches("api.github.com"));
        assert!(!m.matches("notgithub.com"));
    }

    #[test]
    fn test_glob_match() {
        let m = DomainMatcher::new("*.github.com", &DomainMatchMode::Glob);
        assert!(m.matches("api.github.com"));
        assert!(m.matches("raw.github.com"));
        assert!(!m.matches("github.com"));
    }

    #[test]
    fn test_whitelist_takes_precedence() {
        let wl = vec![DomainMatcher::new("github.com", &DomainMatchMode::Suffix)];
        let bl = vec![DomainMatcher::new("evil.com", &DomainMatchMode::Suffix)];

        // In whitelist → not suspicious
        assert!(!is_domain_suspicious("github.com", &wl, &bl));
        assert!(!is_domain_suspicious("api.github.com", &wl, &bl));

        // Not in whitelist → suspicious (blacklist ignored when whitelist active)
        assert!(is_domain_suspicious("example.com", &wl, &bl));
        assert!(is_domain_suspicious("evil.com", &wl, &bl));
    }

    #[test]
    fn test_blacklist_only() {
        let wl: Vec<DomainMatcher> = vec![];
        let bl = vec![DomainMatcher::new("evil.com", &DomainMatchMode::Suffix)];

        assert!(is_domain_suspicious("evil.com", &wl, &bl));
        assert!(is_domain_suspicious("sub.evil.com", &wl, &bl));
        assert!(!is_domain_suspicious("github.com", &wl, &bl));
    }

    #[test]
    fn test_no_lists_nothing_suspicious() {
        let wl: Vec<DomainMatcher> = vec![];
        let bl: Vec<DomainMatcher> = vec![];
        assert!(!is_domain_suspicious("anything.com", &wl, &bl));
    }
}
