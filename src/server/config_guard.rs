//! Centralized deny-list for configuration updates.
//!
//! Both the MCP self-tuning path (`grob_configure`) and the web config API
//! (`/api/config`) share this guard to prevent credential leaks and security
//! weakening through config writes.

#[cfg(feature = "mcp")]
use crate::features::mcp::server::types::ConfigSection;

/// Top-level TOML sections that are never writable via any config API.
const DENIED_SECTIONS: &[&str] = &["providers", "dlp"];

/// Per-section keys that are never writable via any config API.
const DENIED_KEYS: &[(&str, &str)] = &[
    ("router", "api_key"),
    ("budget", "api_key"),
    ("cache", "api_key"),
];

/// Checks whether a (section, key) pair is blocked by the deny-list.
///
/// Returns `true` when the write must be rejected:
/// - The entire `providers` section (contains API keys).
/// - The entire `dlp` section (security must not be weakened).
/// - Any `api_key` field in any section.
pub fn is_section_or_key_denied(section: &str, key: &str) -> bool {
    if DENIED_SECTIONS.contains(&section) {
        return true;
    }
    if key == "api_key" {
        return true;
    }
    DENIED_KEYS.iter().any(|(s, k)| *s == section && *k == key)
}

/// Validates a key update against the deny-list using [`ConfigSection`].
///
/// Delegates to [`is_section_or_key_denied`] after converting the enum to a
/// string. This keeps the MCP path backward-compatible.
#[cfg(feature = "mcp")]
pub fn is_key_denied(section: &ConfigSection, key: &str) -> bool {
    let section_str = match section {
        ConfigSection::Router => "router",
        ConfigSection::Budget => "budget",
        ConfigSection::Dlp => "dlp",
        ConfigSection::Cache => "cache",
    };
    is_section_or_key_denied(section_str, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_providers_section() {
        assert!(is_section_or_key_denied("providers", "anything"));
        assert!(is_section_or_key_denied("providers", "api_key"));
        assert!(is_section_or_key_denied("providers", "name"));
    }

    #[test]
    fn deny_dlp_section() {
        assert!(is_section_or_key_denied("dlp", "enabled"));
        assert!(is_section_or_key_denied("dlp", "scan_input"));
        assert!(is_section_or_key_denied("dlp", "scan_output"));
        assert!(is_section_or_key_denied("dlp", "no_builtins"));
        assert!(is_section_or_key_denied("dlp", "anything"));
    }

    #[test]
    fn deny_api_key_anywhere() {
        assert!(is_section_or_key_denied("router", "api_key"));
        assert!(is_section_or_key_denied("budget", "api_key"));
        assert!(is_section_or_key_denied("cache", "api_key"));
        assert!(is_section_or_key_denied("server", "api_key"));
    }

    #[test]
    fn allow_safe_keys() {
        assert!(!is_section_or_key_denied("router", "default"));
        assert!(!is_section_or_key_denied("router", "think"));
        assert!(!is_section_or_key_denied("budget", "monthly_limit_usd"));
        assert!(!is_section_or_key_denied("cache", "enabled"));
        assert!(!is_section_or_key_denied("cache", "ttl_secs"));
    }

    #[cfg(feature = "mcp")]
    mod mcp_compat {
        use super::*;
        use crate::features::mcp::server::types::ConfigSection;

        #[test]
        fn deny_dlp_via_enum() {
            assert!(is_key_denied(&ConfigSection::Dlp, "enabled"));
            assert!(is_key_denied(&ConfigSection::Dlp, "scan_input"));
        }

        #[test]
        fn deny_credentials_via_enum() {
            assert!(is_key_denied(&ConfigSection::Router, "api_key"));
            assert!(is_key_denied(&ConfigSection::Budget, "api_key"));
        }

        #[test]
        fn allow_safe_via_enum() {
            assert!(!is_key_denied(&ConfigSection::Router, "default"));
            assert!(!is_key_denied(&ConfigSection::Cache, "ttl_secs"));
        }
    }
}
