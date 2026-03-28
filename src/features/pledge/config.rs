//! Pledge configuration: profiles, rules, and matching logic.

use serde::{Deserialize, Serialize};

/// Top-level pledge configuration section (`[pledge]` in TOML).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PledgeConfig {
    /// Master switch — when false, pledge filtering is a no-op.
    #[serde(default)]
    pub enabled: bool,
    /// Profile applied when no rule matches (default: "full").
    #[serde(default = "default_profile_name")]
    pub default_profile: String,
    /// Ordered list of matching rules evaluated top-to-bottom.
    #[serde(default)]
    pub rules: Vec<PledgeRule>,
}

impl Default for PledgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_profile: default_profile_name(),
            rules: Vec::new(),
        }
    }
}

fn default_profile_name() -> String {
    "full".to_string()
}

/// Matches a request source or token prefix to a pledge profile.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PledgeRule {
    /// Match by request source (e.g. "mcp", "cli", "api").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Match by bearer token prefix (e.g. "grob_ci_").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_prefix: Option<String>,
    /// Profile name to apply when this rule matches.
    pub profile: String,
}

/// Named pledge profile defining which tools are allowed.
///
/// An empty `allowed_tools` list with `allow_all = true` means no restriction.
/// An empty list with `allow_all = false` means no tools at all.
#[derive(Debug, Clone)]
pub struct PledgeProfile {
    /// Human-readable profile name.
    pub name: &'static str,
    /// When true, all tools pass through (allowed_tools is ignored).
    pub allow_all: bool,
    /// Explicit tool name allowlist (only when `allow_all` is false).
    pub allowed_tools: &'static [&'static str],
}
