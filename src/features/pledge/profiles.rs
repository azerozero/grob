//! Built-in pledge profiles: predefined tool allowlists per security posture.

use super::config::{PledgeConfig, PledgeProfile, ResolvedProfile};

/// Read-only: file reading, search, and web lookup only.
pub const READ_ONLY: PledgeProfile = PledgeProfile {
    name: "read_only",
    allow_all: false,
    allowed_tools: &["read_file", "grep", "list_dir", "web_search"],
};

/// Execute: shell and file manipulation (no web, no admin).
pub const EXECUTE: PledgeProfile = PledgeProfile {
    name: "execute",
    allow_all: false,
    allowed_tools: &["bash", "read_file", "write_file", "grep", "list_dir"],
};

/// Full: no restrictions — all tools pass through.
pub const FULL: PledgeProfile = PledgeProfile {
    name: "full",
    allow_all: true,
    allowed_tools: &[],
};

/// None: frozen session — every tool is stripped.
pub const NONE: PledgeProfile = PledgeProfile {
    name: "none",
    allow_all: false,
    allowed_tools: &[],
};

/// All built-in profiles for lookup by name.
const PROFILES: &[&PledgeProfile] = &[&READ_ONLY, &EXECUTE, &FULL, &NONE];

/// Resolves a profile name against config-defined and built-in profiles.
///
/// FAIL-CLOSED by design (the whole point of this slice): config profiles are
/// consulted first (so an operator can override a built-in), then the four
/// built-ins. An **unknown** name resolves to `none` (every tool stripped) and
/// is logged — it must NEVER fall back to `full`, which would silently grant all
/// tools on a typo. Startup configs are additionally rejected by
/// [`AppConfig::validate`](crate::config::AppConfig) via [`is_known`], but this
/// runtime guard also covers profiles set dynamically over RPC.
pub fn resolve(config: &PledgeConfig, name: &str) -> ResolvedProfile {
    if let Some(p) = config.profiles.iter().find(|p| p.name == name) {
        return ResolvedProfile {
            allow_all: p.allow_all,
            allowed_tools: p.allowed_tools.clone(),
            allowed_patterns: compile_patterns(&p.allowed_tool_patterns),
        };
    }
    if let Some(p) = PROFILES.iter().find(|p| p.name == name) {
        return ResolvedProfile {
            allow_all: p.allow_all,
            allowed_tools: p.allowed_tools.iter().map(|s| (*s).to_string()).collect(),
            allowed_patterns: Vec::new(),
        };
    }
    tracing::warn!(
        profile = %name,
        "pledge: unknown profile name — failing closed to `none` (all tools stripped)"
    );
    ResolvedProfile {
        allow_all: false,
        allowed_tools: Vec::new(),
        allowed_patterns: Vec::new(),
    }
}

/// Compiles tool-name glob patterns, silently dropping any that fail to compile.
///
/// Config-loaded patterns are validated up front by
/// [`AppConfig::validate`](crate::config::AppConfig), so a failure here can only
/// come from a profile set dynamically over RPC — in which case the offending
/// pattern is fail-closed (dropped, so it matches nothing) rather than panicking.
fn compile_patterns(patterns: &[String]) -> Vec<globset::GlobMatcher> {
    patterns
        .iter()
        .filter_map(|p| match globset::Glob::new(p) {
            Ok(g) => Some(g.compile_matcher()),
            Err(e) => {
                tracing::warn!(pattern = %p, error = %e, "pledge: invalid tool pattern dropped");
                None
            }
        })
        .collect()
}

/// Returns `true` when `name` resolves to a config-defined or built-in profile.
///
/// Used by config validation to reject an unknown `default_profile` / rule
/// profile at load time, rather than silently failing closed at runtime.
pub fn is_known(config: &PledgeConfig, name: &str) -> bool {
    config.profiles.iter().any(|p| p.name == name) || PROFILES.iter().any(|p| p.name == name)
}
