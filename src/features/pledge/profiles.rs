//! Built-in pledge profiles: predefined tool allowlists per security posture.

use super::config::PledgeProfile;

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

/// Resolves a profile name to its definition, falling back to [`FULL`].
pub fn resolve(name: &str) -> &'static PledgeProfile {
    PROFILES.iter().find(|p| p.name == name).unwrap_or(&&FULL)
}
