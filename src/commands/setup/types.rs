//! Shared types, enums, and constants for the setup wizard.
//!
//! Internal to the `setup` module; submodules access these through
//! `super::types::*`.

/// Known coding tools that grob can proxy.
pub(super) const TOOLS: &[ToolInfo] = &[
    ToolInfo {
        name: "Claude Code",
        tag: "anthropic",
        endpoint: "/v1/messages",
        needs_anthropic: true,
        needs_openai: false,
    },
    ToolInfo {
        name: "Codex CLI",
        tag: "openai",
        endpoint: "/v1/responses",
        needs_anthropic: false,
        needs_openai: true,
    },
    ToolInfo {
        name: "Forge",
        tag: "anthropic",
        endpoint: "/v1/messages",
        needs_anthropic: true,
        needs_openai: false,
    },
    ToolInfo {
        name: "Aider",
        tag: "any",
        endpoint: "/v1/messages or /v1/chat/completions",
        needs_anthropic: true,
        needs_openai: false,
    },
    ToolInfo {
        name: "Continue.dev",
        tag: "any",
        endpoint: "/v1/messages or /v1/chat/completions",
        needs_anthropic: true,
        needs_openai: false,
    },
    ToolInfo {
        name: "Cursor",
        tag: "openai",
        endpoint: "/v1/chat/completions (BYOK)",
        needs_anthropic: false,
        needs_openai: true,
    },
];

pub(super) struct ToolInfo {
    pub(super) name: &'static str,
    pub(super) tag: &'static str,
    pub(super) endpoint: &'static str,
    pub(super) needs_anthropic: bool,
    pub(super) needs_openai: bool,
}

/// Auth capabilities per provider.
pub(super) const PROVIDER_AUTH: &[(&str, bool, &str, &str)] = &[
    // (name, supports_oauth, oauth_id, env_var)
    ("anthropic", true, "anthropic-max", "ANTHROPIC_API_KEY"),
    ("openai", true, "openai-codex", "OPENAI_API_KEY"),
    ("gemini", true, "gemini", "GEMINI_API_KEY"),
    ("openrouter", false, "", "OPENROUTER_API_KEY"),
    ("deepseek", false, "", "DEEPSEEK_API_KEY"),
    ("mistral", false, "", "MISTRAL_API_KEY"),
];

/// Known top-level TOML sections in grob.toml (for schema drift detection).
pub(super) const KNOWN_SECTIONS: &[&str] = &[
    "version",
    "server",
    "router",
    "providers",
    "models",
    "presets",
    "budget",
    "dlp",
    "auth",
    "tap",
    "security",
    "cache",
    "compliance",
    "tool_layer",
    "mcp",
    "user",
    "otel",
    "log_export",
    "pledge",
    "tee",
    "fips",
    "policies",
    "harness",
];

/// Deprecated config keys and their migration hints.
pub(super) const DEPRECATED_KEYS: &[(&str, &str)] = &[
    (
        "openai_compat",
        "Renamed to [server.openai_compat]. Move the section under [server].",
    ),
    (
        "rate_limit",
        "Moved to [security]. Use rate_limit_rps and rate_limit_burst under [security].",
    ),
];

/// Overrides collected from the auth screen.
pub(super) struct AuthOverride {
    pub(super) provider: String,
    pub(super) use_oauth: bool,
    pub(super) oauth_id: String,
    pub(super) entered_key: Option<String>,
    pub(super) env_var: String,
}

/// Custom endpoint configured during setup.
pub(super) struct CustomEndpoint {
    /// User-chosen name for this provider (e.g. "my-llm").
    pub(super) name: String,
    /// `"openai_compatible"` or `"anthropic_compatible"`.
    pub(super) provider_type: String,
    /// Base URL (e.g. `https://my-llm.company.com/v1`).
    pub(super) base_url: String,
    /// API key entered by the user (None = set later via env var).
    pub(super) api_key: Option<String>,
}

/// All wizard choices, collected before any disk write.
pub(super) struct Choices {
    pub(super) tools: Vec<usize>,
    pub(super) preset: String,
    pub(super) preset_desc: String,
    pub(super) auth: Vec<AuthOverride>,
    pub(super) fallback: FallbackChoice,
    pub(super) fallback_key: Option<String>,
    pub(super) custom_endpoints: Vec<CustomEndpoint>,
    pub(super) compliance: Compliance,
    pub(super) budget: Option<BudgetChoice>,
}

/// Monthly budget cap chosen by the user.
///
/// `currency` is cosmetic only : the config schema stores the numeric value
/// in `[budget] monthly_limit_usd` regardless of the currency label. Grob
/// does no forex conversion.
#[derive(Clone)]
pub(super) struct BudgetChoice {
    pub(super) amount: i64,
    pub(super) currency: &'static str,
}

/// Fallback provider chosen in the wizard.
///
/// Always prompted (even when a preset ships a fallback) so the user can
/// explicitly opt out and avoid the phantom `$OPENROUTER_API_KEY not set`
/// warning at startup.
#[derive(Clone)]
pub(super) enum FallbackChoice {
    /// No fallback provider. Any preset-shipped fallback provider and
    /// related model mappings are stripped from the written config.
    None,
    /// OpenRouter (the common default, reads `$OPENROUTER_API_KEY`).
    OpenRouter,
    /// Gemini OAuth/API key as fallback.
    Gemini,
    /// Keep whatever fallback the preset defines (expert mode).
    KeepPreset,
}

#[derive(Clone, Copy)]
pub(super) enum Compliance {
    Standard,
    Dlp,
    EuGdpr,
    Enterprise,
    LocalOnly,
}

/// Flags from CLI arguments and environment overrides.
pub struct SetupFlags {
    /// Accepts all defaults without interactive prompts.
    pub yes: bool,
    /// Previews changes without writing to disk.
    pub dry_run: bool,
    /// Restricts the wizard to a single section (providers, budget, compliance, fallback).
    pub edit_section: Option<String>,
}
