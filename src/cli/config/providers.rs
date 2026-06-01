//! Provider configuration, auth type, and multi-account key pool.
//!
//! Moved here from providers/mod.rs to break the cli <-> providers dependency
//! cycle. These are TOML-deserialized config types that naturally belong alongside
//! the other config structs. providers/mod.rs re-exports them for backward
//! compatibility.

use std::collections::HashMap;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::cli::BudgetUsd;

use super::reliability::{CircuitBreakerProviderConfig, HealthCheckProviderConfig};

/// Authentication type for providers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum AuthType {
    /// API key authentication.
    #[default]
    ApiKey,
    /// OAuth 2.0 authentication.
    OAuth,
}

/// Provider configuration from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Unique provider name used in routing and logging.
    pub name: String,
    /// Provider backend type (e.g., `"anthropic"`, `"openai"`, `"gemini"`).
    pub provider_type: String,

    /// Authentication type (default: api_key).
    #[serde(default)]
    pub auth_type: AuthType,

    /// API key (required for auth_type = "apikey").
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::auth::token_store::serialize_secret_opt",
        deserialize_with = "crate::auth::token_store::deserialize_secret_opt"
    )]
    pub api_key: Option<SecretString>,

    /// OAuth provider ID (required for auth_type = "oauth").
    /// References a token stored in TokenStore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_provider: Option<String>,

    /// Google Cloud Project ID (for Vertex AI provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,

    /// Location/Region (for Vertex AI provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    /// Custom base URL override for the provider API endpoint.
    pub base_url: Option<String>,

    /// Custom HTTP headers (e.g., {"X-Novita-Source": "grob"}).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    /// List of model identifiers this provider supports.
    pub models: Vec<String>,
    /// Whether this provider is enabled; defaults to `true` when absent.
    pub enabled: Option<bool>,

    /// Per-provider monthly budget in USD (optional, overrides global).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_usd: Option<BudgetUsd>,

    /// Provider region for GDPR filtering (e.g., "eu", "us", "global").
    /// None defaults to "global" (no restriction).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,

    /// Accepts any model name not explicitly configured in `[[models]]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_through: Option<bool>,

    /// Forces a Codex reasoning effort (`"minimal"`, `"low"`, `"medium"`,
    /// `"high"`, `"xhigh"`) for this provider, overriding the per-request
    /// auto-mapping. The value is sent verbatim — the backend validates it — so
    /// newer tiers work without a grob release. Only affects the OpenAI
    /// Responses (Codex) path. Lower effort cuts latency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,

    /// Codex processing tier — `"priority"` enables faster ("1.5x") handling,
    /// `"default"` is standard. Only affects the OpenAI Responses (Codex) path.
    /// `"priority"` is applied only to models that offer it (see
    /// [`CodexOptions::priority_models`]) and silently dropped for others
    /// (codex/mini) that would reject it. Omit this field (or leave it unset) to
    /// disable — nothing is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_tier: Option<String>,

    /// Codex (OpenAI Responses API) tuning: which models support the `priority`
    /// tier / default to `xhigh` effort, and the reasoning-effort auto-mapping.
    ///
    /// Optional — the defaults track the current ChatGPT Codex line-up, so most
    /// configs omit it. Only affects the OpenAI Responses (Codex) path. See
    /// [`CodexOptions`].
    #[serde(default)]
    pub codex: CodexOptions,

    /// Path to PEM client certificate for mTLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    /// Path to PEM client private key for mTLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    /// Path to custom CA certificate for verifying the upstream server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<String>,

    /// Multi-account key pool for chaining API keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolConfig>,

    /// Passive circuit breaker configuration (RE-1a, ADR-0018).
    ///
    /// Opt-in. When absent the breaker stays disabled (Caddy defaults
    /// `max_fails = 1`, `fail_duration = 0`). Applies to every
    /// `(provider, model)` endpoint served by this provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerProviderConfig>,

    /// Active health check configuration (RE-1b, ADR-0018).
    ///
    /// Opt-in. When absent no probe runs and the provider is considered
    /// healthy by this signal. When enabled, a background tokio task
    /// polls `health_uri` on the `health_interval` cadence. Orthogonal to
    /// `circuit_breaker` above — an endpoint is healthy only when both
    /// signals agree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckProviderConfig>,

    /// Per-provider retry budget before falling back to the next mapping.
    ///
    /// Different providers benefit from different retry counts: Anthropic
    /// (smaller scale, frequent 429) is well served by the tight global
    /// default of 2, while OpenAI / OpenRouter / DeepSeek tolerate 3 thanks
    /// to better queueing and only occasional 5xx. Absent → use the global
    /// `MAX_RETRIES` default (2). An explicit `0` disables retries entirely
    /// (single attempt before falling through to the next mapping).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
}

impl ProviderConfig {
    /// Returns `true` if the provider is enabled.
    ///
    /// Semantics:
    /// - `enabled = true`  → enabled.
    /// - `enabled = false` → disabled.
    /// - `enabled` absent  → enabled (sensible default for newly added blocks).
    ///
    /// Typo safety: `#[serde(deny_unknown_fields)]` on [`ProviderConfig`]
    /// rejects misspelled keys (e.g. `enbaled`) at parse time, so an absent
    /// `enabled` field genuinely means "not specified" rather than "typo'd".
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

/// Codex (OpenAI Responses API) tuning knobs.
///
/// Shapes how grob maps requests onto the Responses API for the ChatGPT Codex
/// (OAuth) backend. Every field has a default matching OpenAI's current model
/// line-up, so the whole block is optional.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodexOptions {
    /// Models that support the `priority` (1.5x) service tier and receive the
    /// `xhigh` reasoning effort by default.
    ///
    /// Each entry is matched case-insensitively against the resolved model name:
    /// an exact match always qualifies, and a prefix match qualifies unless the
    /// model name contains `mini` (the fast tier never gets priority/xhigh unless
    /// listed verbatim). Defaults to `["gpt-5.5", "gpt-5.4"]`. Add new flagship
    /// model names here when OpenAI ships them — no grob release required.
    #[serde(default = "default_priority_models")]
    pub priority_models: Vec<String>,

    /// When `true`, the reasoning effort is auto-mapped from the request's
    /// extended-thinking budget (`>= reasoning_xhigh_min_budget` → `xhigh`, else
    /// `medium`; no thinking → `low`). When `false` (default), the effort is the
    /// flat model-based default: `xhigh` for [`Self::priority_models`], otherwise
    /// unset (the backend picks). An explicit `reasoning_effort` always wins.
    #[serde(default)]
    pub reasoning_auto_map: bool,

    /// Thinking budget (tokens) at/above which auto-mapping selects `xhigh`
    /// (below it, `medium`). Only consulted when `reasoning_auto_map` is `true`.
    /// Defaults to 16000.
    #[serde(default = "default_reasoning_xhigh_min_budget")]
    pub reasoning_xhigh_min_budget: u32,
}

impl Default for CodexOptions {
    fn default() -> Self {
        Self {
            priority_models: default_priority_models(),
            reasoning_auto_map: false,
            reasoning_xhigh_min_budget: default_reasoning_xhigh_min_budget(),
        }
    }
}

// NOTE: The flagship models that expose the `priority` (1.5x) tier per the Codex
// catalog. Prefix-matched, so future point releases (e.g. `gpt-5.5-...`) inherit
// it; `-mini` variants are excluded by the matcher as the fast/standard tier.
fn default_priority_models() -> Vec<String> {
    vec!["gpt-5.5".to_string(), "gpt-5.4".to_string()]
}

// NOTE: 16000 tokens is the threshold above which Claude Code's explicit-budget
// thinking turns warrant the backend's max reasoning tier. Only used in the
// opt-in `reasoning_auto_map` mode; the default flat mapping ignores it.
fn default_reasoning_xhigh_min_budget() -> u32 {
    16_000
}

/// Strategy for cycling through pooled API keys.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PoolStrategy {
    /// Exhaust one key before moving to the next.
    #[default]
    Sequential,
    /// Rotate keys on every request.
    RoundRobin,
    /// Use first key; only switch on error.
    Fallback,
}

/// Multi-account key pool configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PoolConfig {
    /// Key rotation strategy (default: sequential).
    #[serde(default)]
    pub strategy: PoolStrategy,
    /// Additional API keys beyond the primary `api_key`.
    pub keys: Vec<String>,
}
