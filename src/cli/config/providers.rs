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
