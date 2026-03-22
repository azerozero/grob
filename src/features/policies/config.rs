//! Policy configuration structs deserialized from TOML `[[policies]]` sections.

use serde::{Deserialize, Serialize};

/// Match rules for a policy. All fields are optional; `None` means "match any".
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MatchRules {
    /// Glob pattern for tenant identifier.
    #[serde(default)]
    pub tenant: Option<String>,
    /// Glob pattern for deployment zone.
    #[serde(default)]
    pub zone: Option<String>,
    /// Glob pattern for project name.
    #[serde(default)]
    pub project: Option<String>,
    /// Glob pattern for user identifier.
    #[serde(default)]
    pub user: Option<String>,
    /// Glob pattern for agent identifier.
    #[serde(default)]
    pub agent: Option<String>,
    /// Compliance tags (matches if ANY tag is present in request).
    #[serde(default)]
    pub compliance: Option<Vec<String>>,
    /// Glob pattern for model name.
    #[serde(default)]
    pub model: Option<String>,
    /// Glob pattern for provider name.
    #[serde(default)]
    pub provider: Option<String>,
    /// Matches only when DLP was triggered.
    #[serde(default)]
    pub dlp_triggered: Option<bool>,
    /// Matches only when estimated cost exceeds this threshold.
    #[serde(default)]
    pub cost_above: Option<f64>,
    /// Matches a specific route type.
    #[serde(default)]
    pub route_type: Option<String>,
}

/// Override for DLP settings when this policy matches.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct DlpOverride {
    /// Override secret action.
    #[serde(default)]
    pub secrets: Option<String>,
    /// Override PII action.
    #[serde(default)]
    pub pii: Option<String>,
    /// Override injection action.
    #[serde(default)]
    pub injection: Option<String>,
}

/// Override for rate limiting when this policy matches.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RateLimitOverride {
    /// Requests per second.
    #[serde(default)]
    pub rps: Option<u32>,
}

/// Override for routing when this policy matches.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RoutingOverride {
    /// Preferred zone for provider selection.
    #[serde(default)]
    pub prefer_zone: Option<String>,
    /// Override model name.
    #[serde(default)]
    pub model: Option<String>,
}

/// Override for budget when this policy matches.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BudgetOverride {
    /// Monthly budget in USD.
    #[serde(default)]
    pub monthly_usd: Option<f64>,
}

/// Override for log export when this policy matches.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LogExportOverride {
    /// Content mode: "none", "plaintext", "encrypted".
    #[serde(default)]
    pub content: Option<String>,
    /// Named auditor recipients for encrypted content.
    #[serde(default)]
    pub recipients: Option<Vec<String>>,
}

/// A single policy definition from the TOML config.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyConfig {
    /// Human-readable policy name.
    pub name: String,
    /// Match rules that determine when this policy applies.
    #[serde(default, rename = "match")]
    pub match_rules: MatchRules,
    /// DLP overrides.
    #[serde(default)]
    pub dlp: Option<DlpOverride>,
    /// Rate limit overrides.
    #[serde(default)]
    pub rate_limit: Option<RateLimitOverride>,
    /// Routing overrides.
    #[serde(default)]
    pub routing: Option<RoutingOverride>,
    /// Budget overrides.
    #[serde(default)]
    pub budget: Option<BudgetOverride>,
    /// Log export overrides.
    #[serde(default)]
    pub log_export: Option<LogExportOverride>,
    /// HIT (Human Intent Token) authorization overrides.
    #[serde(default)]
    pub hit: Option<super::hit::HitOverride>,
}
