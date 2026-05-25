//! Pricing source and token-accounting configuration.
//!
//! Controls two independent concerns:
//!
//! - **Where prices come from**: the built-in hardcoded table (offline-safe,
//!   the default) versus a live OpenRouter fetch refreshed in the background.
//! - **How token usage is accounted**: trusting provider-reported usage on the
//!   response hot path (`api`) versus consolidating it off the hot path
//!   (`estimate`) so request latency is never gated on the spend journal.

use serde::{Deserialize, Serialize};

/// Strategy for accounting token usage into the spend tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenCountingMode {
    /// Trust the provider-reported usage and record spend synchronously.
    ///
    /// Strong consistency: a request's cost is committed to the spend journal
    /// before the response returns, so budget checks see it immediately.
    #[default]
    Api,
    /// Record spend off the response hot path via a detached task.
    ///
    /// Provider-reported usage remains the source of truth; the spend mutex
    /// and JSONL journal write are moved out of the request path so latency is
    /// not gated on disk I/O. Counters consolidate a fraction of a second
    /// later, so concurrent budget checks may lag by at most one in-flight
    /// request. A local heuristic estimate is used only when a provider omits
    /// usage entirely.
    Estimate,
}

/// Pricing source and token-accounting settings (`[pricing]` in `grob.toml`).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PricingConfig {
    /// Fetch live prices from OpenRouter at startup and refresh periodically.
    ///
    /// Defaults to `false`: grob uses only its built-in hardcoded price table,
    /// which means startup performs **no network I/O** and works air-gapped.
    /// When enabled, the initial fetch runs in a background task (it never
    /// blocks the listener from binding) and merges over the hardcoded table.
    #[serde(default)]
    pub fetch_openrouter: bool,
    /// Background refresh interval in hours when `fetch_openrouter` is enabled.
    ///
    /// Clamped to a minimum of 1 hour at runtime. Ignored when fetching is off.
    #[serde(default = "default_refresh_interval_hours")]
    pub refresh_interval_hours: u64,
    /// Token-counting mode: `api` (synchronous, default) or `estimate` (async).
    #[serde(default)]
    pub token_counting: TokenCountingMode,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            fetch_openrouter: false,
            refresh_interval_hours: default_refresh_interval_hours(),
            token_counting: TokenCountingMode::default(),
        }
    }
}

// NOTE: OpenRouter prices change rarely (model launches, occasional cuts), so a
// daily refresh keeps the table fresh without hammering a third-party endpoint.
fn default_refresh_interval_hours() -> u64 {
    24
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_offline_and_synchronous() {
        let cfg = PricingConfig::default();
        assert!(
            !cfg.fetch_openrouter,
            "OpenRouter fetch must be off by default (no startup network I/O)"
        );
        assert_eq!(cfg.refresh_interval_hours, 24);
        assert_eq!(cfg.token_counting, TokenCountingMode::Api);
    }

    #[test]
    fn parses_estimate_mode_and_keeps_refresh_default() {
        let cfg: PricingConfig =
            toml::from_str("fetch_openrouter = true\ntoken_counting = \"estimate\"").unwrap();
        assert!(cfg.fetch_openrouter);
        assert_eq!(cfg.token_counting, TokenCountingMode::Estimate);
        assert_eq!(cfg.refresh_interval_hours, 24);
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(toml::from_str::<PricingConfig>("bogus_field = true").is_err());
    }
}
