//! Resolved policy: the merged result of all matching policies for a request.

use super::config::{
    BudgetOverride, DlpOverride, LogExportOverride, RateLimitOverride, RoutingOverride,
};
use super::hit::HitOverride;

/// Merged policy result after evaluating all matching policies.
#[derive(Debug, Clone, Default)]
pub struct ResolvedPolicy {
    /// Whether any policy matched (false = default deny).
    pub matched: bool,
    /// Merged DLP overrides.
    pub dlp: Option<DlpOverride>,
    /// Merged rate limit overrides (most restrictive).
    pub rate_limit: Option<RateLimitOverride>,
    /// Merged routing overrides.
    pub routing: Option<RoutingOverride>,
    /// Merged budget overrides (most restrictive).
    pub budget: Option<BudgetOverride>,
    /// Merged log export overrides (union of recipients).
    pub log_export: Option<LogExportOverride>,
    /// HIT authorization overrides.
    pub hit: Option<HitOverride>,
}

impl ResolvedPolicy {
    /// Returns a default-deny policy (no match found).
    pub fn default_deny() -> Self {
        Self {
            matched: false,
            ..Default::default()
        }
    }
}
