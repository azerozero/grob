//! Budget configuration for monthly spend caps and warning thresholds.

use serde::{Deserialize, Serialize};

use crate::cli::BudgetUsd;

/// Budget configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BudgetConfig {
    /// Global monthly hard cap in USD (0 = unlimited)
    #[serde(default)]
    pub monthly_limit_usd: BudgetUsd,
    /// Log warning at this percentage of budget (default: 80)
    #[serde(default = "default_warn_percent")]
    pub warn_at_percent: u32,
}

// NOTE: 80% gives ~6 days warning before exhaustion at constant spend rate
// on a monthly budget, enough time for a human to react and adjust.
fn default_warn_percent() -> u32 {
    80
}
