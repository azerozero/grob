//! Budget configuration for monthly spend caps and warning thresholds.

use serde::{Deserialize, Serialize};

use crate::cli::BudgetUsd;

/// Budget configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConfig {
    /// Global monthly hard cap in USD (0 = unlimited)
    #[serde(default)]
    pub monthly_limit_usd: BudgetUsd,
    /// Log warning at this percentage of budget (default: 80)
    #[serde(default = "default_warn_percent")]
    pub warn_at_percent: u32,
    /// Number of replicas sharing this budget (default 1).
    ///
    /// Spend is tracked per process: the in-memory total is seeded once at
    /// startup and updated only by this replica, so a peer writing to the same
    /// journal stays invisible until restart. Mounting a shared volume does
    /// **not** make the budget shared. N replicas therefore each allow
    /// `monthly_limit_usd`, and the fleet can spend `N ×` the cap.
    ///
    /// Declaring the replica count makes each one enforce its share, turning
    /// the configured amount into a real ceiling on what the fleet can spend.
    /// Needs no coordination: no shared store, no gossip, not one packet.
    ///
    /// The cost is utilisation — a replica cannot spend an idle peer's share —
    /// which for a *cost* cap is usually the right trade: under-spending is
    /// recoverable, an overrun is not.
    #[serde(default = "default_budget_replicas")]
    pub replicas: u32,
    /// Safety margin withheld from the budget, in percent (default 0).
    ///
    /// Absorbs what division cannot: a replica restarting mid-month replays the
    /// journal and resumes from the recorded total, but rounding and in-flight
    /// requests still leave a small residue.
    #[serde(default)]
    pub margin_percent: u32,
}

// One daemon is the default deployment, so the configured budget is already
// the fleet budget.
fn default_budget_replicas() -> u32 {
    1
}

// Hand-written rather than derived: a derived `Default` would give
// `replicas = 0`, and dividing a budget by zero replicas is meaningless.
impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            monthly_limit_usd: BudgetUsd::default(),
            warn_at_percent: default_warn_percent(),
            replicas: default_budget_replicas(),
            margin_percent: 0,
        }
    }
}

// NOTE: 80% gives ~6 days warning before exhaustion at constant spend rate
// on a monthly budget, enough time for a human to react and adjust.
fn default_warn_percent() -> u32 {
    80
}
