//! `grob/budget/*` namespace: spend tracking and breakdown.

use super::auth::{require_role, CallerIdentity};
use super::types::{BudgetCurrent, Role, SpendBreakdown};
use crate::server::AppState;
use jsonrpsee::types::ErrorObjectOwned;
use std::sync::Arc;

/// Returns the current month's spend and budget limit.
pub async fn current(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<BudgetCurrent, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let inner = state.snapshot();
    let tracker = state.observability.spend_tracker.lock().await;
    let total = tracker.total();
    let budget = inner.config.budget.monthly_limit_usd.value();

    Ok(BudgetCurrent {
        total_usd: total,
        budget_usd: budget,
        remaining_usd: if budget > 0.0 {
            (budget - total).max(0.0)
        } else {
            f64::INFINITY
        },
    })
}

/// Returns per-provider spend breakdown for the current period.
pub async fn breakdown(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<Vec<SpendBreakdown>, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let tracker = state.observability.spend_tracker.lock().await;
    let data = tracker.provider_breakdown();

    Ok(data
        .into_iter()
        .map(|(provider, spent_usd, request_count)| SpendBreakdown {
            provider,
            spent_usd,
            request_count,
        })
        .collect())
}
