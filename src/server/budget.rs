use crate::features::token_pricing::TokenCounter;
use crate::models::RouteType;
use crate::providers::AuthType;
use std::sync::Arc;
use tracing::warn;

use super::{AppError, AppState, ReloadableState};

/// Maximum retries per provider before falling back to the next mapping.
pub(crate) const MAX_RETRIES: u32 = 2;

/// Data needed to record Prometheus metrics for a completed request.
pub(crate) struct RequestMetrics<'a> {
    pub model: &'a str,
    pub provider: &'a str,
    pub route_type: &'a RouteType,
    pub status: &'a str,
    pub latency_ms: u64,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cost_usd: f64,
}

/// Record Prometheus metrics for a completed request.
///
/// Naming follows Prometheus/OpenMetrics conventions:
/// - Counters end with `_total`
/// - Units in metric name as suffix (`_seconds`, `_usd`)
/// - No label names embedded in metric names
pub(crate) fn record_request_metrics(m: &RequestMetrics<'_>) {
    let model_label = m.model.to_string();
    let provider_label = m.provider.to_string();
    let route_label = m.route_type.to_string();
    let status_label = m.status.to_string();
    metrics::counter!("grob_requests_total",
        "model" => model_label.clone(), "provider" => provider_label.clone(), "route_type" => route_label, "status" => status_label
    )
    .increment(1);
    metrics::histogram!("grob_request_duration_seconds",
        "model" => model_label.clone(), "provider" => provider_label.clone()
    )
    .record(m.latency_ms as f64 / 1000.0);
    metrics::counter!("grob_input_tokens_total",
        "model" => model_label.clone(), "provider" => provider_label.clone()
    )
    .increment(m.input_tokens as u64);
    metrics::counter!("grob_output_tokens_total",
        "model" => model_label.clone(), "provider" => provider_label.clone()
    )
    .increment(m.output_tokens as u64);
    if m.cost_usd > 0.0 {
        // Gauge used as monotonic accumulator (Counter only supports u64,
        // but cost is fractional USD). Supports rate() in PromQL.
        // Month-to-date persistent total is in grob_spend_usd (set in /metrics).
        metrics::gauge!("grob_request_cost_usd",
            "model" => model_label, "provider" => provider_label
        )
        .increment(m.cost_usd);
    }
}

/// Check budget before a request. Returns Err(AppError::BudgetExceeded) if any limit is hit.
pub(crate) async fn check_budget(
    state: &Arc<AppState>,
    inner: &Arc<ReloadableState>,
    provider_name: &str,
    model_name: &str,
) -> Result<(), AppError> {
    let budget_config = &inner.config.budget;
    let global_limit = budget_config.monthly_limit_usd;

    let provider_limit = inner
        .config
        .providers
        .iter()
        .find(|p| p.name == provider_name)
        .and_then(|p| p.budget_usd);

    let model_limit = inner.find_model(model_name).and_then(|m| m.budget_usd);

    let tracker = state.spend_tracker.lock().await;

    if let Err(e) = tracker.check_budget(
        provider_name,
        model_name,
        global_limit,
        provider_limit,
        model_limit,
    ) {
        return Err(AppError::BudgetExceeded(e.message));
    }

    if let Some(warning) = tracker.check_warnings(
        provider_name,
        model_name,
        global_limit,
        provider_limit,
        model_limit,
        budget_config.warn_at_percent,
    ) {
        warn!("Budget warning: {}", warning);
    }

    Ok(())
}

/// Record spend after a successful request (global + per-tenant if applicable)
pub(crate) async fn record_spend(
    state: &Arc<AppState>,
    provider_name: &str,
    model_name: &str,
    cost: f64,
    tenant_id: Option<&str>,
) {
    if cost > 0.0 {
        let mut tracker = state.spend_tracker.lock().await;
        if let Some(tenant) = tenant_id {
            tracker.record_tenant(tenant, provider_name, model_name, cost);
        } else {
            tracker.record(provider_name, model_name, cost);
        }
    }
}

/// Check if a provider uses OAuth (subscription = $0 cost)
pub(crate) fn is_provider_subscription(inner: &Arc<ReloadableState>, provider_name: &str) -> bool {
    inner
        .config
        .providers
        .iter()
        .find(|p| p.name == provider_name)
        .map(|p| p.auth_type == AuthType::OAuth)
        .unwrap_or(false)
}

/// Calculate cost using dynamic pricing table
pub(crate) async fn calculate_cost(
    state: &Arc<AppState>,
    actual_model: &str,
    input_tokens: u32,
    output_tokens: u32,
    is_subscription: bool,
) -> TokenCounter {
    let table = state.pricing_table.read().await;
    TokenCounter::with_pricing(
        actual_model,
        input_tokens,
        output_tokens,
        is_subscription,
        Some(&table),
    )
}

/// Check if a provider error is retryable (429, 500, 502, 503, network errors).
pub(crate) fn is_retryable(e: &crate::providers::error::ProviderError) -> bool {
    match e {
        crate::providers::error::ProviderError::ApiError { status, .. } => {
            matches!(status, 429 | 500 | 502 | 503)
        }
        crate::providers::error::ProviderError::HttpError(_) => true,
        _ => false,
    }
}

/// Calculate retry delay with exponential backoff and jitter.
pub(crate) fn retry_delay(attempt: u32) -> std::time::Duration {
    let base_ms = 200u64 * 4u64.pow(attempt);
    let jitter = rand::random::<u64>() % (base_ms / 2 + 1);
    std::time::Duration::from_millis(base_ms + jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_retryable_429() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 429,
            message: "rate limited".to_string(),
        };
        assert!(is_retryable(&err));
    }

    #[test]
    fn test_is_retryable_500() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 500,
            message: "internal error".to_string(),
        };
        assert!(is_retryable(&err));
    }

    #[test]
    fn test_is_not_retryable_400() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 400,
            message: "bad request".to_string(),
        };
        assert!(!is_retryable(&err));
    }

    #[test]
    fn test_is_not_retryable_401() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 401,
            message: "unauthorized".to_string(),
        };
        assert!(!is_retryable(&err));
    }

    #[test]
    fn test_retry_delay_exponential_backoff() {
        let d0 = retry_delay(0);
        let d1 = retry_delay(1);
        let d2 = retry_delay(2);

        // Base: 200ms * 4^attempt. With jitter, delay is in [base, base*1.5)
        assert!(d0.as_millis() >= 200 && d0.as_millis() < 400);
        assert!(d1.as_millis() >= 800 && d1.as_millis() < 1600);
        assert!(d2.as_millis() >= 3200 && d2.as_millis() < 6400);
    }

    #[test]
    fn test_record_request_metrics_does_not_panic() {
        // Smoke test: verify metrics recording doesn't panic
        record_request_metrics(&RequestMetrics {
            model: "test-model",
            provider: "test-provider",
            route_type: &RouteType::Default,
            status: "ok",
            latency_ms: 100,
            input_tokens: 50,
            output_tokens: 25,
            cost_usd: 0.001,
        });
    }
}
