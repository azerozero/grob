use crate::features::token_pricing::TokenCounter;
use crate::models::RouteType;
use crate::providers::AuthType;
use std::sync::Arc;
use tracing::warn;

use super::{AppError, AppState, ReloadableState};

/// Maximum retries per provider before falling back to the next mapping.
/// NOTE: 2 retries (3 total attempts) balances latency vs resilience — most
/// transient 429/5xx errors resolve within 2 exponential-backoff cycles (~1-4s),
/// while more retries would unacceptably delay user-facing LLM responses.
///
/// Acts as the **global default**. Individual providers can override the
/// budget via `[[providers]] max_retries = N` — see
/// [`provider_max_retries`] for the per-provider lookup helper.
pub(crate) const MAX_RETRIES: u32 = 2;

/// Resolves the retry budget for a named provider.
///
/// Returns the value of `[[providers]] max_retries = N` when set, or the
/// global [`MAX_RETRIES`] default when the provider is absent or did not
/// override the budget. Used by the dispatch retry loop so per-provider
/// tuning (Anthropic = 2, OpenAI / OpenRouter = 3, DeepSeek = 3) applies
/// without hard-coding provider names in the dispatch path.
pub(crate) fn provider_max_retries(inner: &Arc<ReloadableState>, provider_name: &str) -> u32 {
    resolve_max_retries(&inner.config.providers, provider_name)
}

/// Pure lookup helper for [`provider_max_retries`].
///
/// Decoupled from `ReloadableState` so unit tests can pass a literal
/// `[ProviderConfig]` slice without standing up the full app state graph.
pub(crate) fn resolve_max_retries(
    providers: &[crate::cli::ProviderConfig],
    provider_name: &str,
) -> u32 {
    providers
        .iter()
        .find(|p| p.name == provider_name)
        .and_then(|p| p.max_retries)
        .unwrap_or(MAX_RETRIES)
}

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
    let global_limit = budget_config.monthly_limit_usd.value();

    let provider_limit = inner
        .config
        .providers
        .iter()
        .find(|p| p.name == provider_name)
        .and_then(|p| p.budget_usd.map(|b| b.value()));

    let model_limit = inner
        .find_model(model_name)
        .and_then(|m| m.budget_usd.map(|b| b.value()));

    let tracker = state.observability.spend_tracker.lock().await;

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
        &crate::features::token_pricing::spend::BudgetLimits {
            global_limit,
            provider_limit,
            model_limit,
            warn_at_percent: budget_config.warn_at_percent,
        },
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
        let mut tracker = state.observability.spend_tracker.lock().await;
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
    let table = state.observability.pricing_table.read().await;
    TokenCounter::with_pricing(
        actual_model,
        input_tokens,
        output_tokens,
        is_subscription,
        Some(&table),
    )
}

/// Check if a provider error is retryable (429, 500, 502, 503, network errors).
///
/// Notably excludes 401 (`authentication_error`): a revoked OAuth token is a
/// permanent failure that requires operator action (`grob connect
/// --force-reauth`). 401 with `rate_limit_error` payload is handled as 429.
pub(crate) fn is_retryable(e: &crate::providers::error::ProviderError) -> bool {
    match e {
        crate::providers::error::ProviderError::ApiError { status, message } => match status {
            429 | 500 | 502 | 503 => true,
            401 => is_rate_limit_payload(message),
            _ => false,
        },
        crate::providers::error::ProviderError::HttpError(_) => true,
        _ => false,
    }
}

/// Returns `true` when a 401 payload actually carries a `rate_limit_error`.
///
/// Some upstreams (notably Anthropic) will return 401 with
/// `"type": "rate_limit_error"` — that is a transient signal, not a revoked
/// credential. Any other 401 is treated as a permanent authentication failure.
pub(crate) fn is_rate_limit_payload(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("rate_limit_error") || lower.contains("\"rate_limit\"")
}

/// Returns `true` when a 401 response indicates a revoked or invalid OAuth token.
///
/// Used by the provider loop to abort fallback and surface a terminal
/// `authentication_error` to the client.
pub(crate) fn is_auth_revoked_error(e: &crate::providers::error::ProviderError) -> bool {
    match e {
        crate::providers::error::ProviderError::ApiError {
            status: 401,
            message,
        } => !is_rate_limit_payload(message),
        _ => false,
    }
}

/// Base delay (ms) before the first retry.
/// NOTE: 200ms is long enough for provider-side rate-limit windows to rotate,
/// short enough to keep total retry budget under ~5s for 2 retries.
const BASE_RETRY_MS: u64 = 200;
/// Exponential growth factor for successive retries (200ms -> 800ms -> 3200ms).
/// NOTE: Factor of 4 (not 2) reduces collision probability with other clients
/// hitting the same rate-limit window, per AWS exponential-backoff guidance.
const RETRY_BACKOFF_FACTOR: u64 = 4;

/// Calculate retry delay with exponential backoff and jitter.
pub(crate) fn retry_delay(attempt: u32) -> std::time::Duration {
    let base_ms = BASE_RETRY_MS * RETRY_BACKOFF_FACTOR.pow(attempt);
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
    fn test_401_with_rate_limit_payload_is_retryable() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 401,
            message:
                r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}"#
                    .to_string(),
        };
        assert!(is_retryable(&err));
        assert!(!is_auth_revoked_error(&err));
    }

    #[test]
    fn test_401_authentication_error_marks_revoked() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 401,
            message: r#"{"type":"error","error":{"type":"authentication_error","message":"invalid bearer token"}}"#
                .to_string(),
        };
        assert!(!is_retryable(&err));
        assert!(is_auth_revoked_error(&err));
    }

    #[test]
    fn test_429_is_not_auth_revoked() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 429,
            message: "rate limited".to_string(),
        };
        assert!(is_retryable(&err));
        assert!(!is_auth_revoked_error(&err));
    }

    #[test]
    fn test_500_is_retryable_not_auth_revoked() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 500,
            message: "internal".to_string(),
        };
        assert!(is_retryable(&err));
        assert!(!is_auth_revoked_error(&err));
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

    // ── per-provider max_retries resolution ────────────────────────────────

    /// Builds a stub provider config — only the two fields the lookup reads.
    fn provider_with_retries(name: &str, max_retries: Option<u32>) -> crate::cli::ProviderConfig {
        crate::cli::ProviderConfig {
            name: name.into(),
            provider_type: "stub".into(),
            auth_type: crate::cli::AuthType::ApiKey,
            api_key: None,
            oauth_provider: None,
            project_id: None,
            location: None,
            base_url: None,
            headers: None,
            models: vec![],
            enabled: Some(true),
            budget_usd: None,
            region: None,
            pass_through: None,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            pool: None,
            circuit_breaker: None,
            health_check: None,
            max_retries,
        }
    }

    #[test]
    fn resolve_max_retries_falls_back_to_default_for_unknown_provider() {
        let providers = vec![provider_with_retries("anthropic", Some(5))];
        assert_eq!(resolve_max_retries(&providers, "openai"), MAX_RETRIES);
    }

    #[test]
    fn resolve_max_retries_falls_back_to_default_when_unset() {
        let providers = vec![provider_with_retries("anthropic", None)];
        assert_eq!(resolve_max_retries(&providers, "anthropic"), MAX_RETRIES);
    }

    #[test]
    fn resolve_max_retries_honors_anthropic_override_at_two() {
        // Anthropic: smaller scale, frequent 429 — keep budget tight at 2.
        let providers = vec![provider_with_retries("anthropic", Some(2))];
        assert_eq!(resolve_max_retries(&providers, "anthropic"), 2);
    }

    #[test]
    fn resolve_max_retries_honors_openai_override_at_three() {
        // OpenAI: better queueing — 3 retries amortise transient 429s.
        let providers = vec![provider_with_retries("openai", Some(3))];
        assert_eq!(resolve_max_retries(&providers, "openai"), 3);
    }

    #[test]
    fn resolve_max_retries_honors_openrouter_override_at_three() {
        // DeepSeek / OpenRouter: sporadic 5xx — 3 retries.
        let providers = vec![provider_with_retries("openrouter", Some(3))];
        assert_eq!(resolve_max_retries(&providers, "openrouter"), 3);
    }

    #[test]
    fn resolve_max_retries_honors_zero_override() {
        // Explicit `max_retries = 0` disables retries (no fallback).
        let providers = vec![provider_with_retries("flaky", Some(0))];
        assert_eq!(resolve_max_retries(&providers, "flaky"), 0);
    }

    #[test]
    fn resolve_max_retries_isolates_per_provider_overrides() {
        // Two providers with different budgets — neither should leak.
        let providers = vec![
            provider_with_retries("anthropic", Some(2)),
            provider_with_retries("openai", Some(3)),
            provider_with_retries("default-provider", None),
        ];
        assert_eq!(resolve_max_retries(&providers, "anthropic"), 2);
        assert_eq!(resolve_max_retries(&providers, "openai"), 3);
        assert_eq!(
            resolve_max_retries(&providers, "default-provider"),
            MAX_RETRIES
        );
    }
}
