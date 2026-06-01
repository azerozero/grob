use crate::features::token_pricing::TokenCounter;
use crate::models::{
    CanonicalRequest, ContentBlock, KnownContentBlock, MessageContent, RouteType, SystemPrompt,
};
use crate::providers::{AuthType, ProviderResponse};
use std::sync::Arc;
use tracing::warn;

use super::{AppState, ReloadableState, RequestError};

/// Maximum retries per provider before falling back to the next mapping.
/// NOTE: 2 retries (3 total attempts) balances latency vs resilience — most
/// transient 429/5xx errors resolve within 2 exponential-backoff cycles (~1-4s),
/// while more retries would unacceptably delay user-facing LLM responses.
///
/// Acts as the **global default**. Individual providers can override the
/// budget via `[[providers]] max_retries = N` — see [`provider_max_retries`]
/// for the per-provider lookup helper.
pub(crate) const MAX_RETRIES: u32 = 2;

/// Resolves the retry budget for a named provider.
///
/// Returns the value of `[[providers]] max_retries = N` when set, or the
/// global [`MAX_RETRIES`] default when the provider is absent or did not
/// override the budget. Used by the dispatch retry loop so per-provider
/// tuning applies without hard-coding provider names in the dispatch path.
pub(crate) fn provider_max_retries(inner: &Arc<ReloadableState>, provider_name: &str) -> u32 {
    resolve_max_retries(&inner.config.providers, provider_name)
}

/// Pure lookup helper backing [`provider_max_retries`].
///
/// Decoupled from [`ReloadableState`] so unit tests can pass a literal
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

/// Check budget before a request, scoped to a specific tenant.
///
/// Per-tenant overspend is enforced against a tenant-isolated counter so a
/// single tenant exceeding its quota cannot block other tenants. The global
/// counter is still consulted for un-tagged callers and provides the
/// rate-limiting baseline for non-tenant-aware deployments.
pub(crate) async fn check_budget_for_tenant(
    state: &Arc<AppState>,
    inner: &Arc<ReloadableState>,
    provider_name: &str,
    model_name: &str,
    tenant_id: Option<&str>,
) -> Result<(), RequestError> {
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

    // Per-tenant limits use the same numeric caps as the global config; in
    // a future revision they will key on a `[budget.tenants]` map. Tenants
    // overspending their slice cannot trip the global counter for other
    // tenants because `check_tenant_budget` reads the per-tenant cache.
    if let Some(tenant) = tenant_id {
        if let Err(e) = tracker.check_tenant_budget(
            Some(tenant),
            provider_name,
            model_name,
            global_limit,
            provider_limit,
            model_limit,
        ) {
            return Err(RequestError::BudgetExceeded {
                limit_usd: e.limit_usd,
                actual_usd: e.actual_usd,
            });
        }
    } else if let Err(e) = tracker.check_budget(
        provider_name,
        model_name,
        global_limit,
        provider_limit,
        model_limit,
    ) {
        return Err(RequestError::BudgetExceeded {
            limit_usd: e.limit_usd,
            actual_usd: e.actual_usd,
        });
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

/// Record spend after a successful request (global + per-tenant if applicable).
///
/// Honours [`crate::cli::TokenCountingMode`]:
///
/// - [`Api`](crate::cli::TokenCountingMode::Api) (default): the spend is
///   committed synchronously before this function returns, so the next budget
///   check sees it immediately (strong consistency).
/// - [`Estimate`](crate::cli::TokenCountingMode::Estimate): the spend mutex and
///   journal write are moved off the response hot path into a detached task, so
///   request latency is never gated on disk I/O. Counters consolidate a beat
///   later; under heavy concurrency a budget check may lag by at most one
///   in-flight request.
pub(crate) async fn record_spend(
    state: &Arc<AppState>,
    provider_name: &str,
    model_name: &str,
    cost: f64,
    tenant_id: Option<&str>,
) {
    if cost <= 0.0 {
        return;
    }

    // Cheap Copy read; the guard is dropped before any `.await`.
    let mode = state.snapshot().config.pricing.token_counting;

    match mode {
        crate::cli::TokenCountingMode::Api => {
            commit_spend(state, provider_name, model_name, cost, tenant_id).await;
        }
        crate::cli::TokenCountingMode::Estimate => {
            // Consolidate the API-reported cost asynchronously so the response
            // path doesn't wait on the spend mutex / JSONL append.
            let state = state.clone();
            let provider = provider_name.to_string();
            let model = model_name.to_string();
            let tenant = tenant_id.map(str::to_string);
            tokio::spawn(async move {
                commit_spend(&state, &provider, &model, cost, tenant.as_deref()).await;
            });
        }
    }
}

/// Locks the spend tracker and records the cost (global or per-tenant).
async fn commit_spend(
    state: &Arc<AppState>,
    provider_name: &str,
    model_name: &str,
    cost: f64,
    tenant_id: Option<&str>,
) {
    let mut tracker = state.observability.spend_tracker.lock().await;
    if let Some(tenant) = tenant_id {
        tracker.record_tenant(tenant, provider_name, model_name, cost);
    } else {
        tracker.record(provider_name, model_name, cost);
    }
}

/// Returns `true` when token counting runs in off-hot-path estimate mode.
pub(crate) fn is_estimate_mode(state: &Arc<AppState>) -> bool {
    matches!(
        state.snapshot().config.pricing.token_counting,
        crate::cli::TokenCountingMode::Estimate
    )
}

/// Resolves the token counts to bill, falling back to a local estimate.
///
/// Provider-reported usage is authoritative. Only when a provider omits usage
/// entirely (both counts zero) **and** token counting is in
/// [`Estimate`](crate::cli::TokenCountingMode::Estimate) mode does this estimate
/// from the request and response text, so genuinely-consumed tokens are not
/// silently billed as `$0`. In `api` mode (or with reported usage) the provider
/// numbers are returned unchanged.
pub(crate) fn effective_token_counts(
    state: &Arc<AppState>,
    request: &CanonicalRequest,
    response: &ProviderResponse,
) -> (u32, u32) {
    let usage = &response.usage;
    let usage_absent = usage.input_tokens == 0 && usage.output_tokens == 0;
    if usage_absent && is_estimate_mode(state) {
        let input = estimate_input_tokens(request);
        let output = estimate_output_tokens(response);
        tracing::debug!(
            estimated_input_tokens = input,
            estimated_output_tokens = output,
            "provider omitted usage; billing from local token estimate"
        );
        (input, output)
    } else {
        (usage.input_tokens, usage.output_tokens)
    }
}

/// Converts a character count to an approximate token count (~4 chars/token).
///
/// A deliberately cheap, tokenizer-free heuristic that only feeds the
/// estimate-mode fallback; saturates rather than overflowing on huge inputs.
/// Shared by the non-streaming estimators and the streaming spend fallback
/// (which passes an accumulated `text_delta` length directly).
pub(crate) fn tokens_from_chars(chars: usize) -> u32 {
    u32::try_from(chars.div_ceil(4)).unwrap_or(u32::MAX)
}

/// Estimates input tokens from a request's system prompt and message text.
///
/// Non-text blocks (images, tool I/O) are ignored — this is a coarse fallback.
pub(crate) fn estimate_input_tokens(req: &CanonicalRequest) -> u32 {
    let mut chars = 0usize;
    if let Some(system) = &req.system {
        match system {
            SystemPrompt::Text(t) => chars += t.chars().count(),
            SystemPrompt::Blocks(blocks) => {
                chars += blocks.iter().map(|b| b.text.chars().count()).sum::<usize>();
            }
        }
    }
    for msg in &req.messages {
        match &msg.content {
            MessageContent::Text(t) => chars += t.chars().count(),
            MessageContent::Blocks(blocks) => chars += content_blocks_chars(blocks),
        }
    }
    tokens_from_chars(chars)
}

/// Estimates output tokens from a response's text content blocks.
pub(crate) fn estimate_output_tokens(resp: &ProviderResponse) -> u32 {
    tokens_from_chars(content_blocks_chars(&resp.content))
}

/// Sums the character count of text content blocks, ignoring non-text blocks.
fn content_blocks_chars(blocks: &[ContentBlock]) -> usize {
    blocks
        .iter()
        .map(|b| match b {
            ContentBlock::Known(KnownContentBlock::Text { text, .. }) => text.chars().count(),
            _ => 0,
        })
        .sum()
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

    fn request_with_text(system: Option<&str>, user: &str) -> CanonicalRequest {
        let mut body = serde_json::json!({
            "model": "m",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": user}],
        });
        if let Some(s) = system {
            body["system"] = serde_json::json!(s);
        }
        serde_json::from_value(body).expect("valid request")
    }

    fn response_with_text(text: &str) -> ProviderResponse {
        serde_json::from_value(serde_json::json!({
            "id": "r",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
            "model": "m",
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }))
        .expect("valid response")
    }

    #[test]
    fn tokens_from_chars_rounds_up() {
        assert_eq!(tokens_from_chars(0), 0);
        assert_eq!(tokens_from_chars(1), 1);
        assert_eq!(tokens_from_chars(4), 1);
        assert_eq!(tokens_from_chars(5), 2);
    }

    #[test]
    fn estimate_input_counts_system_and_messages() {
        // "you are concise" (15) + "hello there friend" (18) = 33 chars.
        let req = request_with_text(Some("you are concise"), "hello there friend");
        assert_eq!(estimate_input_tokens(&req), tokens_from_chars(15 + 18));
    }

    #[test]
    fn estimate_input_ignores_absent_system() {
        let req = request_with_text(None, "abcd"); // 4 chars → 1 token
        assert_eq!(estimate_input_tokens(&req), 1);
    }

    #[test]
    fn estimate_output_counts_text_blocks() {
        // "abcd efgh" = 9 chars → ceil(9/4) = 3 tokens.
        assert_eq!(estimate_output_tokens(&response_with_text("abcd efgh")), 3);
    }

    // ── per-provider max_retries resolution ────────────────────────────────

    /// Builds a stub provider config carrying only the fields the lookup reads.
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
            reasoning_effort: None,
            service_tier: None,
            codex: crate::cli::CodexOptions::default(),
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
    fn resolve_max_retries_honors_override() {
        // OpenAI: better queueing — 3 retries amortise transient 429s.
        let providers = vec![provider_with_retries("openai", Some(3))];
        assert_eq!(resolve_max_retries(&providers, "openai"), 3);
    }

    #[test]
    fn resolve_max_retries_honors_zero_override() {
        // Explicit `max_retries = 0` disables retries (single attempt, no fallback retry).
        let providers = vec![provider_with_retries("flaky", Some(0))];
        assert_eq!(resolve_max_retries(&providers, "flaky"), 0);
    }

    #[test]
    fn resolve_max_retries_isolates_per_provider_overrides() {
        // Distinct budgets must not leak between providers.
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
