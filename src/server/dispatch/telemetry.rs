use crate::providers::ProviderResponse;
use tracing::info;

use super::DispatchContext;
use crate::server::{calculate_cost, record_request_metrics, record_spend, RequestMetrics};

/// Outcome of a successful provider dispatch, used for metrics and telemetry.
pub(crate) struct DispatchOutcome<'a> {
    pub mapping: &'a crate::cli::ModelMapping,
    pub decision: &'a crate::models::RouteDecision,
    pub response: &'a ProviderResponse,
    pub latency_ms: u64,
}

/// Calculate cost and emit performance metrics + Prometheus counters.
pub(crate) async fn calculate_and_record_metrics(
    ctx: &DispatchContext<'_>,
    outcome: &DispatchOutcome<'_>,
    is_subscription: bool,
) -> f64 {
    let mapping = outcome.mapping;
    let response = outcome.response;
    let decision = outcome.decision;
    let latency_ms = outcome.latency_ms;
    let tok_s = (response.usage.output_tokens as f32 * 1000.0) / latency_ms as f32;
    let cost = calculate_cost(
        ctx.state,
        &mapping.actual_model,
        response.usage.input_tokens,
        response.usage.output_tokens,
        is_subscription,
    )
    .await;
    info!(
        "📊 {}@{} {}ms {:.0}t/s {}tok ${:.4}{}",
        mapping.actual_model,
        mapping.provider,
        latency_ms,
        tok_s,
        response.usage.output_tokens,
        cost.estimated_cost_usd,
        if is_subscription {
            " (subscription)"
        } else {
            ""
        }
    );

    record_request_metrics(&RequestMetrics {
        model: &mapping.actual_model,
        provider: &mapping.provider,
        route_type: &decision.route_type,
        status: "ok",
        latency_ms,
        input_tokens: response.usage.input_tokens,
        output_tokens: response.usage.output_tokens,
        cost_usd: cost.estimated_cost_usd,
    });

    cost.estimated_cost_usd
}

/// Record spend tracking, message tracing, and audit logging for a successful response.
pub(crate) async fn record_success_telemetry(
    ctx: &DispatchContext<'_>,
    outcome: &DispatchOutcome<'_>,
    cost_usd: f64,
) {
    let mapping = outcome.mapping;
    let decision = outcome.decision;
    let response = outcome.response;
    let latency_ms = outcome.latency_ms;
    record_spend(
        ctx.state,
        &mapping.provider,
        &decision.model_name,
        cost_usd,
        ctx.tenant_id.as_deref(),
    )
    .await;

    if let Some(ref trace_id) = ctx.trace_id {
        ctx.state
            .observability
            .message_tracer
            .trace_response(trace_id, response, latency_ms);
    }

    ctx.log_audit_if_enabled(super::AuditEntry {
        action: crate::security::audit_log::AuditEvent::Response,
        backend: &mapping.provider,
        dlp_rules: vec![],
        duration_ms: latency_ms,
        model_name: Some(&mapping.actual_model),
        token_counts: Some((response.usage.input_tokens, response.usage.output_tokens)),
        risk_level: Some(crate::security::audit_log::RiskLevel::Low),
        dlp_blocked: false,
        dlp_had_injection: false,
        dlp_had_pii: false,
        dlp_had_redact_or_warn: false,
    });
}

/// Serialize the response and store it in the cache if enabled.
pub(crate) async fn store_response_cache(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
    cache_key: &Option<String>,
    response: &ProviderResponse,
) -> Option<Vec<u8>> {
    let response_bytes = serde_json::to_vec(response).ok();

    if let (Some(ref cache), Some(ref key), Some(ref bytes)) = (
        &ctx.state.security.response_cache,
        cache_key,
        &response_bytes,
    ) {
        cache
            .put(
                key.clone(),
                crate::cache::CachedResponse {
                    body: bytes.clone(),
                    content_type: "application/json".to_string(),
                    provider: mapping.provider.clone(),
                    model: mapping.actual_model.clone(),
                },
            )
            .await;
    }

    response_bytes
}
