//! Shared dispatch pipeline for provider routing.
//!
//! Both `handle_messages()` (Anthropic native) and `handle_openai_chat_completions()`
//! delegate to the single `dispatch()` function, which orchestrates the full pipeline:
//! DLP scanning → cache lookup → routing → provider loop with fallback → audit → response.

mod provider_loop;
mod telemetry;

use crate::cli::ModelStrategy;
use crate::features::dlp::DlpEngine;
use crate::models::CanonicalRequest;
use crate::providers::ProviderResponse;
use axum::http::HeaderMap;
use bytes::Bytes;
use futures::stream::Stream;
use std::pin::Pin;
use std::sync::Arc;

use super::{
    apply_transparency_headers, calculate_cost, is_provider_subscription, log_audit,
    record_request_metrics, resolve_provider_mappings, sanitize_provider_response_reported,
    AppError, AppState, AuditCompliance, AuditParams, ReloadableState, RequestMetrics,
};
use crate::features::watch::events::{DlpDirection, WatchEvent};

/// All context needed to dispatch a request through the provider pipeline.
pub(crate) struct DispatchContext<'a> {
    pub state: &'a Arc<AppState>,
    pub inner: &'a Arc<ReloadableState>,
    pub dlp: &'a Option<Arc<DlpEngine>>,
    /// Original model name as requested by the client.
    pub model: String,
    /// Whether the client requested a streaming response.
    pub is_streaming: bool,
    /// Tenant identifier from JWT claims (multi-tenant deployments).
    pub tenant_id: Option<String>,
    /// Client IP for audit logging.
    pub peer_ip: String,
    pub req_id: &'a str,
    pub start_time: std::time::Instant,
    pub headers: &'a HeaderMap,
    /// Message tracer context. None for OpenAI compat endpoint.
    pub trace_id: Option<String>,
}

/// Variable fields for an audit log entry (fields that differ per call site).
struct AuditEntry<'a> {
    action: crate::security::audit_log::AuditEvent,
    backend: &'a str,
    dlp_rules: Vec<String>,
    duration_ms: u64,
    model_name: Option<&'a str>,
    token_counts: Option<(u32, u32)>,
    risk_level: Option<crate::security::audit_log::RiskLevel>,
    dlp_blocked: bool,
    dlp_had_injection: bool,
    dlp_had_pii: bool,
    dlp_had_redact_or_warn: bool,
}

impl DispatchContext<'_> {
    /// Run DLP input sanitization if enabled, emitting watch events for actions taken.
    fn sanitize_input(&self, request: &mut CanonicalRequest) {
        if let Some(ref dlp_engine) = self.dlp {
            if dlp_engine.config.scan_input {
                let reports = dlp_engine.sanitize_request_reported(request);
                self.emit_dlp_events(&reports, DlpDirection::Request);
            }
        }
    }

    /// Run DLP output sanitization if enabled, emitting watch events for actions taken.
    fn sanitize_output(&self, response: &mut ProviderResponse) {
        if let Some(ref dlp_engine) = self.dlp {
            if dlp_engine.config.scan_output {
                let reports = sanitize_provider_response_reported(response, dlp_engine);
                self.emit_dlp_events(&reports, DlpDirection::Response);
            }
        }
    }

    /// Emits [`WatchEvent::DlpAction`] for each DLP action report.
    fn emit_dlp_events(
        &self,
        reports: &[crate::features::dlp::DlpActionReport],
        direction: DlpDirection,
    ) {
        for report in reports {
            self.state.event_bus.emit(WatchEvent::DlpAction {
                request_id: self.req_id.to_string(),
                direction: direction.clone(),
                action: report.action.clone(),
                rule_type: report.rule_type.clone(),
                detail: report.detail.clone(),
                timestamp: chrono::Utc::now(),
            });
        }
    }

    /// Records a provider success in the scorer or circuit breaker.
    ///
    /// Prefers the adaptive scorer (which wraps the circuit breaker);
    /// falls back to the bare circuit breaker when no scorer is configured.
    pub(crate) async fn record_provider_success(&self, provider: &str, latency_ms: u64) {
        if let Some(ref scorer) = self.state.security.provider_scorer {
            scorer.record_success(provider, latency_ms).await;
        } else if let Some(ref cb) = self.state.security.circuit_breakers {
            cb.record_success(provider).await;
        }
    }

    /// Records a provider failure in the scorer or circuit breaker.
    ///
    /// Prefers the adaptive scorer (which wraps the circuit breaker);
    /// falls back to the bare circuit breaker when no scorer is configured.
    pub(crate) async fn record_provider_failure(&self, provider: &str) {
        if let Some(ref scorer) = self.state.security.provider_scorer {
            scorer.record_failure(provider).await;
        } else if let Some(ref cb) = self.state.security.circuit_breakers {
            cb.record_failure(provider).await;
        }
    }

    /// Emit an audit log entry if the audit log is enabled.
    /// Centralizes the repeated `AuditParams` / `AuditCompliance` construction.
    fn log_audit_if_enabled(&self, entry: AuditEntry<'_>) {
        if let Some(ref al) = self.state.security.audit_log {
            log_audit(&AuditParams {
                audit_log: al,
                tenant_id: self.tenant_id.as_deref().unwrap_or("anon"),
                action: entry.action,
                backend: entry.backend,
                dlp_rules: entry.dlp_rules,
                ip: &self.peer_ip,
                duration_ms: entry.duration_ms,
                eu: AuditCompliance {
                    config: &self.inner.config.compliance,
                    model_name: entry.model_name,
                    token_counts: entry.token_counts,
                    risk_level: entry.risk_level,
                },
                dlp_blocked: entry.dlp_blocked,
                dlp_had_injection: entry.dlp_had_injection,
                dlp_had_pii: entry.dlp_had_pii,
                dlp_had_redact_or_warn: entry.dlp_had_redact_or_warn,
            });
        }
    }
}

/// Result of a successful dispatch — the handler decides how to format this.
pub(crate) enum DispatchResult {
    /// Cache hit — pre-built HTTP response.
    CacheHit(axum::response::Response),
    /// Streaming response from a provider.
    Streaming {
        /// DLP + Tap wrapped stream (Anthropic SSE format).
        stream: Pin<
            Box<dyn Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send>,
        >,
        provider: String,
        actual_model: String,
        /// Upstream headers to forward (e.g., rate-limit headers).
        upstream_headers: Vec<(String, String)>,
        /// Proxy overhead in ms (time from request receipt to first SSE byte).
        overhead_ms: u64,
    },
    /// Non-streaming response from a provider.
    Complete {
        response: ProviderResponse,
        provider: String,
        actual_model: String,
        /// Pre-serialized JSON bytes (serialized once, used for cache + response).
        response_bytes: Option<Vec<u8>>,
        /// Time spent inside the provider call (ms), used for overhead calculation.
        provider_duration_ms: u64,
    },
    /// Fan-out response (multiple providers called in parallel).
    FanOut { response: ProviderResponse },
}

/// Run the full dispatch pipeline: DLP → cache → route → provider loop.
///
/// Returns a `DispatchResult` that the handler transforms into the appropriate
/// response format (OpenAI or Anthropic native).
pub(crate) async fn dispatch(
    ctx: &DispatchContext<'_>,
    request: &mut CanonicalRequest,
) -> Result<DispatchResult, AppError> {
    // ── Step 1: DLP input scanning ──
    scan_dlp_input(ctx, request)?;

    // ── Step 1.5: MCP tool calibration ──
    #[cfg(feature = "mcp")]
    if let Some(ref mcp) = ctx.state.security.mcp {
        crate::features::mcp::calibration::calibrate_tools(mcp, request);
    }

    // ── Step 2: Cache key ──
    let cache_key = ctx
        .state
        .security
        .response_cache
        .as_ref()
        .and_then(|_cache| {
            crate::cache::ResponseCache::compute_key_from_request(
                ctx.tenant_id.as_deref().unwrap_or("anon"),
                request,
            )
        });

    // ── Step 3: Route ──
    let decision = ctx
        .inner
        .router
        .route(request)
        .map_err(|e| AppError::RoutingError(e.to_string()))?;

    // ── Step 4: Resolve provider mappings ──
    let sorted_mappings = resolve_provider_mappings(ctx.inner, ctx.headers, &decision)?;

    // ── Step 5: Cache hit (non-streaming only) ──
    if let Some(hit) = check_cache(ctx, &cache_key).await {
        return Ok(hit);
    }

    // ── Step 6: Fan-out strategy ──
    if let Some(model_config) = ctx.inner.find_model(&decision.model_name) {
        if model_config.strategy == ModelStrategy::FanOut {
            if let Some(ref fan_out_config) = model_config.fan_out {
                return dispatch_fan_out(ctx, request, &sorted_mappings, fan_out_config, &decision)
                    .await;
            }
        }
    }

    // ── Step 7: Provider loop with fallback/retry ──
    provider_loop::dispatch_provider_loop(ctx, request, &sorted_mappings, &decision, &cache_key)
        .await
}

/// Check the response cache for a hit (non-streaming requests only).
async fn check_cache(
    ctx: &DispatchContext<'_>,
    cache_key: &Option<String>,
) -> Option<DispatchResult> {
    if ctx.is_streaming {
        return None;
    }
    let cache = ctx.state.security.response_cache.as_ref()?;
    let key = cache_key.as_ref()?;
    let cached = cache.get(key).await?;

    // Body is controlled (from our own cache), so the builder cannot fail.
    let mut resp = axum::response::Response::builder()
        .status(200)
        .header("content-type", &cached.content_type)
        .header("x-grob-cache", "hit")
        .body(axum::body::Body::from(cached.body.clone()))
        .ok()?;
    if super::should_apply_transparency(&ctx.inner.config) {
        apply_transparency_headers(
            resp.headers_mut(),
            &cached.provider,
            &cached.model,
            ctx.req_id,
        );
    }
    Some(DispatchResult::CacheHit(resp))
}

/// DLP input scanning with risk assessment and audit logging.
fn scan_dlp_input(
    ctx: &DispatchContext<'_>,
    request: &mut CanonicalRequest,
) -> Result<(), AppError> {
    let Some(ref dlp_engine) = ctx.dlp else {
        return Ok(());
    };
    if !dlp_engine.config.scan_input {
        return Ok(());
    }

    if let Err(block_err) = dlp_engine.sanitize_request_checked(request) {
        // Emit DLP block event for `grob watch`.
        let (block_rule_type, block_detail) = match &block_err {
            crate::features::dlp::DlpBlockError::InjectionBlocked(dets) => {
                ("injection", format!("{} injection(s) detected", dets.len()))
            }
            crate::features::dlp::DlpBlockError::UrlExfilBlocked(dets) => (
                "url_exfil",
                format!("{} exfiltration URL(s) detected", dets.len()),
            ),
        };
        ctx.state.event_bus.emit(WatchEvent::DlpAction {
            request_id: ctx.req_id.to_string(),
            direction: DlpDirection::Request,
            action: "block".into(),
            rule_type: block_rule_type.into(),
            detail: block_detail,
            timestamp: chrono::Utc::now(),
        });

        let had_injection = matches!(
            &block_err,
            crate::features::dlp::DlpBlockError::InjectionBlocked(_)
        );
        let risk = crate::security::risk::assess_risk(&crate::security::risk::SecurityOutcome {
            dlp_rules_triggered: 1,
            was_blocked: true,
            had_injection,
            had_pii: false,
        });

        let compliance = &ctx.inner.config.compliance;
        if compliance.enabled && compliance.risk_classification {
            let threshold = crate::security::audit_log::RiskLevel::from_str_threshold(
                &compliance.escalation_threshold,
            );
            crate::security::risk::maybe_escalate(&crate::security::risk::EscalationEvent {
                risk,
                threshold,
                webhook_url: &compliance.escalation_webhook,
                event_id: ctx.req_id,
                tenant_id: ctx.tenant_id.as_deref().unwrap_or("anon"),
                model: &ctx.model,
            });
        }

        ctx.log_audit_if_enabled(AuditEntry {
            action: crate::security::audit_log::AuditEvent::DlpBlock,
            backend: "BLOCKED",
            dlp_rules: vec![block_err.to_string()],
            duration_ms: ctx.start_time.elapsed().as_millis() as u64,
            model_name: Some(&ctx.model),
            token_counts: None,
            risk_level: Some(risk),
            dlp_blocked: true,
            dlp_had_injection: had_injection,
            dlp_had_pii: false,
            dlp_had_redact_or_warn: false,
        });
        return Err(AppError::DlpBlocked(format!("{}", block_err)));
    }
    Ok(())
}

/// Handle fan-out strategy (dispatch to multiple providers in parallel).
async fn dispatch_fan_out(
    ctx: &DispatchContext<'_>,
    request: &CanonicalRequest,
    sorted_mappings: &[crate::cli::ModelMapping],
    fan_out_config: &crate::cli::FanOutConfig,
    decision: &crate::models::RouteDecision,
) -> Result<DispatchResult, AppError> {
    let mut fan_request = request.clone();
    ctx.sanitize_input(&mut fan_request);

    match super::fan_out::handle_fan_out(
        &fan_request,
        sorted_mappings,
        fan_out_config,
        &ctx.inner.provider_registry,
    )
    .await
    {
        Ok((response, provider_info)) => {
            handle_fan_out_success(ctx, response, &provider_info, decision).await
        }
        Err(e) => Err(AppError::ProviderError(format!("Fan-out failed: {}", e))),
    }
}

/// Process a successful fan-out response: DLP output scan, cost tracking, metrics, audit.
async fn handle_fan_out_success(
    ctx: &DispatchContext<'_>,
    mut response: ProviderResponse,
    provider_info: &[(String, String)],
    decision: &crate::models::RouteDecision,
) -> Result<DispatchResult, AppError> {
    ctx.sanitize_output(&mut response);

    let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
    record_fan_out_costs(ctx, &response, provider_info).await;

    record_request_metrics(&RequestMetrics {
        model: &ctx.model,
        provider: "fan_out",
        route_type: &decision.route_type,
        status: "success",
        latency_ms,
        input_tokens: response.usage.input_tokens,
        output_tokens: response.usage.output_tokens,
        cost_usd: 0.0,
    });

    ctx.log_audit_if_enabled(AuditEntry {
        action: crate::security::audit_log::AuditEvent::Response,
        backend: "fan_out",
        dlp_rules: vec![],
        duration_ms: latency_ms,
        model_name: Some(
            provider_info
                .first()
                .map(|(_, m)| m.as_str())
                .unwrap_or("fan_out"),
        ),
        token_counts: Some((response.usage.input_tokens, response.usage.output_tokens)),
        risk_level: Some(crate::security::audit_log::RiskLevel::Low),
        dlp_blocked: false,
        dlp_had_injection: false,
        dlp_had_pii: false,
        dlp_had_redact_or_warn: false,
    });

    response.model = ctx.model.clone();
    Ok(DispatchResult::FanOut { response })
}

/// Track cost for each provider in a fan-out response.
async fn record_fan_out_costs(
    ctx: &DispatchContext<'_>,
    response: &ProviderResponse,
    provider_info: &[(String, String)],
) {
    for (provider_name, actual_model) in provider_info {
        let is_subscription = is_provider_subscription(ctx.inner, provider_name);
        let counter = calculate_cost(
            ctx.state,
            actual_model,
            response.usage.input_tokens,
            response.usage.output_tokens,
            is_subscription,
        )
        .await;
        let mut tracker = ctx.state.observability.spend_tracker.lock().await;
        tracker.record(provider_name, actual_model, counter.estimated_cost_usd);
    }
}
