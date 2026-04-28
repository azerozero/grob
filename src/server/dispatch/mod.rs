//! Shared dispatch pipeline for provider routing.
//!
//! Both `handle_messages()` (Anthropic native) and `handle_openai_chat_completions()`
//! delegate to the single `dispatch()` function, which orchestrates the full pipeline:
//! DLP scanning → cache lookup → routing → provider loop with fallback → audit → response.

mod provider_loop;
mod resolver;
mod retry;
mod telemetry;

use crate::cli::ModelStrategy;
use crate::features::dlp::DlpEngine;
#[cfg(feature = "mcp")]
use crate::features::mcp::server::types::ComplexityHint;
use crate::models::CanonicalRequest;
use crate::providers::ProviderResponse;
use axum::http::HeaderMap;
use bytes::Bytes;
use futures::stream::Stream;
use std::pin::Pin;
use std::sync::Arc;

use super::{
    calculate_cost, is_provider_subscription, log_audit, record_request_metrics,
    resolve_provider_mappings, sanitize_provider_response_reported, AppState, AuditCompliance,
    AuditParams, ReloadableState, RequestError, RequestMetrics,
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
    /// Audit-emitted flag — flipped by `log_audit_if_enabled` so the
    /// outer audit middleware can skip writing a duplicate entry.
    pub audited: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Resolved policy for this request (when policies feature is enabled).
    #[cfg(feature = "policies")]
    #[allow(dead_code)]
    pub resolved_policy: Option<crate::features::policies::resolved::ResolvedPolicy>,
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
                action: report.action.to_string(),
                rule_type: report.rule_type.to_string(),
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

    /// Records a successful dispatch on the routing-layer per-endpoint CB (RE-1a).
    ///
    /// Orthogonal to the security-layer global per-provider CB above.
    pub(crate) fn record_endpoint_success(&self, provider: &str, model: &str) {
        self.inner
            .provider_registry
            .record_endpoint_success(provider, model);
    }

    /// Records a failed dispatch on the routing-layer per-endpoint CB (RE-1a).
    pub(crate) fn record_endpoint_failure(&self, provider: &str, model: &str) {
        self.inner
            .provider_registry
            .record_endpoint_failure(provider, model);
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
            // Flag so the outer audit middleware skips a duplicate entry.
            self.audited
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

/// Result of a successful dispatch — the handler decides how to format this.
pub(crate) enum DispatchResult {
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
        /// Time spent inside the provider call (ms), used for overhead calculation.
        provider_duration_ms: u64,
    },
    /// Fan-out response (multiple providers called in parallel).
    FanOut { response: ProviderResponse },
}

/// Resolves the client complexity hint from available sources.
///
/// Priority: `X-Grob-Hint` header → `metadata.grob_hint` body field →
/// one-shot MCP `grob_hint` slot (consumed on read).
#[cfg(feature = "mcp")]
pub(crate) fn resolve_grob_hint(
    ctx: &DispatchContext<'_>,
    request: &CanonicalRequest,
) -> Option<ComplexityHint> {
    // 1. Header: X-Grob-Hint
    if let Some(hint) = ctx
        .headers
        .get("x-grob-hint")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| serde_json::from_value(serde_json::Value::String(s.to_string())).ok())
    {
        return Some(hint);
    }

    // 2. Body: metadata.grob_hint
    if let Some(hint) = request
        .metadata
        .as_ref()
        .and_then(|m| m.get("grob_hint"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
    {
        return Some(hint);
    }

    // 3. MCP one-shot slot (consume on read)
    ctx.state
        .grob_hint
        .lock()
        .ok()
        .and_then(|mut slot| slot.take())
}

/// Run the full dispatch pipeline: DLP → cache → route → provider loop.
///
/// Returns a `DispatchResult` that the handler transforms into the appropriate
/// response format (OpenAI or Anthropic native).
pub(crate) async fn dispatch(
    ctx: &DispatchContext<'_>,
    request: &mut CanonicalRequest,
) -> Result<DispatchResult, RequestError> {
    // ── Step 0: Resolve complexity hint ──
    // Resolved up-front (borrows `request` immutably) but applied post-routing
    // so the client-declared tier overrides the algorithmic scorer.
    #[cfg(feature = "mcp")]
    let grob_hint = resolve_grob_hint(ctx, request);

    // ── Step 1: DLP input scanning ──
    scan_dlp_input(ctx, request)?;

    // ── Step 1.5: MCP tool calibration ──
    #[cfg(feature = "mcp")]
    if let Some(ref mcp) = ctx.state.security.mcp {
        crate::features::mcp::calibration::calibrate_tools(mcp, request);
    }

    // ── Step 1.6: Pledge tool filtering ──
    if ctx.inner.config.pledge.enabled {
        let filter = crate::features::pledge::PledgeFilter::new(&ctx.inner.config.pledge);
        let token = ctx
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| ctx.headers.get("x-api-key").and_then(|v| v.to_str().ok()));
        filter.apply(request, ctx.tenant_id.as_deref(), token);
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
    #[cfg_attr(not(feature = "mcp"), allow(unused_mut))]
    let mut decision = ctx
        .inner
        .router
        .route(request)
        .map_err(|e| RequestError::RoutingError(e.to_string()))?;

    // ── Step 3.5: Apply client-declared complexity hint ──
    // The hint (header / body metadata / MCP one-shot) overrides whatever tier
    // the algorithmic scorer produced, so a client that knows its task is
    // trivial can opt out of `[[tiers]]` fan-out for this request.
    #[cfg(feature = "mcp")]
    if let Some(hint) = grob_hint {
        let tier = match hint {
            ComplexityHint::Trivial => crate::routing::classify::ComplexityTier::Trivial,
            ComplexityHint::Medium => crate::routing::classify::ComplexityTier::Medium,
            ComplexityHint::Complex => crate::routing::classify::ComplexityTier::Complex,
        };
        tracing::debug!(
            hint = %hint,
            previous_tier = ?decision.complexity_tier,
            "dispatch: grob_hint overrides complexity tier"
        );
        decision.complexity_tier = Some(tier);
    }

    // ── Step 4: Resolve provider mappings ──
    let sorted_mappings = resolve_provider_mappings(ctx.inner, ctx.headers, &decision)?;

    // ── Step 4.5: Tool layer (aliasing, injection, capability gating) ──
    if let Some(ref tool_layer) = ctx.state.security.tool_layer {
        if let Some(primary) = sorted_mappings.first() {
            tool_layer.process(request, &primary.provider, &primary.actual_model);
        }
    }

    // ── Step 5: Cache hit (non-streaming only) ──
    if let Some(hit) = check_cache(ctx, &cache_key).await {
        return Ok(hit);
    }

    // ── Step 5.5: Tier-based fan-out ──
    // When the complexity scorer assigns a tier AND the matching [[tiers]]
    // entry has fanout=true, dispatch to all tier providers in parallel.
    if let Some(ref tier) = decision.complexity_tier {
        let tier_name = tier.to_string();
        if let Some(tier_cfg) = ctx.inner.config.tiers.iter().find(|t| t.name == tier_name) {
            if tier_cfg.fanout {
                let fan_out_config = crate::cli::FanOutConfig {
                    mode: crate::cli::FanOutMode::Fastest,
                    judge_model: None,
                    judge_criteria: None,
                    count: None,
                };
                return dispatch_fan_out(
                    ctx,
                    request,
                    &sorted_mappings,
                    &fan_out_config,
                    &decision,
                )
                .await;
            }
        }
    }

    // ── Step 6: Fan-out strategy (model-level) ──
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
///
/// Returns `DispatchResult::Complete` with the deserialized `ProviderResponse`
/// so the handler can apply format translation (e.g. Anthropic → OpenAI).
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

    // Deserialize cached bytes back into ProviderResponse so the handler
    // can apply endpoint-specific format translation (e.g. OpenAI compat).
    let response: ProviderResponse = serde_json::from_slice(&cached.body).ok()?;

    Some(DispatchResult::Complete {
        response,
        provider: cached.provider.clone(),
        actual_model: cached.model.clone(),
        provider_duration_ms: 0,
    })
}

/// DLP input scanning with risk assessment and audit logging.
fn scan_dlp_input(
    ctx: &DispatchContext<'_>,
    request: &mut CanonicalRequest,
) -> Result<(), RequestError> {
    let Some(ref dlp_engine) = ctx.dlp else {
        return Ok(());
    };
    if !dlp_engine.config.scan_input {
        return Ok(());
    }

    match dlp_engine.sanitize_request_checked(request) {
        Ok(reports) => {
            ctx.emit_dlp_events(&reports, DlpDirection::Request);
            Ok(())
        }
        Err(block_err) => {
            // Emit DLP block event for `grob watch`.
            let (block_rule_type, block_detail) = match &block_err {
                crate::features::dlp::DlpBlockError::InjectionBlocked(dets) => {
                    ("injection", format!("{} injection(s) detected", dets.len()))
                }
                crate::features::dlp::DlpBlockError::UrlExfilBlocked(dets) => (
                    "url_exfil",
                    format!("{} exfiltration URL(s) detected", dets.len()),
                ),
                crate::features::dlp::DlpBlockError::IndirectInjectionBlocked(dets) => (
                    "indirect_injection",
                    format!("{} indirect injection(s) detected", dets.len()),
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
                    | crate::features::dlp::DlpBlockError::IndirectInjectionBlocked(_)
            );
            let risk =
                crate::security::risk::assess_risk(&crate::security::risk::SecurityOutcome {
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
            Err(RequestError::DlpBlocked(format!("{}", block_err)))
        }
    }
}

/// Handle fan-out strategy (dispatch to multiple providers in parallel).
async fn dispatch_fan_out(
    ctx: &DispatchContext<'_>,
    request: &CanonicalRequest,
    sorted_mappings: &[crate::cli::ModelMapping],
    fan_out_config: &crate::cli::FanOutConfig,
    decision: &crate::models::RouteDecision,
) -> Result<DispatchResult, RequestError> {
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
        Err(e) => Err(RequestError::ProviderUpstream {
            provider: "fan_out".to_string(),
            status: 502,
            body: Some(format!("Fan-out failed: {}", e)),
        }),
    }
}

/// Process a successful fan-out response: DLP output scan, cost tracking, metrics, audit.
async fn handle_fan_out_success(
    ctx: &DispatchContext<'_>,
    mut response: ProviderResponse,
    provider_info: &[(String, String)],
    decision: &crate::models::RouteDecision,
) -> Result<DispatchResult, RequestError> {
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
