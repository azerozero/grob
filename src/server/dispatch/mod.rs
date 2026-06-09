//! Shared dispatch pipeline for provider routing.
//!
//! Both `handle_messages()` (Anthropic native) and `handle_openai_chat_completions()`
//! delegate to the single `dispatch()` function, which orchestrates the full pipeline:
//! DLP scanning → cache lookup → routing → provider loop with fallback → audit → response.

mod provider_loop;
mod resolver;
mod retry;
mod spend_stream;
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
    calculate_cost, check_budget_for_tenant, effective_token_counts, is_provider_subscription,
    log_audit, record_request_metrics, record_spend, resolve_provider_mappings,
    sanitize_provider_response_reported, AppState, AuditCompliance, AuditParams, ReloadableState,
    RequestError, RequestMetrics,
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
    /// Virtual-key model scope. When non-empty, the resolved model must be in
    /// this list; `None`/empty means the key is unscoped. Enforced post-routing.
    pub allowed_models: Option<Vec<String>>,
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
    request: &mut CanonicalRequest,
) -> Result<Option<ComplexityHint>, RequestError> {
    // 1. Header: X-Grob-Hint
    if let Some(value) = ctx.headers.get("x-grob-hint") {
        let raw = value
            .to_str()
            .map_err(|_| RequestError::BadRequest("invalid X-Grob-Hint header".to_string()))?;
        let hint = parse_complexity_hint(serde_json::Value::String(raw.to_string()))
            .map_err(|msg| RequestError::BadRequest(format!("invalid X-Grob-Hint: {msg}")))?;
        strip_grob_hint_metadata(request);
        return Ok(Some(hint));
    }

    // 2. Body: metadata.grob_hint
    if let Some(value) = request
        .metadata
        .as_ref()
        .and_then(|m| m.get("grob_hint"))
        .cloned()
    {
        let hint = parse_complexity_hint(value).map_err(|msg| {
            RequestError::BadRequest(format!("invalid metadata.grob_hint: {msg}"))
        })?;
        strip_grob_hint_metadata(request);
        return Ok(Some(hint));
    }

    // 3. MCP one-shot slot (consume on read)
    Ok(ctx
        .state
        .grob_hint
        .lock()
        .ok()
        .and_then(|mut slot| slot.take()))
}

#[cfg(feature = "mcp")]
fn parse_complexity_hint(value: serde_json::Value) -> Result<ComplexityHint, String> {
    serde_json::from_value(value)
        .map_err(|_| "expected one of: trivial, medium, complex".to_string())
}

#[cfg(feature = "mcp")]
fn strip_grob_hint_metadata(request: &mut CanonicalRequest) {
    if let Some(metadata) = request.metadata.as_mut() {
        metadata.remove("grob_hint");
        if metadata.is_empty() {
            request.metadata = None;
        }
    }
}

#[cfg(feature = "mcp")]
fn salt_cache_key_with_grob_hint(
    cache_key: Option<String>,
    grob_hint: Option<ComplexityHint>,
) -> Option<String> {
    let key = cache_key?;
    let Some(hint) = grob_hint else {
        return Some(key);
    };
    Some(format!("{key}|grob_hint={hint}"))
}

/// Returns `true` when a configured tier name matches the request's tier.
///
/// Extracted so the tier-lookup equality in [`dispatch`] is unit-testable
/// without constructing a full [`DispatchContext`].
#[inline]
fn tier_name_matches(tier_cfg_name: &str, request_tier_name: &str) -> bool {
    tier_cfg_name == request_tier_name
}

/// Returns `true` when a model is configured for the fan-out strategy.
///
/// Extracted so the strategy comparison in [`dispatch`] is unit-testable
/// without constructing a full [`DispatchContext`].
#[inline]
fn is_fan_out_strategy(strategy: &ModelStrategy) -> bool {
    *strategy == ModelStrategy::FanOut
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
    // Resolved up-front but applied post-routing so the client-declared tier
    // overrides the algorithmic scorer.
    #[cfg(feature = "mcp")]
    let grob_hint = resolve_grob_hint(ctx, request)?;

    // ── Step 1: DLP input scanning ──
    scan_dlp_input(ctx, request)?;

    // ── Step 1.4: Tool-call spike anomaly detection (T-AD1) ──
    // Runs after DLP so scoped DLP blocks take precedence, and before
    // routing so a runaway client cannot exhaust provider quotas before
    // the spike is observed.
    check_tool_spike(ctx, request)?;

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
    #[cfg(feature = "mcp")]
    let cache_key = salt_cache_key_with_grob_hint(cache_key, grob_hint);

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
    // `resolve_provider_mappings` enforces the virtual-key `allowed_models` scope
    // on the *effective* logical model (after any `[[tiers]].model` override),
    // before any provider mapping is used — so a routing remap or a tier override
    // to a forbidden model is rejected here, ahead of every upstream call.
    let sorted_mappings = resolve_provider_mappings(
        ctx.inner,
        ctx.headers,
        &decision,
        ctx.allowed_models.as_deref(),
    )?;

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
        if let Some(tier_cfg) = ctx
            .inner
            .config
            .tiers
            .iter()
            .find(|t| tier_name_matches(&t.name, &tier_name))
        {
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
        if is_fan_out_strategy(&model_config.strategy) {
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

/// Returns `true` when DLP input scanning is disabled for this request.
///
/// Extracted so the early-return guard in [`scan_dlp_input`] is unit-testable
/// without constructing a full [`DispatchContext`].
#[inline]
fn dlp_input_scan_disabled(scan_input: bool) -> bool {
    !scan_input
}

/// Returns `true` when a DLP block should escalate via the compliance webhook.
///
/// Extracted so the compliance-escalation guard in [`scan_dlp_input`] is
/// unit-testable without constructing a full [`DispatchContext`].
#[inline]
fn should_escalate_compliance(enabled: bool, risk_classification: bool) -> bool {
    enabled && risk_classification
}

/// DLP input scanning with risk assessment and audit logging.
fn scan_dlp_input(
    ctx: &DispatchContext<'_>,
    request: &mut CanonicalRequest,
) -> Result<(), RequestError> {
    let Some(ref dlp_engine) = ctx.dlp else {
        return Ok(());
    };
    if dlp_input_scan_disabled(dlp_engine.config.scan_input) {
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
            if should_escalate_compliance(compliance.enabled, compliance.risk_classification) {
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

/// Runs the per-session tool-call spike anomaly detector (T-AD1).
///
/// Counts the `tool_use` and `tool_result` content blocks in the
/// incoming request and feeds them into a 60-second rolling window
/// keyed by session id (falling back to user id, then tenant id).
/// Crossing the warn threshold logs and emits a metric; crossing the
/// block threshold writes an audit entry and returns
/// [`RequestError::ToolSpikeBlocked`] (HTTP 429).
///
/// Returns `Ok(())` when the detector is disabled or the request is
/// below all thresholds.
///
/// # Errors
///
/// Returns [`RequestError::ToolSpikeBlocked`] when the rolling-window
/// tool-call total for the resolved session key reaches the configured
/// block threshold.
fn check_tool_spike(
    ctx: &DispatchContext<'_>,
    request: &CanonicalRequest,
) -> Result<(), RequestError> {
    use crate::security::tool_spike::{count_tool_blocks, resolve_key};
    use crate::security::SpikeAction;

    let Some(detector) = ctx.state.security.tool_spike_detector.as_ref() else {
        return Ok(());
    };

    let count = count_tool_blocks(request);
    let key = resolve_key(request, ctx.tenant_id.as_deref());

    match detector.observe(&key, count) {
        SpikeAction::Allow => Ok(()),
        SpikeAction::Warn => {
            // NOTE: session keys are unbounded, so they stay in the
            // structured log (high cardinality) rather than a metric label.
            metrics::counter!("grob_tool_spike_warn_total").increment(1);
            tracing::warn!(
                session = %key,
                rolling_total = detector.current_total(&key),
                threshold = detector.config().warn_per_min,
                "tool_spike: warn threshold crossed"
            );
            Ok(())
        }
        SpikeAction::Block => {
            metrics::counter!("grob_tool_spike_blocked_total").increment(1);
            let total = detector.current_total(&key);
            let block_threshold = detector.config().block_per_min;
            tracing::warn!(
                session = %key,
                rolling_total = total,
                threshold = block_threshold,
                "tool_spike: block threshold crossed, returning 429"
            );

            ctx.log_audit_if_enabled(AuditEntry {
                action: crate::security::audit_log::AuditEvent::ToolSpikeBlocked,
                backend: "BLOCKED",
                dlp_rules: vec![format!(
                    "tool_spike: {} tool calls in 60s window (threshold {})",
                    total, block_threshold
                )],
                duration_ms: ctx.start_time.elapsed().as_millis() as u64,
                model_name: Some(&ctx.model),
                token_counts: None,
                risk_level: Some(crate::security::audit_log::RiskLevel::High),
                dlp_blocked: true,
                dlp_had_injection: false,
                dlp_had_pii: false,
                dlp_had_redact_or_warn: false,
            });

            Err(RequestError::ToolSpikeBlocked(format!(
                "tool-call spike anomaly: {} tool calls observed in 60s window for session {} (block threshold {})",
                total, key, block_threshold
            )))
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
    // Budget enforcement: fan-out returns from `dispatch()` *before* the
    // provider loop, which is where the per-attempt budget gate lives. Without
    // this check, fan-out — the most expensive dispatch (N providers in
    // parallel) — would bypass budget caps entirely. Each participating mapping
    // is checked; if any provider/model/global cap is already reached the whole
    // fan-out is rejected before any upstream call is made.
    for mapping in sorted_mappings {
        check_budget_for_tenant(
            ctx.state,
            ctx.inner,
            &mapping.provider,
            &decision.model_name,
            ctx.tenant_id.as_deref(),
        )
        .await?;
    }

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
            handle_fan_out_success(ctx, &fan_request, response, &provider_info, decision).await
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
    request: &CanonicalRequest,
    mut response: ProviderResponse,
    provider_info: &[(String, String)],
    decision: &crate::models::RouteDecision,
) -> Result<DispatchResult, RequestError> {
    ctx.sanitize_output(&mut response);

    let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
    record_fan_out_costs(ctx, request, &response, provider_info).await;

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
    request: &CanonicalRequest,
    response: &ProviderResponse,
    provider_info: &[(String, String)],
) {
    // Bill provider-reported usage, or a local estimate when usage is absent in
    // estimate mode (computed once for the shared fan-out response).
    let (input_tokens, output_tokens) = effective_token_counts(ctx.state, request, response);
    // Cache reads bill separately from input (a fraction of the input rate),
    // shared across the fan-out providers.
    let cache_read_tokens = response.usage.cache_read_tokens();
    for (provider_name, actual_model) in provider_info {
        let is_subscription = is_provider_subscription(ctx.inner, provider_name);
        let counter = calculate_cost(
            ctx.state,
            actual_model,
            input_tokens,
            output_tokens,
            cache_read_tokens,
            is_subscription,
        )
        .await;
        // Route through the shared recorder so the configured token-counting
        // mode (synchronous `api` vs off-hot-path `estimate`) is honoured here too.
        record_spend(
            ctx.state,
            provider_name,
            actual_model,
            counter.estimated_cost_usd,
            ctx.tenant_id.as_deref(),
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── scan_dlp_input guards ──

    #[test]
    fn dlp_input_scan_disabled_inverts_scan_flag() {
        // `!scan_input`: disabled when scanning is off. The "delete !" mutant
        // would return the flag verbatim, flipping both outcomes.
        assert!(dlp_input_scan_disabled(false));
        assert!(!dlp_input_scan_disabled(true));
    }

    #[test]
    fn should_escalate_compliance_requires_both_flags() {
        // `enabled && risk_classification`: the `&&` → `||` mutant would
        // escalate whenever either flag is set, so assert all four cells.
        assert!(should_escalate_compliance(true, true));
        assert!(!should_escalate_compliance(true, false));
        assert!(!should_escalate_compliance(false, true));
        assert!(!should_escalate_compliance(false, false));
    }

    // ── dispatch routing guards ──

    #[test]
    fn tier_name_matches_is_equality() {
        // `==`: the `==` → `!=` mutant inverts every comparison.
        assert!(tier_name_matches("complex", "complex"));
        assert!(!tier_name_matches("complex", "trivial"));
    }

    #[test]
    fn is_fan_out_strategy_only_for_fan_out() {
        // `== ModelStrategy::FanOut`: the `==` → `!=` mutant inverts selection.
        assert!(is_fan_out_strategy(&ModelStrategy::FanOut));
        assert!(!is_fan_out_strategy(&ModelStrategy::Fallback));
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn parse_complexity_hint_rejects_unknown_values() {
        assert_eq!(
            parse_complexity_hint(serde_json::json!("trivial")).expect("valid hint"),
            ComplexityHint::Trivial
        );
        assert!(parse_complexity_hint(serde_json::json!("urgent")).is_err());
    }

    // ── allowed_models post-routing enforcement (real dispatch() wiring) ──

    /// Provider that records whether it was reached. The Forbidden path must
    /// reject before any provider call, so `called` must stay `false`.
    struct CountingProvider {
        called: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl crate::providers::LlmProvider for CountingProvider {
        async fn send_message(
            &self,
            _request: CanonicalRequest,
        ) -> Result<ProviderResponse, crate::providers::error::ProviderError> {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(crate::providers::error::ProviderError::ApiError {
                status: 500,
                message: "mock provider must not be reached".to_string(),
            })
        }

        async fn send_message_stream(
            &self,
            _request: CanonicalRequest,
        ) -> Result<crate::providers::StreamResponse, crate::providers::error::ProviderError>
        {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(crate::providers::error::ProviderError::ApiError {
                status: 500,
                message: "mock provider must not be reached".to_string(),
            })
        }

        async fn count_tokens(
            &self,
            _request: crate::models::CountTokensRequest,
        ) -> Result<crate::models::CountTokensResponse, crate::providers::error::ProviderError>
        {
            Err(crate::providers::error::ProviderError::ApiError {
                status: 500,
                message: "mock".to_string(),
            })
        }

        fn supports_model(&self, _model: &str) -> bool {
            true
        }
    }

    /// Builds a minimal real [`AppState`] with a mock provider registered as
    /// "mock". Uses `build_recorder().handle()` so no global Prometheus recorder
    /// is installed (no process-global singleton contention).
    fn test_app_state(
        config: crate::cli::AppConfig,
        called: Arc<std::sync::atomic::AtomicBool>,
    ) -> Arc<AppState> {
        let mut registry = crate::providers::ProviderRegistry::new();
        registry.insert_provider_for_test("mock", Arc::new(CountingProvider { called }));
        let router = crate::routing::classify::Router::new(config.clone());
        let reloadable = Arc::new(ReloadableState::new(
            config.clone(),
            router,
            Arc::new(registry),
        ));

        let home = tempfile::tempdir().expect("tempdir");
        let grob_store = Arc::new(
            crate::storage::GrobStore::open(&home.path().join("grob.db")).expect("grob store"),
        );
        let token_store =
            crate::auth::TokenStore::with_store(grob_store.clone()).expect("token store");
        // Keep the storage dir alive for the process; the test is short-lived.
        std::mem::forget(home);

        let message_tracer: Arc<dyn crate::traits::Tracer> = Arc::new(
            crate::shared::message_tracing::MessageTracer::new(config.server.tracing.clone()),
        );
        let spend_tracker: Box<dyn crate::traits::SpendTracking> = Box::new(
            crate::features::token_pricing::spend::SpendTracker::with_store(grob_store.clone()),
        );
        let pricing_table = crate::features::token_pricing::init_pricing_table(&config.pricing);
        let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle();

        Arc::new(AppState {
            inner: std::sync::RwLock::new(reloadable),
            token_store,
            grob_store,
            config_source: crate::cli::ConfigSource::File(std::path::PathBuf::from("test.toml")),
            active_requests: std::sync::atomic::AtomicU64::new(0),
            started_at: chrono::Utc::now(),
            actual_oauth_callback_port: std::sync::atomic::AtomicU16::new(0),
            event_bus: crate::features::watch::EventBus::new(),
            log_exporter: None,
            #[cfg(feature = "mcp")]
            grob_hint: std::sync::Mutex::new(None),
            #[cfg(feature = "policies")]
            hit_pending: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            observability: crate::server::ObservabilityState {
                message_tracer,
                metrics_handle,
                spend_tracker: tokio::sync::Mutex::new(spend_tracker),
                pricing_table,
            },
            security: crate::server::SecurityState {
                jwt_validator: None,
                rate_limiter: None,
                dlp_sessions: None,
                circuit_breakers: None,
                audit_log: None,
                response_cache: None,
                tap_sender: None,
                provider_scorer: None,
                #[cfg(feature = "mcp")]
                mcp: None,
                tool_layer: None,
                tool_spike_detector: None,
            },
        })
    }

    /// dispatch() must reject a scoped key when routing remaps the inbound model
    /// to a forbidden one — BEFORE any provider is reached. Red if dispatch stops
    /// passing `ctx.allowed_models` to `resolve_provider_mappings`.
    #[tokio::test]
    async fn dispatch_rejects_remapped_forbidden_model_before_provider() {
        use crate::models::{Message, MessageContent, ThinkingConfig};

        // `thinking` routes via `[router] think = "beta"` → decision.model_name
        // becomes "beta", which the key (allowed only "alpha") forbids.
        let toml = r#"
[server]
host = "127.0.0.1"
port = 18097

[router]
default = "alpha"
think = "beta"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha", "beta"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"

[[models]]
name = "beta"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "beta"
"#;
        let config = crate::cli::AppConfig::from_content(toml, "dispatch_allowed_models_test")
            .expect("config parses");

        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state = test_app_state(config, called.clone());
        let inner = state.snapshot();
        let dlp: Option<Arc<DlpEngine>> = None;
        let headers = HeaderMap::new();

        let ctx = DispatchContext {
            state: &state,
            inner: &inner,
            dlp: &dlp,
            model: "alpha".to_string(),
            is_streaming: false,
            tenant_id: None,
            allowed_models: Some(vec!["alpha".to_string()]),
            peer_ip: "127.0.0.1".to_string(),
            req_id: "test-req",
            start_time: std::time::Instant::now(),
            headers: &headers,
            trace_id: None,
            audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(feature = "policies")]
            resolved_policy: None,
        };

        let mut request = CanonicalRequest {
            model: "alpha".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text("Think hard.".to_string()),
            }],
            max_tokens: 1024,
            system: None,
            tools: None,
            tool_choice: None,
            thinking: Some(ThinkingConfig {
                r#type: "enabled".to_string(),
                budget_tokens: Some(10_000),
            }),
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            extensions: Default::default(),
        };

        let result = dispatch(&ctx, &mut request).await;

        assert!(
            matches!(result, Err(RequestError::Forbidden(_))),
            "scoped key must be rejected (403) on the remapped 'beta' model"
        );
        assert!(
            !called.load(std::sync::atomic::Ordering::SeqCst),
            "the provider must NOT be reached when the resolved model is forbidden"
        );
    }
}
