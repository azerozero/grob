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
    calculate_cost, check_budget_for_tenant, effective_token_counts, evaluate_context_guard,
    is_provider_subscription, log_audit, record_request_metrics, record_spend,
    resolve_provider_mappings, sanitize_provider_response_reported, AppState, AuditCompliance,
    AuditParams, ContextGuardDecision, ContextGuardInfo, ReloadableState, RequestError,
    RequestMetrics,
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
    /// Virtual-key provider scope. When non-empty, only mappings whose provider
    /// is in this list survive resolution; empty means the key is unscoped.
    pub allowed_providers: Vec<String>,
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
        /// Optional context-window warning metadata.
        context_guard: Option<ContextGuardInfo>,
    },
    /// Non-streaming response from a provider.
    Complete {
        response: ProviderResponse,
        provider: String,
        actual_model: String,
        /// Time spent inside the provider call (ms), used for overhead calculation.
        provider_duration_ms: u64,
        /// Optional context-window warning metadata.
        context_guard: Option<ContextGuardInfo>,
    },
    /// Fan-out response (multiple providers called in parallel).
    FanOut {
        response: ProviderResponse,
        /// Optional context-window warning metadata.
        context_guard: Option<ContextGuardInfo>,
    },
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
    // `dlp_triggered` feeds the post-route policy context (Step 5.4).
    #[cfg_attr(not(feature = "policies"), allow(unused_variables))]
    let dlp_triggered = scan_dlp_input(ctx, request)?;

    // Security: DLP sanitizes the canonical request in place. Drop any verbatim
    // Responses passthrough body so the OpenAI provider rebuilds from the
    // sanitized request — otherwise the original, un-redacted bytes would be
    // forwarded upstream, bypassing DLP. The rebuild path stays cache-friendly
    // (typed content + prompt_cache_key), so the only cost is a one-request cache
    // miss when DLP actually fires.
    if dlp_triggered {
        request.extensions.responses_passthrough_body = None;
    }

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

    // ── Step 1.55: Inbound tool well-formedness validation ──
    // Strips (or, in reject mode, 400s on) tools with a missing name or a
    // malformed `input_schema`. Well-formedness only — client tools are
    // arbitrary and are NOT checked against grob's internal catalogue. Runs
    // before pledge so malformed tools never reach the allowlist check.
    match crate::features::tool_validation::validate_inbound_tools(
        request,
        &ctx.inner.config.tool_validation,
    ) {
        Ok(stripped) => warn_stripped_tools(&stripped),
        Err(reason) => return Err(RequestError::BadRequest(reason)),
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
        &ctx.allowed_providers,
    )?;

    let context_guard = match evaluate_context_guard(
        ctx.inner,
        request,
        &decision.model_name,
        sorted_mappings.first(),
    ) {
        ContextGuardDecision::Ok => None,
        ContextGuardDecision::Warn(info) => {
            tracing::warn!(
                estimated_input_tokens = info.estimated_input_tokens,
                context_window = info.context_window,
                usage_ratio = info.usage_ratio,
                model = %decision.model_name,
                "request is approaching the configured context window; compact soon"
            );
            metrics::counter!("grob_context_guard_warnings_total",
                "model" => decision.model_name.clone(),
            )
            .increment(1);
            Some(info)
        }
        ContextGuardDecision::Block(info) => {
            metrics::counter!("grob_context_guard_blocks_total",
                "model" => decision.model_name.clone(),
            )
            .increment(1);
            return Err(RequestError::ContextWindowExceeded {
                message: context_window_exceeded_message(&info),
                estimated_input_tokens: info.estimated_input_tokens,
                context_window: info.context_window,
                usage_ratio: info.usage_ratio,
            });
        }
    };

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

    // NOTE: Policy budget/rate_limit overrides are enforced per *effective*
    // provider inside the provider loop (`provider_loop.rs`) and per fan-out
    // participant (`dispatch_fan_out`), NOT here — the first sorted mapping is
    // not necessarily the provider actually called (adaptive scorer reorders,
    // circuit-breaker/health skips a mapping, fan-out hits several). A
    // provider-keyed policy must see the real provider, so enforcement moves to
    // the point where the candidate is chosen. `dlp_triggered` is threaded down
    // for `dlp_triggered`-keyed policies.

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
                    dlp_triggered,
                    context_guard,
                )
                .await;
            }
        }
    }

    // ── Step 6: Fan-out strategy (model-level) ──
    if let Some(model_config) = ctx.inner.find_model(&decision.model_name) {
        if is_fan_out_strategy(&model_config.strategy) {
            if let Some(ref fan_out_config) = model_config.fan_out {
                return dispatch_fan_out(
                    ctx,
                    request,
                    &sorted_mappings,
                    fan_out_config,
                    &decision,
                    dlp_triggered,
                    context_guard,
                )
                .await;
            }
        }
    }

    // ── Step 7: Provider loop with fallback/retry ──
    provider_loop::dispatch_provider_loop(
        ctx,
        request,
        &sorted_mappings,
        &decision,
        &cache_key,
        dlp_triggered,
        context_guard,
    )
    .await
}

fn context_window_exceeded_message(info: &ContextGuardInfo) -> String {
    let mut message =
        "Input exceeds the configured context window. Compact the conversation and retry."
            .to_string();
    if let Some(handoff) = &info.handoff {
        message.push_str("\n\nLast recap:\n");
        message.push_str(handoff);
        message.push_str("\n\nSuggested action:\nRun /compact, then retry the last request.");
    } else {
        message.push_str("\n\nSuggested action:\nRun /compact, then retry the last request.");
    }
    message
}

/// Re-evaluates `[[policies]]` with the *enriched* request context and applies
/// the `budget` and `rate_limit` overrides.
///
/// The pre-route eval in the handler builds a [`RequestContext`] with empty
/// `provider`/`route_type`/`dlp_triggered`/`estimated_cost` (routing/DLP have not
/// run yet), so any policy keyed on those criteria never matches. This second
/// evaluation — once routing + DLP have run — populates them so such policies
/// match, then enforces their overrides.
///
/// # Load-bearing order
///
/// 1. Runs AFTER routing + provider-mapping resolution (so `provider`/`route_type`
///    are known) and AFTER the cache check (a cache hit incurs no provider cost
///    or rate, so it must not be budget-/rate-blocked).
/// 2. The `budget` override is enforced HERE, BEFORE the provider loop's spend
///    check ([`check_budget_for_tenant`]), so a per-policy cap rejects ahead of
///    any upstream call.
/// 3. The `rate_limit` override is a SECOND limiter check: the pre-handler
///    rate-limit middleware ran before any policy was evaluated, so it cannot see
///    a policy override. A dedicated [`AppState::policy_rate_limiter`] keeps these
///    custom-rps buckets off the middleware's default-rate buckets.
///
/// `routing` and `log_export` overrides are intentionally NOT applied in this
/// slice (explicit follow-up).
///
/// [`RequestContext`]: crate::features::policies::context::RequestContext
#[cfg(feature = "policies")]
async fn enforce_post_route_policy(
    ctx: &DispatchContext<'_>,
    request: &CanonicalRequest,
    decision: &crate::models::RouteDecision,
    provider: &str,
    dlp_triggered: bool,
) -> Result<(), RequestError> {
    let Some(matcher) = ctx.inner.policy_matcher.as_ref() else {
        return Ok(());
    };

    // Best-effort estimated cost (input only — output is unknown pre-call) so
    // `cost_above`-keyed policies can match.
    let input_tokens = super::estimate_input_tokens(request);
    let estimated_cost = calculate_cost(ctx.state, &decision.model_name, input_tokens, 0, 0, false)
        .await
        .estimated_cost_usd;

    let header = |name: &str| {
        ctx.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    let rctx = crate::features::policies::context::RequestContext {
        tenant: ctx.tenant_id.clone(),
        zone: None,
        project: header("x-grob-project"),
        user: None,
        agent: header("user-agent"),
        compliance: vec![],
        model: decision.model_name.clone(),
        provider: provider.to_string(),
        route_type: decision.route_type.to_string(),
        dlp_triggered,
        estimated_cost,
    };

    let policy = matcher.evaluate(&rctx);
    if !policy.matched {
        return Ok(());
    }

    // (2) Budget override — enforced before the provider loop's spend check.
    if let Some(limit) = policy.budget.as_ref().and_then(|b| b.monthly_usd) {
        let tracker = ctx.state.observability.spend_tracker.lock().await;
        let result = match ctx.tenant_id.as_deref() {
            Some(tenant) => tracker.check_tenant_budget(
                Some(tenant),
                provider,
                &decision.model_name,
                limit,
                None,
                None,
            ),
            None => tracker.check_budget(provider, &decision.model_name, limit, None, None),
        };
        if let Err(e) = result {
            return Err(RequestError::BudgetExceeded {
                limit_usd: e.limit_usd,
                actual_usd: e.actual_usd,
            });
        }
    }

    // (3) Rate-limit override — second, policy-aware limiter check.
    if let Some(rps) = policy.rate_limit.as_ref().and_then(|r| r.rps) {
        let key = crate::security::RateLimitKey::Tenant(
            ctx.tenant_id.clone().unwrap_or_else(|| "anon".to_string()),
        );
        let (allowed, _, _) = ctx
            .state
            .policy_rate_limiter
            .check_with_rps(&key, rps)
            .await;
        if !allowed {
            return Err(RequestError::RateLimitedLocal(
                "policy rate limit exceeded".to_string(),
            ));
        }
    }

    Ok(())
}

/// No-op when the `policies` feature is disabled, so the per-candidate call sites
/// in the provider loop / fan-out need no `#[cfg]` gating.
#[cfg(not(feature = "policies"))]
async fn enforce_post_route_policy(
    _ctx: &DispatchContext<'_>,
    _request: &CanonicalRequest,
    _decision: &crate::models::RouteDecision,
    _provider: &str,
    _dlp_triggered: bool,
) -> Result<(), RequestError> {
    Ok(())
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
        context_guard: None,
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

/// Returns `true` when DLP produced at least one redact/warn report.
///
/// Extracted so the trigger flag in [`scan_dlp_input`] is unit-testable
/// without constructing a full [`DispatchContext`].
#[inline]
fn dlp_reports_triggered<T>(reports: &[T]) -> bool {
    !reports.is_empty()
}

/// Builds the audit `dlp_rules_triggered` entries for a set of redact/warn reports.
///
/// Each entry is `"<rule_type>: <detail>"` (e.g. `"secret: AWS access key"`),
/// mirroring the format the block path uses so a caviardage is named in the
/// per-tenant audit log exactly like a block is.
///
/// Extracted so the formatting is unit-testable without a full pipeline.
#[inline]
fn redaction_audit_rules(reports: &[crate::features::dlp::DlpActionReport]) -> Vec<String> {
    reports
        .iter()
        .map(|r| format!("{}: {}", r.rule_type, r.detail))
        .collect()
}

/// Returns `true` when any DLP report concerns personally identifiable information.
///
/// Drives the C2 (Restricted) vs C1 (Internal) split for a caviardage: a
/// redacted PII field is Restricted, a redacted secret is Internal.
///
/// Extracted so the PII guard is unit-testable without a full pipeline.
#[inline]
fn reports_have_pii(reports: &[crate::features::dlp::DlpActionReport]) -> bool {
    reports
        .iter()
        .any(|r| matches!(r.rule_type, crate::features::dlp::DlpRuleType::Pii))
}

/// Logs a warning when tool validation stripped malformed inbound tools.
///
/// Extracted so the non-empty guard is unit-testable; the inline `if` was
/// otherwise only reachable through the full `dispatch` pipeline.
#[inline]
fn warn_stripped_tools(stripped: &[String]) {
    if !stripped.is_empty() {
        tracing::warn!(
            tools = ?stripped,
            "tool validation: stripped malformed inbound tools"
        );
    }
}

/// DLP input scanning with risk assessment and audit logging.
///
/// Returns `Ok(true)` when DLP acted on the request (one or more redact/warn
/// reports), `Ok(false)` when scanning is off or nothing matched. That flag
/// feeds the post-route policy context so `dlp_triggered`-keyed policies match.
fn scan_dlp_input(
    ctx: &DispatchContext<'_>,
    request: &mut CanonicalRequest,
) -> Result<bool, RequestError> {
    let Some(ref dlp_engine) = ctx.dlp else {
        return Ok(false);
    };
    if dlp_input_scan_disabled(dlp_engine.config.scan_input) {
        return Ok(false);
    }

    match dlp_engine.sanitize_request_checked(request) {
        Ok(reports) => {
            let triggered = dlp_reports_triggered(&reports);
            ctx.emit_dlp_events(&reports, DlpDirection::Request);
            if triggered {
                // A caviardage (redact/warn) is a security-relevant event in
                // its own right, just like a block. Emit a classified audit
                // entry here so the per-tenant audit log — and the Loki
                // dashboards built on it — record the redaction as C1 (secret,
                // Internal) or C2 (PII, Restricted), instead of leaving the
                // request indistinguishable from clean (Nc) traffic on the
                // later Response entry. Blocks already do this in the Err arm.
                ctx.log_audit_if_enabled(AuditEntry {
                    action: crate::security::audit_log::AuditEvent::DlpWarn,
                    backend: "REDACTED",
                    dlp_rules: redaction_audit_rules(&reports),
                    duration_ms: ctx.start_time.elapsed().as_millis() as u64,
                    model_name: Some(&ctx.model),
                    token_counts: None,
                    risk_level: Some(crate::security::audit_log::RiskLevel::Medium),
                    dlp_blocked: false,
                    dlp_had_injection: false,
                    dlp_had_pii: reports_have_pii(&reports),
                    dlp_had_redact_or_warn: true,
                });
            }
            Ok(triggered)
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
    dlp_triggered: bool,
    context_guard: Option<ContextGuardInfo>,
) -> Result<DispatchResult, RequestError> {
    // Budget enforcement: fan-out returns from `dispatch()` *before* the
    // provider loop, which is where the per-attempt budget gate lives. Without
    // this check, fan-out — the most expensive dispatch (N providers in
    // parallel) — would bypass budget caps entirely. Each participating mapping
    // is checked; if any provider/model/global cap is already reached the whole
    // fan-out is rejected before any upstream call is made.
    //
    // Per-participant policy overrides run here too: every fan-out provider is a
    // real upstream call, so a provider-keyed budget/rate_limit policy must gate
    // each participant.
    for mapping in sorted_mappings {
        enforce_post_route_policy(ctx, request, decision, &mapping.provider, dlp_triggered).await?;
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
            handle_fan_out_success(
                ctx,
                &fan_request,
                response,
                &provider_info,
                decision,
                context_guard,
            )
            .await
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
    context_guard: Option<ContextGuardInfo>,
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
    Ok(DispatchResult::FanOut {
        response,
        context_guard,
    })
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
    use tracing_test::traced_test;

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

    #[test]
    fn dlp_reports_triggered_flags_nonempty_reports() {
        // `!reports.is_empty()`: triggered only when DLP produced a report.
        // The "delete !" mutant would invert both outcomes.
        assert!(!dlp_reports_triggered::<()>(&[]));
        assert!(dlp_reports_triggered(&[()]));
    }

    fn report(
        rule_type: crate::features::dlp::DlpRuleType,
        detail: &str,
    ) -> crate::features::dlp::DlpActionReport {
        crate::features::dlp::DlpActionReport {
            action: crate::features::dlp::DlpAction::Redact,
            rule_type,
            detail: detail.to_string(),
        }
    }

    #[test]
    fn redaction_audit_rules_names_each_report() {
        use crate::features::dlp::DlpRuleType;
        // Each report becomes "<rule_type>: <detail>" so the audit log names a
        // caviardage like it names a block. Empty in, empty out.
        assert!(redaction_audit_rules(&[]).is_empty());
        let rules = redaction_audit_rules(&[
            report(DlpRuleType::Secret, "AWS access key"),
            report(DlpRuleType::Pii, "credit card"),
        ]);
        assert_eq!(rules, vec!["secret: AWS access key", "pii: credit card"]);
    }

    #[test]
    fn reports_have_pii_detects_only_pii_rule_type() {
        use crate::features::dlp::DlpRuleType;
        // PII drives the C2-vs-C1 split. A secret-only set is C1 (false); any
        // PII report flips it to C2 (true). The `any` → `all` mutant would miss
        // a mixed set, so assert all three shapes.
        assert!(!reports_have_pii(&[]));
        assert!(!reports_have_pii(&[report(DlpRuleType::Secret, "token")]));
        assert!(reports_have_pii(&[
            report(DlpRuleType::Secret, "token"),
            report(DlpRuleType::Pii, "iban"),
        ]));
    }

    #[traced_test]
    #[test]
    fn warn_stripped_tools_logs_only_when_nonempty() {
        // The "delete !" mutant would warn on an empty strip list and stay
        // silent on a real one — assert both directions against the log.
        warn_stripped_tools(&[]);
        assert!(!logs_contain("stripped malformed inbound tools"));
        warn_stripped_tools(&["bogus_tool".to_string()]);
        assert!(logs_contain("stripped malformed inbound tools"));
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
                status: 400,
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
                status: 400,
                message: "mock provider must not be reached".to_string(),
            })
        }

        async fn count_tokens(
            &self,
            _request: crate::models::CountTokensRequest,
        ) -> Result<crate::models::CountTokensResponse, crate::providers::error::ProviderError>
        {
            Err(crate::providers::error::ProviderError::ApiError {
                status: 400,
                message: "mock".to_string(),
            })
        }

        fn supports_model(&self, _model: &str) -> bool {
            true
        }
    }

    /// Builds a minimal real [`AppState`] with a mock provider registered as
    /// "mock", delegating to the shared [`crate::server::test_app_state`] builder.
    fn test_app_state(
        config: crate::cli::AppConfig,
        called: Arc<std::sync::atomic::AtomicBool>,
    ) -> Arc<AppState> {
        let mut registry = crate::providers::ProviderRegistry::new();
        registry.insert_provider_for_test("mock", Arc::new(CountingProvider { called }));
        crate::server::test_app_state(config, registry)
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
            allowed_providers: Vec::new(),
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

    // ── SLICE 3: policy overrides (matching fix + budget + rate_limit) ──

    /// Config declaring one policy with a `route_type` condition plus the given
    /// `[policies.*]` override TOML block.
    #[cfg(feature = "policies")]
    fn policy_config(route_type: &str, override_toml: &str) -> crate::cli::AppConfig {
        let toml = format!(
            r#"
[server]
host = "127.0.0.1"
port = 18093

[router]
default = "alpha"

[[providers]]
name = "anthropic"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "alpha"

[[policies]]
name = "p"
[policies.match]
route_type = "{route_type}"
{override_toml}
"#
        );
        crate::cli::AppConfig::from_content(&toml, "policy_override_test").expect("config parses")
    }

    /// Config with a `provider`-keyed policy and TWO mappings (anthropic at
    /// priority 1, openrouter at priority 2), so a fallback to a non-first
    /// provider can be exercised.
    #[cfg(feature = "policies")]
    fn provider_keyed_config(provider: &str, override_toml: &str) -> crate::cli::AppConfig {
        let toml = format!(
            r#"
[server]
host = "127.0.0.1"
port = 18092

[router]
default = "alpha"

[[providers]]
name = "anthropic"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[providers]]
name = "openrouter"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "alpha"
[[models.mappings]]
priority = 2
provider = "openrouter"
actual_model = "alpha"

[[policies]]
name = "p"
[policies.match]
provider = "{provider}"
{override_toml}
"#
        );
        crate::cli::AppConfig::from_content(&toml, "provider_keyed_policy_test")
            .expect("config parses")
    }

    /// Drives a real `dispatch()` for model "alpha" (a plain request routes to
    /// `default`), so the policy enforcement wiring is actually exercised.
    #[cfg(feature = "policies")]
    async fn run_dispatch(
        state: &Arc<AppState>,
        tenant: Option<&str>,
    ) -> Result<DispatchResult, RequestError> {
        let inner = state.snapshot();
        let dlp: Option<Arc<DlpEngine>> = None;
        let headers = HeaderMap::new();
        let ctx = DispatchContext {
            state,
            inner: &inner,
            dlp: &dlp,
            model: "alpha".to_string(),
            is_streaming: false,
            tenant_id: tenant.map(|s| s.to_string()),
            allowed_models: None,
            allowed_providers: Vec::new(),
            peer_ip: "127.0.0.1".to_string(),
            req_id: "test",
            start_time: std::time::Instant::now(),
            headers: &headers,
            trace_id: None,
            audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            resolved_policy: None,
        };
        let mut request: CanonicalRequest = serde_json::from_value(serde_json::json!({
            "model": "alpha",
            "max_tokens": 16,
            "messages": [{ "role": "user", "content": "hi" }]
        }))
        .expect("request");
        dispatch(&ctx, &mut request).await
    }

    // (1) Matching is fixed: a policy keyed on route_type matches only once the
    // context is enriched. The empty pre-route context (route_type = "") — what
    // the handler eval produces — never matches, which is the bug.
    #[cfg(feature = "policies")]
    #[tokio::test]
    async fn policy_keyed_on_route_type_matches_only_when_context_is_enriched() {
        use crate::features::policies::context::RequestContext;

        let config = policy_config("background", "[policies.budget]\nmonthly_usd = 1.0");
        let state =
            crate::server::test_app_state(config, crate::providers::ProviderRegistry::new());
        let inner = state.snapshot();
        let matcher = inner.policy_matcher.as_ref().expect("matcher built");

        let empty = RequestContext {
            route_type: String::new(),
            ..Default::default()
        };
        assert!(
            !matcher.evaluate(&empty).matched,
            "empty pre-route context must NOT match a route_type policy (the bug)"
        );

        let enriched = RequestContext {
            route_type: "background".to_string(),
            ..Default::default()
        };
        let resolved = matcher.evaluate(&enriched);
        assert!(resolved.matched, "enriched context must match the policy");
        assert!(resolved.budget.is_some(), "the budget override is resolved");
    }

    // (2) Budget override blocks via the REAL dispatch() path, before the
    // provider is reached. Red if the per-candidate enforcement is removed from
    // the provider loop.
    #[cfg(feature = "policies")]
    #[tokio::test]
    async fn dispatch_policy_budget_override_blocks_before_provider() {
        let config = policy_config("default", "[policies.budget]\nmonthly_usd = 5.0");
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut registry = crate::providers::ProviderRegistry::new();
        registry.insert_provider_for_test(
            "anthropic",
            Arc::new(CountingProvider {
                called: called.clone(),
            }),
        );
        let state = crate::server::test_app_state(config, registry);

        {
            let mut tracker = state.observability.spend_tracker.lock().await;
            tracker.record("anthropic", "alpha", 10.0); // over the 5.0 cap
        }

        let result = run_dispatch(&state, None).await;
        assert!(
            matches!(result, Err(RequestError::BudgetExceeded { .. })),
            "dispatch must block on the policy budget cap"
        );
        assert!(
            !called.load(std::sync::atomic::Ordering::SeqCst),
            "the provider must NOT be reached when the budget policy blocks"
        );
    }

    // (3) Rate-limit override throttles via REAL dispatch(): rps = 1, the second
    // immediate dispatch is rejected. Red if the per-candidate enforcement is
    // removed.
    #[cfg(feature = "policies")]
    #[tokio::test]
    async fn dispatch_policy_rate_limit_override_throttles() {
        let config = policy_config("default", "[policies.rate_limit]\nrps = 1");
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut registry = crate::providers::ProviderRegistry::new();
        registry.insert_provider_for_test("anthropic", Arc::new(CountingProvider { called }));
        let state = crate::server::test_app_state(config, registry);

        // First dispatch consumes the single token (provider reached, then errors).
        let first = run_dispatch(&state, Some("tenant-1")).await;
        assert!(
            !matches!(first, Err(RequestError::RateLimitedLocal(_))),
            "first request within rps must not be rate-limited"
        );

        // Second immediate dispatch is throttled before the provider.
        let second = run_dispatch(&state, Some("tenant-1")).await;
        assert!(
            matches!(second, Err(RequestError::RateLimitedLocal(_))),
            "second immediate dispatch must hit the policy rps override"
        );
    }

    // (point 1 + 3) A `provider`-keyed policy must match the EFFECTIVE provider.
    // anthropic (priority 1) is unregistered → skipped; dispatch falls back to
    // openrouter, and the openrouter-keyed budget policy fires — proving the
    // enforcement sees the real provider, not just the first mapping.
    #[cfg(feature = "policies")]
    #[tokio::test]
    async fn dispatch_provider_keyed_policy_matches_effective_fallback_provider() {
        let config = provider_keyed_config("openrouter", "[policies.budget]\nmonthly_usd = 5.0");
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut registry = crate::providers::ProviderRegistry::new();
        // Only openrouter is registered → anthropic is skipped and openrouter is
        // the effective (fallback) provider.
        registry.insert_provider_for_test(
            "openrouter",
            Arc::new(CountingProvider {
                called: called.clone(),
            }),
        );
        let state = crate::server::test_app_state(config, registry);

        {
            let mut tracker = state.observability.spend_tracker.lock().await;
            tracker.record("openrouter", "alpha", 10.0); // over the 5.0 cap
        }

        let result = run_dispatch(&state, None).await;
        assert!(
            matches!(result, Err(RequestError::BudgetExceeded { .. })),
            "the openrouter-keyed budget policy must fire on the fallback provider"
        );
        assert!(
            !called.load(std::sync::atomic::Ordering::SeqCst),
            "openrouter must NOT be called once its budget policy blocks"
        );
    }

    // ── SLICE 4: HIT on the non-streaming dispatch path ──

    /// Mock provider returning a non-streaming response that contains a `Bash`
    /// tool_use block.
    #[cfg(feature = "policies")]
    struct ToolUseProvider;

    #[cfg(feature = "policies")]
    #[async_trait::async_trait]
    impl crate::providers::LlmProvider for ToolUseProvider {
        async fn send_message(
            &self,
            _request: CanonicalRequest,
        ) -> Result<ProviderResponse, crate::providers::error::ProviderError> {
            Ok(serde_json::from_value(serde_json::json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "content": [
                    { "type": "text", "text": "ok" },
                    { "type": "tool_use", "id": "tu_1", "name": "Bash", "input": { "command": "ls" } }
                ],
                "model": "alpha",
                "stop_reason": "tool_use",
                "usage": { "input_tokens": 1, "output_tokens": 1 }
            }))
            .unwrap())
        }

        async fn send_message_stream(
            &self,
            _request: CanonicalRequest,
        ) -> Result<crate::providers::StreamResponse, crate::providers::error::ProviderError>
        {
            Err(crate::providers::error::ProviderError::ApiError {
                status: 400,
                message: "no stream".to_string(),
            })
        }

        async fn count_tokens(
            &self,
            _request: crate::models::CountTokensRequest,
        ) -> Result<crate::models::CountTokensResponse, crate::providers::error::ProviderError>
        {
            Err(crate::providers::error::ProviderError::ApiError {
                status: 400,
                message: "no count".to_string(),
            })
        }

        fn supports_model(&self, _model: &str) -> bool {
            true
        }
    }

    // Real dispatch(): a non-stream response carrying a denied tool_use must come
    // back with that tool_use STRIPPED. Red if the HIT call is removed from
    // dispatch_non_streaming.
    #[cfg(feature = "policies")]
    #[tokio::test]
    async fn dispatch_non_stream_hit_deny_strips_tool_use_from_response() {
        use crate::models::{ContentBlock, KnownContentBlock};

        let toml = r#"
[server]
host = "127.0.0.1"
port = 18091

[router]
default = "alpha"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"
"#;
        let config =
            crate::cli::AppConfig::from_content(toml, "hit_non_stream_test").expect("config");
        let mut registry = crate::providers::ProviderRegistry::new();
        registry.insert_provider_for_test("mock", Arc::new(ToolUseProvider));
        let state = crate::server::test_app_state(config, registry);

        // Resolved HIT policy denying Bash (as the handler would attach it).
        let hit: crate::features::policies::hit::HitOverride =
            serde_json::from_value(serde_json::json!({ "deny": ["Bash"] })).unwrap();
        let resolved = crate::features::policies::resolved::ResolvedPolicy {
            matched: true,
            hit: Some(hit),
            ..Default::default()
        };

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
            allowed_models: None,
            allowed_providers: Vec::new(),
            peer_ip: "127.0.0.1".to_string(),
            req_id: "req-dispatch-hit",
            start_time: std::time::Instant::now(),
            headers: &headers,
            trace_id: None,
            audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            resolved_policy: Some(resolved),
        };
        let mut request: CanonicalRequest = serde_json::from_value(serde_json::json!({
            "model": "alpha",
            "max_tokens": 16,
            "messages": [{ "role": "user", "content": "go" }]
        }))
        .unwrap();

        let result = dispatch(&ctx, &mut request).await.expect("dispatch ok");
        let DispatchResult::Complete { response, .. } = result else {
            panic!("expected a Complete result");
        };

        let has_tool_use = response
            .content
            .iter()
            .any(|b| matches!(b, ContentBlock::Known(KnownContentBlock::ToolUse { .. })));
        assert!(
            !has_tool_use,
            "the denied tool_use must be stripped from the non-stream response"
        );
        // The text block survives.
        assert!(response
            .content
            .iter()
            .any(|b| matches!(b, ContentBlock::Known(KnownContentBlock::Text { .. }))));
    }

    // ── SLICE 6: inbound tool validation wiring ──

    /// Records the tool names of the request it receives, then fails fast.
    struct ToolRecordingProvider {
        seen: Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl crate::providers::LlmProvider for ToolRecordingProvider {
        async fn send_message(
            &self,
            request: CanonicalRequest,
        ) -> Result<ProviderResponse, crate::providers::error::ProviderError> {
            let names = request
                .tools
                .as_ref()
                .map(|t| t.iter().filter_map(|t| t.name.clone()).collect())
                .unwrap_or_default();
            *self.seen.lock().unwrap() = names;
            Err(crate::providers::error::ProviderError::ApiError {
                status: 400,
                message: "recorded".to_string(),
            })
        }

        async fn send_message_stream(
            &self,
            _request: CanonicalRequest,
        ) -> Result<crate::providers::StreamResponse, crate::providers::error::ProviderError>
        {
            Err(crate::providers::error::ProviderError::ApiError {
                status: 400,
                message: "no stream".to_string(),
            })
        }

        async fn count_tokens(
            &self,
            _request: crate::models::CountTokensRequest,
        ) -> Result<crate::models::CountTokensResponse, crate::providers::error::ProviderError>
        {
            Err(crate::providers::error::ProviderError::ApiError {
                status: 400,
                message: "no count".to_string(),
            })
        }

        fn supports_model(&self, _model: &str) -> bool {
            true
        }
    }

    // Real dispatch(): a malformed inbound tool must be stripped (Step 1.55)
    // BEFORE the provider is called, while the well-formed tool reaches it. Red
    // if the tool-validation call is removed from dispatch.
    #[tokio::test]
    async fn dispatch_strips_malformed_inbound_tool_before_provider() {
        let toml = r#"
[server]
host = "127.0.0.1"
port = 18090

[router]
default = "alpha"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"
"#;
        let config =
            crate::cli::AppConfig::from_content(toml, "tool_validation_dispatch").expect("config");
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let mut registry = crate::providers::ProviderRegistry::new();
        registry.insert_provider_for_test(
            "mock",
            Arc::new(ToolRecordingProvider { seen: seen.clone() }),
        );
        let state = crate::server::test_app_state(config, registry);

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
            allowed_models: None,
            allowed_providers: Vec::new(),
            peer_ip: "127.0.0.1".to_string(),
            req_id: "req-toolval",
            start_time: std::time::Instant::now(),
            headers: &headers,
            trace_id: None,
            audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(feature = "policies")]
            resolved_policy: None,
        };
        // Two tools: one well-formed, one malformed (input_schema is a string).
        let mut request: CanonicalRequest = serde_json::from_value(serde_json::json!({
            "model": "alpha",
            "max_tokens": 16,
            "messages": [{ "role": "user", "content": "hi" }],
            "tools": [
                { "name": "good_tool", "input_schema": { "type": "object" } },
                { "name": "bad_tool", "input_schema": "not-a-schema" }
            ]
        }))
        .unwrap();

        let _ = dispatch(&ctx, &mut request).await;

        let received = seen.lock().unwrap().clone();
        assert!(
            received.contains(&"good_tool".to_string()),
            "the well-formed tool must reach the provider"
        );
        assert!(
            !received.contains(&"bad_tool".to_string()),
            "the malformed tool must be stripped before the provider; got {received:?}"
        );
    }
}
