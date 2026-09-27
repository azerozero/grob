//! Shared dispatch pipeline for provider routing.
//!
//! Both `handle_messages()` (Anthropic native) and `handle_openai_chat_completions()`
//! delegate to the single `dispatch()` function, which orchestrates the full pipeline:
//! DLP scanning → cache lookup → routing → provider loop with fallback → audit → response.

mod preflight;
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
impl DispatchContext<'_> {
    /// Agent this request's spend is attributed to, if any.
    ///
    /// Two bodies rather than a gated call site: every caller stays
    /// feature-agnostic, and a build without `agents` attributes to nothing
    /// instead of failing to compile.
    #[cfg(feature = "agents")]
    pub(crate) fn agent_id(&self) -> Option<&str> {
        self.agent.id()
    }

    /// Agent attribution is unavailable without the `agents` feature.
    #[cfg(not(feature = "agents"))]
    pub(crate) fn agent_id(&self) -> Option<&str> {
        None
    }
}

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
    /// Calling-agent attribution parsed from request headers.
    ///
    /// Carried, never inferred: a wrong attribution is worse than none,
    /// because it points an investigation at the wrong agent.
    #[cfg(feature = "agents")]
    pub agent: crate::features::agents::AgentContext,
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
    /// Hands the request's inline images to the media slice.
    ///
    /// Off unless `[media] mode` says otherwise, and non-blocking when on:
    /// the call returns before any inspection happens, so the request path
    /// is unchanged either way.
    #[cfg(feature = "media")]
    fn observe_media(&self, request: &CanonicalRequest) {
        // No home directory means no journal to write to, so there is
        // nothing useful to observe.
        let Some(home) = crate::grob_home() else {
            return;
        };
        crate::features::media::observe::observe_request(
            request,
            &self.inner.config.media,
            home,
            self.tenant_id.clone(),
            self.dlp.clone(),
        );
    }

    /// No-op when the media feature is compiled out.
    #[cfg(not(feature = "media"))]
    fn observe_media(&self, _request: &CanonicalRequest) {}

    /// Inspects images before dispatch when `[media] mode = "blocking"`.
    ///
    /// Returns `Forbidden` when the verdict refuses. The two refusal reasons
    /// are reported distinctly on purpose: findings mean the request must
    /// change, a failed inspection means the sidecar must be fixed, and an
    /// operator reading a log line should be able to tell which.
    #[cfg(feature = "media")]
    async fn gate_media(&self, request: &CanonicalRequest) -> Result<(), RequestError> {
        use crate::features::media::blocking::{inspect_blocking, DenyReason, Verdict};

        let config = &self.inner.config.media;
        if !config.is_blocking() {
            return Ok(());
        }
        match inspect_blocking(request, config, self.dlp.as_deref()).await {
            Verdict::Allow => Ok(()),
            Verdict::Deny { rules, reason } => {
                let message = match reason {
                    DenyReason::Findings => {
                        tracing::warn!(?rules, "media inspection refused a request");
                        "request refused: an attached image matched a data-loss rule"
                    }
                    DenyReason::NotInspected => {
                        tracing::error!(
                            "media inspection could not complete; refusing per on_failure=deny"
                        );
                        "request refused: an attached image could not be inspected"
                    }
                };
                Err(RequestError::Forbidden(message.to_string()))
            }
        }
    }

    /// No-op when the media feature is compiled out.
    #[cfg(not(feature = "media"))]
    async fn gate_media(&self, _request: &CanonicalRequest) -> Result<(), RequestError> {
        Ok(())
    }

    /// Run DLP input sanitization if enabled, emitting watch events for actions taken.
    fn sanitize_input(&self, request: &mut CanonicalRequest) {
        self.observe_media(request);
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

    /// Records a provider success through the configured availability authority.
    pub(crate) async fn record_provider_success(&self, provider: &str, latency_ms: u64) {
        if let Some(ref availability) = self.state.security.provider_availability {
            availability.record_success(provider, latency_ms).await;
        }
    }

    /// Records a provider failure through the configured availability authority.
    pub(crate) async fn record_provider_failure(&self, provider: &str) {
        if let Some(ref availability) = self.state.security.provider_availability {
            availability.record_failure(provider).await;
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
                // From this request's own snapshot, so a concurrent reload
                // cannot attribute the decision to a policy set that was not
                // the one applied.
                policy_revision: self.inner.policy_revision.full(),
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

    // ── Step 1: Security and tool preflight ──
    // `dlp_triggered` feeds the post-route policy context (Step 5.4).
    #[cfg_attr(not(feature = "policies"), allow(unused_variables))]
    let dlp_triggered = preflight::run(ctx, request)?;

    // ── Step 2: Cache key ──
    let cache_key = ctx
        .state
        .security
        .response_cache
        .as_ref()
        .and_then(|_cache| {
            crate::cache::ResponseCache::compute_key_from_request(
                &serde_json::to_string(&(
                    ctx.tenant_id.as_deref().unwrap_or("anon"),
                    ctx.inner.cache_epoch,
                    &ctx.allowed_models,
                    &ctx.allowed_providers,
                ))
                .ok()?,
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

    let context_guard = enforce_context_guard(
        ctx.inner,
        request,
        &decision.model_name,
        sorted_mappings.first(),
    )?;

    // ── Step 4.5: Tool layer (aliasing, injection, capability gating) ──
    if let Some(ref tool_layer) = ctx.inner.tool_layer {
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

    // Tier fan-out takes priority over model-level fan-out; both share dispatch.
    if let Some(fan_out_config) = resolve_fan_out_config(ctx.inner, &decision) {
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

/// Applies the context-window guard before cache access and provider dispatch.
fn enforce_context_guard(
    inner: &ReloadableState,
    request: &CanonicalRequest,
    model: &str,
    first_mapping: Option<&crate::cli::ModelMapping>,
) -> Result<Option<ContextGuardInfo>, RequestError> {
    match evaluate_context_guard(inner, request, model, first_mapping) {
        ContextGuardDecision::Ok => Ok(None),
        ContextGuardDecision::Warn(info) => {
            tracing::warn!(
                estimated_input_tokens = info.estimated_input_tokens,
                context_window = info.context_window,
                usage_ratio = info.usage_ratio,
                model = %model,
                "request is approaching the configured context window; compact soon"
            );
            metrics::counter!("grob_context_guard_warnings_total",
                "model" => model.to_string(),
            )
            .increment(1);
            Ok(Some(info))
        }
        ContextGuardDecision::Block(info) => {
            metrics::counter!("grob_context_guard_blocks_total",
                "model" => model.to_string(),
            )
            .increment(1);
            Err(RequestError::ContextWindowExceeded {
                message: context_window_exceeded_message(&info),
                estimated_input_tokens: info.estimated_input_tokens,
                context_window: info.context_window,
                usage_ratio: info.usage_ratio,
            })
        }
    }
}

/// Resolves tier precedence independently from executing a fan-out request.
fn resolve_fan_out_config<'a>(
    inner: &'a ReloadableState,
    decision: &crate::models::RouteDecision,
) -> Option<std::borrow::Cow<'a, crate::cli::FanOutConfig>> {
    let tier = decision.complexity_tier.as_ref().and_then(|tier| {
        let name = tier.to_string();
        inner
            .config
            .tiers
            .iter()
            .find(|configured| configured.name == name)
    });
    if tier.is_some_and(|tier| tier.fanout) {
        return Some(std::borrow::Cow::Owned(crate::cli::FanOutConfig {
            mode: crate::cli::FanOutMode::Fastest,
            judge_model: None,
            judge_criteria: None,
            count: None,
        }));
    }
    let model = inner.find_model(&decision.model_name)?;
    if model.strategy != ModelStrategy::FanOut {
        return None;
    }
    model.fan_out.as_ref().map(std::borrow::Cow::Borrowed)
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
///    a policy override. A dedicated [`AppState::scoped_rate_limiter`] keeps these
///    custom-rps buckets off the middleware's default-rate buckets.
///
/// `routing` and `log_export` overrides are intentionally NOT applied in this
/// slice (explicit follow-up).
///
/// [`RequestContext`]: crate::features::policies::context::RequestContext
async fn enforce_post_route_policy(
    ctx: &DispatchContext<'_>,
    request: &CanonicalRequest,
    decision: &crate::models::RouteDecision,
    provider: &str,
    dlp_triggered: bool,
) -> Result<(), RequestError> {
    ctx.gate_media(request).await?;

    // Keep the media gate in one body for every feature combination. A second
    // cfg-disabled function body also appears in cargo-mutants' source scan,
    // producing a survivor that no all-features test can execute.
    #[cfg(not(feature = "policies"))]
    {
        let _ = (decision, provider, dlp_triggered);
        Ok(())
    }

    #[cfg(feature = "policies")]
    {
        let Some(matcher) = ctx.inner.policy_matcher.as_ref() else {
            return Ok(());
        };

        // Best-effort estimated cost (input only — output is unknown pre-call) so
        // `cost_above`-keyed policies can match.
        let input_tokens = super::estimate_input_tokens(request);
        let estimated_cost =
            calculate_cost(ctx.state, &decision.model_name, input_tokens, 0, 0, false)
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
            // A policy budget is a fleet-wide amount like every other cap, so it
            // takes this replica's share. Without this, moving a cap into a policy
            // would quietly exempt it from the fleet ceiling that `[budget]`
            // enforces everywhere else — the limit would still be honoured per
            // process, and still be multiplied by the replica count.
            let budget_config = &ctx.inner.config.budget;
            let limit = crate::security::replica_budget_share(
                limit,
                budget_config.replicas,
                budget_config.margin_percent,
            );
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
            // A policy rps is a fleet-wide number like every other configured
            // limit, so it takes this replica's share too. Without this, naming a
            // rate limit in a policy would quietly exempt it from the fleet
            // ceiling that `[security]` enforces everywhere else.
            let sec = &ctx.inner.config.security;
            let rps = crate::security::replica_share(
                rps,
                sec.rate_limit_replicas,
                sec.rate_limit_margin_percent,
            );
            let (allowed, _, _) = ctx
                .state
                .scoped_rate_limiter
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
            ctx.agent_id(),
        )
        .await;
    }
}

#[cfg(test)]
mod tests;
