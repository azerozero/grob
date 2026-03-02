//! Shared dispatch pipeline for provider routing.
//!
//! Both `handle_messages()` (Anthropic native) and `handle_openai_chat_completions()`
//! delegate to the single `dispatch()` function, which orchestrates the full pipeline:
//! DLP scanning → cache lookup → routing → provider loop with fallback → audit → response.

mod telemetry;

use crate::cli::ModelStrategy;
use crate::features::dlp::DlpEngine;
use crate::models::{AnthropicRequest, RouteType};
use crate::providers::ProviderResponse;
use axum::http::HeaderMap;
use bytes::Bytes;
use futures::stream::Stream;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{error, info, warn};

use super::{
    apply_transparency_headers, calculate_cost, check_budget, format_route_type,
    inject_continuation_text, is_provider_subscription, is_retryable, log_audit,
    record_request_metrics, resolve_provider_mappings, retry_delay, sanitize_provider_response,
    should_inject_continuation, AppError, AppState, AuditCompliance, AuditParams, ReloadableState,
    RequestMetrics, MAX_RETRIES,
};

use telemetry::{calculate_and_record_metrics, record_success_telemetry, store_response_cache};

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
}

impl DispatchContext<'_> {
    /// Run DLP input sanitization if enabled.
    fn sanitize_input(&self, request: &mut AnthropicRequest) {
        if let Some(ref dlp_engine) = self.dlp {
            if dlp_engine.config.scan_input {
                dlp_engine.sanitize_request(request);
            }
        }
    }

    /// Run DLP output sanitization if enabled.
    fn sanitize_output(&self, response: &mut ProviderResponse) {
        if let Some(ref dlp_engine) = self.dlp {
            if dlp_engine.config.scan_output {
                sanitize_provider_response(response, dlp_engine);
            }
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
    },
    /// Non-streaming response from a provider.
    Complete {
        response: ProviderResponse,
        provider: String,
        actual_model: String,
        /// Pre-serialized JSON bytes (serialized once, used for cache + response).
        response_bytes: Option<Vec<u8>>,
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
    request: &mut AnthropicRequest,
) -> Result<DispatchResult, AppError> {
    // ── Step 1: DLP input scanning ──
    scan_dlp_input(ctx, request)?;

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
    dispatch_provider_loop(ctx, request, &sorted_mappings, &decision, &cache_key).await
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
    request: &mut AnthropicRequest,
) -> Result<(), AppError> {
    let Some(ref dlp_engine) = ctx.dlp else {
        return Ok(());
    };
    if !dlp_engine.config.scan_input {
        return Ok(());
    }

    if let Err(block_err) = dlp_engine.sanitize_request_checked(request) {
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
        });
        return Err(AppError::DlpBlocked(format!("{}", block_err)));
    }
    Ok(())
}

/// Handle fan-out strategy (dispatch to multiple providers in parallel).
async fn dispatch_fan_out(
    ctx: &DispatchContext<'_>,
    request: &AnthropicRequest,
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

/// Check if a provider is available: exists in registry and circuit breaker is not open.
/// Returns `None` if the provider should be skipped.
async fn resolve_provider(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
) -> Option<Arc<dyn crate::providers::LlmProvider>> {
    let provider = ctx
        .inner
        .provider_registry
        .provider(&mapping.provider)
        .or_else(|| {
            info!(
                "⚠️ Provider {} not found in registry, trying next fallback",
                mapping.provider
            );
            None
        })?;

    // Check availability: scorer (which wraps CB) takes priority over bare CB
    if let Some(ref scorer) = ctx.state.security.provider_scorer {
        if !scorer.can_execute(&mapping.provider).await {
            info!(
                "⚡ Provider {} unavailable (scorer/CB), skipping",
                mapping.provider
            );
            metrics::counter!(
                "grob_circuit_breaker_rejected_total",
                "provider" => mapping.provider.clone()
            )
            .increment(1);
            return None;
        }
    } else if let Some(ref cb) = ctx.state.security.circuit_breakers {
        if !cb.can_execute(&mapping.provider).await {
            info!("⚡ Circuit breaker open for {}, skipping", mapping.provider);
            metrics::counter!(
                "grob_circuit_breaker_rejected_total",
                "provider" => mapping.provider.clone()
            )
            .increment(1);
            return None;
        }
    }

    Some(provider)
}

/// Provider loop with fallback and per-provider retry.
async fn dispatch_provider_loop(
    ctx: &DispatchContext<'_>,
    request: &mut AnthropicRequest,
    sorted_mappings: &[crate::cli::ModelMapping],
    decision: &crate::models::RouteDecision,
    cache_key: &Option<String>,
) -> Result<DispatchResult, AppError> {
    // Re-sort mappings by adaptive score when scorer is enabled
    let rescored;
    let effective_mappings: &[crate::cli::ModelMapping] =
        if let Some(ref scorer) = ctx.state.security.provider_scorer {
            rescored = scorer.sort_mappings(sorted_mappings.to_vec()).await;
            &rescored
        } else {
            sorted_mappings
        };

    for (idx, mapping) in effective_mappings.iter().enumerate() {
        let Some(provider) = resolve_provider(ctx, mapping).await else {
            continue;
        };

        check_budget(
            ctx.state,
            ctx.inner,
            &mapping.provider,
            &decision.model_name,
        )
        .await?;

        log_dispatch_attempt(ctx, mapping, decision, idx, effective_mappings.len());

        let (provider_request, original_model) =
            prepare_provider_request(ctx, request, mapping, &decision.route_type);

        let is_subscription = is_provider_subscription(ctx.inner, &mapping.provider);

        if let Some(ref trace_id) = ctx.trace_id {
            ctx.state.observability.message_tracer.trace_request(
                trace_id,
                &provider_request,
                &mapping.provider,
                &decision.route_type,
                ctx.is_streaming,
            );
        }

        let result = if ctx.is_streaming {
            dispatch_streaming(ctx, provider_request, provider.as_ref(), mapping).await
        } else {
            dispatch_non_streaming(
                ctx,
                provider_request,
                provider.as_ref(),
                &ProviderAttempt {
                    mapping,
                    decision,
                    cache_key,
                    original_model: &original_model,
                    is_subscription,
                },
            )
            .await
        };

        match result {
            Ok(dispatch_result) => return Ok(dispatch_result),
            Err(ProviderLoopAction::Continue) => continue,
        }
    }

    // All providers exhausted — try backward-compat direct lookup
    if let Some(result) = try_direct_provider_lookup(ctx, request, &decision.model_name).await? {
        return Ok(result);
    }

    // Audit: all providers failed
    ctx.log_audit_if_enabled(AuditEntry {
        action: crate::security::audit_log::AuditEvent::Error,
        backend: "NONE",
        dlp_rules: vec![],
        duration_ms: ctx.start_time.elapsed().as_millis() as u64,
        model_name: None,
        token_counts: None,
        risk_level: None,
    });

    error!(
        request_id = ctx.req_id,
        "❌ All provider mappings failed for model: {}", decision.model_name
    );
    Err(AppError::ProviderError(format!(
        "All {} provider mappings failed for model: {}",
        effective_mappings.len(),
        decision.model_name
    )))
}

/// Log the dispatch attempt info line (route type, stream mode, model → provider).
fn log_dispatch_attempt(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
    decision: &crate::models::RouteDecision,
    idx: usize,
    total: usize,
) {
    let retry_info = if idx > 0 {
        format!(" [{}/{}]", idx + 1, total)
    } else {
        String::new()
    };
    let stream_mode = if ctx.is_streaming { "stream" } else { "sync" };
    let route_type_display = format_route_type(decision);

    info!(
        request_id = ctx.req_id,
        "[{:<15}:{}] {:<25} → {}/{}{}",
        route_type_display,
        stream_mode,
        ctx.model,
        mapping.provider,
        mapping.actual_model,
        retry_info
    );
}

/// Clone the request, substitute the actual model, run DLP, and optionally inject continuation.
fn prepare_provider_request(
    ctx: &DispatchContext<'_>,
    request: &AnthropicRequest,
    mapping: &crate::cli::ModelMapping,
    route_type: &RouteType,
) -> (AnthropicRequest, String) {
    let mut provider_request = request.clone();
    let original_model = provider_request.model.clone();
    provider_request.model = mapping.actual_model.clone();
    ctx.sanitize_input(&mut provider_request);

    if mapping.inject_continuation_prompt && *route_type != RouteType::Background {
        if let Some(last_msg) = provider_request.messages.last_mut() {
            if should_inject_continuation(last_msg) {
                info!(
                    "💉 Injecting continuation prompt for model: {}",
                    mapping.actual_model
                );
                inject_continuation_text(last_msg);
            }
        }
    }

    (provider_request, original_model)
}

/// Backward-compat fallback: try direct model→provider lookup from the registry.
async fn try_direct_provider_lookup(
    ctx: &DispatchContext<'_>,
    request: &AnthropicRequest,
    model_name: &str,
) -> Result<Option<DispatchResult>, AppError> {
    let Ok(provider) = ctx.inner.provider_registry.provider_for_model(model_name) else {
        return Ok(None);
    };
    info!(
        "📦 Using provider from registry (direct lookup): {}",
        model_name
    );
    let mut fallback_request = request.clone();
    let original_model = fallback_request.model.clone();
    fallback_request.model = model_name.to_string();

    let mut response = provider
        .send_message(fallback_request)
        .await
        .map_err(|e| AppError::ProviderError(e.to_string()))?;
    response.model = original_model;

    Ok(Some(DispatchResult::Complete {
        response,
        provider: model_name.to_string(),
        actual_model: model_name.to_string(),
        response_bytes: None,
    }))
}

/// Wrap a raw provider stream with DLP sanitization and Tap recording layers.
fn wrap_stream_with_middleware(
    ctx: &DispatchContext<'_>,
    raw_stream: Pin<
        Box<dyn Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send>,
    >,
    tap_request_body: Option<String>,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send>> {
    let stream: Pin<
        Box<dyn Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send>,
    > = if let Some(ref dlp_engine) = ctx.dlp {
        if dlp_engine.config.scan_output {
            Box::pin(crate::features::dlp::stream::DlpStream::new(
                raw_stream,
                Arc::clone(dlp_engine),
            ))
        } else {
            raw_stream
        }
    } else {
        raw_stream
    };

    if let Some(ref tap) = ctx.state.security.tap_sender {
        let tap_req_id = uuid::Uuid::new_v4().to_string();
        if let Some(body_json) = tap_request_body {
            tap.try_send(crate::features::tap::TapEvent::Request {
                request_id: tap_req_id.clone(),
                tenant_id: ctx.tenant_id.clone(),
                model: ctx.model.clone(),
                body: body_json,
            });
        }
        Box::pin(crate::features::tap::stream::TapStream::new(
            stream,
            Arc::clone(tap),
            tap_req_id,
        ))
    } else {
        stream
    }
}

/// Internal signal to continue the provider loop.
enum ProviderLoopAction {
    Continue,
}

/// Handle the streaming path for a single provider attempt.
async fn dispatch_streaming(
    ctx: &DispatchContext<'_>,
    provider_request: AnthropicRequest,
    provider: &dyn crate::providers::LlmProvider,
    mapping: &crate::cli::ModelMapping,
) -> Result<DispatchResult, ProviderLoopAction> {
    // Capture request body for tap before ownership moves
    let tap_request_body = if ctx.state.security.tap_sender.is_some() {
        serde_json::to_string(&provider_request).ok()
    } else {
        None
    };

    match provider.send_message_stream(provider_request).await {
        Ok(stream_response) => {
            let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
            if let Some(ref scorer) = ctx.state.security.provider_scorer {
                scorer.record_success(&mapping.provider, latency_ms).await;
            } else if let Some(ref cb) = ctx.state.security.circuit_breakers {
                cb.record_success(&mapping.provider).await;
            }

            let stream = wrap_stream_with_middleware(ctx, stream_response.stream, tap_request_body);

            let upstream_headers: Vec<(String, String)> =
                stream_response.headers.into_iter().collect();

            Ok(DispatchResult::Streaming {
                stream,
                provider: mapping.provider.clone(),
                actual_model: mapping.actual_model.clone(),
                upstream_headers,
            })
        }
        Err(e) => {
            if let Some(ref scorer) = ctx.state.security.provider_scorer {
                scorer.record_failure(&mapping.provider).await;
            } else if let Some(ref cb) = ctx.state.security.circuit_breakers {
                cb.record_failure(&mapping.provider).await;
            }
            if let Some(ref trace_id) = ctx.trace_id {
                ctx.state
                    .observability
                    .message_tracer
                    .trace_error(trace_id, &e.to_string());
            }
            handle_provider_error(mapping, &e);
            Err(ProviderLoopAction::Continue)
        }
    }
}

/// Emit shared provider-error metrics (rate-limit counter + error counter).
fn emit_provider_error_metrics(
    mapping: &crate::cli::ModelMapping,
    e: &crate::providers::error::ProviderError,
) {
    let is_rate_limit = matches!(
        e,
        crate::providers::error::ProviderError::ApiError { status: 429, .. }
    );
    if is_rate_limit {
        warn!("Provider {} rate limited", mapping.provider);
        metrics::counter!(
            "grob_ratelimit_hits_total",
            "provider" => mapping.provider.clone()
        )
        .increment(1);
    }
    metrics::counter!(
        "grob_provider_errors_total",
        "provider" => mapping.provider.clone()
    )
    .increment(1);
}

/// Classify a provider error, emit metrics, and decide whether to retry or break.
/// Returns `true` if the retry loop should continue (retryable + attempts remaining).
fn classify_and_handle_error(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
    e: &crate::providers::error::ProviderError,
    attempt: u32,
) -> bool {
    if let Some(ref trace_id) = ctx.trace_id {
        ctx.state
            .observability
            .message_tracer
            .trace_error(trace_id, &e.to_string());
    }
    emit_provider_error_metrics(mapping, e);
    is_retryable(e) && attempt < MAX_RETRIES
}

/// Per-provider dispatch parameters (non-streaming path).
struct ProviderAttempt<'a> {
    mapping: &'a crate::cli::ModelMapping,
    decision: &'a crate::models::RouteDecision,
    cache_key: &'a Option<String>,
    original_model: &'a str,
    is_subscription: bool,
}

/// Handle the non-streaming path with retry for a single provider.
async fn dispatch_non_streaming(
    ctx: &DispatchContext<'_>,
    provider_request: AnthropicRequest,
    provider: &dyn crate::providers::LlmProvider,
    attempt: &ProviderAttempt<'_>,
) -> Result<DispatchResult, ProviderLoopAction> {
    // Wrap in Option so we can move (not clone) on the final attempt.
    let mut owned_request = Some(provider_request);
    for retry in 0..=MAX_RETRIES {
        if retry > 0 {
            let delay = retry_delay(retry - 1);
            warn!(
                "⏳ Retrying provider {} (attempt {}/{}), backoff {}ms",
                attempt.mapping.provider,
                retry + 1,
                MAX_RETRIES + 1,
                delay.as_millis()
            );
            tokio::time::sleep(delay).await;
        }

        // Clone for earlier attempts; move on the last to avoid an extra allocation.
        let req = if retry < MAX_RETRIES {
            owned_request.as_ref().expect("set before loop").clone()
        } else {
            owned_request.take().expect("set before loop")
        };

        match provider.send_message(req).await {
            Ok(mut response) => {
                let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
                if let Some(ref scorer) = ctx.state.security.provider_scorer {
                    scorer
                        .record_success(&attempt.mapping.provider, latency_ms)
                        .await;
                } else if let Some(ref cb) = ctx.state.security.circuit_breakers {
                    cb.record_success(&attempt.mapping.provider).await;
                }
                ctx.sanitize_output(&mut response);
                response.model = attempt.original_model.to_string();

                let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
                let outcome = telemetry::DispatchOutcome {
                    mapping: attempt.mapping,
                    decision: attempt.decision,
                    response: &response,
                    latency_ms,
                };
                let cost_usd =
                    calculate_and_record_metrics(ctx, &outcome, attempt.is_subscription).await;
                record_success_telemetry(ctx, &outcome, cost_usd).await;
                let response_bytes =
                    store_response_cache(ctx, attempt.mapping, attempt.cache_key, &response).await;

                return Ok(DispatchResult::Complete {
                    response,
                    provider: attempt.mapping.provider.clone(),
                    actual_model: attempt.mapping.actual_model.clone(),
                    response_bytes,
                });
            }
            Err(e) => {
                if classify_and_handle_error(ctx, attempt.mapping, &e, retry) {
                    warn!(
                        "⚠️ Provider {} failed (retryable): {}",
                        attempt.mapping.provider, e
                    );
                    continue;
                }

                if let Some(ref scorer) = ctx.state.security.provider_scorer {
                    scorer.record_failure(&attempt.mapping.provider).await;
                } else if let Some(ref cb) = ctx.state.security.circuit_breakers {
                    cb.record_failure(&attempt.mapping.provider).await;
                }
                info!(
                    "⚠️ Provider {} failed: {}, trying next fallback",
                    attempt.mapping.provider, e
                );
                break;
            }
        }
    }
    Err(ProviderLoopAction::Continue)
}

/// Log provider error metrics for the streaming path.
fn handle_provider_error(
    mapping: &crate::cli::ModelMapping,
    e: &crate::providers::error::ProviderError,
) {
    emit_provider_error_metrics(mapping, e);
    info!(
        "⚠️ Provider {} streaming failed: {}, trying next fallback",
        mapping.provider, e
    );
}
