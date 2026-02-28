//! Shared dispatch logic for provider routing.
//!
//! Both `handle_messages()` (Anthropic native) and `handle_openai_chat_completions()`
//! share ~90% identical logic: DLP → cache → routing → provider loop → audit → response.
//! This module extracts that shared pipeline into a single `dispatch()` function.

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
    record_request_metrics, record_spend, resolve_provider_mappings, retry_delay,
    sanitize_provider_response, should_inject_continuation, AppError, AppState, AuditCompliance,
    AuditParams, ReloadableState, RequestMetrics, MAX_RETRIES,
};

/// All context needed to dispatch a request through the provider pipeline.
pub(crate) struct DispatchContext<'a> {
    pub state: &'a Arc<AppState>,
    pub inner: &'a Arc<ReloadableState>,
    pub dlp: &'a Option<Arc<DlpEngine>>,
    /// Original model name as requested by the client.
    pub model: String,
    pub is_streaming: bool,
    pub tenant_id: Option<String>,
    pub peer_ip: String,
    pub req_id: &'a str,
    pub start_time: std::time::Instant,
    pub headers: &'a HeaderMap,
    /// Message tracer context. None for OpenAI compat endpoint.
    pub trace_id: Option<String>,
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
    let cache_key = ctx.state.response_cache.as_ref().and_then(|_cache| {
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
    if !ctx.is_streaming {
        if let (Some(ref cache), Some(ref key)) = (&ctx.state.response_cache, &cache_key) {
            if let Some(cached) = cache.get(key).await {
                let mut resp = axum::response::Response::builder()
                    .status(200)
                    .header("content-type", &cached.content_type)
                    .header("x-grob-cache", "hit")
                    .body(axum::body::Body::from(cached.body.clone()))
                    .expect("cached response");
                if super::should_apply_transparency(&ctx.inner.config) {
                    apply_transparency_headers(
                        resp.headers_mut(),
                        &cached.provider,
                        &cached.model,
                        ctx.req_id,
                    );
                }
                return Ok(DispatchResult::CacheHit(resp));
            }
        }
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

        if ctx.inner.config.compliance.enabled && ctx.inner.config.compliance.risk_classification {
            let threshold = crate::security::audit_log::RiskLevel::from_str_threshold(
                &ctx.inner.config.compliance.escalation_threshold,
            );
            crate::security::risk::maybe_escalate(
                risk,
                threshold,
                &ctx.inner.config.compliance.escalation_webhook,
                ctx.req_id,
                ctx.tenant_id.as_deref().unwrap_or("anon"),
                &ctx.model,
            );
        }

        if let Some(ref al) = ctx.state.audit_log {
            log_audit(&AuditParams {
                audit_log: al,
                tenant_id: ctx.tenant_id.as_deref().unwrap_or("anon"),
                action: crate::security::audit_log::AuditEvent::DlpBlock,
                backend: "BLOCKED",
                dlp_rules: vec![block_err.to_string()],
                ip: &ctx.peer_ip,
                duration_ms: ctx.start_time.elapsed().as_millis() as u64,
                eu: AuditCompliance {
                    config: &ctx.inner.config.compliance,
                    model_name: Some(&ctx.model),
                    token_counts: None,
                    risk_level: Some(risk),
                },
            });
        }
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

    // DLP on input
    if let Some(ref dlp_engine) = ctx.dlp {
        if dlp_engine.config.scan_input {
            dlp_engine.sanitize_request(&mut fan_request);
        }
    }

    match super::fan_out::handle_fan_out(
        &fan_request,
        sorted_mappings,
        fan_out_config,
        &ctx.inner.provider_registry,
    )
    .await
    {
        Ok((mut response, provider_info)) => {
            // DLP on output
            if let Some(ref dlp_engine) = ctx.dlp {
                if dlp_engine.config.scan_output {
                    sanitize_provider_response(&mut response, dlp_engine);
                }
            }

            // Track cost for ALL providers called
            let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
            for (prov, actual) in &provider_info {
                let is_sub = is_provider_subscription(ctx.inner, prov);
                let counter = calculate_cost(
                    ctx.state,
                    actual,
                    response.usage.input_tokens,
                    response.usage.output_tokens,
                    is_sub,
                )
                .await;
                let mut tracker = ctx.state.spend_tracker.lock().await;
                tracker.record(prov, actual, counter.estimated_cost_usd);
            }

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

            // Audit: fan-out success
            if let Some(ref al) = ctx.state.audit_log {
                let fan_out_model = provider_info
                    .first()
                    .map(|(_, m)| m.as_str())
                    .unwrap_or("fan_out");
                log_audit(&AuditParams {
                    audit_log: al,
                    tenant_id: ctx.tenant_id.as_deref().unwrap_or("anon"),
                    action: crate::security::audit_log::AuditEvent::Response,
                    backend: "fan_out",
                    dlp_rules: vec![],
                    ip: &ctx.peer_ip,
                    duration_ms: latency_ms,
                    eu: AuditCompliance {
                        config: &ctx.inner.config.compliance,
                        model_name: Some(fan_out_model),
                        token_counts: Some((
                            response.usage.input_tokens,
                            response.usage.output_tokens,
                        )),
                        risk_level: Some(crate::security::audit_log::RiskLevel::Low),
                    },
                });
            }

            // Restore original model name
            response.model = ctx.model.clone();
            Ok(DispatchResult::FanOut { response })
        }
        Err(e) => Err(AppError::ProviderError(format!("Fan-out failed: {}", e))),
    }
}

/// Provider loop with fallback and per-provider retry.
async fn dispatch_provider_loop(
    ctx: &DispatchContext<'_>,
    request: &mut AnthropicRequest,
    sorted_mappings: &[crate::cli::ModelMapping],
    decision: &crate::models::RouteDecision,
    cache_key: &Option<String>,
) -> Result<DispatchResult, AppError> {
    for (idx, mapping) in sorted_mappings.iter().enumerate() {
        let Some(provider) = ctx.inner.provider_registry.get_provider(&mapping.provider) else {
            info!(
                "⚠️ Provider {} not found in registry, trying next fallback",
                mapping.provider
            );
            continue;
        };

        // Circuit breaker check
        if let Some(ref cb) = ctx.state.circuit_breakers {
            if !cb.can_execute(&mapping.provider).await {
                info!("⚡ Circuit breaker open for {}, skipping", mapping.provider);
                metrics::counter!(
                    "grob_circuit_breaker_rejected_total",
                    "provider" => mapping.provider.clone()
                )
                .increment(1);
                continue;
            }
        }

        // Budget check
        check_budget(
            ctx.state,
            ctx.inner,
            &mapping.provider,
            &decision.model_name,
        )
        .await?;

        let retry_info = if idx > 0 {
            format!(" [{}/{}]", idx + 1, sorted_mappings.len())
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

        let (provider_request, original_model) =
            prepare_provider_request(ctx, request, mapping, &decision.route_type);

        let is_sub = is_provider_subscription(ctx.inner, &mapping.provider);

        // Trace the request (Messages handler only)
        if let Some(ref trace_id) = ctx.trace_id {
            ctx.state.message_tracer.trace_request(
                trace_id,
                &provider_request,
                &mapping.provider,
                &decision.route_type,
                ctx.is_streaming,
            );
        }

        if ctx.is_streaming {
            match dispatch_streaming(ctx, provider_request, provider.as_ref(), mapping).await {
                Ok(result) => return Ok(result),
                Err(ProviderLoopAction::Continue) => continue,
            }
        } else {
            match dispatch_non_streaming(
                ctx,
                provider_request,
                provider.as_ref(),
                &ProviderAttempt {
                    mapping,
                    decision,
                    cache_key,
                    original_model: &original_model,
                    is_sub,
                },
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(ProviderLoopAction::Continue) => continue,
            }
        }
    }

    // All providers exhausted — try backward-compat direct lookup
    if let Some(result) = try_direct_provider_lookup(ctx, request, &decision.model_name).await? {
        return Ok(result);
    }

    // Audit: all providers failed
    if let Some(ref al) = ctx.state.audit_log {
        log_audit(&AuditParams {
            audit_log: al,
            tenant_id: ctx.tenant_id.as_deref().unwrap_or("anon"),
            action: crate::security::audit_log::AuditEvent::Error,
            backend: "NONE",
            dlp_rules: vec![],
            ip: &ctx.peer_ip,
            duration_ms: ctx.start_time.elapsed().as_millis() as u64,
            eu: AuditCompliance {
                config: &ctx.inner.config.compliance,
                model_name: None,
                token_counts: None,
                risk_level: None,
            },
        });
    }

    error!(
        request_id = ctx.req_id,
        "❌ All provider mappings failed for model: {}", decision.model_name
    );
    Err(AppError::ProviderError(format!(
        "All {} provider mappings failed for model: {}",
        sorted_mappings.len(),
        decision.model_name
    )))
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

    if let Some(ref dlp_engine) = ctx.dlp {
        if dlp_engine.config.scan_input {
            dlp_engine.sanitize_request(&mut provider_request);
        }
    }

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
    let Ok(provider) = ctx
        .inner
        .provider_registry
        .get_provider_for_model(model_name)
    else {
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

    if let Some(ref tap) = ctx.state.tap_sender {
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
    provider: &dyn crate::providers::AnthropicProvider,
    mapping: &crate::cli::ModelMapping,
) -> Result<DispatchResult, ProviderLoopAction> {
    // Capture request body for tap before ownership moves
    let tap_request_body = if ctx.state.tap_sender.is_some() {
        serde_json::to_string(&provider_request).ok()
    } else {
        None
    };

    match provider.send_message_stream(provider_request).await {
        Ok(stream_response) => {
            if let Some(ref cb) = ctx.state.circuit_breakers {
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
            // Record circuit breaker failure
            if let Some(ref cb) = ctx.state.circuit_breakers {
                cb.record_failure(&mapping.provider).await;
            }
            if let Some(ref trace_id) = ctx.trace_id {
                ctx.state
                    .message_tracer
                    .trace_error(trace_id, &e.to_string());
            }
            handle_provider_error(ctx, mapping, &e);
            Err(ProviderLoopAction::Continue)
        }
    }
}

/// Calculate cost and emit performance metrics + Prometheus counters.
async fn calculate_and_record_metrics(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
    decision: &crate::models::RouteDecision,
    response: &ProviderResponse,
    latency_ms: u64,
    is_sub: bool,
) -> f64 {
    let tok_s = (response.usage.output_tokens as f32 * 1000.0) / latency_ms as f32;
    let cost = calculate_cost(
        ctx.state,
        &mapping.actual_model,
        response.usage.input_tokens,
        response.usage.output_tokens,
        is_sub,
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
        if is_sub { " (subscription)" } else { "" }
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
async fn record_success_telemetry(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
    decision: &crate::models::RouteDecision,
    response: &ProviderResponse,
    latency_ms: u64,
    cost_usd: f64,
) {
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
            .message_tracer
            .trace_response(trace_id, response, latency_ms);
    }

    if let Some(ref al) = ctx.state.audit_log {
        log_audit(&AuditParams {
            audit_log: al,
            tenant_id: ctx.tenant_id.as_deref().unwrap_or("anon"),
            action: crate::security::audit_log::AuditEvent::Response,
            backend: &mapping.provider,
            dlp_rules: vec![],
            ip: &ctx.peer_ip,
            duration_ms: latency_ms,
            eu: AuditCompliance {
                config: &ctx.inner.config.compliance,
                model_name: Some(&mapping.actual_model),
                token_counts: Some((response.usage.input_tokens, response.usage.output_tokens)),
                risk_level: Some(crate::security::audit_log::RiskLevel::Low),
            },
        });
    }
}

/// Serialize the response and store it in the cache if enabled.
async fn store_response_cache(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
    cache_key: &Option<String>,
    response: &ProviderResponse,
) -> Option<Vec<u8>> {
    let response_bytes = serde_json::to_vec(response).ok();

    if let (Some(ref cache), Some(ref key), Some(ref bytes)) =
        (&ctx.state.response_cache, cache_key, &response_bytes)
    {
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

/// Classify a provider error, emit metrics, and decide whether to retry or break.
/// Returns `true` if the retry loop should continue (retryable + attempts remaining).
fn classify_and_handle_error(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
    e: &crate::providers::error::ProviderError,
    attempt: u32,
) -> bool {
    let retryable = is_retryable(e);
    if let Some(ref trace_id) = ctx.trace_id {
        ctx.state
            .message_tracer
            .trace_error(trace_id, &e.to_string());
    }

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

    retryable && attempt < MAX_RETRIES
}

/// Per-provider dispatch parameters (non-streaming path).
struct ProviderAttempt<'a> {
    mapping: &'a crate::cli::ModelMapping,
    decision: &'a crate::models::RouteDecision,
    cache_key: &'a Option<String>,
    original_model: &'a str,
    is_sub: bool,
}

/// Handle the non-streaming path with retry for a single provider.
async fn dispatch_non_streaming(
    ctx: &DispatchContext<'_>,
    provider_request: AnthropicRequest,
    provider: &dyn crate::providers::AnthropicProvider,
    pa: &ProviderAttempt<'_>,
) -> Result<DispatchResult, ProviderLoopAction> {
    let mut last_error = None;
    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            let delay = retry_delay(attempt - 1);
            warn!(
                "⏳ Retrying provider {} (attempt {}/{}), backoff {}ms",
                pa.mapping.provider,
                attempt + 1,
                MAX_RETRIES + 1,
                delay.as_millis()
            );
            tokio::time::sleep(delay).await;
        }

        match provider.send_message(provider_request.clone()).await {
            Ok(mut response) => {
                if let Some(ref cb) = ctx.state.circuit_breakers {
                    cb.record_success(&pa.mapping.provider).await;
                }
                if let Some(ref dlp_engine) = ctx.dlp {
                    if dlp_engine.config.scan_output {
                        sanitize_provider_response(&mut response, dlp_engine);
                    }
                }
                response.model = pa.original_model.to_string();

                let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
                let cost_usd = calculate_and_record_metrics(
                    ctx,
                    pa.mapping,
                    pa.decision,
                    &response,
                    latency_ms,
                    pa.is_sub,
                )
                .await;
                record_success_telemetry(
                    ctx,
                    pa.mapping,
                    pa.decision,
                    &response,
                    latency_ms,
                    cost_usd,
                )
                .await;
                let response_bytes =
                    store_response_cache(ctx, pa.mapping, pa.cache_key, &response).await;

                return Ok(DispatchResult::Complete {
                    response,
                    provider: pa.mapping.provider.clone(),
                    actual_model: pa.mapping.actual_model.clone(),
                    response_bytes,
                });
            }
            Err(e) => {
                if classify_and_handle_error(ctx, pa.mapping, &e, attempt) {
                    warn!(
                        "⚠️ Provider {} failed (retryable): {}",
                        pa.mapping.provider, e
                    );
                    last_error = Some(e);
                    continue;
                }

                if let Some(ref cb) = ctx.state.circuit_breakers {
                    cb.record_failure(&pa.mapping.provider).await;
                }
                info!(
                    "⚠️ Provider {} failed: {}, trying next fallback",
                    pa.mapping.provider, e
                );
                last_error = Some(e);
                break;
            }
        }
    }
    let _ = last_error;
    Err(ProviderLoopAction::Continue)
}

/// Log provider error metrics (shared between streaming and non-streaming).
fn handle_provider_error(
    _ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
    e: &crate::providers::error::ProviderError,
) {
    let is_rate_limit = matches!(
        e,
        crate::providers::error::ProviderError::ApiError { status: 429, .. }
    );
    if is_rate_limit {
        warn!("Provider {} rate limited, falling back", mapping.provider);
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
    info!(
        "⚠️ Provider {} streaming failed: {}, trying next fallback",
        mapping.provider, e
    );
}
