//! Provider fallback loop: resolve, dispatch, retry, and error handling.

use super::{telemetry, AuditEntry, DispatchContext, DispatchResult};
use crate::models::RouteType;
use bytes::Bytes;
use futures::stream::Stream;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{info, warn};

use super::super::{
    check_budget, format_route_type, inject_continuation_text, is_auth_revoked_error,
    is_provider_subscription, is_retryable, retry_delay, AppError, MAX_RETRIES,
};
use super::telemetry::{
    calculate_and_record_metrics, record_success_telemetry, store_response_cache,
};

/// Check if a provider is available: exists in registry and circuit breaker is not open.
/// Returns `None` if the provider should be skipped.
pub(super) async fn resolve_provider(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
) -> Option<Arc<dyn crate::providers::LlmProvider>> {
    let provider = ctx
        .inner
        .provider_registry
        .provider(&mapping.provider)
        .or_else(|| {
            info!(
                "Provider {} not found in registry, trying next fallback",
                mapping.provider
            );
            None
        })?;

    // Check availability: scorer (which wraps CB) takes priority over bare CB
    if let Some(ref scorer) = ctx.state.security.provider_scorer {
        if !scorer.can_execute(&mapping.provider).await {
            info!(
                "Provider {} unavailable (scorer/CB), skipping",
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
            info!("Circuit breaker open for {}, skipping", mapping.provider);
            metrics::counter!(
                "grob_circuit_breaker_rejected_total",
                "provider" => mapping.provider.clone()
            )
            .increment(1);
            return None;
        }
    }

    // Routing-layer passive CB (RE-1a, ADR-0018). Per-endpoint, orthogonal
    // to the global per-provider security CB above — an endpoint can be
    // down while the provider still has other endpoints up.
    if !ctx
        .inner
        .provider_registry
        .is_endpoint_healthy(&mapping.provider, &mapping.actual_model)
    {
        info!(
            "Endpoint {}/{} tripped by passive CB, skipping",
            mapping.provider, mapping.actual_model
        );
        metrics::counter!(
            "grob_routing_endpoint_cb_rejected_total",
            "provider" => mapping.provider.clone(),
            "model" => mapping.actual_model.clone(),
        )
        .increment(1);
        return None;
    }

    Some(provider)
}

/// Provider loop with fallback and per-provider retry.
pub(super) async fn dispatch_provider_loop(
    ctx: &DispatchContext<'_>,
    request: &mut crate::models::CanonicalRequest,
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

        // Emit RequestStart event for `grob watch`.
        ctx.state
            .event_bus
            .emit(crate::features::watch::events::WatchEvent::RequestStart {
                request_id: ctx.req_id.to_string(),
                model: mapping.actual_model.clone(),
                provider: mapping.provider.clone(),
                input_tokens: 0,
                route_type: decision.route_type.to_string(),
                timestamp: chrono::Utc::now(),
            });

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
            Err(ProviderLoopAction::RateLimited) => {
                if let Some(ok) = try_rotate_and_retry(
                    ctx,
                    request,
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
                {
                    return Ok(ok);
                }
                emit_fallback(
                    ctx,
                    mapping,
                    effective_mappings.get(idx + 1),
                    "rate limited",
                );
                tokio::task::yield_now().await;
                continue;
            }
            Err(ProviderLoopAction::Continue) => {
                emit_fallback(
                    ctx,
                    mapping,
                    effective_mappings.get(idx + 1),
                    "provider error",
                );
                tokio::task::yield_now().await;
                continue;
            }
            Err(ProviderLoopAction::AuthRevoked(msg)) => {
                tracing::error!(
                    provider = %mapping.provider,
                    "OAuth token for provider {} revoked. Run: grob connect --force-reauth",
                    mapping.provider
                );
                // Abort the fallback cascade: this is a user-actionable error,
                // not a transient provider failure.
                return Err(AppError::AuthenticationError(format!(
                    "OAuth token for provider '{}' revoked. Run: grob connect --force-reauth. Details: {}",
                    mapping.provider, msg
                )));
            }
        }
    }

    // All providers exhausted -- try backward-compat direct lookup
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
        dlp_blocked: false,
        dlp_had_injection: false,
        dlp_had_pii: false,
        dlp_had_redact_or_warn: false,
    });

    tracing::error!(
        request_id = ctx.req_id,
        "All provider mappings failed for model: {}",
        decision.model_name
    );
    Err(AppError::ProviderError(format!(
        "All {} provider mappings failed for model: {}",
        effective_mappings.len(),
        decision.model_name
    )))
}

/// Log the dispatch attempt info line (route type, stream mode, model -> provider).
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
        "[{:<15}:{}] {:<25} -> {}/{}{}",
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
    request: &crate::models::CanonicalRequest,
    mapping: &crate::cli::ModelMapping,
    route_type: &RouteType,
) -> (crate::models::CanonicalRequest, String) {
    let mut provider_request = request.clone();
    let original_model = provider_request.model.clone();
    provider_request.model = mapping.actual_model.clone();
    ctx.sanitize_input(&mut provider_request);

    if mapping.inject_continuation_prompt && *route_type != RouteType::Background {
        if let Some(last_msg) = provider_request.messages.last_mut() {
            if should_inject_continuation(last_msg) {
                info!(
                    "Injecting continuation prompt for model: {}",
                    mapping.actual_model
                );
                inject_continuation_text(last_msg);
            }
        }
    }

    (provider_request, original_model)
}

/// Attempts key pool rotation and retry on rate limit.
///
/// Returns `Some(result)` if the retry succeeded, `None` if rotation was
/// unavailable or the retry also failed.
async fn try_rotate_and_retry(
    ctx: &DispatchContext<'_>,
    request: &mut crate::models::CanonicalRequest,
    provider: &dyn crate::providers::LlmProvider,
    attempt: &ProviderAttempt<'_>,
) -> Option<DispatchResult> {
    if !provider.rotate_key_pool() {
        return None;
    }
    info!(
        "Provider {} rate-limited, rotated to next pooled key — retrying",
        attempt.mapping.provider
    );
    let (retry_request, _) =
        prepare_provider_request(ctx, request, attempt.mapping, &attempt.decision.route_type);
    let retry_result = if ctx.is_streaming {
        dispatch_streaming(ctx, retry_request, provider, attempt.mapping).await
    } else {
        dispatch_non_streaming(ctx, retry_request, provider, attempt).await
    };
    retry_result.ok()
}

/// Emits a fallback event for `grob watch`.
fn emit_fallback(
    ctx: &DispatchContext<'_>,
    from: &crate::cli::ModelMapping,
    next: Option<&crate::cli::ModelMapping>,
    reason: &str,
) {
    if let Some(next) = next {
        ctx.state
            .event_bus
            .emit(crate::features::watch::events::WatchEvent::Fallback {
                request_id: ctx.req_id.to_string(),
                from_provider: from.provider.clone(),
                to_provider: next.provider.clone(),
                reason: reason.to_string(),
                timestamp: chrono::Utc::now(),
            });
    }
}

/// Backward-compat fallback: try direct model->provider lookup from the registry.
async fn try_direct_provider_lookup(
    ctx: &DispatchContext<'_>,
    request: &crate::models::CanonicalRequest,
    model_name: &str,
) -> Result<Option<DispatchResult>, AppError> {
    let Ok(provider) = ctx.inner.provider_registry.provider_for_model(model_name) else {
        return Ok(None);
    };
    info!(
        "Using provider from registry (direct lookup): {}",
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
        provider_duration_ms: 0,
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

    // HIT stream: intercept tool_use blocks for human authorization.
    #[cfg(feature = "policies")]
    let stream = {
        let hit_policy = ctx.resolved_policy.as_ref().and_then(|p| p.hit.clone());
        if let Some(hit) = hit_policy {
            Box::pin(crate::features::policies::stream::HitStream::new(
                stream,
                hit,
                ctx.req_id.to_string(),
                Some(Arc::clone(&ctx.state.hit_pending)),
                Some(ctx.state.event_bus.clone()),
                ctx.state.security.audit_log.clone(),
            ))
                as Pin<
                    Box<
                        dyn Stream<Item = Result<Bytes, crate::providers::error::ProviderError>>
                            + Send,
                    >,
                >
        } else {
            stream
        }
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
    /// Rate-limited (429): the caller should attempt key pool rotation
    /// before falling through to the next provider mapping.
    RateLimited,
    /// Terminal auth failure (401 `authentication_error`): do NOT fall back
    /// to sibling providers — surface the error directly to the client so the
    /// user is prompted to run `grob connect --force-reauth`.
    AuthRevoked(String),
}

/// Handle the streaming path for a single provider attempt.
async fn dispatch_streaming(
    ctx: &DispatchContext<'_>,
    provider_request: crate::models::CanonicalRequest,
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
            // Overhead = time from request receipt to first SSE byte (before provider responded).
            let overhead_ms = ctx.start_time.elapsed().as_millis() as u64;
            let latency_ms = overhead_ms;
            ctx.record_provider_success(&mapping.provider, latency_ms)
                .await;
            ctx.record_endpoint_success(&mapping.provider, &mapping.actual_model);

            let stream = wrap_stream_with_middleware(ctx, stream_response.stream, tap_request_body);

            let upstream_headers: Vec<(String, String)> =
                stream_response.headers.into_iter().collect();

            Ok(DispatchResult::Streaming {
                stream,
                provider: mapping.provider.clone(),
                actual_model: mapping.actual_model.clone(),
                upstream_headers,
                overhead_ms,
            })
        }
        Err(e) => {
            ctx.record_provider_failure(&mapping.provider).await;
            ctx.record_endpoint_failure(&mapping.provider, &mapping.actual_model);
            if let Some(ref trace_id) = ctx.trace_id {
                ctx.state
                    .observability
                    .message_tracer
                    .trace_error(trace_id, &e.to_string());
            }
            handle_provider_error(mapping, &e);
            if is_auth_revoked_error(&e) {
                return Err(ProviderLoopAction::AuthRevoked(e.to_string()));
            }
            let is_rate_limit = matches!(
                e,
                crate::providers::error::ProviderError::ApiError { status: 429, .. }
            );
            if is_rate_limit {
                Err(ProviderLoopAction::RateLimited)
            } else {
                Err(ProviderLoopAction::Continue)
            }
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
    provider_request: crate::models::CanonicalRequest,
    provider: &dyn crate::providers::LlmProvider,
    attempt: &ProviderAttempt<'_>,
) -> Result<DispatchResult, ProviderLoopAction> {
    // Wrap in Option so we can move (not clone) on the final attempt.
    let mut owned_request = Some(provider_request);
    for retry in 0..=MAX_RETRIES {
        if retry > 0 {
            let delay = retry_delay(retry - 1);
            warn!(
                "Retrying provider {} (attempt {}/{}), backoff {}ms",
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

        let provider_start = std::time::Instant::now();
        match provider.send_message(req).await {
            Ok(mut response) => {
                let provider_duration_ms = provider_start.elapsed().as_millis() as u64;
                let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
                ctx.record_provider_success(&attempt.mapping.provider, latency_ms)
                    .await;
                ctx.record_endpoint_success(
                    &attempt.mapping.provider,
                    &attempt.mapping.actual_model,
                );
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
                let cached_bytes =
                    store_response_cache(ctx, attempt.mapping, attempt.cache_key, &response).await;

                // Emit RequestEnd event for `grob watch`.
                ctx.state
                    .event_bus
                    .emit(crate::features::watch::events::WatchEvent::RequestEnd {
                        request_id: ctx.req_id.to_string(),
                        model: attempt.mapping.actual_model.clone(),
                        provider: attempt.mapping.provider.clone(),
                        output_tokens: response.usage.output_tokens,
                        latency_ms,
                        cost_usd,
                        timestamp: chrono::Utc::now(),
                    });

                // Emit to external log sinks.
                if let Some(ref exporter) = ctx.state.log_exporter {
                    let (encrypted_content, content_recipients) =
                        build_encrypted_content(ctx, &cached_bytes);

                    exporter.emit(&crate::features::log_export::LogEntry {
                        request_id: ctx.req_id.to_string(),
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        model: attempt.mapping.actual_model.clone(),
                        provider: attempt.mapping.provider.clone(),
                        input_tokens: response.usage.input_tokens,
                        output_tokens: response.usage.output_tokens,
                        latency_ms,
                        cost_usd,
                        status: "success".to_string(),
                        dlp_actions: vec![],
                        tenant_id: ctx.tenant_id.clone(),
                        encrypted_content,
                        content_recipients,
                    });
                }

                return Ok(DispatchResult::Complete {
                    response,
                    provider: attempt.mapping.provider.clone(),
                    actual_model: attempt.mapping.actual_model.clone(),
                    provider_duration_ms,
                });
            }
            Err(e) => {
                // 401 authentication_error is terminal — abort the cascade.
                if is_auth_revoked_error(&e) {
                    ctx.record_provider_failure(&attempt.mapping.provider).await;
                    return Err(ProviderLoopAction::AuthRevoked(e.to_string()));
                }

                if classify_and_handle_error(ctx, attempt.mapping, &e, retry) {
                    // On 429, try rotating to next pooled key before retrying.
                    let is_rate_limit = matches!(
                        e,
                        crate::providers::error::ProviderError::ApiError { status: 429, .. }
                    );
                    if is_rate_limit && provider.rotate_key_pool() {
                        info!(
                            "Provider {} rate-limited, rotated to next pooled key",
                            attempt.mapping.provider
                        );
                    }
                    warn!(
                        "Provider {} failed (retryable): {}",
                        attempt.mapping.provider, e
                    );
                    continue;
                }

                // Before giving up on this provider, try key rotation for 429.
                let is_rate_limit = matches!(
                    e,
                    crate::providers::error::ProviderError::ApiError { status: 429, .. }
                );
                if is_rate_limit && provider.rotate_key_pool() {
                    info!(
                        "Provider {} exhausted retries but rotated to next pooled key",
                        attempt.mapping.provider
                    );
                    // Reset owned_request for another attempt cycle.
                    continue;
                }

                ctx.record_provider_failure(&attempt.mapping.provider).await;
                ctx.record_endpoint_failure(
                    &attempt.mapping.provider,
                    &attempt.mapping.actual_model,
                );
                info!(
                    "Provider {} failed: {}, trying next fallback",
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
        "Provider {} streaming failed: {}, trying next fallback",
        mapping.provider, e
    );
}

use super::super::should_inject_continuation;

/// Builds encrypted content for log export when policy requires it.
///
/// Returns `(None, None)` when encryption is not configured or no policy matches.
#[allow(unused_variables)]
fn build_encrypted_content(
    ctx: &DispatchContext<'_>,
    response_bytes: &Option<Vec<u8>>,
) -> (Option<String>, Option<Vec<String>>) {
    #[cfg(feature = "policies")]
    {
        use crate::features::log_export::ContentMode;

        // Check if log export is configured for encryption.
        if ctx.state.log_exporter.is_none() {
            return (None, None);
        }
        let log_config = &ctx.inner.config.log_export;
        if log_config.content != ContentMode::Encrypted {
            return (None, None);
        }

        // Resolve recipients from access policies.
        let access_ctx = crate::features::log_export::access_policy::AccessContext {
            tenant: ctx.tenant_id.clone(),
            compliance: vec![],
            dlp_triggered: false,
        };
        let recipient_keys = crate::features::log_export::access_policy::resolve_recipients(
            &log_config.access_policies,
            &log_config.auditors,
            &access_ctx,
        );
        if recipient_keys.is_empty() {
            return (None, None);
        }

        // Build content string from response.
        let content = response_bytes
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();

        // Encrypt.
        let recipient_names: Vec<String> = log_config
            .access_policies
            .iter()
            .flat_map(|p| p.recipients.clone())
            .collect();

        match crate::features::log_export::encryption::encrypt_for_recipients(
            &content,
            &recipient_keys,
        ) {
            Ok(encrypted) => (Some(encrypted), Some(recipient_names)),
            Err(e) => {
                tracing::warn!("Failed to encrypt log content: {}", e);
                (None, None)
            }
        }
    }
    #[cfg(not(feature = "policies"))]
    {
        (None, None)
    }
}
