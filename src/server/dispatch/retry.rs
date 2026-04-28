//! Single-provider dispatch with retry + error classification.
//!
//! Owns the inner loop of the provider fallback cascade: sending the request,
//! classifying failures, deciding whether to retry with backoff, rotating the
//! key pool on rate-limit, and wiring the output stream through the DLP, HIT,
//! and Tap middleware layers.
//!
//! The caller ([`super::provider_loop::dispatch_provider_loop`]) decides which
//! mapping to try next; this module decides what happens *within* a single
//! mapping attempt.

use bytes::Bytes;
use futures::stream::Stream;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{info, warn};

use super::super::{is_auth_revoked_error, is_retryable, provider_max_retries, retry_delay};
use super::rate_limit::RateLimitHandler;
use super::telemetry::{
    calculate_and_record_metrics, record_success_telemetry, store_response_cache,
};
use super::{telemetry, DispatchContext, DispatchResult};

/// Internal signal from the per-attempt dispatch back to the outer provider loop.
pub(super) enum ProviderLoopAction {
    /// Non-terminal failure: move to the next mapping in the priority list.
    Continue,
    /// Rate-limited (429): the caller should attempt key pool rotation
    /// before falling through to the next provider mapping.
    RateLimited,
    /// Terminal auth failure (401 `authentication_error`): do NOT fall back
    /// to sibling providers — surface the error directly to the client so the
    /// user is prompted to run `grob connect --force-reauth`.
    AuthRevoked(String),
}

/// Per-provider dispatch parameters (non-streaming path).
pub(super) struct ProviderAttempt<'a> {
    pub mapping: &'a crate::cli::ModelMapping,
    pub decision: &'a crate::models::RouteDecision,
    pub cache_key: &'a Option<String>,
    pub original_model: &'a str,
    pub is_subscription: bool,
}

/// Emit shared provider-error metrics (rate-limit counter + error counter).
fn emit_provider_error_metrics(
    mapping: &crate::cli::ModelMapping,
    e: &crate::providers::error::ProviderError,
) {
    if e.is_rate_limit() {
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
    max_retries: u32,
) -> bool {
    if let Some(ref trace_id) = ctx.trace_id {
        ctx.state
            .observability
            .message_tracer
            .trace_error(trace_id, &e.to_string());
    }
    emit_provider_error_metrics(mapping, e);
    is_retryable(e) && attempt < max_retries
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

/// Attempts key pool rotation and retry on rate limit.
///
/// Returns `Some(result)` if the retry succeeded, `None` if rotation was
/// unavailable or the retry also failed.
pub(super) async fn try_rotate_and_retry(
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
    let (retry_request, _) = super::provider_loop::prepare_provider_request(
        ctx,
        request,
        attempt.mapping,
        &attempt.decision.route_type,
    );
    let retry_result = if ctx.is_streaming {
        dispatch_streaming(ctx, retry_request, provider, attempt.mapping).await
    } else {
        dispatch_non_streaming(ctx, retry_request, provider, attempt).await
    };
    retry_result.ok()
}

/// Handle the streaming path for a single provider attempt.
pub(super) async fn dispatch_streaming(
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
            if e.is_rate_limit() {
                Err(ProviderLoopAction::RateLimited)
            } else {
                Err(ProviderLoopAction::Continue)
            }
        }
    }
}

/// Handle the non-streaming path with retry for a single provider.
pub(super) async fn dispatch_non_streaming(
    ctx: &DispatchContext<'_>,
    provider_request: crate::models::CanonicalRequest,
    provider: &dyn crate::providers::LlmProvider,
    attempt: &ProviderAttempt<'_>,
) -> Result<DispatchResult, ProviderLoopAction> {
    // Wrap in Option so we can move (not clone) on the final attempt.
    let mut owned_request = Some(provider_request);
    // Resolve per-provider retry budget (`[[providers]] max_retries = N`)
    // with fallback to the global default. Looked up once per provider
    // dispatch — config is static for the lifetime of the loop.
    let max_retries = provider_max_retries(ctx.inner, &attempt.mapping.provider);
    for retry in 0..=max_retries {
        if retry > 0 {
            let delay = retry_delay(retry - 1);
            warn!(
                "Retrying provider {} (attempt {}/{}), backoff {}ms",
                attempt.mapping.provider,
                retry + 1,
                max_retries + 1,
                delay.as_millis()
            );
            tokio::time::sleep(delay).await;
        }

        // Clone for earlier attempts; move on the last to avoid an extra allocation.
        let req = if retry < max_retries {
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

                if classify_and_handle_error(ctx, attempt.mapping, &e, retry, max_retries) {
                    // On rate-limit, try rotating to next pooled key before retrying.
                    if e.is_rate_limit() && provider.rotate_key_pool() {
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

                // Before giving up on this provider, try key rotation on rate-limit.
                if e.is_rate_limit() && provider.rotate_key_pool() {
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

/// Wrap a raw provider stream with DLP sanitization, HIT authorization, and Tap recording layers.
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
