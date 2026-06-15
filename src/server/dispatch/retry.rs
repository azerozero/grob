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
use std::time::Instant;
use tracing::{info, warn};

use super::super::{is_auth_revoked_error, is_retryable, provider_max_retries, retry_delay};
use super::telemetry::{
    calculate_and_record_metrics, record_success_telemetry, store_response_cache,
};
use super::{telemetry, DispatchContext, DispatchResult};
use crate::providers::error::ProviderError;
use crate::server::RequestError;

/// Internal signal from the per-attempt dispatch back to the outer provider loop.
pub(super) enum ProviderLoopAction {
    /// Non-terminal failure: move to the next mapping in the priority list.
    ///
    /// Carries the captured upstream error so the loop can surface the real
    /// cause to the client when every mapping fails, instead of a generic 502.
    Continue(Box<RequestError>),
    /// Rate-limited (429): the caller should attempt key pool rotation before
    /// falling through to the next provider mapping. Carries the captured
    /// upstream error for the same reason as [`ProviderLoopAction::Continue`].
    RateLimited(Box<RequestError>),
    /// Terminal auth failure (401 `authentication_error`): do NOT fall back
    /// to sibling providers — surface the error directly to the client so the
    /// user is prompted to run `grob connect --force-reauth`.
    AuthRevoked(String),
}

/// Captures a provider failure as a [`RequestError`] preserving the upstream
/// status and body verbatim.
///
/// The blanket `From<ProviderError>` flattens a 429 to a body-less
/// `RateLimited`, dropping the diagnostic payload (e.g. ChatGPT's
/// `usage_limit_reached` with `resets_in_seconds`). Keeping status + body here
/// lets the loop surface the true upstream cause when every mapping fails,
/// rather than a misleading fallback or a generic 502.
pub(super) fn capture_upstream_error(provider: &str, err: &ProviderError) -> RequestError {
    use crate::providers::error::is_context_window_exceeded_message;

    match err {
        ProviderError::ApiError { message, .. } if is_context_window_exceeded_message(message) => {
            context_window_error(message.clone())
        }
        ProviderError::ApiError { status, message } => RequestError::ProviderUpstream {
            provider: provider.to_string(),
            status: *status,
            body: Some(message.clone()),
        },
        ProviderError::ProtocolError(message) if is_context_window_exceeded_message(message) => {
            context_window_error(message.clone())
        }
        ProviderError::ProtocolError(message) => RequestError::ProviderProtocol {
            provider: provider.to_string(),
            body: message.clone(),
        },
        ProviderError::InvalidRequest(message) if is_context_window_exceeded_message(message) => {
            context_window_error(message.clone())
        }
        other => RequestError::ProviderUpstream {
            provider: provider.to_string(),
            status: 502,
            body: Some(other.to_string()),
        },
    }
}

fn context_window_error(_message: String) -> RequestError {
    RequestError::ContextWindowExceeded {
        message: "Input exceeds the configured context window. Compact the conversation and retry.\n\nSuggested action:\nRun /compact, then retry the last request.".to_string(),
        estimated_input_tokens: 0,
        context_window: 0,
        usage_ratio: 1.0,
    }
}

/// Per-provider dispatch parameters (non-streaming path).
pub(super) struct ProviderAttempt<'a> {
    pub mapping: &'a crate::cli::ModelMapping,
    pub decision: &'a crate::models::RouteDecision,
    pub cache_key: &'a Option<String>,
    pub original_model: &'a str,
    pub is_subscription: bool,
    pub context_guard: Option<crate::server::ContextGuardInfo>,
}

/// Per-provider dispatch parameters (streaming path).
///
/// Carries the routing metadata the spend wrapper needs to attribute cost,
/// captured before the request is consumed by `send_message_stream`.
pub(super) struct StreamingAttempt<'a> {
    pub mapping: &'a crate::cli::ModelMapping,
    pub decision: &'a crate::models::RouteDecision,
    pub is_subscription: bool,
    pub context_guard: Option<crate::server::ContextGuardInfo>,
}

/// Traces cancellation before a streaming response body exists.
///
/// Normal streams are traced by the response body wrapper in `handlers.rs`.
/// This guard covers the earlier gap while waiting for upstream response
/// headers: if the client disconnects there, no body wrapper is ever created.
struct PreStreamTraceGuard {
    tracer: Option<Arc<dyn crate::traits::Tracer>>,
    trace_id: Option<String>,
    start_time: Instant,
}

impl PreStreamTraceGuard {
    fn new(ctx: &DispatchContext<'_>) -> Self {
        let (tracer, trace_id) = match &ctx.trace_id {
            Some(id) => (
                Some(Arc::clone(&ctx.state.observability.message_tracer)),
                Some(id.clone()),
            ),
            None => (None, None),
        };

        Self {
            tracer,
            trace_id,
            start_time: ctx.start_time,
        }
    }

    fn disarm(&mut self) {
        self.tracer = None;
        self.trace_id = None;
    }

    fn finish(&mut self, status: &str) {
        let (Some(tracer), Some(trace_id)) = (self.tracer.take(), self.trace_id.take()) else {
            return;
        };

        tracer.trace_stream_end(
            &trace_id,
            0,
            0,
            self.start_time.elapsed().as_millis() as u64,
            status,
            None,
        );
    }
}

impl Drop for PreStreamTraceGuard {
    fn drop(&mut self) {
        self.finish("dropped_before_stream");
    }
}

/// Returns `true` when a provider error reports a 429 rate-limit upstream.
///
/// Defers to the `RequestError::RateLimited` mapping rules so the
/// classification logic lives in one place: a 429 status code OR a 401 with a
/// `rate_limit_error` payload (Anthropic-style). Callers that need to know
/// specifically whether they hit a 429 (e.g. to rotate a key pool) consult
/// this helper rather than re-implement the matcher.
pub(super) fn is_upstream_rate_limit(e: &crate::providers::error::ProviderError) -> bool {
    use crate::providers::error::ProviderError;
    match e {
        ProviderError::ApiError { status: 429, .. } => true,
        ProviderError::ApiError {
            status: 401,
            message,
        } => super::super::budget::is_rate_limit_payload(message),
        _ => false,
    }
}

/// Emit shared provider-error metrics (rate-limit counter + error counter).
fn emit_provider_error_metrics(
    mapping: &crate::cli::ModelMapping,
    e: &crate::providers::error::ProviderError,
) {
    if is_upstream_rate_limit(e) {
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
    should_retry_after_error(is_retryable(e), attempt, max_retries)
}

/// Returns `true` when a failed attempt should be retried.
///
/// A retry happens only when the error is retryable *and* attempts remain
/// (`attempt < max_retries`). Extracted so the decision in
/// [`classify_and_handle_error`] is unit-testable without a [`DispatchContext`].
#[inline]
fn should_retry_after_error(retryable: bool, attempt: u32, max_retries: u32) -> bool {
    retryable && attempt < max_retries
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

/// Rotates through the key pool, retrying once per remaining key on rate limit.
///
/// Each rotation gives the next pooled key its own retry budget. Returns
/// `Some(result)` on the first success, or `None` when the pool is exhausted, a
/// retry fails for a non-rate-limit reason, or no pool rotation is available.
pub(super) async fn try_rotate_and_retry(
    ctx: &DispatchContext<'_>,
    request: &mut crate::models::CanonicalRequest,
    provider: &dyn crate::providers::LlmProvider,
    attempt: &ProviderAttempt<'_>,
) -> Option<DispatchResult> {
    // Walk the remaining pooled keys. `rotate_key_pool` marks the current key
    // exhausted and advances to the next non-exhausted one, returning false once
    // the whole pool is spent — so this loop is bounded by the pool size.
    while rotation_available(provider.rotate_key_pool()) {
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
            dispatch_streaming(
                ctx,
                retry_request,
                provider,
                &StreamingAttempt {
                    mapping: attempt.mapping,
                    decision: attempt.decision,
                    is_subscription: attempt.is_subscription,
                    context_guard: attempt.context_guard.clone(),
                },
            )
            .await
        } else {
            dispatch_non_streaming(ctx, retry_request, provider, attempt).await
        };
        match retry_result {
            Ok(result) => return Some(result),
            // Still rate-limited on this key → rotate to the next one.
            Err(ProviderLoopAction::RateLimited(_)) => continue,
            // A non-rate-limit failure won't be fixed by trying another key.
            Err(_) => return None,
        }
    }
    None
}

/// Handle the streaming path for a single provider attempt.
pub(super) async fn dispatch_streaming(
    ctx: &DispatchContext<'_>,
    provider_request: crate::models::CanonicalRequest,
    provider: &dyn crate::providers::LlmProvider,
    attempt: &StreamingAttempt<'_>,
) -> Result<DispatchResult, ProviderLoopAction> {
    let mapping = attempt.mapping;
    let mut pre_stream_trace = PreStreamTraceGuard::new(ctx);

    // Capture request body for tap before ownership moves.
    let tap_request_body = if ctx.state.security.tap_sender.is_some() {
        serde_json::to_string(&provider_request).ok()
    } else {
        None
    };

    // Capture the input-token estimate before the request is consumed below.
    // Only read as the estimate-mode fallback when the provider omits usage;
    // skip the work in `api` mode.
    let estimated_input_tokens = if crate::server::is_estimate_mode(ctx.state) {
        crate::server::estimate_input_tokens(&provider_request)
    } else {
        0
    };

    match provider.send_message_stream(provider_request).await {
        Ok(stream_response) => {
            pre_stream_trace.disarm();
            // Overhead = time from request receipt to first SSE byte (before provider responded).
            let overhead_ms = ctx.start_time.elapsed().as_millis() as u64;
            let latency_ms = overhead_ms;
            ctx.record_provider_success(&mapping.provider, latency_ms)
                .await;
            ctx.record_endpoint_success(&mapping.provider, &mapping.actual_model);

            // Spend accounting: streaming previously recorded no persistent
            // spend. Wrap the post-provider byte stream so cost is committed on
            // termination (provider usage, else estimate-mode fallback).
            let spend_ctx = super::spend_stream::SpendStreamContext {
                state: Arc::clone(ctx.state),
                provider: mapping.provider.clone(),
                model_name: attempt.decision.model_name.clone(),
                actual_model: mapping.actual_model.clone(),
                route_type: attempt.decision.route_type,
                tenant_id: ctx.tenant_id.clone(),
                is_subscription: attempt.is_subscription,
                estimated_input_tokens,
                start_time: ctx.start_time,
                trace_id: ctx.trace_id.clone(),
            };
            let accounted =
                super::spend_stream::SpendStream::new(stream_response.stream, spend_ctx);

            let stream = wrap_stream_with_middleware(ctx, Box::pin(accounted), tap_request_body);

            let upstream_headers: Vec<(String, String)> =
                stream_response.headers.into_iter().collect();

            Ok(DispatchResult::Streaming {
                stream,
                provider: mapping.provider.clone(),
                actual_model: mapping.actual_model.clone(),
                upstream_headers,
                overhead_ms,
                context_guard: attempt.context_guard.clone(),
            })
        }
        Err(e) => {
            pre_stream_trace.disarm();
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
            let captured = Box::new(capture_upstream_error(&mapping.provider, &e));
            if is_upstream_rate_limit(&e) {
                Err(ProviderLoopAction::RateLimited(captured))
            } else {
                Err(ProviderLoopAction::Continue(captured))
            }
        }
    }
}

/// Returns `true` when this loop iteration is a retry (needs a backoff sleep).
///
/// The first iteration (`retry == 0`) is the initial attempt, not a retry.
/// Extracted so the `retry > 0` boundary in [`dispatch_non_streaming`] is
/// unit-testable without a [`DispatchContext`].
#[inline]
fn is_backoff_attempt(retry: u32) -> bool {
    retry > 0
}

/// Maps a retry counter to its zero-based backoff exponent (`retry - 1`).
///
/// Only called when [`is_backoff_attempt`] holds, so `retry >= 1` and the
/// subtraction never underflows. Extracted so the `retry - 1` arithmetic in
/// [`dispatch_non_streaming`] is unit-testable without a [`DispatchContext`].
#[inline]
fn backoff_step(retry: u32) -> u32 {
    retry - 1
}

/// Returns `true` when the request must be cloned (more attempts remain).
///
/// On the final attempt (`retry == max_retries`) the owned request is moved
/// instead of cloned. Extracted so the `retry < max_retries` boundary in
/// [`dispatch_non_streaming`] is unit-testable without a [`DispatchContext`].
#[inline]
fn should_clone_for_retry(retry: u32, max_retries: u32) -> bool {
    retry < max_retries
}

/// Returns `true` only when the error is a rate-limit *and* rotation succeeds.
///
/// The `rotate` closure is invoked solely when `rate_limited` holds, preserving
/// the original short-circuit (`is_upstream_rate_limit(e) && rotate_key_pool()`)
/// so a non-429 error never advances the key pool. Extracted so the guard in
/// [`dispatch_non_streaming`] is unit-testable without a [`DispatchContext`].
#[inline]
fn try_rotation_on_rate_limit(rate_limited: bool, rotate: impl FnOnce() -> bool) -> bool {
    rate_limited && rotate()
}

/// Returns `true` when key-pool rotation was unavailable (`!rotated`).
///
/// Extracted so the early-return guard in [`try_rotate_and_retry`] is
/// unit-testable without a [`DispatchContext`].
#[inline]
fn rotation_unavailable(rotated: bool) -> bool {
    !rotated
}

/// Returns `true` while the key pool yielded a fresh key to retry with.
///
/// Sibling of [`rotation_unavailable`], extracted so the loop-guard `!` in
/// [`try_rotate_and_retry`] is unit-testable without a [`DispatchContext`].
#[inline]
fn rotation_available(rotated: bool) -> bool {
    !rotation_unavailable(rotated)
}

/// Handle the non-streaming path with retry for a single provider.
pub(super) async fn dispatch_non_streaming(
    ctx: &DispatchContext<'_>,
    provider_request: crate::models::CanonicalRequest,
    provider: &dyn crate::providers::LlmProvider,
    attempt: &ProviderAttempt<'_>,
) -> Result<DispatchResult, ProviderLoopAction> {
    // Capture an input-token estimate before the request is consumed below. It
    // is only ever read when the provider omits usage in estimate mode; skip
    // the work entirely otherwise.
    let estimated_input_tokens = if crate::server::is_estimate_mode(ctx.state) {
        crate::server::estimate_input_tokens(&provider_request)
    } else {
        0
    };

    // Resolve the per-provider retry budget (`[[providers]] max_retries = N`),
    // falling back to the global default. Looked up once per dispatch — config
    // is static for the lifetime of this loop (a hot reload swaps the snapshot
    // for *future* requests, never an in-flight one).
    let max_retries = provider_max_retries(ctx.inner, &attempt.mapping.provider);

    // Wrap in Option so we can move (not clone) on the final attempt.
    let mut owned_request = Some(provider_request);
    // Most recent failure, captured so the outer loop can surface the real
    // upstream error (status + body, rate-limit flag) instead of a generic 502.
    let mut last_error: Option<(bool, RequestError)> = None;
    for retry in 0..=max_retries {
        if is_backoff_attempt(retry) {
            let delay = retry_delay(backoff_step(retry));
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
        let req = if should_clone_for_retry(retry, max_retries) {
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

                // HIT authorization: inspect tool_use blocks and strip any the
                // policy denies (the streaming path does this via HitStream).
                // Runs after DLP and before caching so a denied tool is neither
                // returned nor cached.
                #[cfg(feature = "policies")]
                authorize_non_streaming_response(ctx, &mut response).await;

                let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
                let outcome = telemetry::DispatchOutcome {
                    mapping: attempt.mapping,
                    decision: attempt.decision,
                    response: &response,
                    latency_ms,
                    estimated_input_tokens,
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
                    context_guard: attempt.context_guard.clone(),
                });
            }
            Err(e) => {
                // 401 authentication_error is terminal — abort the cascade.
                if is_auth_revoked_error(&e) {
                    ctx.record_provider_failure(&attempt.mapping.provider).await;
                    return Err(ProviderLoopAction::AuthRevoked(e.to_string()));
                }

                // Remember the latest failure so it can be surfaced verbatim if
                // this provider is ultimately given up on.
                last_error = Some((
                    is_upstream_rate_limit(&e),
                    capture_upstream_error(&attempt.mapping.provider, &e),
                ));

                if classify_and_handle_error(ctx, attempt.mapping, &e, retry, max_retries) {
                    // On 429, try rotating to next pooled key before retrying.
                    let rate_limited = is_upstream_rate_limit(&e);
                    if try_rotation_on_rate_limit(rate_limited, || provider.rotate_key_pool()) {
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
                let rate_limited = is_upstream_rate_limit(&e);
                if try_rotation_on_rate_limit(rate_limited, || provider.rotate_key_pool()) {
                    info!(
                        "Provider {} exhausted retries but rotated to next pooled key",
                        attempt.mapping.provider
                    );
                    // Retries are exhausted (this is reached only on the final
                    // iteration): the rotation just advances the pool pointer so a
                    // later request starts on a fresh key. `owned_request` was
                    // already moved out on the last attempt; `continue` falls
                    // through to the loop exit rather than starting a new attempt.
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
    match last_error {
        Some((true, err)) => Err(ProviderLoopAction::RateLimited(Box::new(err))),
        Some((false, err)) => Err(ProviderLoopAction::Continue(Box::new(err))),
        None => Err(ProviderLoopAction::Continue(Box::new(
            RequestError::ProviderUpstream {
                provider: attempt.mapping.provider.clone(),
                status: 502,
                body: None,
            },
        ))),
    }
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

/// Maximum time the non-streaming path waits for a human HIT approval before
/// denying the tool_use.
///
/// Bounded so a synchronous request can never block indefinitely (DoS); a
/// streaming request keeps the connection open via `HitStream` instead.
#[cfg(feature = "policies")]
const HIT_APPROVAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Applies HIT authorization to a non-streaming response *in place*, reusing the
/// stream's `evaluate_tool_use` decision logic and signed-receipt mechanism.
///
/// Each `tool_use` block is evaluated against `policy`; denied or timed-out tools
/// are STRIPPED from `response.content`, approved ones kept. Approvals
/// (Simple/MultiSig/Quorum) wait on the same channel the `/api/hit/approve`
/// endpoint resolves, but bounded by `approval_timeout` — a timeout denies rather
/// than blocking forever. Returns the signed receipts (also written to the audit
/// log) so callers/tests can observe the decisions.
#[cfg(feature = "policies")]
async fn apply_hit_to_response(
    response: &mut crate::providers::ProviderResponse,
    policy: &crate::features::policies::hit::HitOverride,
    request_id: &str,
    hit_pending: &Option<Arc<crate::features::policies::stream::HitPendingApprovals>>,
    event_bus: &Option<crate::features::watch::EventBus>,
    audit_log: &Option<Arc<crate::security::AuditLog>>,
    approval_timeout: std::time::Duration,
) -> Vec<crate::features::policies::hit_auth::HitAuthorization> {
    use crate::features::policies::hit::{evaluate_tool_use, HitDecision, ToolUseInfo};
    use crate::features::policies::hit_auth::{AuthDecision, AuthMethod};
    use crate::features::policies::stream::approval::setup_approval;
    use crate::features::policies::stream::{write_hit_receipt, ReceiptContext};
    use crate::models::{ContentBlock, KnownContentBlock};

    let mut receipts = Vec::new();
    let mut last_hash: Option<String> = None;
    let original = std::mem::take(&mut response.content);
    let mut kept = Vec::with_capacity(original.len());

    for block in original {
        let tool = match &block {
            ContentBlock::Known(KnownContentBlock::ToolUse { name, input, .. }) => {
                Some((name.clone(), input.to_string()))
            }
            _ => None,
        };
        let Some((name, input_preview)) = tool else {
            kept.push(block);
            continue;
        };
        let info = ToolUseInfo {
            name: name.clone(),
            input_preview: input_preview.clone(),
        };

        // Mirror the streaming receipt mapping exactly (see `apply_hit_decision`
        // / `apply_require_approval` in `policies::stream`).
        let (approve, decision, method, signer): (bool, AuthDecision, AuthMethod, &str) =
            match evaluate_tool_use(policy, &info) {
                HitDecision::AutoApprove => (
                    true,
                    AuthDecision::Approve,
                    AuthMethod::MachineKey,
                    "policy",
                ),
                HitDecision::Deny => (false, AuthDecision::Deny, AuthMethod::MachineKey, "policy"),
                HitDecision::RequireApproval if policy.auth_method == AuthMethod::MachineKey => (
                    true,
                    AuthDecision::Approve,
                    AuthMethod::MachineKey,
                    "machine_key",
                ),
                HitDecision::RequireApproval => {
                    let rx = setup_approval(
                        request_id,
                        &name,
                        &input_preview,
                        policy,
                        hit_pending,
                        event_bus,
                    );
                    match tokio::time::timeout(approval_timeout, rx).await {
                        Ok(Ok(true)) => (true, AuthDecision::Approve, policy.auth_method, "human"),
                        Ok(Ok(false)) => (false, AuthDecision::Deny, policy.auth_method, "human"),
                        // Channel dropped without a decision → deny (as streaming does).
                        Ok(Err(_)) => (false, AuthDecision::Deny, policy.auth_method, "human"),
                        // Bounded timeout → deny, and drop the now-orphaned pending entry.
                        Err(_) => {
                            if let Some(store) = hit_pending {
                                if let Ok(mut map) = store.lock() {
                                    map.remove(&format!("{request_id}:{name}"));
                                }
                            }
                            (false, AuthDecision::Deny, policy.auth_method, "timeout")
                        }
                    }
                }
            };

        receipts.push(write_hit_receipt(
            &mut last_hash,
            audit_log,
            request_id,
            ReceiptContext {
                tool_name: &name,
                tool_input: &input_preview,
                decision,
                auth_method: method,
                signer,
            },
        ));

        if approve {
            kept.push(block);
        } else {
            metrics::counter!("grob_hit_denied_total").increment(1);
            tracing::info!(
                request_id = %request_id,
                tool = %name,
                "HIT: tool_use stripped from non-stream response"
            );
        }
    }

    response.content = kept;
    receipts
}

/// HIT authorization for the non-streaming path.
///
/// Mirrors the streaming `wrap_stream_with_middleware` HIT layer: same
/// `policy.hit` (read from `ctx.resolved_policy`), same signed receipts, same
/// approval channel — only the unbounded `Paused` wait is replaced by a bounded
/// timeout, since a synchronous request cannot stay open forever.
#[cfg(feature = "policies")]
async fn authorize_non_streaming_response(
    ctx: &DispatchContext<'_>,
    response: &mut crate::providers::ProviderResponse,
) {
    let Some(policy) = ctx.resolved_policy.as_ref().and_then(|p| p.hit.clone()) else {
        return;
    };
    apply_hit_to_response(
        response,
        &policy,
        ctx.req_id,
        &Some(Arc::clone(&ctx.state.hit_pending)),
        &Some(ctx.state.event_bus.clone()),
        &ctx.state.security.audit_log,
        HIT_APPROVAL_TIMEOUT,
    )
    .await;
}

/// Returns `true` when the log-export content mode requests encryption.
///
/// Extracted so the mode comparison in [`build_encrypted_content`] is
/// unit-testable without a [`DispatchContext`].
#[cfg(feature = "policies")]
#[inline]
fn encryption_enabled(mode: &crate::features::log_export::ContentMode) -> bool {
    *mode == crate::features::log_export::ContentMode::Encrypted
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
        // Check if log export is configured for encryption.
        if ctx.state.log_exporter.is_none() {
            return (None, None);
        }
        let log_config = &ctx.inner.config.log_export;
        if !encryption_enabled(&log_config.content) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CanonicalRequest, RouteType};
    use crate::providers::ProviderResponse;
    use crate::traits::Tracer;
    use std::cell::Cell;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingTracer {
        stream_ends: Mutex<Vec<(String, u64, usize, String)>>,
    }

    impl Tracer for RecordingTracer {
        fn new_trace_id(&self) -> String {
            "trace".to_string()
        }

        fn trace_request(
            &self,
            _id: &str,
            _request: &CanonicalRequest,
            _provider: &str,
            _route_type: &RouteType,
            _is_stream: bool,
        ) {
        }

        fn trace_response(&self, _id: &str, _response: &ProviderResponse, _latency_ms: u64) {}

        fn trace_stream_end(
            &self,
            id: &str,
            chunk_count: u64,
            byte_count: usize,
            _latency_ms: u64,
            status: &str,
            _usage: Option<crate::traits::StreamTraceUsage>,
        ) {
            self.stream_ends.lock().unwrap().push((
                id.to_string(),
                chunk_count,
                byte_count,
                status.to_string(),
            ));
        }

        fn trace_error(&self, _id: &str, _error: &str) {}
    }

    // ── pre-stream trace guard ──

    #[test]
    fn pre_stream_trace_guard_records_drop_before_stream() {
        let tracer = Arc::new(RecordingTracer::default());

        {
            let _guard = PreStreamTraceGuard {
                tracer: Some(tracer.clone()),
                trace_id: Some("abc123".to_string()),
                start_time: Instant::now(),
            };
        }

        let events = tracer.stream_ends.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "abc123");
        assert_eq!(events[0].1, 0);
        assert_eq!(events[0].2, 0);
        assert_eq!(events[0].3, "dropped_before_stream");
    }

    #[test]
    fn pre_stream_trace_guard_disarm_suppresses_drop_trace() {
        let tracer = Arc::new(RecordingTracer::default());

        {
            let mut guard = PreStreamTraceGuard {
                tracer: Some(tracer.clone()),
                trace_id: Some("abc123".to_string()),
                start_time: Instant::now(),
            };
            guard.disarm();
        }

        assert!(tracer.stream_ends.lock().unwrap().is_empty());
    }

    // ── classify_and_handle_error retry decision ──

    #[test]
    fn should_retry_requires_retryable_and_budget() {
        // `retryable && attempt < max_retries`.
        // The `&&` → `||` mutant retries on either condition; the `<` → `>` /
        // `<` → `==` mutant flips the budget comparison.
        assert!(should_retry_after_error(true, 0, 3));
        assert!(should_retry_after_error(true, 2, 3));
        // Not retryable: never retry, even with budget left.
        assert!(!should_retry_after_error(false, 0, 3));
        // Retryable but budget exhausted: `attempt == max_retries`.
        assert!(!should_retry_after_error(true, 3, 3));
        // Retryable but over budget: `attempt > max_retries`.
        assert!(!should_retry_after_error(true, 4, 3));
    }

    // ── dispatch_non_streaming loop arithmetic ──

    #[test]
    fn is_backoff_attempt_only_after_first() {
        // `retry > 0`: the `>` → `==` mutant would treat the initial attempt
        // (retry 0) as a backoff and skip the real first retry.
        assert!(!is_backoff_attempt(0));
        assert!(is_backoff_attempt(1));
        assert!(is_backoff_attempt(2));
    }

    #[test]
    fn backoff_step_is_retry_minus_one() {
        // `retry - 1`: the `-` → `+` mutant doubles the exponent and the
        // `-` → `/` mutant leaves it unchanged (`retry / 1`).
        assert_eq!(backoff_step(1), 0);
        assert_eq!(backoff_step(2), 1);
        assert_eq!(backoff_step(3), 2);
    }

    #[test]
    fn should_clone_until_final_attempt() {
        // `retry < max_retries`: the `<` → `>` / `<` → `==` mutant would move
        // the request too early (and clone on the final attempt).
        assert!(should_clone_for_retry(0, 2));
        assert!(should_clone_for_retry(1, 2));
        // Final attempt: move, do not clone.
        assert!(!should_clone_for_retry(2, 2));
        assert!(!should_clone_for_retry(3, 2));
    }

    // ── rate-limit rotation guards ──

    #[test]
    fn rotation_skipped_when_not_rate_limited() {
        // `rate_limited && rotate()`: the closure must NOT run when the error
        // is not a rate limit (short-circuit). The `&&` → `||` mutant would
        // invoke rotation unconditionally and return true.
        let rotated = Cell::new(false);
        let result = try_rotation_on_rate_limit(false, || {
            rotated.set(true);
            true
        });
        assert!(!result, "non-429 error must not trigger rotation");
        assert!(!rotated.get(), "rotate closure must not run for non-429");
    }

    #[test]
    fn rotation_attempted_when_rate_limited() {
        let rotated = Cell::new(false);
        let result = try_rotation_on_rate_limit(true, || {
            rotated.set(true);
            true
        });
        assert!(result);
        assert!(rotated.get(), "rotate closure must run on 429");
        // Rotation attempted but unavailable → overall false.
        assert!(!try_rotation_on_rate_limit(true, || false));
    }

    #[test]
    fn rotation_unavailable_inverts_rotated_flag() {
        // `!rotated`: the "delete !" mutant would early-return when rotation
        // actually succeeded (and proceed when it failed).
        assert!(rotation_unavailable(false));
        assert!(!rotation_unavailable(true));
    }

    #[test]
    fn rotation_available_tracks_successful_rotation() {
        // `!rotation_unavailable`: the `try_rotate_and_retry` loop continues
        // while a fresh key was rotated in. The "delete !" mutant would loop
        // only when rotation had already failed.
        assert!(rotation_available(true));
        assert!(!rotation_available(false));
    }

    // ── build_encrypted_content mode gate ──

    #[cfg(feature = "policies")]
    #[test]
    fn encryption_enabled_only_for_encrypted_mode() {
        use crate::features::log_export::ContentMode;
        // `mode == Encrypted` (used as `!encryption_enabled(...)` → return).
        // The `!=` → `==` mutant inverts which modes proceed to encryption.
        assert!(encryption_enabled(&ContentMode::Encrypted));
        assert!(!encryption_enabled(&ContentMode::Plaintext));
        assert!(!encryption_enabled(&ContentMode::None));
    }

    // ── SLICE 4: HIT on the non-streaming path ──

    #[cfg(feature = "policies")]
    fn response_with_tool_use(tool: &str) -> ProviderResponse {
        serde_json::from_value(serde_json::json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [
                { "type": "text", "text": "running it" },
                { "type": "tool_use", "id": "tu_1", "name": tool, "input": { "command": "rm -rf /" } }
            ],
            "model": "alpha",
            "stop_reason": "tool_use",
            "usage": { "input_tokens": 5, "output_tokens": 3 }
        }))
        .expect("response")
    }

    #[cfg(feature = "policies")]
    fn has_tool_use(response: &ProviderResponse) -> bool {
        use crate::models::{ContentBlock, KnownContentBlock};
        response
            .content
            .iter()
            .any(|b| matches!(b, ContentBlock::Known(KnownContentBlock::ToolUse { .. })))
    }

    #[cfg(feature = "policies")]
    fn hit_policy(json: serde_json::Value) -> crate::features::policies::hit::HitOverride {
        serde_json::from_value(json).expect("HitOverride")
    }

    // (1) Deny → the tool_use is actually stripped from the rendered response,
    // and a signed receipt (consistent with the streaming path) is emitted.
    #[cfg(feature = "policies")]
    #[tokio::test]
    async fn non_stream_hit_deny_strips_tool_use_and_signs_receipt() {
        use crate::features::policies::hit_auth::{AuthDecision, AuthMethod};

        let mut response = response_with_tool_use("Bash");
        let policy = hit_policy(serde_json::json!({ "deny": ["Bash"] }));

        let receipts = apply_hit_to_response(
            &mut response,
            &policy,
            "req-deny",
            &None,
            &None,
            &None,
            std::time::Duration::from_millis(50),
        )
        .await;

        // Tool stripped, the text block survives.
        assert!(!has_tool_use(&response), "denied tool_use must be removed");
        assert_eq!(response.content.len(), 1, "the text block is kept");

        // Signed receipt mirrors the streaming policy-deny mapping.
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].decision, AuthDecision::Deny);
        assert_eq!(receipts[0].auth_method, AuthMethod::MachineKey);
        assert_eq!(receipts[0].signer, "policy");
        assert_eq!(receipts[0].tool_name, "Bash");
        assert!(receipts[0].verify(), "the HMAC receipt must verify");
    }

    // (2) RequireApproval with no human decision → the bounded timeout denies
    // (strips) deterministically, NEVER blocking indefinitely.
    #[cfg(feature = "policies")]
    #[tokio::test]
    async fn non_stream_hit_require_approval_times_out_to_deny() {
        use crate::features::policies::hit_auth::AuthDecision;
        use crate::features::policies::stream::HitPendingApprovals;

        let mut response = response_with_tool_use("Bash");
        // Empty policy → any tool defaults to RequireApproval, auth_method Prompt.
        let policy = hit_policy(serde_json::json!({}));
        // Real pending map so the approval sender is kept alive (forcing a timeout
        // rather than an immediate channel-closed deny).
        let pending_map: Arc<HitPendingApprovals> =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let pending: Option<Arc<HitPendingApprovals>> = Some(Arc::clone(&pending_map));
        let bus = Some(crate::features::watch::EventBus::new());

        let start = std::time::Instant::now();
        let receipts = apply_hit_to_response(
            &mut response,
            &policy,
            "req-timeout",
            &pending,
            &bus,
            &None,
            std::time::Duration::from_millis(60),
        )
        .await;
        let elapsed = start.elapsed();

        // Deterministic deny on timeout: tool stripped.
        assert!(
            !has_tool_use(&response),
            "timed-out tool_use must be stripped"
        );
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].decision, AuthDecision::Deny);
        assert_eq!(receipts[0].signer, "timeout");
        // Bounded: returns shortly after the timeout, never blocks forever.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "approval wait must be bounded (was {elapsed:?})"
        );
        // The orphaned pending entry was cleaned up.
        assert!(
            pending_map.lock().unwrap().is_empty(),
            "the timed-out approval entry must be removed"
        );
    }

    // (3) Auto-approve → the tool_use is kept and an Approve receipt is signed.
    #[cfg(feature = "policies")]
    #[tokio::test]
    async fn non_stream_hit_auto_approve_keeps_tool_use() {
        use crate::features::policies::hit_auth::AuthDecision;

        let mut response = response_with_tool_use("Read");
        let policy = hit_policy(serde_json::json!({ "auto_approve": ["Read"] }));

        let receipts = apply_hit_to_response(
            &mut response,
            &policy,
            "req-approve",
            &None,
            &None,
            &None,
            std::time::Duration::from_millis(50),
        )
        .await;

        assert!(
            has_tool_use(&response),
            "auto-approved tool_use must be kept"
        );
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].decision, AuthDecision::Approve);
        assert!(receipts[0].verify());
    }
}
