use crate::models::CanonicalRequest;
use axum::{
    body::Body,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use futures::stream::{Stream, TryStreamExt};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};
use tracing::{debug, error};

use super::middleware::AuditedAlready;
use super::{
    apply_transparency_headers, dispatch, extract_api_credential, extract_client_ip, openai_compat,
    responses_compat, should_apply_transparency, AppState, RequestError, RequestId,
};

/// Extracts tenant_id with this priority:
///   1. VirtualKeyContext (operator-provisioned binding)
///   2. JWT `tenant` claim
///   3. `X-Tenant-ID` request header
///
/// JWT and VirtualKey paths cannot be overridden by the client header so a
/// caller cannot impersonate another tenant in authenticated mode. The
/// header path is only consulted when no authenticated tenant exists.
fn extract_tenant_id(
    vk_ctx: &Option<axum::Extension<crate::auth::virtual_keys::VirtualKeyContext>>,
    claims: &Option<axum::Extension<crate::auth::GrobClaims>>,
    headers: &HeaderMap,
) -> Option<String> {
    if let Some(vk) = vk_ctx.as_ref() {
        return Some(vk.tenant_id.clone());
    }
    if let Some(c) = claims.as_ref() {
        return Some(c.tenant_id().to_string());
    }
    headers
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Drop guard that decrements the active request counter
struct ActiveRequestGuard(Arc<AppState>);

impl ActiveRequestGuard {
    fn new(state: &Arc<AppState>) -> Self {
        state
            .active_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(Arc::clone(state))
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.0
            .active_requests
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Default)]
struct ResponseTraceUsage {
    input_tokens: u32,
    output_tokens: u32,
    cache_creation_input_tokens: u32,
    cache_read_input_tokens: u32,
    saw_usage: bool,
}

impl ResponseTraceUsage {
    fn as_trace_usage(&self) -> Option<crate::traits::StreamTraceUsage> {
        self.saw_usage.then_some(crate::traits::StreamTraceUsage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cache_creation_input_tokens: nonzero(self.cache_creation_input_tokens),
            cache_read_input_tokens: nonzero(self.cache_read_input_tokens),
        })
    }
}

fn nonzero(value: u32) -> Option<u32> {
    (value > 0).then_some(value)
}

const TRACE_USAGE_MAX_CARRY: usize = 8 * 1024;

fn scan_response_trace_usage(chunk: &str, carry: &mut String, usage: &mut ResponseTraceUsage) {
    let scan_owned;
    let scan: &str = if carry.is_empty() {
        chunk
    } else {
        carry.push_str(chunk);
        scan_owned = std::mem::take(carry);
        &scan_owned
    };

    let (complete, tail) = match scan.rfind("\n\n") {
        Some(pos) => (&scan[..pos + 2], &scan[pos + 2..]),
        None => ("", scan),
    };

    if complete.contains("\"usage\"") {
        accumulate_response_trace_usage(complete, usage);
    }

    if !tail.is_empty() {
        let start = tail.len().saturating_sub(TRACE_USAGE_MAX_CARRY);
        carry.push_str(&tail[tail.ceil_char_boundary(start)..]);
    }
}

fn flush_response_trace_usage(carry: &mut String, usage: &mut ResponseTraceUsage) {
    if carry.is_empty() {
        return;
    }
    let tail = std::mem::take(carry);
    if tail.contains("\"usage\"") {
        accumulate_response_trace_usage(&tail, usage);
    }
}

fn accumulate_response_trace_usage(buffer: &str, usage: &mut ResponseTraceUsage) {
    for event in crate::providers::streaming::parse_sse_events(buffer) {
        match event.event.as_deref() {
            Some("message_start") => {
                parse_response_trace_usage_json(&event.data, "/message/usage", usage);
            }
            Some("message_delta") => {
                parse_response_trace_usage_json(&event.data, "/usage", usage);
            }
            Some("response.completed") | Some("response.incomplete") | Some("response.failed") => {
                parse_response_trace_usage_json(&event.data, "/response/usage", usage);
            }
            _ => {
                parse_response_trace_usage_json(&event.data, "/usage", usage);
            }
        }
    }
}

fn parse_response_trace_usage_json(data: &str, pointer: &str, usage: &mut ResponseTraceUsage) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(data) else {
        return;
    };
    let Some(value) = json.pointer(pointer) else {
        return;
    };
    update_response_trace_usage(value, usage);
}

fn update_response_trace_usage(value: &serde_json::Value, usage: &mut ResponseTraceUsage) {
    let cache_read = value
        .get("cache_read_input_tokens")
        .or_else(|| value.pointer("/input_tokens_details/cached_tokens"))
        .or_else(|| value.pointer("/prompt_tokens_details/cached_tokens"))
        .and_then(serde_json::Value::as_u64)
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX));

    let input = value
        .get("input_tokens")
        .or_else(|| value.get("prompt_tokens"))
        .and_then(serde_json::Value::as_u64);
    if let Some(input) = input {
        let mut input = u32::try_from(input).unwrap_or(u32::MAX);
        if value.get("cache_read_input_tokens").is_none() {
            input = input.saturating_sub(cache_read.unwrap_or(0));
        }
        if input > 0 || usage.input_tokens == 0 {
            usage.input_tokens = input;
        }
        usage.saw_usage = true;
    }

    let output = value
        .get("output_tokens")
        .or_else(|| value.get("completion_tokens"))
        .and_then(serde_json::Value::as_u64);
    if let Some(output) = output {
        usage.output_tokens = usage
            .output_tokens
            .max(u32::try_from(output).unwrap_or(u32::MAX));
        usage.saw_usage = true;
    }

    if let Some(cache_creation) = value
        .get("cache_creation_input_tokens")
        .and_then(serde_json::Value::as_u64)
    {
        usage.cache_creation_input_tokens = usage
            .cache_creation_input_tokens
            .max(u32::try_from(cache_creation).unwrap_or(u32::MAX));
        usage.saw_usage = true;
    }

    if let Some(cache_read) = cache_read {
        usage.cache_read_input_tokens = usage.cache_read_input_tokens.max(cache_read);
        usage.saw_usage = true;
    }
}

struct ResponseTraceStream<S> {
    inner: Pin<Box<S>>,
    tracer: Arc<dyn crate::traits::Tracer>,
    trace_id: String,
    chunk_count: u64,
    byte_count: usize,
    usage: ResponseTraceUsage,
    usage_carry: String,
    start_time: Instant,
    ended: bool,
}

impl<S> ResponseTraceStream<S> {
    fn finish(&mut self, status: &str) {
        if self.ended {
            return;
        }
        self.ended = true;
        flush_response_trace_usage(&mut self.usage_carry, &mut self.usage);
        self.tracer.trace_stream_end(
            &self.trace_id,
            self.chunk_count,
            self.byte_count,
            self.start_time.elapsed().as_millis() as u64,
            status,
            self.usage.as_trace_usage(),
        );
    }
}

impl<S> Unpin for ResponseTraceStream<S> {}

impl<S> Stream for ResponseTraceStream<S>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let seq = this.chunk_count;
                this.chunk_count += 1;
                this.byte_count += chunk.len();
                let text = String::from_utf8_lossy(&chunk);
                scan_response_trace_usage(&text, &mut this.usage_carry, &mut this.usage);
                this.tracer
                    .trace_stream_chunk(&this.trace_id, seq, chunk.as_ref());
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.tracer
                    .trace_error(&this.trace_id, &format!("stream error: {err}"));
                this.finish("error");
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                this.finish("complete");
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> Drop for ResponseTraceStream<S> {
    fn drop(&mut self) {
        self.finish("dropped");
    }
}

fn trace_response_stream<S>(
    stream: S,
    tracer: Arc<dyn crate::traits::Tracer>,
    trace_id: String,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
{
    Box::pin(ResponseTraceStream {
        inner: Box::pin(stream),
        tracer,
        trace_id,
        chunk_count: 0,
        byte_count: 0,
        usage: ResponseTraceUsage::default(),
        usage_carry: String::new(),
        start_time: Instant::now(),
        ended: false,
    })
}

/// Build a JSON response with optional transparency headers.
fn build_json_response(
    body: Vec<u8>,
    transparency: Option<(&str, &str, &str)>,
) -> Result<Response, RequestError> {
    let mut resp = Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .map_err(|e| RequestError::Internal(anyhow::anyhow!("response builder: {}", e)))?;
    if let Some((provider, actual_model, req_id)) = transparency {
        apply_transparency_headers(resp.headers_mut(), provider, actual_model, req_id);
    }
    Ok(resp)
}

/// Build an SSE streaming response builder with standard headers.
fn build_sse_response() -> axum::http::response::Builder {
    Response::builder()
        .status(200)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
}

/// Serializes a value to JSON bytes, returning a `RequestError` on failure.
fn serialize_response<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, RequestError> {
    serde_json::to_vec(value).map_err(|e| {
        error!("Failed to serialize response: {}", e);
        RequestError::Internal(anyhow::anyhow!("response serialization failed: {}", e))
    })
}

/// Holds shared pre-dispatch state built by [`prepare_dispatch`].
struct DispatchPrelude {
    inner: Arc<super::ReloadableState>,
    dlp: Option<Arc<crate::features::dlp::DlpEngine>>,
    tenant_id: Option<String>,
    peer_ip: String,
    transparency_enabled: bool,
    /// Set by the dispatch path when it has emitted an audit entry — used
    /// by the audit middleware to skip duplicate logging.
    audited: Arc<std::sync::atomic::AtomicBool>,
}

/// Marks the response with the [`AuditedAlready`] extension when dispatch
/// has emitted its own audit entry, so the outer audit middleware skips a
/// duplicate write.
fn mark_audited_if_set(audited: &Arc<std::sync::atomic::AtomicBool>, response: &mut Response) {
    if audited.load(std::sync::atomic::Ordering::Acquire) {
        response.extensions_mut().insert(AuditedAlready);
    }
}

/// Builds the shared pre-dispatch state common to all three handlers.
fn prepare_dispatch(
    state: &Arc<AppState>,
    claims: &Option<axum::Extension<crate::auth::GrobClaims>>,
    vk_ctx: &Option<axum::Extension<crate::auth::virtual_keys::VirtualKeyContext>>,
    headers: &HeaderMap,
) -> DispatchPrelude {
    let tenant_id = extract_tenant_id(vk_ctx, claims, headers);
    let peer_ip = extract_client_ip(headers);
    let inner = state.snapshot();
    let session_key = tenant_id
        .as_deref()
        .or_else(|| extract_api_credential(headers));
    let dlp = state
        .security
        .dlp_sessions
        .as_ref()
        .map(|mgr| mgr.engine_for(session_key));
    let transparency_enabled = should_apply_transparency(&inner.config);
    DispatchPrelude {
        inner,
        dlp,
        tenant_id,
        peer_ip,
        transparency_enabled,
        audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

/// Forwards the `anthropic-beta` header into the canonical request extensions.
fn forward_beta_header(request: &mut CanonicalRequest, headers: &HeaderMap) {
    request.extensions.client_beta = headers
        .get("anthropic-beta")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
}

/// Converts a [`dispatch::DispatchResult`] into an HTTP response.
///
/// The caller provides format-specific closures for the two arms that need
/// translation (streaming and complete). Cache-hit and fan-out use the
/// closures as well, keeping every format-specific concern outside this fn.
fn finish_dispatch<S, C, F>(
    result: dispatch::DispatchResult,
    transparency_enabled: bool,
    req_id: &str,
    start_time: std::time::Instant,
    on_streaming: S,
    on_complete: C,
    on_fan_out: F,
) -> Result<Response, RequestError>
where
    S: FnOnce(
        std::pin::Pin<
            Box<
                dyn futures::Stream<
                        Item = Result<bytes::Bytes, crate::providers::error::ProviderError>,
                    > + Send,
            >,
        >,
    ) -> Body,
    C: FnOnce(crate::providers::ProviderResponse) -> Result<Vec<u8>, RequestError>,
    F: FnOnce(crate::providers::ProviderResponse) -> Response,
{
    match result {
        dispatch::DispatchResult::Streaming {
            stream,
            provider,
            actual_model,
            upstream_headers,
            overhead_ms,
        } => {
            let body = on_streaming(stream);
            let mut response_builder =
                build_sse_response().header("x-grob-overhead-duration-ms", overhead_ms);

            for (name, value) in &upstream_headers {
                response_builder = response_builder.header(name.as_str(), value.as_str());
            }

            if transparency_enabled {
                let mut hdrs = HeaderMap::new();
                apply_transparency_headers(&mut hdrs, &provider, &actual_model, req_id);
                for (k, v) in hdrs {
                    if let Some(k) = k {
                        response_builder = response_builder.header(k, v);
                    }
                }
            }

            let response = response_builder
                .body(body)
                .map_err(|e| RequestError::Internal(anyhow::anyhow!("response builder: {}", e)))?;
            Ok(response)
        }

        dispatch::DispatchResult::Complete {
            response,
            provider,
            actual_model,
            provider_duration_ms,
        } => {
            // Overhead = total time - provider call time.
            let total_ms = start_time.elapsed().as_millis() as u64;
            let overhead_ms = total_ms.saturating_sub(provider_duration_ms);

            // Always run on_complete so the caller can apply format translation
            // (e.g. Anthropic → OpenAI for /v1/chat/completions).
            let body = on_complete(response)?;
            let transparency =
                transparency_enabled.then_some((provider.as_str(), actual_model.as_str(), req_id));
            let mut resp = build_json_response(body, transparency)?;
            resp.headers_mut().insert(
                "x-grob-overhead-duration-ms",
                axum::http::HeaderValue::from(overhead_ms),
            );
            Ok(resp)
        }

        dispatch::DispatchResult::FanOut { response } => {
            let total_ms = start_time.elapsed().as_millis() as u64;
            let mut resp = on_fan_out(response);
            resp.headers_mut().insert(
                "x-grob-overhead-duration-ms",
                axum::http::HeaderValue::from(total_ms),
            );
            Ok(resp)
        }
    }
}

/// Handle /v1/chat/completions requests (OpenAI-compatible endpoint)
/// Supports both streaming (SSE) and non-streaming responses, plus tool calling.
pub(crate) async fn handle_openai_chat_completions(
    State(state): State<Arc<AppState>>,
    claims: Option<axum::Extension<crate::auth::GrobClaims>>,
    vk_ctx: Option<axum::Extension<crate::auth::virtual_keys::VirtualKeyContext>>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    headers: HeaderMap,
    Json(openai_request): Json<openai_compat::OpenAIRequest>,
) -> Result<Response, RequestError> {
    let _guard = ActiveRequestGuard::new(&state);
    let model = openai_request.model.clone();
    let is_streaming = openai_request.stream == Some(true);

    let prelude = prepare_dispatch(&state, &claims, &vk_ctx, &headers);
    let trace_id = state.observability.message_tracer.new_trace_id();

    // Transform OpenAI → Anthropic format
    let mut request =
        openai_compat::transform_openai_to_canonical(openai_request).map_err(|e| {
            RequestError::ParseError(format!("Failed to transform OpenAI request: {}", e))
        })?;
    forward_beta_header(&mut request, &headers);

    let start_time = std::time::Instant::now();
    #[cfg(feature = "policies")]
    let resolved_policy =
        evaluate_policy_if_configured(&state, prelude.tenant_id.as_deref(), &model, &headers);
    let audited_flag = prelude.audited.clone();
    let ctx = dispatch::DispatchContext {
        state: &state,
        inner: &prelude.inner,
        dlp: &prelude.dlp,
        model: model.clone(),
        is_streaming,
        tenant_id: prelude.tenant_id,
        peer_ip: prelude.peer_ip,
        req_id: &request_id.0,
        start_time,
        headers: &headers,
        trace_id: Some(trace_id.clone()),
        audited: audited_flag.clone(),
        #[cfg(feature = "policies")]
        resolved_policy,
    };

    let result = match dispatch::dispatch(&ctx, &mut request).await {
        Ok(r) => r,
        Err(e) => {
            let mut response = e.into_response();
            mark_audited_if_set(&audited_flag, &mut response);
            return Ok(response);
        }
    };
    let model_for_stream = model.clone();
    let model_for_fanout = model.clone();
    let tracer_for_stream = Arc::clone(&state.observability.message_tracer);
    let trace_id_for_stream = trace_id.clone();

    let mut response = finish_dispatch(
        result,
        prelude.transparency_enabled,
        &request_id.0,
        start_time,
        |stream| {
            let mut transformer = openai_compat::AnthropicToOpenAIStream::new(model_for_stream);
            let mapped = stream
                .map_ok(move |bytes| transformer.transform_bytes(&bytes))
                .try_filter(|b| futures::future::ready(!b.is_empty()));
            let body_stream = mapped.map_err(|e| std::io::Error::other(e.to_string()));
            Body::from_stream(trace_response_stream(
                body_stream,
                tracer_for_stream,
                trace_id_for_stream,
            ))
        },
        |resp| {
            let openai_response = openai_compat::transform_canonical_to_openai(resp, model.clone());
            serialize_response(&openai_response)
        },
        |resp| {
            let openai_response =
                openai_compat::transform_canonical_to_openai(resp, model_for_fanout);
            Json(openai_response).into_response()
        },
    )?;
    mark_audited_if_set(&audited_flag, &mut response);
    Ok(response)
}

/// Handle /v1/responses requests (OpenAI Responses API — used by Codex CLI)
/// Supports both streaming (named SSE events) and non-streaming responses.
pub(crate) async fn handle_responses(
    State(state): State<Arc<AppState>>,
    claims: Option<axum::Extension<crate::auth::GrobClaims>>,
    vk_ctx: Option<axum::Extension<crate::auth::virtual_keys::VirtualKeyContext>>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    headers: HeaderMap,
    Json(responses_request): Json<responses_compat::ResponsesRequest>,
) -> Result<Response, RequestError> {
    let _guard = ActiveRequestGuard::new(&state);
    let model = responses_request.model.clone();
    let is_streaming = responses_request.stream == Some(true);

    // Surface the inbound Codex CLI request shape so a proxy operator can see
    // the requested model and the service_tier (`"priority"` = the ~1.5x faster
    // mode) and reasoning effort the real client sends.
    tracing::info!(
        "↘️  Codex inbound: model={} service_tier={:?} effort={:?} stream={}",
        model,
        responses_request.service_tier,
        responses_request
            .reasoning
            .as_ref()
            .and_then(|r| r.effort.clone()),
        is_streaming,
    );

    let prelude = prepare_dispatch(&state, &claims, &vk_ctx, &headers);
    let trace_id = state.observability.message_tracer.new_trace_id();

    // Transform Responses → canonical format
    let mut request = responses_compat::transform_responses_to_canonical(responses_request)
        .map_err(|e| {
            RequestError::ParseError(format!("Failed to transform Responses request: {}", e))
        })?;
    forward_beta_header(&mut request, &headers);

    let start_time = std::time::Instant::now();
    #[cfg(feature = "policies")]
    let resolved_policy =
        evaluate_policy_if_configured(&state, prelude.tenant_id.as_deref(), &model, &headers);
    let audited_flag = prelude.audited.clone();
    let ctx = dispatch::DispatchContext {
        state: &state,
        inner: &prelude.inner,
        dlp: &prelude.dlp,
        model: model.clone(),
        is_streaming,
        tenant_id: prelude.tenant_id,
        peer_ip: prelude.peer_ip,
        req_id: &request_id.0,
        start_time,
        headers: &headers,
        trace_id: Some(trace_id.clone()),
        audited: audited_flag.clone(),
        #[cfg(feature = "policies")]
        resolved_policy,
    };

    let result = match dispatch::dispatch(&ctx, &mut request).await {
        Ok(r) => r,
        Err(e) => {
            let mut response = e.into_response();
            mark_audited_if_set(&audited_flag, &mut response);
            return Ok(response);
        }
    };
    let model_for_stream = model.clone();
    let model_for_fanout = model.clone();
    let tracer_for_stream = Arc::clone(&state.observability.message_tracer);
    let trace_id_for_stream = trace_id.clone();

    let mut response = finish_dispatch(
        result,
        prelude.transparency_enabled,
        &request_id.0,
        start_time,
        |stream| {
            let mut transformer =
                responses_compat::AnthropicToResponsesStream::new(model_for_stream);
            let mapped = stream
                .map_ok(move |bytes| transformer.transform_bytes(&bytes))
                .try_filter(|b| futures::future::ready(!b.is_empty()));
            let body_stream = mapped.map_err(|e| std::io::Error::other(e.to_string()));
            Body::from_stream(trace_response_stream(
                body_stream,
                tracer_for_stream,
                trace_id_for_stream,
            ))
        },
        |resp| {
            let responses_response =
                responses_compat::transform_canonical_to_responses(resp, model.clone());
            serialize_response(&responses_response)
        },
        |resp| {
            let responses_response =
                responses_compat::transform_canonical_to_responses(resp, model_for_fanout);
            Json(responses_response).into_response()
        },
    )?;
    mark_audited_if_set(&audited_flag, &mut response);
    Ok(response)
}

/// Handle /v1/models endpoint (OpenAI-compatible)
pub(crate) async fn handle_openai_models(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let inner = state.snapshot();
    let models: Vec<serde_json::Value> = inner
        .config
        .models
        .iter()
        .map(|m| {
            serde_json::json!({
                "id": m.name,
                "object": "model",
                "created": 0,
                "owned_by": "grob",
                "capabilities": {
                    "tool_calling": true,
                    "streaming": true
                }
            })
        })
        .collect();
    Json(serde_json::json!({ "object": "list", "data": models }))
}

/// Handle /v1/messages requests (both streaming and non-streaming)
pub(crate) async fn handle_messages(
    State(state): State<Arc<AppState>>,
    claims: Option<axum::Extension<crate::auth::GrobClaims>>,
    vk_ctx: Option<axum::Extension<crate::auth::virtual_keys::VirtualKeyContext>>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    headers: HeaderMap,
    Json(request_json): Json<serde_json::Value>,
) -> Result<Response, RequestError> {
    let _guard = ActiveRequestGuard::new(&state);
    let req_id = &request_id.0;
    let model: String = request_json
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string();

    let prelude = prepare_dispatch(&state, &claims, &vk_ctx, &headers);
    let trace_id = state.observability.message_tracer.new_trace_id();

    // DEBUG: Log request body for debugging (gate serialization on log level)
    if tracing::event_enabled!(tracing::Level::DEBUG) {
        if let Ok(json_str) = serde_json::to_string_pretty(&request_json) {
            tracing::debug!("📥 Incoming request body:\n{}", json_str);
        }
    }

    let mut request: CanonicalRequest = serde_json::from_value(request_json).map_err(|e| {
        tracing::error!("❌ Failed to parse request: {}", e);
        RequestError::ParseError(format!("Invalid request format: {}", e))
    })?;
    forward_beta_header(&mut request, &headers);

    let is_streaming = request.stream == Some(true);

    let start_time = std::time::Instant::now();
    #[cfg(feature = "policies")]
    let resolved_policy =
        evaluate_policy_if_configured(&state, prelude.tenant_id.as_deref(), &model, &headers);
    let audited_flag = prelude.audited.clone();
    let ctx = dispatch::DispatchContext {
        state: &state,
        inner: &prelude.inner,
        dlp: &prelude.dlp,
        model: model.clone(),
        is_streaming,
        tenant_id: prelude.tenant_id,
        peer_ip: prelude.peer_ip,
        req_id,
        start_time,
        headers: &headers,
        trace_id: Some(trace_id.clone()),
        audited: audited_flag.clone(),
        #[cfg(feature = "policies")]
        resolved_policy,
    };

    let result = match dispatch::dispatch(&ctx, &mut request).await {
        Ok(r) => r,
        Err(e) => {
            let mut response = e.into_response();
            mark_audited_if_set(&audited_flag, &mut response);
            return Ok(response);
        }
    };
    let tracer_for_stream = Arc::clone(&state.observability.message_tracer);
    let trace_id_for_stream = trace_id.clone();

    let mut response = finish_dispatch(
        result,
        prelude.transparency_enabled,
        req_id,
        start_time,
        |stream| {
            let body_stream = stream.map_err(|e| {
                error!("Stream error: {}", e);
                std::io::Error::other(e.to_string())
            });
            Body::from_stream(trace_response_stream(
                body_stream,
                tracer_for_stream,
                trace_id_for_stream,
            ))
        },
        |resp| serialize_response(&resp),
        |resp| Json(resp).into_response(),
    )?;
    mark_audited_if_set(&audited_flag, &mut response);
    Ok(response)
}

/// Handle /v1/messages/count_tokens requests
pub(crate) async fn handle_count_tokens(
    State(state): State<Arc<AppState>>,
    Json(request_json): Json<serde_json::Value>,
) -> Result<Response, RequestError> {
    let model = request_json
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");
    debug!("Received count_tokens request for model: {}", model);

    // Get snapshot of reloadable state
    let inner = state.snapshot();

    // Build a lightweight routing request from the JSON without cloning the full body.
    let mut routing_request = CanonicalRequest {
        model: model.to_string(),
        messages: Vec::new(),
        max_tokens: 1024,
        system: None,
        tools: None,
        tool_choice: None,
        thinking: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop_sequences: None,
        stream: None,
        metadata: None,
        extensions: Default::default(),
    };
    let decision = inner
        .router
        .route(&mut routing_request)
        .map_err(|e| RequestError::RoutingError(e.to_string()))?;

    debug!(
        "🧮 Routed count_tokens: {} → {} ({})",
        model, decision.model_name, decision.route_type
    );

    // Deserialize the full count_tokens request (consumes the JSON value — no clone).
    use crate::models::CountTokensRequest;
    let count_request: CountTokensRequest = serde_json::from_value(request_json).map_err(|e| {
        RequestError::ParseError(format!("Invalid count_tokens request format: {}", e))
    })?;

    // Try model mappings with fallback (1:N mapping)
    if let Some(model_config) = inner.find_model(&decision.model_name) {
        let mut sorted_mappings = model_config.mappings.clone();
        sorted_mappings.sort_by_key(|m| m.priority);

        for mapping in &sorted_mappings {
            let Some(provider) = inner.provider_registry.provider(&mapping.provider) else {
                continue;
            };

            let mut req = count_request.clone();
            req.model = mapping.actual_model.clone();

            match provider.count_tokens(req).await {
                Ok(response) => return Ok(Json(response).into_response()),
                Err(e) => {
                    debug!("Provider {} count_tokens failed: {}", mapping.provider, e);
                    continue;
                }
            }
        }

        Err(RequestError::ProviderUpstream {
            provider: "all".to_string(),
            status: 502,
            body: Some(format!(
                "All {} provider mappings failed for token counting: {}",
                sorted_mappings.len(),
                decision.model_name
            )),
        })
    } else if let Ok(provider) = inner
        .provider_registry
        .provider_for_model(&decision.model_name)
    {
        let mut req = count_request.clone();
        req.model = decision.model_name.clone();
        let response = provider
            .count_tokens(req)
            .await
            .map_err(RequestError::from)?;
        Ok(Json(response).into_response())
    } else {
        Err(RequestError::RoutingError(format!(
            "No model mapping or provider found for token counting: {}",
            decision.model_name
        )))
    }
}

/// Evaluates the policy engine if configured. Returns `None` when no policies
/// are loaded (backward compatible) or when the `policies` feature is disabled.
#[cfg(feature = "policies")]
fn evaluate_policy_if_configured(
    state: &Arc<AppState>,
    tenant: Option<&str>,
    model: &str,
    headers: &axum::http::HeaderMap,
) -> Option<crate::features::policies::resolved::ResolvedPolicy> {
    let inner = state.snapshot();
    let matcher = inner.policy_matcher.as_ref()?;
    let ctx = crate::features::policies::context::RequestContext {
        tenant: tenant.map(|s| s.to_string()),
        zone: None,
        project: headers
            .get("x-grob-project")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        user: None,
        agent: headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        compliance: vec![],
        model: model.to_string(),
        provider: String::new(),
        route_type: String::new(),
        dlp_triggered: false,
        estimated_cost: 0.0,
    };
    Some(matcher.evaluate(&ctx))
}
