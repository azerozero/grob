use crate::models::CanonicalRequest;
use axum::{
    body::Body,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use futures::stream::TryStreamExt;
use std::sync::Arc;
use tracing::{debug, error};

use super::{
    apply_transparency_headers, dispatch, extract_api_credential, extract_client_ip, openai_compat,
    responses_compat, should_apply_transparency, AppError, AppState, RequestId,
};

/// Extracts tenant_id from VirtualKeyContext (preferred) or GrobClaims.
fn extract_tenant_id(
    vk_ctx: &Option<axum::Extension<crate::auth::virtual_keys::VirtualKeyContext>>,
    claims: &Option<axum::Extension<crate::auth::GrobClaims>>,
) -> Option<String> {
    vk_ctx
        .as_ref()
        .map(|vk| vk.tenant_id.clone())
        .or_else(|| claims.as_ref().map(|c| c.tenant_id().to_string()))
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

/// Build a JSON response with optional transparency headers.
fn build_json_response(
    body: Vec<u8>,
    transparency: Option<(&str, &str, &str)>,
) -> Result<Response, AppError> {
    let mut resp = Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .map_err(|e| AppError::ProviderError(format!("response builder: {}", e)))?;
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

/// Serializes a value to JSON bytes, returning an `AppError` on failure.
fn serialize_response<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(value).map_err(|e| {
        error!("Failed to serialize response: {}", e);
        AppError::ProviderError(format!("response serialization failed: {}", e))
    })
}

/// Holds shared pre-dispatch state built by [`prepare_dispatch`].
struct DispatchPrelude {
    inner: Arc<super::ReloadableState>,
    dlp: Option<Arc<crate::features::dlp::DlpEngine>>,
    tenant_id: Option<String>,
    peer_ip: String,
    transparency_enabled: bool,
}

/// Builds the shared pre-dispatch state common to all three handlers.
fn prepare_dispatch(
    state: &Arc<AppState>,
    claims: &Option<axum::Extension<crate::auth::GrobClaims>>,
    vk_ctx: &Option<axum::Extension<crate::auth::virtual_keys::VirtualKeyContext>>,
    headers: &HeaderMap,
) -> DispatchPrelude {
    let tenant_id = extract_tenant_id(vk_ctx, claims);
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
) -> Result<Response, AppError>
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
    C: FnOnce(crate::providers::ProviderResponse) -> Result<Vec<u8>, AppError>,
    F: FnOnce(crate::providers::ProviderResponse) -> Response,
{
    match result {
        dispatch::DispatchResult::CacheHit(mut resp) => {
            // Cache hit: entire elapsed time is overhead (no provider call).
            let overhead_ms = start_time.elapsed().as_millis() as u64;
            resp.headers_mut().insert(
                "x-grob-overhead-duration-ms",
                axum::http::HeaderValue::from(overhead_ms),
            );
            Ok(resp)
        }

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
                .map_err(|e| AppError::ProviderError(format!("response builder: {}", e)))?;
            Ok(response)
        }

        dispatch::DispatchResult::Complete {
            response,
            provider,
            actual_model,
            response_bytes,
            provider_duration_ms,
        } => {
            // Overhead = total time - provider call time.
            let total_ms = start_time.elapsed().as_millis() as u64;
            let overhead_ms = total_ms.saturating_sub(provider_duration_ms);

            let body = match response_bytes {
                Some(bytes) => bytes,
                None => on_complete(response)?,
            };
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
) -> Result<Response, AppError> {
    let _guard = ActiveRequestGuard::new(&state);
    let model = openai_request.model.clone();
    let is_streaming = openai_request.stream == Some(true);

    let prelude = prepare_dispatch(&state, &claims, &vk_ctx, &headers);

    // Transform OpenAI → Anthropic format
    let mut request = openai_compat::transform_openai_to_canonical(openai_request)
        .map_err(|e| AppError::ParseError(format!("Failed to transform OpenAI request: {}", e)))?;
    forward_beta_header(&mut request, &headers);

    let start_time = std::time::Instant::now();
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
        trace_id: None,
    };

    let result = dispatch::dispatch(&ctx, &mut request).await?;
    let model_for_stream = model.clone();
    let model_for_fanout = model.clone();

    finish_dispatch(
        result,
        prelude.transparency_enabled,
        &request_id.0,
        start_time,
        |stream| {
            let mut transformer = openai_compat::AnthropicToOpenAIStream::new(model_for_stream);
            let mapped = stream
                .map_ok(move |bytes| transformer.transform_bytes(&bytes))
                .try_filter(|b| futures::future::ready(!b.is_empty()));
            Body::from_stream(mapped.map_err(|e| std::io::Error::other(e.to_string())))
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
    )
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
) -> Result<Response, AppError> {
    let _guard = ActiveRequestGuard::new(&state);
    let model = responses_request.model.clone();
    let is_streaming = responses_request.stream == Some(true);

    let prelude = prepare_dispatch(&state, &claims, &vk_ctx, &headers);

    // Transform Responses → canonical format
    let mut request = responses_compat::transform_responses_to_canonical(responses_request)
        .map_err(|e| {
            AppError::ParseError(format!("Failed to transform Responses request: {}", e))
        })?;
    forward_beta_header(&mut request, &headers);

    let start_time = std::time::Instant::now();
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
        trace_id: None,
    };

    let result = dispatch::dispatch(&ctx, &mut request).await?;
    let model_for_stream = model.clone();
    let model_for_fanout = model.clone();

    finish_dispatch(
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
            Body::from_stream(mapped.map_err(|e| std::io::Error::other(e.to_string())))
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
    )
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
) -> Result<Response, AppError> {
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
        AppError::ParseError(format!("Invalid request format: {}", e))
    })?;
    forward_beta_header(&mut request, &headers);

    let is_streaming = request.stream == Some(true);

    let start_time = std::time::Instant::now();
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
        trace_id: Some(trace_id),
    };

    let result = dispatch::dispatch(&ctx, &mut request).await?;

    finish_dispatch(
        result,
        prelude.transparency_enabled,
        req_id,
        start_time,
        |stream| {
            let body_stream = stream.map_err(|e| {
                error!("Stream error: {}", e);
                std::io::Error::other(e.to_string())
            });
            Body::from_stream(body_stream)
        },
        |resp| serialize_response(&resp),
        |resp| Json(resp).into_response(),
    )
}

/// Handle /v1/messages/count_tokens requests
pub(crate) async fn handle_count_tokens(
    State(state): State<Arc<AppState>>,
    Json(request_json): Json<serde_json::Value>,
) -> Result<Response, AppError> {
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
        .map_err(|e| AppError::RoutingError(e.to_string()))?;

    debug!(
        "🧮 Routed count_tokens: {} → {} ({})",
        model, decision.model_name, decision.route_type
    );

    // Deserialize the full count_tokens request (consumes the JSON value — no clone).
    use crate::models::CountTokensRequest;
    let count_request: CountTokensRequest = serde_json::from_value(request_json)
        .map_err(|e| AppError::ParseError(format!("Invalid count_tokens request format: {}", e)))?;

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

        Err(AppError::ProviderError(format!(
            "All {} provider mappings failed for token counting: {}",
            sorted_mappings.len(),
            decision.model_name
        )))
    } else if let Ok(provider) = inner
        .provider_registry
        .provider_for_model(&decision.model_name)
    {
        let mut req = count_request.clone();
        req.model = decision.model_name.clone();
        let response = provider
            .count_tokens(req)
            .await
            .map_err(|e| AppError::ProviderError(e.to_string()))?;
        Ok(Json(response).into_response())
    } else {
        Err(AppError::ProviderError(format!(
            "No model mapping or provider found for token counting: {}",
            decision.model_name
        )))
    }
}
