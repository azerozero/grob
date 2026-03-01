use crate::models::AnthropicRequest;
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
    should_apply_transparency, AppError, AppState, RequestId,
};

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

/// Handle /v1/chat/completions requests (OpenAI-compatible endpoint)
/// Supports both streaming (SSE) and non-streaming responses, plus tool calling.
pub(crate) async fn handle_openai_chat_completions(
    State(state): State<Arc<AppState>>,
    claims: Option<axum::Extension<crate::auth::GrobClaims>>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    headers: HeaderMap,
    Json(openai_request): Json<openai_compat::OpenAIRequest>,
) -> Result<Response, AppError> {
    let _guard = ActiveRequestGuard::new(&state);
    let model = openai_request.model.clone();
    let is_streaming = openai_request.stream == Some(true);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id().to_string());
    let peer_ip = extract_client_ip(&headers);

    let inner = state.snapshot();
    let session_key = tenant_id
        .as_deref()
        .or_else(|| extract_api_credential(&headers));
    let dlp = state
        .security
        .dlp_sessions
        .as_ref()
        .map(|mgr| mgr.engine_for(session_key));

    // Transform OpenAI → Anthropic format
    let mut anthropic_request = openai_compat::transform_openai_to_anthropic(openai_request)
        .map_err(|e| AppError::ParseError(format!("Failed to transform OpenAI request: {}", e)))?;

    let ctx = dispatch::DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: model.clone(),
        is_streaming,
        tenant_id,
        peer_ip,
        req_id: &request_id.0,
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
    };

    let transparency_enabled = should_apply_transparency(&inner.config);

    match dispatch::dispatch(&ctx, &mut anthropic_request).await? {
        dispatch::DispatchResult::CacheHit(resp) => Ok(resp),

        dispatch::DispatchResult::Streaming {
            stream,
            provider,
            actual_model,
            ..
        } => {
            let mut transformer = openai_compat::AnthropicToOpenAIStream::new(model.clone());
            let mapped = stream
                .map_ok(move |bytes| transformer.transform_bytes(&bytes))
                .try_filter(|b| futures::future::ready(!b.is_empty()));
            let body = Body::from_stream(mapped.map_err(|e| std::io::Error::other(e.to_string())));
            let mut response = build_sse_response()
                .body(body)
                .map_err(|e| AppError::ProviderError(format!("response builder: {}", e)))?;
            if transparency_enabled {
                apply_transparency_headers(
                    response.headers_mut(),
                    &provider,
                    &actual_model,
                    &request_id.0,
                );
            }
            Ok(response)
        }

        dispatch::DispatchResult::Complete {
            response: anthropic_response,
            provider,
            actual_model,
            ..
        } => {
            let openai_response =
                openai_compat::transform_anthropic_to_openai(anthropic_response, model.clone());
            let transparency = transparency_enabled.then_some((
                provider.as_str(),
                actual_model.as_str(),
                request_id.0.as_str(),
            ));
            let body = serde_json::to_vec(&openai_response).unwrap_or_else(|e| {
                tracing::warn!("Failed to serialize OpenAI response: {}", e);
                Vec::new()
            });
            build_json_response(body, transparency)
        }

        dispatch::DispatchResult::FanOut { response } => {
            let openai_response =
                openai_compat::transform_anthropic_to_openai(response, model.clone());
            Ok(Json(openai_response).into_response())
        }
    }
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
    let tenant_id = claims.as_ref().map(|c| c.tenant_id().to_string());
    let peer_ip = extract_client_ip(&headers);
    let inner = state.snapshot();
    let session_key = tenant_id
        .as_deref()
        .or_else(|| extract_api_credential(&headers));
    let dlp = state
        .security
        .dlp_sessions
        .as_ref()
        .map(|mgr| mgr.engine_for(session_key));
    let trace_id = state.observability.message_tracer.new_trace_id();

    // DEBUG: Log request body for debugging (gate serialization on log level)
    if tracing::event_enabled!(tracing::Level::DEBUG) {
        if let Ok(json_str) = serde_json::to_string_pretty(&request_json) {
            tracing::debug!("📥 Incoming request body:\n{}", json_str);
        }
    }

    let mut request: AnthropicRequest = serde_json::from_value(request_json).map_err(|e| {
        tracing::error!("❌ Failed to parse request: {}", e);
        AppError::ParseError(format!("Invalid request format: {}", e))
    })?;

    let is_streaming = request.stream == Some(true);

    let ctx = dispatch::DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: model.clone(),
        is_streaming,
        tenant_id,
        peer_ip,
        req_id,
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: Some(trace_id),
    };

    let transparency_enabled = should_apply_transparency(&inner.config);

    match dispatch::dispatch(&ctx, &mut request).await? {
        dispatch::DispatchResult::CacheHit(resp) => Ok(resp),

        dispatch::DispatchResult::Streaming {
            stream,
            provider,
            actual_model,
            upstream_headers,
        } => {
            let body_stream = stream.map_err(|e| {
                error!("Stream error: {}", e);
                std::io::Error::other(e.to_string())
            });
            let body = Body::from_stream(body_stream);
            let mut response_builder = build_sse_response();

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
        } => {
            let body = response_bytes.unwrap_or_else(|| {
                serde_json::to_vec(&response).unwrap_or_else(|e| {
                    tracing::warn!("Failed to serialize Anthropic response: {}", e);
                    Vec::new()
                })
            });
            let transparency = transparency_enabled.then_some((
                provider.as_str(),
                actual_model.as_str(),
                req_id.as_str(),
            ));
            build_json_response(body, transparency)
        }

        dispatch::DispatchResult::FanOut { response } => Ok(Json(response).into_response()),
    }
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
    let mut routing_request = AnthropicRequest {
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
