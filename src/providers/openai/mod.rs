//! OpenAI provider implementation.

mod streaming;
mod transform;
pub(crate) mod types;

/// Test-only entry points for the OpenAI request/response translation layer.
///
/// Exposes the otherwise `pub(crate)` provider transforms as JSON-returning
/// helpers so integration tests in `tests/enterprise/translation_test.rs` can
/// pin the wire format without coupling to the internal type aliases.
///
/// Although unconditionally compiled (so the integration test suite under
/// `tests/` can reach it without enabling extra features), every entry point
/// re-encodes its input through `serde_json::Value`, so production callers
/// have no incentive to use it over the typed transform API.
#[doc(hidden)]
pub mod test_api {
    use super::transform;
    use crate::models::CanonicalRequest;
    use crate::providers::ProviderResponse;

    /// Outbound: translates a canonical (Anthropic-shaped) request to the
    /// OpenAI Chat Completions wire format and returns it as a JSON [`Value`].
    ///
    /// # Errors
    ///
    /// Returns `Err` containing the underlying provider error message if the
    /// transformation or JSON serialization step fails.
    ///
    /// [`Value`]: serde_json::Value
    pub fn anthropic_to_openai_request(
        request: &CanonicalRequest,
    ) -> Result<serde_json::Value, String> {
        let openai_req = transform::transform_request(request).map_err(|e| e.to_string())?;
        serde_json::to_value(&openai_req).map_err(|e| e.to_string())
    }

    /// Inbound: translates an OpenAI Chat Completions response (raw JSON) into
    /// the canonical [`ProviderResponse`] (Anthropic-shaped) used by the
    /// dispatch pipeline.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the input JSON cannot be parsed as a valid OpenAI
    /// Chat Completions response shape.
    pub fn openai_response_to_anthropic(
        openai_json: serde_json::Value,
    ) -> Result<ProviderResponse, String> {
        let openai_resp: super::types::OpenAIResponse =
            serde_json::from_value(openai_json).map_err(|e| e.to_string())?;
        Ok(transform::transform_response(openai_resp))
    }

    /// Outbound: translates a canonical request to the OpenAI Responses API
    /// wire format (used by Codex CLI / ChatGPT OAuth path).
    ///
    /// # Errors
    ///
    /// Returns `Err` containing the underlying provider error message if the
    /// transformation or JSON serialization step fails.
    pub fn anthropic_to_responses_request(
        request: &CanonicalRequest,
        instructions: &str,
    ) -> Result<serde_json::Value, String> {
        let resp_req = transform::transform_to_responses_request(request, instructions)
            .map_err(|e| e.to_string())?;
        serde_json::to_value(&resp_req).map_err(|e| e.to_string())
    }
}

use super::{
    base::ProviderBase, error::ProviderError, LlmProvider, ProviderResponse, StreamResponse, Usage,
};
use crate::auth::OAuthConfig;
use crate::models::{CanonicalRequest, CountTokensRequest, CountTokensResponse};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use bytes::Bytes;
use std::collections::HashMap;
use types::*;

/// Official Codex instructions from OpenAI
const CODEX_INSTRUCTIONS: &str = include_str!("./codex_instructions.md");

/// OpenAI provider implementation
pub struct OpenAIProvider {
    base: ProviderBase,
}

impl OpenAIProvider {
    /// Check if the model is a Codex model that requires /v1/responses endpoint
    fn is_codex_model(model: &str) -> bool {
        model.to_lowercase().contains("codex")
    }

    /// Creates an OpenAI provider with custom HTTP headers.
    pub fn with_headers(
        params: super::ProviderParams,
        custom_headers: Vec<(String, String)>,
    ) -> Self {
        Self {
            base: ProviderBase::new(params, custom_headers),
        }
    }

    /// Extract ChatGPT account ID from JWT access token
    fn extract_account_id(access_token: &str) -> Option<String> {
        let parts: Vec<&str> = access_token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let payload = parts[1];
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
        let json_str = String::from_utf8(decoded).ok()?;
        let json: serde_json::Value = serde_json::from_str(&json_str).ok()?;
        json.get("https://api.openai.com/auth")?
            .get("chatgpt_account_id")?
            .as_str()
            .map(|s| s.to_string())
    }

    /// Build a request with OAuth headers for ChatGPT/Codex endpoints.
    fn apply_oauth_headers(
        req_builder: reqwest::RequestBuilder,
        auth_value: &str,
        is_codex: bool,
        provider_name: &str,
    ) -> reqwest::RequestBuilder {
        let Some(account_id) = Self::extract_account_id(auth_value) else {
            return req_builder;
        };

        let mut builder = req_builder
            .header("chatgpt-account-id", account_id)
            .header(
                "User-Agent",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            )
            .header("Origin", "https://chatgpt.com")
            .header("Referer", "https://chatgpt.com/")
            .header(
                "sec-ch-ua",
                "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            )
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"macOS\"")
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-origin");

        if is_codex {
            builder = builder
                .header("OpenAI-Beta", "responses=experimental")
                .header("originator", "codex_cli_rs");
            tracing::debug!(
                "Using OAuth Bearer token for ChatGPT Codex on {}",
                provider_name
            );
        } else {
            tracing::debug!("Using OAuth Bearer token for ChatGPT on {}", provider_name);
        }

        builder
    }

    /// Determine base URL based on auth type.
    fn effective_base_url(&self) -> &str {
        if self.base.is_oauth() {
            "https://chatgpt.com/backend-api"
        } else {
            &self.base.base_url
        }
    }

    /// Check response status and return error if not successful.
    async fn check_response(
        response: reqwest::Response,
    ) -> Result<reqwest::Response, ProviderError> {
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ProviderError::ApiError {
                status,
                message: error_text,
            });
        }
        Ok(response)
    }

    /// Sends via OpenAI Responses API (Codex / ChatGPT OAuth path).
    async fn send_responses_api(
        &self,
        request: &CanonicalRequest,
        auth_value: &str,
        base_url: &str,
    ) -> Result<ProviderResponse, ProviderError> {
        let responses_request =
            transform::transform_to_responses_request(request, CODEX_INSTRUCTIONS)?;

        let endpoint = if self.base.is_oauth() {
            "/codex/responses"
        } else {
            "/responses"
        };
        let url = format!("{}{}", base_url, endpoint);

        tracing::debug!(
            "Using {} endpoint for Codex model: {}",
            endpoint,
            request.model
        );

        let mut req_builder = self
            .base
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", auth_value))
            .header("Content-Type", "application/json")
            .header("accept", "text/event-stream");

        if self.base.is_oauth() {
            req_builder = Self::apply_oauth_headers(req_builder, auth_value, true, &self.base.name);
        }

        req_builder = self.base.apply_headers(req_builder);

        // SAFETY: auth_value is sent only in the Authorization header to the upstream API.
        // It is never logged or exposed in tracing output.
        let response = req_builder
            .timeout(self.base.api_timeout)
            .json(&responses_request)
            .send()
            .await?;

        let response = Self::check_response(response).await?;
        let response_text = response.text().await?;
        tracing::debug!(
            "Responses API response length: {} bytes",
            response_text.len()
        );

        let content_blocks = transform::parse_sse_response(&response_text)?;

        Ok(ProviderResponse {
            id: "sse-response".to_string(),
            r#type: "message".to_string(),
            role: "assistant".to_string(),
            content: content_blocks,
            model: request.model.clone(),
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        })
    }

    /// Sends via standard OpenAI Chat Completions API.
    async fn send_chat_completions(
        &self,
        request: &CanonicalRequest,
        auth_value: &str,
        base_url: &str,
    ) -> Result<ProviderResponse, ProviderError> {
        let openai_request = transform::transform_request(request)?;
        let url = format!("{}/chat/completions", base_url);

        let mut req_builder = self
            .base
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", auth_value))
            .header("Content-Type", "application/json");

        if self.base.is_oauth() {
            req_builder =
                Self::apply_oauth_headers(req_builder, auth_value, false, &self.base.name);
        }

        req_builder = self.base.apply_headers(req_builder);

        // SAFETY: auth_value is sent only in the Authorization header to the upstream API.
        // It is never logged or exposed in tracing output.
        let response = req_builder
            .timeout(self.base.api_timeout)
            .json(&openai_request)
            .send()
            .await?;

        let response = Self::check_response(response).await?;
        let response_text = response.text().await?;
        tracing::debug!(
            "OpenAI provider response length: {} bytes",
            response_text.len()
        );

        let openai_response: OpenAIResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                tracing::error!("Failed to parse OpenAI response: {}", e);
                tracing::debug!(
                    "Response body (truncated): {}",
                    &response_text[..response_text.len().min(200)]
                );
                e
            })?;

        Ok(transform::transform_response(openai_response))
    }
}

#[async_trait]
impl LlmProvider for OpenAIProvider {
    async fn send_message(
        &self,
        request: CanonicalRequest,
    ) -> Result<ProviderResponse, ProviderError> {
        let auth_value = self.base.resolve_auth(OAuthConfig::openai_codex).await?;
        let base_url = self.effective_base_url();

        if self.base.is_oauth() || Self::is_codex_model(&request.model) {
            self.send_responses_api(&request, &auth_value, base_url)
                .await
        } else {
            self.send_chat_completions(&request, &auth_value, base_url)
                .await
        }
    }

    async fn count_tokens(
        &self,
        request: CountTokensRequest,
    ) -> Result<CountTokensResponse, ProviderError> {
        Ok(super::helpers::estimate_token_count(&request))
    }

    async fn send_message_stream(
        &self,
        request: CanonicalRequest,
    ) -> Result<StreamResponse, ProviderError> {
        use futures::stream::TryStreamExt;

        let auth_value = self.base.resolve_auth(OAuthConfig::openai_codex).await?;
        let base_url = self.effective_base_url();
        let is_codex = Self::is_codex_model(&request.model);

        let (url, request_body) = if is_codex {
            tracing::debug!(
                "Using /v1/responses endpoint for Codex model (streaming): {}",
                request.model
            );
            let responses_request =
                transform::transform_to_responses_request(&request, CODEX_INSTRUCTIONS)?;
            let body = serde_json::to_value(&responses_request)
                .map_err(ProviderError::SerializationError)?;
            (format!("{}/responses", base_url), body)
        } else {
            let openai_request = transform::transform_request(&request)?;
            let body =
                serde_json::to_value(&openai_request).map_err(ProviderError::SerializationError)?;
            (format!("{}/chat/completions", base_url), body)
        };

        let mut req_builder = self
            .base
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", auth_value))
            .header("Content-Type", "application/json")
            .header("accept", "text/event-stream");

        if self.base.is_oauth() {
            req_builder =
                Self::apply_oauth_headers(req_builder, &auth_value, is_codex, &self.base.name);
        }

        req_builder = self.base.apply_headers(req_builder);

        // SAFETY: auth_value is sent only in the Authorization header to the upstream API.
        // It is never logged or exposed in tracing output.
        let response = req_builder
            .timeout(self.base.api_timeout)
            .json(&request_body)
            .send()
            .await?;

        let response = Self::check_response(response).await?;

        // Transform OpenAI SSE format to Anthropic SSE format
        use crate::providers::streaming::SseStream;
        use futures::stream::StreamExt;
        use std::sync::{Arc, Mutex};

        let message_id = format!("msg_{}", uuid::Uuid::new_v4());
        let state = Arc::new(Mutex::new(StreamTransformState::default()));
        let state_for_cleanup = state.clone();

        let sse_stream = SseStream::new(response.bytes_stream());
        let provider_name = self.base.name.clone();
        let model_name = request.model.clone();

        let transformed_stream = sse_stream
            .then(move |result| {
                let message_id = message_id.clone();
                let state = state.clone();
                let provider_name = provider_name.clone();
                async move {
                    match result {
                        Ok(sse_event) => {
                            process_sse_event(&sse_event.data, &state, &message_id, &provider_name)
                        }
                        Err(e) => {
                            tracing::error!("Stream error: {}", e);
                            Err(ProviderError::HttpError(e))
                        }
                    }
                }
            })
            .try_filter(|bytes| futures::future::ready(!bytes.is_empty()));

        // Stream finalization: ensure proper termination
        let finalized_stream = transformed_stream
            .chain(futures::stream::once(async move {
                let state = state_for_cleanup.lock().unwrap_or_else(|e| e.into_inner());
                tracing::debug!(
                    "Stream finalization: message_started={}, stream_ended={}",
                    state.message_started,
                    state.stream_ended
                );

                if state.message_started && !state.stream_ended {
                    tracing::warn!("Stream ended without finish_reason - sending end events");
                    let output = build_stream_finalization_output(&state);
                    Ok(Bytes::from(output))
                } else {
                    Ok(Bytes::new())
                }
            }))
            .try_filter(|bytes| futures::future::ready(!bytes.is_empty()));

        use crate::providers::streaming::LoggingSseStream;
        let logging_stream =
            LoggingSseStream::new(finalized_stream, self.base.name.clone(), model_name);

        Ok(StreamResponse {
            stream: Box::pin(logging_stream),
            headers: HashMap::new(),
        })
    }

    fn supports_model(&self, model: &str) -> bool {
        self.base.supports_model(model)
    }

    fn base_url(&self) -> Option<&str> {
        Some(&self.base.base_url)
    }

    fn rotate_key_pool(&self) -> bool {
        self.base
            .key_pool
            .as_ref()
            .is_some_and(|pool| pool.rotate_on_error())
    }
}

/// Transform a single OpenAI SSE event into Anthropic SSE format.
/// Returns empty bytes for events that should be filtered out (empty, [DONE], post-end).
fn process_sse_event(
    data: &str,
    state: &std::sync::Arc<std::sync::Mutex<StreamTransformState>>,
    message_id: &str,
    provider_name: &str,
) -> Result<Bytes, ProviderError> {
    // Skip if stream already ended
    if state.lock().unwrap_or_else(|e| e.into_inner()).stream_ended {
        return Ok(Bytes::new());
    }

    let trimmed = data.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return Ok(Bytes::new());
    }

    // Check for error response (some providers return HTTP 200 with error in body)
    if let Ok(error_response) = serde_json::from_str::<OpenAIStreamError>(data) {
        let status = error_response.status_code.unwrap_or(500);
        let error_type = error_response.error.r#type.as_deref().unwrap_or("unknown");
        tracing::error!(
            "{} upstream error ({}): {} [type={}]",
            provider_name,
            status,
            error_response.error.message,
            error_type
        );
        return Err(ProviderError::ApiError {
            status,
            message: format!("{}: {}", provider_name, error_response.error.message),
        });
    }

    match serde_json::from_str::<OpenAIStreamChunk>(data) {
        Ok(chunk) => {
            let sse_output = streaming::transform_openai_chunk_to_anthropic_sse(
                &chunk,
                message_id,
                &mut state.lock().unwrap_or_else(|e| e.into_inner()),
            );
            Ok(Bytes::from(sse_output))
        }
        Err(e) => {
            tracing::warn!(
                "{} failed to parse chunk: {} - Data: {}",
                provider_name,
                e,
                data
            );
            Ok(Bytes::new())
        }
    }
}

/// Build finalization SSE output for streams that ended without finish_reason.
fn build_stream_finalization_output(state: &StreamTransformState) -> String {
    let mut output = String::new();

    if state.text_block_open {
        let block_stop = serde_json::json!({
            "type": "content_block_stop",
            "index": state.text_block_index
        });
        output.push_str(&format!(
            "event: content_block_stop\ndata: {}\n\n",
            block_stop
        ));
    }

    for block_index in state.tool_blocks.values() {
        let block_stop = serde_json::json!({
            "type": "content_block_stop",
            "index": block_index
        });
        output.push_str(&format!(
            "event: content_block_stop\ndata: {}\n\n",
            block_stop
        ));
    }

    let message_delta = serde_json::json!({
        "type": "message_delta",
        "delta": { "stop_reason": "end_turn", "stop_sequence": null },
        "usage": { "output_tokens": 0 }
    });
    output.push_str(&format!(
        "event: message_delta\ndata: {}\n\n",
        message_delta
    ));

    let message_stop = serde_json::json!({ "type": "message_stop" });
    output.push_str(&format!("event: message_stop\ndata: {}\n\n", message_stop));

    output
}

#[cfg(test)]
mod tests {
    use super::streaming::transform_openai_chunk_to_anthropic_sse;
    use super::types::*;

    #[test]
    fn test_parse_stream_error_response() {
        let error_json = r#"{"status_code":500,"error":{"message":"Encountered a server error, please try again.","type":"server_error","param":"","code":"","id":""}}"#;
        let error: OpenAIStreamError = serde_json::from_str(error_json).unwrap();
        assert_eq!(error.status_code, Some(500));
        assert_eq!(
            error.error.message,
            "Encountered a server error, please try again."
        );
        assert_eq!(error.error.r#type, Some("server_error".to_string()));
    }

    #[test]
    fn test_stream_error_does_not_match_valid_chunk() {
        let valid_chunk = r#"{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"gpt-4","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}"#;
        let result = serde_json::from_str::<OpenAIStreamError>(valid_chunk);
        assert!(
            result.is_err(),
            "Valid chunk should not parse as error response"
        );
    }

    #[test]
    fn test_parse_error_without_status_code() {
        let error_json = r#"{"error":{"message":"Rate limit exceeded","type":"rate_limit_error"}}"#;
        let error: OpenAIStreamError = serde_json::from_str(error_json).unwrap();
        assert_eq!(error.status_code, None);
        assert_eq!(error.error.message, "Rate limit exceeded");
    }

    fn transform_chunk(json: &str, msg_id: &str, state: &mut StreamTransformState) -> String {
        let chunk: OpenAIStreamChunk = serde_json::from_str(json).unwrap();
        transform_openai_chunk_to_anthropic_sse(&chunk, msg_id, state)
    }

    #[test]
    fn test_tool_call_before_text_gets_distinct_indices() {
        let mut state = StreamTransformState::default();
        let id = "msg_test";

        let out = transform_chunk(
            r#"{
            "id":"gen-1","model":"kimi","choices":[{"index":0,"delta":{
                "role":"assistant","content":null,
                "tool_calls":[{"index":0,"id":"functions.Bash:0","type":"function",
                    "function":{"name":"Bash","arguments":null}}]
            },"finish_reason":null}]
        }"#,
            id,
            &mut state,
        );
        assert!(out.contains("tool_use"));
        assert!(out.contains(r#""name":"Bash"#));

        let out = transform_chunk(
            r#"{
            "id":"gen-1","model":"kimi","choices":[{"index":0,"delta":{
                "content":null,
                "tool_calls":[{"index":0,"id":"functions.Bash:0","type":"function",
                    "function":{"name":null,"arguments":"{\"command\":\"git log\"}"}}]
            },"finish_reason":null}]
        }"#,
            id,
            &mut state,
        );
        assert!(out.contains("input_json_delta"));

        let out = transform_chunk(
            r#"{
            "id":"gen-1","model":"kimi","choices":[{"index":0,"delta":{
                "content":" ","reasoning":null
            },"finish_reason":null}]
        }"#,
            id,
            &mut state,
        );
        assert!(out.contains(r#""index":1"#));
        assert!(!out.contains(r#""index":0"#));

        let out = transform_chunk(
            r#"{
            "id":"gen-1","model":"kimi","choices":[{"index":0,"delta":{
                "content":""
            },"finish_reason":"tool_calls"}]
        }"#,
            id,
            &mut state,
        );
        assert!(out.contains("tool_use"));
        assert!(out.contains("message_stop"));
    }

    #[test]
    fn test_text_before_tool_call_normal_ordering() {
        let mut state = StreamTransformState::default();
        let id = "msg_test";

        let out = transform_chunk(
            r#"{
            "id":"gen-1","model":"test","choices":[{"index":0,"delta":{
                "content":"Let me check"
            },"finish_reason":null}]
        }"#,
            id,
            &mut state,
        );
        assert!(out.contains(r#""index":0"#));
        assert!(out.contains("text_delta"));

        let out = transform_chunk(
            r#"{
            "id":"gen-1","model":"test","choices":[{"index":0,"delta":{
                "content":null,
                "tool_calls":[{"index":0,"id":"call_123","type":"function",
                    "function":{"name":"Bash","arguments":"{}"}}]
            },"finish_reason":null}]
        }"#,
            id,
            &mut state,
        );
        assert!(out.contains("content_block_stop"));
        assert!(out.contains(r#""index":1"#));
        assert!(out.contains("tool_use"));
    }

    #[test]
    fn test_reasoning_becomes_thinking_block() {
        let mut state = StreamTransformState::default();
        let id = "msg_test";

        let out = transform_chunk(
            r#"{
            "id":"gen-1","model":"kimi","choices":[{"index":0,"delta":{
                "content":"","reasoning":"thinking about it"
            },"finish_reason":null}]
        }"#,
            id,
            &mut state,
        );
        assert!(out.contains("thinking about it"));
        assert!(out.contains("\"type\":\"thinking\""));
        assert!(out.contains("thinking_delta"));
    }
}
