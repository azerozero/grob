use super::{
    build_provider_client,
    constants::{
        ANTHROPIC_API_VERSION, ANTHROPIC_BETA_FEATURES, ANTHROPIC_DOMAIN,
        MIN_ANTHROPIC_SIGNATURE_LENGTH, RATE_LIMIT_REQUESTS_LOW, RATE_LIMIT_TOKENS_LOW,
    },
    error::ProviderError,
    LlmProvider, ProviderResponse, StreamResponse,
};
use crate::auth::{OAuthConfig, TokenStore};
use crate::models::{
    AnthropicRequest, ContentBlock, CountTokensRequest, CountTokensResponse, KnownContentBlock,
    MessageContent,
};
use async_trait::async_trait;
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;

/// Headers to forward from Anthropic responses (rate limits, etc.)
const ANTHROPIC_FORWARD_HEADERS: &[&str] = &[
    "anthropic-ratelimit-requests-limit",
    "anthropic-ratelimit-requests-remaining",
    "anthropic-ratelimit-requests-reset",
    "anthropic-ratelimit-tokens-limit",
    "anthropic-ratelimit-tokens-remaining",
    "anthropic-ratelimit-tokens-reset",
    "anthropic-ratelimit-input-tokens-limit",
    "anthropic-ratelimit-input-tokens-remaining",
    "anthropic-ratelimit-input-tokens-reset",
    "anthropic-ratelimit-output-tokens-limit",
    "anthropic-ratelimit-output-tokens-remaining",
    "anthropic-ratelimit-output-tokens-reset",
    "retry-after",
];

/// Extract headers to forward from response
fn extract_forward_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for header_name in ANTHROPIC_FORWARD_HEADERS {
        if let Some(value) = headers.get(*header_name) {
            if let Ok(v) = value.to_str() {
                result.insert(header_name.to_string(), v.to_string());
            }
        }
    }
    result
}

/// Rate-limit headers to track: (header_name, metric_name, warn_threshold).
/// A threshold of `0` means no warning is emitted.
const RATE_LIMIT_HEADERS: &[(&str, &str, u64)] = &[
    (
        "anthropic-ratelimit-tokens-remaining",
        "grob_ratelimit_tokens_remaining",
        RATE_LIMIT_TOKENS_LOW,
    ),
    (
        "anthropic-ratelimit-requests-remaining",
        "grob_ratelimit_requests_remaining",
        RATE_LIMIT_REQUESTS_LOW,
    ),
    (
        "anthropic-ratelimit-input-tokens-remaining",
        "grob_ratelimit_input_tokens_remaining",
        0,
    ),
    (
        "anthropic-ratelimit-output-tokens-remaining",
        "grob_ratelimit_output_tokens_remaining",
        0,
    ),
];

/// Parse and log rate limit headers, emit Prometheus metrics when values are low
fn log_rate_limits(headers: &HashMap<String, String>, provider: &str) {
    for &(header, metric, warn_threshold) in RATE_LIMIT_HEADERS {
        if let Some(value) = headers.get(header) {
            if let Ok(remaining) = value.parse::<u64>() {
                if warn_threshold > 0 && remaining < warn_threshold {
                    tracing::warn!(
                        "{} rate limit low: {} {} remaining",
                        provider,
                        remaining,
                        header.trim_start_matches("anthropic-ratelimit-"),
                    );
                }
                metrics::gauge!(metric, "provider" => provider.to_string()).set(remaining as f64);
            }
        }
    }
}

// Thinking block signature handling for Anthropic
//
// What we know works:
//   - Sending thinking blocks WITH valid Anthropic signatures → accepted
//   - Sending thinking blocks WITHOUT a signature field at all (unsigned) → accepted
//   - Omitting thinking blocks from prior turns entirely → accepted
//
// What doesn't work:
//   - Sending thinking blocks with invalid/non-Anthropic signatures → rejected
//   - Sending thinking blocks with signature field removed (was present, now absent) →
//     same as unsigned, should work (identical JSON), but untested in production
//   - Stripping just the signature field was rejected in testing with "Field required"
//
// Strategy:
//   1. Proactive: use heuristic to strip thinking blocks with non-Anthropic signatures
//      (Anthropic signatures are long base64 strings, 200+ chars)
//   2. Fallback: on any signature error from Anthropic, strip all signatures
//      (converting to unsigned blocks), and retry

/// Anthropic signatures are long base64 strings (200+ chars typically).
fn looks_like_anthropic_signature(sig: &str) -> bool {
    use base64::Engine;
    sig.len() >= MIN_ANTHROPIC_SIGNATURE_LENGTH
        && base64::engine::general_purpose::STANDARD
            .decode(sig)
            .is_ok()
}

/// Proactive: strip thinking blocks that don't look like they came from Anthropic.
/// Keeps unsigned blocks and blocks with valid-looking Anthropic signatures.
fn strip_non_anthropic_thinking(request: &mut AnthropicRequest) {
    let mut stripped_count = 0;

    for message in &mut request.messages {
        if let MessageContent::Blocks(blocks) = &mut message.content {
            let before_len = blocks.len();
            blocks.retain(|block| match block {
                ContentBlock::Known(KnownContentBlock::Thinking { raw }) => {
                    match raw.get("signature").and_then(|v| v.as_str()) {
                        None => true,
                        Some(sig) if looks_like_anthropic_signature(sig) => true,
                        Some(_) => {
                            tracing::debug!(
                                "🧹 Stripping thinking block with non-Anthropic signature"
                            );
                            false
                        }
                    }
                }
                _ => true,
            });
            stripped_count += before_len - blocks.len();
        }
    }

    remove_empty_messages(request);

    if stripped_count > 0 {
        tracing::info!(
            "🧹 Stripped {} non-Anthropic thinking block(s)",
            stripped_count
        );
    }
}

/// Fallback: strip all signatures from thinking blocks, converting them to unsigned.
/// Used when Anthropic rejects a signature the heuristic thought was valid.
fn strip_all_thinking_signatures(request: &mut AnthropicRequest) {
    let mut stripped_count = 0;

    for message in &mut request.messages {
        if let MessageContent::Blocks(blocks) = &mut message.content {
            for block in blocks.iter_mut() {
                if let ContentBlock::Known(KnownContentBlock::Thinking { raw }) = block {
                    if let Some(obj) = raw.as_object_mut() {
                        if obj.remove("signature").is_some() {
                            stripped_count += 1;
                        }
                    }
                }
            }
        }
    }

    if stripped_count > 0 {
        tracing::info!(
            "🧹 Fallback: stripped signatures from {} thinking block(s)",
            stripped_count
        );
    }
}

fn remove_empty_messages(request: &mut AnthropicRequest) {
    request.messages.retain(|msg| match &msg.content {
        MessageContent::Text(t) => !t.is_empty(),
        MessageContent::Blocks(b) => !b.is_empty(),
    });
}

/// Sanitize tool_use.id and tool_use_id fields to match Anthropic's pattern requirement.
/// Anthropic requires tool IDs to match: ^[a-zA-Z0-9_-]+
/// Non-Anthropic providers may generate IDs with invalid characters.
fn sanitize_tool_use_ids(request: &mut AnthropicRequest) {
    let mut sanitized_count = 0;

    for message in &mut request.messages {
        if let MessageContent::Blocks(blocks) = &mut message.content {
            for block in blocks.iter_mut() {
                match block {
                    ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                        let sanitized = sanitize_tool_id(id);
                        if sanitized != *id {
                            tracing::debug!("🔧 Sanitized tool_use.id: {} → {}", id, sanitized);
                            *block = ContentBlock::tool_use(sanitized, name.clone(), input.clone());
                            sanitized_count += 1;
                        }
                    }
                    ContentBlock::Known(KnownContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                        cache_control,
                    }) => {
                        let sanitized = sanitize_tool_id(tool_use_id);
                        if sanitized != *tool_use_id {
                            tracing::debug!(
                                "🔧 Sanitized tool_use_id: {} → {}",
                                tool_use_id,
                                sanitized
                            );
                            *block = ContentBlock::Known(KnownContentBlock::ToolResult {
                                tool_use_id: sanitized,
                                content: content.clone(),
                                is_error: *is_error,
                                cache_control: cache_control.clone(),
                            });
                            sanitized_count += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if sanitized_count > 0 {
        tracing::info!("🔧 Sanitized {} tool IDs for Anthropic", sanitized_count);
    }
}

/// Sanitize a tool ID to match pattern ^[a-zA-Z0-9_-]+
fn sanitize_tool_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Generic Anthropic-compatible provider
/// Works with: Anthropic, OpenRouter, z.ai, Minimax, etc.
/// Any provider that accepts Anthropic Messages API format
pub struct AnthropicCompatibleProvider {
    name: String,
    api_key: String,
    base_url: String,
    /// Pre-computed messages endpoint URL (avoids format! on every request).
    messages_url: String,
    client: Client,
    models: Vec<String>,
    /// Custom headers to add (e.g., "HTTP-Referer" for OpenRouter)
    custom_headers: Vec<(String, String)>,
    /// OAuth provider ID (if using OAuth instead of API key)
    oauth_provider: Option<String>,
    /// Token store for OAuth authentication
    token_store: Option<TokenStore>,
    /// Per-request timeout from server config
    api_timeout: Duration,
}

impl AnthropicCompatibleProvider {
    pub fn new(params: super::ProviderParams) -> Self {
        Self::with_headers(params, Vec::new())
    }

    pub fn with_headers(
        params: super::ProviderParams,
        custom_headers: Vec<(String, String)>,
    ) -> Self {
        let base_url = params.base_url.unwrap_or_default();
        let messages_url = format!("{}/v1/messages", base_url);
        Self {
            name: params.name,
            api_key: params.api_key,
            base_url,
            messages_url,
            client: build_provider_client(params.connect_timeout),
            models: params.models,
            custom_headers,
            oauth_provider: params.oauth_provider,
            token_store: params.token_store,
            api_timeout: params.api_timeout,
        }
    }

    async fn auth_header(&self) -> Result<String, ProviderError> {
        super::auth::resolve_access_token(
            self.oauth_provider.as_deref(),
            self.token_store.as_ref(),
            OAuthConfig::anthropic,
            &self.api_key,
        )
        .await
    }

    fn is_oauth(&self) -> bool {
        self.oauth_provider.is_some() && self.token_store.is_some()
    }

    /// Create a named Anthropic-compatible provider with a fixed base URL.
    pub fn named(name: &str, base_url: &str, params: super::ProviderParams) -> Self {
        Self::new(super::ProviderParams {
            name: name.to_string(),
            base_url: Some(base_url.to_string()),
            ..params
        })
    }

    /// Build a pre-configured request with Anthropic headers and auth.
    fn build_anthropic_request(&self, url: &str, auth_value: &str) -> reqwest::RequestBuilder {
        let mut req_builder = self
            .client
            .post(url)
            .header("anthropic-version", ANTHROPIC_API_VERSION)
            .header("Content-Type", "application/json");

        if self.is_oauth() {
            req_builder = req_builder
                .header("Authorization", format!("Bearer {}", auth_value))
                .header("anthropic-beta", ANTHROPIC_BETA_FEATURES);
        } else {
            req_builder = req_builder.header("x-api-key", auth_value);
        }

        for (key, value) in &self.custom_headers {
            req_builder = req_builder.header(key, value);
        }

        req_builder
    }

    /// Send an HTTP request and check for error status, returning the response.
    /// Shared between streaming and non-streaming paths.
    async fn send_and_check(
        &self,
        url: &str,
        auth_value: &str,
        request: &AnthropicRequest,
    ) -> Result<reqwest::Response, ProviderError> {
        let response = self
            .build_anthropic_request(url, auth_value)
            .timeout(self.api_timeout)
            .json(request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            if status == 401 && self.is_oauth() {
                tracing::warn!("🔄 Received 401, OAuth token may be invalid or expired");
            }

            return Err(ProviderError::ApiError {
                status,
                message: format!("{} API error: {}", self.name, error_text),
            });
        }

        Ok(response)
    }

    async fn try_send_message(
        &self,
        url: &str,
        auth_value: &str,
        request: &AnthropicRequest,
    ) -> Result<ProviderResponse, ProviderError> {
        let response = self.send_and_check(url, auth_value, request).await?;

        // Log rate limit headers from non-streaming responses
        let is_anthropic = self.base_url.contains(ANTHROPIC_DOMAIN);
        if is_anthropic {
            let fwd_headers = extract_forward_headers(response.headers());
            log_rate_limits(&fwd_headers, &self.name);
        }

        let response_text = response.text().await?;
        tracing::debug!(
            "{} provider response received ({} bytes)",
            self.name,
            response_text.len()
        );

        let provider_response: ProviderResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                tracing::error!("Failed to parse {} response: {}", self.name, e);
                tracing::error!("Response body was: {}", response_text);
                e
            })?;

        Ok(provider_response)
    }

    async fn try_send_stream_request(
        &self,
        url: &str,
        auth_value: &str,
        request: &AnthropicRequest,
    ) -> Result<reqwest::Response, ProviderError> {
        self.send_and_check(url, auth_value, request).await
    }

    /// Common setup for both send_message and send_message_stream:
    /// builds URL, sanitizes request for Anthropic backends, resolves auth.
    async fn prepare_anthropic_request(
        &self,
        request: &mut AnthropicRequest,
    ) -> Result<(&str, String, bool), ProviderError> {
        let is_anthropic = self.base_url.contains(ANTHROPIC_DOMAIN);
        if is_anthropic {
            sanitize_tool_use_ids(request);
            strip_non_anthropic_thinking(request);
        }
        let auth_value = self.auth_header().await?;
        Ok((&self.messages_url, auth_value, is_anthropic))
    }
}

#[async_trait]
impl LlmProvider for AnthropicCompatibleProvider {
    async fn send_message(
        &self,
        request: AnthropicRequest,
    ) -> Result<ProviderResponse, ProviderError> {
        let mut request = request;
        let (url, auth_value, is_anthropic) = self.prepare_anthropic_request(&mut request).await?;

        let result = self.try_send_message(url, &auth_value, &request).await;

        // Fallback: if signature error, strip all signed thinking blocks and retry
        if is_anthropic {
            if let Err(ProviderError::ApiError { message, .. }) = &result {
                if message.contains("signature") {
                    tracing::warn!("🔄 Signature error from Anthropic: {}, stripping all signed thinking blocks and retrying", message);
                    strip_all_thinking_signatures(&mut request);
                    return self.try_send_message(url, &auth_value, &request).await;
                }
            }
        }

        result
    }

    async fn count_tokens(
        &self,
        request: CountTokensRequest,
    ) -> Result<CountTokensResponse, ProviderError> {
        // For Anthropic native, use their count_tokens endpoint
        if self.name == "anthropic" {
            let url = format!("{}/v1/messages/count_tokens", self.base_url);
            let auth_value = self.auth_header().await?;

            let response = self
                .build_anthropic_request(&url, &auth_value)
                .timeout(self.api_timeout)
                .json(&request)
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| format!("{}: failed to read error body", self.name));
                return Err(ProviderError::ApiError {
                    status,
                    message: format!("{} count_tokens error: {}", self.name, error_text),
                });
            }

            let count_response: CountTokensResponse = response.json().await?;
            return Ok(count_response);
        }

        Ok(super::helpers::estimate_token_count(&request))
    }

    async fn send_message_stream(
        &self,
        request: AnthropicRequest,
    ) -> Result<StreamResponse, ProviderError> {
        use futures::stream::TryStreamExt;

        let mut request = request;
        let (url, auth_value, is_anthropic) = self.prepare_anthropic_request(&mut request).await?;

        // Try request, fallback: strip all signed thinking blocks on signature error
        let response = match self
            .try_send_stream_request(url, &auth_value, &request)
            .await
        {
            Ok(resp) => resp,
            Err(ProviderError::ApiError { message, .. })
                if is_anthropic && message.contains("signature") =>
            {
                tracing::warn!("🔄 Signature error from Anthropic: {}, stripping all signed thinking blocks and retrying stream", message);
                strip_all_thinking_signatures(&mut request);
                self.try_send_stream_request(url, &auth_value, &request)
                    .await?
            }
            Err(e) => return Err(e),
        };

        // Extract headers to forward (only for Anthropic backend)
        let headers = if is_anthropic {
            let fwd = extract_forward_headers(response.headers());
            log_rate_limits(&fwd, &self.name);
            fwd
        } else {
            HashMap::new()
        };

        // Wrap stream with logging to capture cache statistics
        use crate::providers::streaming::LoggingSseStream;
        let byte_stream = response.bytes_stream().map_err(ProviderError::HttpError);
        let logging_stream =
            LoggingSseStream::new(byte_stream, self.name.clone(), request.model.clone());

        // Return stream with headers for forwarding
        Ok(StreamResponse {
            stream: Box::pin(logging_stream),
            headers,
        })
    }

    fn supports_model(&self, model: &str) -> bool {
        self.models.iter().any(|m| m.eq_ignore_ascii_case(model))
    }

    fn base_url(&self) -> Option<&str> {
        Some(&self.base_url)
    }
}
