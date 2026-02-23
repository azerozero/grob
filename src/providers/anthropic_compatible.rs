use super::{error::ProviderError, AnthropicProvider, ProviderResponse, StreamResponse};
use crate::auth::{OAuthClient, OAuthConfig, TokenStore};
use crate::models::{
    AnthropicRequest, ContentBlock, CountTokensRequest, CountTokensResponse, KnownContentBlock,
    MessageContent,
};
use async_trait::async_trait;
use reqwest::Client;
use secrecy::ExposeSecret;
use std::collections::HashMap;

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
    sig.len() >= 100
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
fn sanitize_tool_use_ids(request: &mut AnthropicRequest, is_anthropic_target: bool) {
    if !is_anthropic_target {
        return;
    }

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
    client: Client,
    models: Vec<String>,
    /// Custom headers to add (e.g., "HTTP-Referer" for OpenRouter)
    custom_headers: Vec<(String, String)>,
    /// OAuth provider ID (if using OAuth instead of API key)
    oauth_provider: Option<String>,
    /// Token store for OAuth authentication
    token_store: Option<TokenStore>,
}

impl AnthropicCompatibleProvider {
    pub fn new(
        name: String,
        api_key: String,
        base_url: String,
        models: Vec<String>,
        oauth_provider: Option<String>,
        token_store: Option<TokenStore>,
    ) -> Self {
        Self::with_headers(
            name,
            api_key,
            base_url,
            models,
            Vec::new(),
            oauth_provider,
            token_store,
        )
    }

    pub fn with_headers(
        name: String,
        api_key: String,
        base_url: String,
        models: Vec<String>,
        custom_headers: Vec<(String, String)>,
        oauth_provider: Option<String>,
        token_store: Option<TokenStore>,
    ) -> Self {
        Self {
            name,
            api_key,
            base_url,
            client: Client::new(),
            models,
            custom_headers,
            oauth_provider,
            token_store,
        }
    }

    /// Get authentication header value (API key or OAuth Bearer token)
    async fn get_auth_header(&self) -> Result<String, ProviderError> {
        // If OAuth provider is configured, use Bearer token
        if let Some(ref oauth_provider_id) = self.oauth_provider {
            if let Some(ref token_store) = self.token_store {
                // Try to get token from store
                if let Some(token) = token_store.get(oauth_provider_id) {
                    // Check if token needs refresh
                    if token.needs_refresh() {
                        tracing::info!(
                            "🔄 Token for '{}' needs refresh, refreshing...",
                            oauth_provider_id
                        );

                        // Refresh token
                        let config = OAuthConfig::anthropic();
                        let oauth_client = OAuthClient::new(config, token_store.clone());

                        match oauth_client.refresh_token(oauth_provider_id).await {
                            Ok(new_token) => {
                                tracing::info!("✅ Token refreshed successfully");
                                return Ok(new_token.access_token.expose_secret().to_string());
                            }
                            Err(e) => {
                                tracing::error!("❌ Failed to refresh token: {}", e);
                                return Err(ProviderError::AuthError(format!(
                                    "Failed to refresh OAuth token: {}",
                                    e
                                )));
                            }
                        }
                    } else {
                        // Token is still valid
                        return Ok(token.access_token.expose_secret().to_string());
                    }
                } else {
                    return Err(ProviderError::AuthError(format!(
                        "OAuth provider '{}' configured but no token found in store",
                        oauth_provider_id
                    )));
                }
            } else {
                return Err(ProviderError::AuthError(
                    "OAuth provider configured but TokenStore not available".to_string(),
                ));
            }
        }

        // Fall back to API key
        Ok(self.api_key.clone())
    }

    /// Check if using OAuth authentication
    fn is_oauth(&self) -> bool {
        self.oauth_provider.is_some() && self.token_store.is_some()
    }

    /// Create z.ai provider (Anthropic-compatible)
    pub fn zai(api_key: String, models: Vec<String>, token_store: Option<TokenStore>) -> Self {
        Self::new(
            "z.ai".to_string(),
            api_key,
            "https://api.z.ai/api/anthropic".to_string(),
            models,
            None,
            token_store,
        )
    }

    /// Create Minimax provider (Anthropic-compatible)
    pub fn minimax(api_key: String, models: Vec<String>, token_store: Option<TokenStore>) -> Self {
        Self::new(
            "minimax".to_string(),
            api_key,
            "https://api.minimax.io/anthropic".to_string(),
            models,
            None,
            token_store,
        )
    }

    /// Create ZenMux provider (Anthropic-compatible proxy)
    pub fn zenmux(api_key: String, models: Vec<String>, token_store: Option<TokenStore>) -> Self {
        Self::new(
            "zenmux".to_string(),
            api_key,
            "https://zenmux.ai/api/anthropic".to_string(),
            models,
            None,
            token_store,
        )
    }

    /// Create Kimi For Coding provider (Anthropic-compatible)
    pub fn kimi_coding(
        api_key: String,
        models: Vec<String>,
        token_store: Option<TokenStore>,
    ) -> Self {
        Self::new(
            "kimi-coding".to_string(),
            api_key,
            "https://api.kimi.com/coding".to_string(),
            models,
            None,
            token_store,
        )
    }

    /// Helper to send a message request (used for retry logic)
    async fn try_send_message(
        &self,
        url: &str,
        auth_value: &str,
        request: &AnthropicRequest,
    ) -> Result<ProviderResponse, ProviderError> {
        let mut req_builder = self
            .client
            .post(url)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json");

        // Set auth header based on OAuth vs API key
        if self.is_oauth() {
            req_builder = req_builder
                .header("Authorization", format!("Bearer {}", auth_value))
                .header("anthropic-beta", "oauth-2025-04-20,claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14");
        } else {
            req_builder = req_builder.header("x-api-key", auth_value);
        }

        // Add custom headers
        for (key, value) in &self.custom_headers {
            req_builder = req_builder.header(key, value);
        }

        let response = req_builder.json(request).send().await?;

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

        let response_text = response.text().await?;
        tracing::debug!("{} provider response body: {}", self.name, response_text);

        let provider_response: ProviderResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                tracing::error!("Failed to parse {} response: {}", self.name, e);
                tracing::error!("Response body was: {}", response_text);
                e
            })?;

        Ok(provider_response)
    }

    /// Helper to send a streaming request (used for retry logic)
    async fn try_send_stream_request(
        &self,
        url: &str,
        auth_value: &str,
        request: &AnthropicRequest,
    ) -> Result<reqwest::Response, ProviderError> {
        let mut req_builder = self
            .client
            .post(url)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json");

        if self.is_oauth() {
            req_builder = req_builder
                .header("Authorization", format!("Bearer {}", auth_value))
                .header("anthropic-beta", "oauth-2025-04-20,claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14");
        } else {
            req_builder = req_builder.header("x-api-key", auth_value);
        }

        for (key, value) in &self.custom_headers {
            req_builder = req_builder.header(key, value);
        }

        let response = req_builder.json(request).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            if status == 401 && self.is_oauth() {
                tracing::warn!(
                    "🔄 Received 401 on streaming, OAuth token may be invalid or expired"
                );
            }

            return Err(ProviderError::ApiError {
                status,
                message: format!("{} API error: {}", self.name, error_text),
            });
        }

        Ok(response)
    }
}

#[async_trait]
impl AnthropicProvider for AnthropicCompatibleProvider {
    async fn send_message(
        &self,
        request: AnthropicRequest,
    ) -> Result<ProviderResponse, ProviderError> {
        let url = format!("{}/v1/messages", self.base_url);

        // Sanitize request for Anthropic targets
        let mut request = request;
        let is_anthropic = self.base_url.contains("anthropic.com");
        sanitize_tool_use_ids(&mut request, is_anthropic);
        if is_anthropic {
            strip_non_anthropic_thinking(&mut request);
        }

        // Get authentication header value (API key or OAuth token)
        let auth_value = self.get_auth_header().await?;

        let result = self.try_send_message(&url, &auth_value, &request).await;

        // Fallback: if signature error, strip all signed thinking blocks and retry
        if is_anthropic {
            if let Err(ProviderError::ApiError { message, .. }) = &result {
                if message.contains("signature") {
                    tracing::warn!("🔄 Signature error from Anthropic: {}, stripping all signed thinking blocks and retrying", message);
                    strip_all_thinking_signatures(&mut request);
                    return self.try_send_message(&url, &auth_value, &request).await;
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

            // Get authentication
            let auth_value = self.get_auth_header().await?;

            let mut req_builder = self
                .client
                .post(&url)
                .header("anthropic-version", "2023-06-01")
                .header("Content-Type", "application/json");

            // Set auth header
            if self.is_oauth() {
                req_builder = req_builder
                    .header("Authorization", format!("Bearer {}", auth_value))
                    .header("anthropic-beta", "oauth-2025-04-20,claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14");
            } else {
                req_builder = req_builder.header("x-api-key", auth_value);
            }

            let response = req_builder.json(&request).send().await?;

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

            let count_response: CountTokensResponse = response.json().await?;
            return Ok(count_response);
        }

        // For other providers, use character-based estimation
        let mut total_chars = 0;

        if let Some(ref system) = request.system {
            let system_text = match system {
                crate::models::SystemPrompt::Text(text) => text.clone(),
                crate::models::SystemPrompt::Blocks(blocks) => blocks
                    .iter()
                    .map(|b| b.text.clone())
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            total_chars += system_text.len();
        }

        for msg in &request.messages {
            use crate::models::MessageContent;
            let content = match &msg.content {
                MessageContent::Text(text) => text.clone(),
                MessageContent::Blocks(blocks) => blocks
                    .iter()
                    .filter_map(|block| match block {
                        ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                            Some(text.clone())
                        }
                        ContentBlock::Known(KnownContentBlock::ToolResult { content, .. }) => {
                            Some(content.to_string())
                        }
                        ContentBlock::Known(KnownContentBlock::Thinking { raw }) => raw
                            .get("thinking")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            };
            total_chars += content.len();
        }

        let estimated_tokens = (total_chars / 4) as u32;

        Ok(CountTokensResponse {
            input_tokens: estimated_tokens,
        })
    }

    async fn send_message_stream(
        &self,
        request: AnthropicRequest,
    ) -> Result<StreamResponse, ProviderError> {
        use futures::stream::TryStreamExt;

        let url = format!("{}/v1/messages", self.base_url);

        // Sanitize request for Anthropic targets
        let mut request = request;
        let is_anthropic = self.base_url.contains("anthropic.com");
        sanitize_tool_use_ids(&mut request, is_anthropic);
        if is_anthropic {
            strip_non_anthropic_thinking(&mut request);
        }

        // Get authentication header value
        let auth_value = self.get_auth_header().await?;

        // Try request, fallback: strip all signed thinking blocks on signature error
        let response = match self
            .try_send_stream_request(&url, &auth_value, &request)
            .await
        {
            Ok(resp) => resp,
            Err(ProviderError::ApiError { message, .. })
                if is_anthropic && message.contains("signature") =>
            {
                tracing::warn!("🔄 Signature error from Anthropic: {}, stripping all signed thinking blocks and retrying stream", message);
                strip_all_thinking_signatures(&mut request);
                self.try_send_stream_request(&url, &auth_value, &request)
                    .await?
            }
            Err(e) => return Err(e),
        };

        // Extract headers to forward (only for Anthropic backend)
        let headers = if is_anthropic {
            extract_forward_headers(response.headers())
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
}
