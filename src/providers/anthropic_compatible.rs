use super::{
    base::ProviderBase,
    constants::{
        ANTHROPIC_API_VERSION, ANTHROPIC_BETA_FEATURES, ANTHROPIC_DOMAIN, RATE_LIMIT_REQUESTS_LOW,
        RATE_LIMIT_TOKENS_LOW,
    },
    error::ProviderError,
    LlmProvider, ProviderResponse, StreamResponse,
};
use crate::auth::OAuthConfig;
use crate::models::{CanonicalRequest, CountTokensRequest, CountTokensResponse};
use async_trait::async_trait;
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

use super::anthropic_sanitize::{
    restore_original_tool_ids, sanitize_tool_use_ids, strip_all_thinking_signatures,
    strip_non_anthropic_thinking, OriginalToolIdMap,
};

/// Merges server-default beta features with client-provided ones, deduplicating.
fn merge_beta_features(client: Option<&str>) -> String {
    let Some(client) = client else {
        return ANTHROPIC_BETA_FEATURES.to_string();
    };
    let mut features: Vec<&str> = ANTHROPIC_BETA_FEATURES.split(',').collect();
    for feat in client.split(',') {
        let feat = feat.trim();
        if !feat.is_empty() && !features.contains(&feat) {
            features.push(feat);
        }
    }
    features.join(",")
}

/// Generic Anthropic-compatible provider.
/// Works with: Anthropic, OpenRouter, z.ai, Minimax, etc.
/// Any provider that accepts Anthropic Messages API format.
pub struct AnthropicCompatibleProvider {
    base: ProviderBase,
    /// Pre-computed messages endpoint URL (avoids format! on every request).
    messages_url: String,
}

impl AnthropicCompatibleProvider {
    /// Creates a provider with default headers from the given parameters.
    pub fn new(params: super::ProviderParams) -> Self {
        Self::with_headers(params, Vec::new())
    }

    /// Creates a provider with custom HTTP headers added to every request.
    pub fn with_headers(
        params: super::ProviderParams,
        custom_headers: Vec<(String, String)>,
    ) -> Self {
        let base = ProviderBase::new(params, custom_headers);
        let messages_url = format!("{}/v1/messages", base.base_url);
        Self { base, messages_url }
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
    fn build_anthropic_request(
        &self,
        url: &str,
        auth_value: &str,
        client_beta: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut req_builder = self
            .base
            .client
            .post(url)
            .header("anthropic-version", ANTHROPIC_API_VERSION)
            .header("Content-Type", "application/json")
            .header("anthropic-beta", merge_beta_features(client_beta));

        if self.base.is_oauth() {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", auth_value));
        } else {
            req_builder = req_builder.header("x-api-key", auth_value);
        }

        self.base.apply_headers(req_builder)
    }

    /// Send an HTTP request and check for error status, returning the response.
    /// Shared between streaming and non-streaming paths.
    async fn send_and_check(
        &self,
        url: &str,
        auth_value: &str,
        request: &CanonicalRequest,
    ) -> Result<reqwest::Response, ProviderError> {
        let response = self
            .build_anthropic_request(url, auth_value, request.extensions.client_beta.as_deref())
            .timeout(self.base.api_timeout)
            .json(request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            if status == 401 && self.base.is_oauth() {
                // A 401 can mean two things:
                //   1. `rate_limit_error` — transient, provider loop will retry.
                //   2. `authentication_error` — terminal, OAuth token revoked.
                // Only invalidate the token for case (2) to avoid triggering
                // reauth loops on rate-limit spikes.
                let lower = error_text.to_ascii_lowercase();
                let is_auth_error =
                    !(lower.contains("rate_limit_error") || lower.contains("\"rate_limit\""));
                if is_auth_error {
                    if let (Some(provider_id), Some(store)) = (
                        self.base.oauth_provider.as_deref(),
                        self.base.token_store.as_ref(),
                    ) {
                        tracing::error!(
                            provider = %provider_id,
                            "OAuth token for provider {} revoked. Run: grob connect --force-reauth",
                            provider_id
                        );
                        if let Err(e) = store.mark_needs_reauth(provider_id) {
                            tracing::warn!(
                                provider = %provider_id,
                                error = %e,
                                "Failed to mark token as needs_reauth"
                            );
                        }
                    } else {
                        tracing::error!(
                            "OAuth 401 but no oauth_provider/token_store attached to base"
                        );
                    }
                } else {
                    tracing::warn!(
                        "🔄 Received 401 with rate_limit payload, treating as transient"
                    );
                }
            }

            return Err(ProviderError::ApiError {
                status,
                message: format!("{} API error: {}", self.base.name, error_text),
            });
        }

        Ok(response)
    }

    async fn try_send_message(
        &self,
        url: &str,
        auth_value: &str,
        request: &CanonicalRequest,
    ) -> Result<ProviderResponse, ProviderError> {
        let response = self.send_and_check(url, auth_value, request).await?;

        // Log rate limit headers from non-streaming responses
        let is_anthropic = self.base.base_url.contains(ANTHROPIC_DOMAIN);
        if is_anthropic {
            let fwd_headers = extract_forward_headers(response.headers());
            log_rate_limits(&fwd_headers, &self.base.name);
        }

        let response_text = response.text().await?;
        tracing::debug!(
            "{} provider response received ({} bytes)",
            self.base.name,
            response_text.len()
        );

        let provider_response: ProviderResponse =
            serde_json::from_str(&response_text).map_err(|e| {
                tracing::error!("Failed to parse {} response: {}", self.base.name, e);
                tracing::error!("Response body was: {}", response_text);
                e
            })?;

        Ok(provider_response)
    }

    async fn try_send_stream_request(
        &self,
        url: &str,
        auth_value: &str,
        request: &CanonicalRequest,
    ) -> Result<reqwest::Response, ProviderError> {
        self.send_and_check(url, auth_value, request).await
    }

    /// Common setup for both send_message and send_message_stream:
    /// builds URL, sanitizes request for Anthropic backends, resolves auth.
    ///
    /// Returns a tuple of `(messages_url, auth_value, is_anthropic, id_map)`.
    /// The `id_map` carries any rewrites applied by `sanitize_tool_use_ids`
    /// so callers can restore the originals on the response.
    async fn prepare_anthropic_request(
        &self,
        request: &mut CanonicalRequest,
    ) -> Result<(&str, String, bool, OriginalToolIdMap), ProviderError> {
        let is_anthropic = self.base.base_url.contains(ANTHROPIC_DOMAIN);
        let mut id_map = OriginalToolIdMap::new();
        if is_anthropic {
            sanitize_tool_use_ids(request, &mut id_map);
            strip_non_anthropic_thinking(request);
        }
        let auth_value = self.base.resolve_auth(OAuthConfig::anthropic).await?;
        Ok((&self.messages_url, auth_value, is_anthropic, id_map))
    }
}

#[async_trait]
impl LlmProvider for AnthropicCompatibleProvider {
    async fn send_message(
        &self,
        request: CanonicalRequest,
    ) -> Result<ProviderResponse, ProviderError> {
        let mut request = request;
        let (url, auth_value, is_anthropic, id_map) =
            self.prepare_anthropic_request(&mut request).await?;

        let mut result = self.try_send_message(url, &auth_value, &request).await;

        // Fallback: if signature error, strip all signed thinking blocks and retry
        if is_anthropic {
            if let Err(ProviderError::ApiError { message, .. }) = &result {
                if message.contains("signature") {
                    tracing::warn!("🔄 Signature error from Anthropic: {}, stripping all signed thinking blocks and retrying", message);
                    strip_all_thinking_signatures(&mut request);
                    result = self.try_send_message(url, &auth_value, &request).await;
                }
            }
        }

        // Restore original tool IDs so downstream clients can map response IDs
        // back to the IDs they sent (audit Bug #2). No-op when sanitization
        // didn't rewrite anything.
        if let Ok(ref mut response) = result {
            restore_original_tool_ids(response, &id_map);
        }

        result
    }

    async fn count_tokens(
        &self,
        request: CountTokensRequest,
    ) -> Result<CountTokensResponse, ProviderError> {
        // For Anthropic native, use their count_tokens endpoint
        if self.base.name == "anthropic" {
            let url = format!("{}/v1/messages/count_tokens", self.base.base_url);
            let auth_value = self.base.resolve_auth(OAuthConfig::anthropic).await?;

            let response = self
                .build_anthropic_request(&url, &auth_value, None)
                .timeout(self.base.api_timeout)
                .json(&request)
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status().as_u16();
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| format!("{}: failed to read error body", self.base.name));
                return Err(ProviderError::ApiError {
                    status,
                    message: format!("{} count_tokens error: {}", self.base.name, error_text),
                });
            }

            let count_response: CountTokensResponse = response.json().await?;
            return Ok(count_response);
        }

        Ok(super::helpers::estimate_token_count(&request))
    }

    async fn send_message_stream(
        &self,
        request: CanonicalRequest,
    ) -> Result<StreamResponse, ProviderError> {
        use futures::stream::TryStreamExt;

        let mut request = request;
        let (url, auth_value, is_anthropic, id_map) =
            self.prepare_anthropic_request(&mut request).await?;
        // NOTE: Streaming responses pass through unchanged; tool ID
        // restoration on streamed `content_block_start` events would require
        // SSE event rewriting and is intentionally out of scope for the
        // initial Bug #2 fix. The non-streaming path covers the common case
        // (single response per call). Future work: see TODO at restore call
        // site below.
        // TODO: implement SSE-time ID rewrite using `id_map` for streaming.
        let _ = id_map;

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
            log_rate_limits(&fwd, &self.base.name);
            fwd
        } else {
            HashMap::new()
        };

        // Wrap stream with logging to capture cache statistics
        use crate::providers::streaming::LoggingSseStream;
        let byte_stream = response.bytes_stream().map_err(ProviderError::HttpError);
        let logging_stream =
            LoggingSseStream::new(byte_stream, self.base.name.clone(), request.model.clone());

        // Return stream with headers for forwarding
        Ok(StreamResponse {
            stream: Box::pin(logging_stream),
            headers,
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
