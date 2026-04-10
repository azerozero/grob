//! LLM provider trait and implementations (Anthropic, OpenAI, Gemini, etc.).

/// Anthropic-compatible provider implementation for native Anthropic API.
pub mod anthropic_compatible;
mod anthropic_sanitize;
/// Authentication helpers for provider API key and OAuth resolution.
pub mod auth;
pub(crate) mod base;
/// Shared constants (timeouts, header names, default URLs).
pub mod constants;
/// Provider error types and conversions.
pub mod error;
/// Google Gemini provider implementation.
pub mod gemini;
/// Shared helper functions for request/response transformation.
pub mod helpers;
/// Multi-account API key pooling for provider key rotation.
pub mod key_pool;
/// OpenAI provider implementation with format translation.
pub mod openai;
/// Provider registry for model lookup and provider resolution.
pub mod registry;
/// SSE streaming utilities shared across providers.
pub mod streaming;

use crate::auth::TokenStore;
use crate::models::{
    CanonicalRequest, ContentBlock, CountTokensRequest, CountTokensResponse, KnownContentBlock,
};
use async_trait::async_trait;
use bytes::Bytes;
use error::ProviderError;
use futures::stream::Stream;
use reqwest::Client;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

/// Provider response that maintains Anthropic API compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderResponse {
    /// Unique identifier for the response message.
    pub id: String,
    /// Object type, always `"message"` for Anthropic-compatible responses.
    pub r#type: String,
    /// Role of the responder, typically `"assistant"`.
    pub role: String,
    /// Ordered list of content blocks in the response.
    pub content: Vec<ContentBlock>,
    /// Model identifier that generated the response.
    pub model: String,
    /// Reason the model stopped generating (e.g., `"end_turn"`, `"max_tokens"`).
    pub stop_reason: Option<String>,
    /// Custom stop sequence that triggered generation to halt, if any.
    pub stop_sequence: Option<String>,
    /// Token usage statistics for the request/response cycle.
    pub usage: Usage,
}

/// Tracks input and output token counts for a provider response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// Number of tokens in the input prompt.
    pub input_tokens: u32,
    /// Number of tokens generated in the output.
    pub output_tokens: u32,
    /// Tokens written to the prompt cache on this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u32>,
    /// Tokens read from the prompt cache on this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_input_tokens: Option<u32>,
}

/// Response from streaming request, includes headers for passthrough
pub struct StreamResponse {
    /// The byte stream (SSE format)
    pub stream: Pin<Box<dyn Stream<Item = Result<Bytes, ProviderError>> + Send>>,
    /// Headers to forward (e.g., Anthropic rate limit headers)
    pub headers: HashMap<String, String>,
}

/// Build an optimized reqwest::Client for provider API calls.
///
/// Applies: TCP_NODELAY (disable Nagle), connect timeout (fail-fast),
/// connection pooling, and HTTP/2 adaptive flow control.
/// When `identity` or `ca` are provided, configures mTLS client
/// certificate authentication and/or custom CA trust.
pub fn build_provider_client(
    connect_timeout: Duration,
    identity: Option<reqwest::Identity>,
    ca: Option<reqwest::Certificate>,
) -> Client {
    let mut builder = Client::builder()
        .tcp_nodelay(true)
        .connect_timeout(connect_timeout)
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(Duration::from_secs(90))
        .http2_adaptive_window(true);

    if let Some(id) = identity {
        builder = builder.identity(id);
    }
    if let Some(cert) = ca {
        builder = builder.add_root_certificate(cert);
    }

    builder.build().unwrap_or_else(|e| {
        tracing::warn!("Provider client build failed, using defaults: {}", e);
        Client::new()
    })
}

/// Logs a warning if a provider base URL uses plaintext HTTP for a non-localhost endpoint.
pub fn warn_if_cleartext(url: &str, provider_name: &str) {
    if url.starts_with("http://")
        && !url.contains("://localhost")
        && !url.contains("://127.0.0.1")
        && !url.contains("://[::1]")
    {
        tracing::warn!(
            "Provider '{}' uses plaintext HTTP: {}. Consider HTTPS for non-local endpoints.",
            provider_name,
            url
        );
    }
}

/// Core provider trait -- all LLM backends implement this.
///
/// Maintains Anthropic Messages API compatibility as the canonical
/// internal format. Non-Anthropic providers translate to/from their
/// native formats in their implementations.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Sends a non-streaming message request to the provider.
    async fn send_message(
        &self,
        request: CanonicalRequest,
    ) -> Result<ProviderResponse, ProviderError>;

    /// Sends a streaming message request, returning an SSE byte stream and headers.
    async fn send_message_stream(
        &self,
        request: CanonicalRequest,
    ) -> Result<StreamResponse, ProviderError>;

    /// Counts tokens for a request (provider-specific or character heuristic).
    async fn count_tokens(
        &self,
        request: CountTokensRequest,
    ) -> Result<CountTokensResponse, ProviderError>;

    /// Returns `true` if this provider serves the given model name.
    fn supports_model(&self, model: &str) -> bool;

    /// Return the provider's base URL for connection warmup.
    /// Override to enable pre-warming TLS connections on startup.
    fn base_url(&self) -> Option<&str> {
        None
    }

    /// Attempts to rotate to the next API key in the pool after a rate-limit error.
    ///
    /// Returns `true` if rotation succeeded (more keys available), `false` if
    /// no key pool is configured or all keys are exhausted.
    fn rotate_key_pool(&self) -> bool {
        false
    }
}

/// Common parameters shared across all provider constructors.
pub struct ProviderParams {
    /// Human-readable provider name from configuration.
    pub name: String,
    /// API key for authenticating requests (wrapped to prevent accidental logging).
    pub api_key: SecretString,
    /// Custom base URL override for the provider endpoint.
    pub base_url: Option<String>,
    /// List of model identifiers this provider serves.
    pub models: Vec<String>,
    /// OAuth provider ID for token-based authentication.
    pub oauth_provider: Option<String>,
    /// Shared token store for OAuth credential retrieval.
    pub token_store: Option<TokenStore>,
    /// Maximum duration to wait for a complete API response.
    pub api_timeout: Duration,
    /// Maximum duration to wait for TCP connection establishment.
    pub connect_timeout: Duration,
    /// Accepts any model name not listed in configured models.
    pub pass_through: bool,
    /// Pre-loaded mTLS client identity (cert + key) for upstream connections.
    pub tls_identity: Option<reqwest::Identity>,
    /// Pre-loaded custom CA certificate for upstream server verification.
    pub tls_ca: Option<reqwest::Certificate>,
    /// Optional multi-account key pool for API key rotation.
    pub key_pool: Option<std::sync::Arc<key_pool::KeyPool>>,
}

// Re-export config types that were moved to cli::config to break the
// cli <-> providers dependency cycle. Downstream code using
// `crate::providers::{AuthType, ProviderConfig}` keeps compiling.
pub use crate::cli::{AuthType, ProviderConfig};

pub use anthropic_compatible::AnthropicCompatibleProvider;
pub use openai::OpenAIProvider;
pub use registry::ProviderRegistry;

// ── Test mocks ───────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-util"))]
pub mod mocks {
    use super::*;
    use futures::stream;

    /// Mock LLM provider that returns a fixed response without making network calls.
    ///
    /// Suitable for unit tests and integration harness tests that need a controllable
    /// provider without a live API endpoint.
    pub struct MockLlmProvider {
        /// Fixed response body returned by `send_message`.
        pub response: ProviderResponse,
        /// Model name reported by `supports_model`.
        pub model: String,
    }

    impl MockLlmProvider {
        /// Creates a provider that always returns a simple text response.
        pub fn text(model: impl Into<String>, content: impl Into<String>) -> Self {
            let model = model.into();
            let text = content.into();
            Self {
                response: ProviderResponse {
                    id: "mock-resp-1".to_string(),
                    r#type: "message".to_string(),
                    role: "assistant".to_string(),
                    model: model.clone(),
                    content: vec![crate::models::ContentBlock::Known(
                        crate::models::KnownContentBlock::Text {
                            text,
                            cache_control: None,
                        },
                    )],
                    usage: Usage {
                        input_tokens: 10,
                        output_tokens: 5,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    },
                    stop_reason: Some("end_turn".to_string()),
                    stop_sequence: None,
                },
                model,
            }
        }
    }

    #[async_trait::async_trait]
    impl LlmProvider for MockLlmProvider {
        async fn send_message(
            &self,
            _request: CanonicalRequest,
        ) -> Result<ProviderResponse, ProviderError> {
            Ok(self.response.clone())
        }

        async fn send_message_stream(
            &self,
            _request: CanonicalRequest,
        ) -> Result<StreamResponse, ProviderError> {
            // Emit a single text_delta chunk followed by message_stop.
            let text = self
                .response
                .content
                .iter()
                .find_map(|b| {
                    if let crate::models::ContentBlock::Known(
                        crate::models::KnownContentBlock::Text { text, .. },
                    ) = b
                    {
                        Some(text.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            let chunk = bytes::Bytes::from(format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{text}\"}}}}\n\n"
            ));
            let stop =
                bytes::Bytes::from("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
            let items: Vec<Result<bytes::Bytes, ProviderError>> = vec![Ok(chunk), Ok(stop)];
            Ok(StreamResponse {
                stream: Box::pin(stream::iter(items)),
                headers: Default::default(),
            })
        }

        async fn count_tokens(
            &self,
            _request: CountTokensRequest,
        ) -> Result<CountTokensResponse, ProviderError> {
            Ok(CountTokensResponse { input_tokens: 10 })
        }

        fn supports_model(&self, model: &str) -> bool {
            model == self.model
        }
    }
}
