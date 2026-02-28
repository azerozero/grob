pub mod anthropic_compatible;
pub mod auth;
pub mod constants;
pub mod error;
pub mod gemini;
pub mod helpers;
pub mod openai;
pub mod registry;
pub mod streaming;

use crate::auth::TokenStore;
use crate::models::{
    AnthropicRequest, ContentBlock, CountTokensRequest, CountTokensResponse, KnownContentBlock,
};
use async_trait::async_trait;
use bytes::Bytes;
use error::ProviderError;
use futures::stream::Stream;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

/// Provider response that maintains Anthropic API compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderResponse {
    pub id: String,
    pub r#type: String,
    pub role: String,
    pub content: Vec<ContentBlock>,
    pub model: String,
    pub stop_reason: Option<String>,
    pub stop_sequence: Option<String>,
    pub usage: Usage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u32>,
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
pub fn build_provider_client(connect_timeout: Duration) -> Client {
    Client::builder()
        .tcp_nodelay(true)
        .connect_timeout(connect_timeout)
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(Duration::from_secs(90))
        .http2_adaptive_window(true)
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// Main provider trait - all providers must implement this
/// Maintains Anthropic Messages API compatibility
#[async_trait]
pub trait AnthropicProvider: Send + Sync {
    /// Send a message request to the provider
    /// Must transform to/from Anthropic format as needed
    async fn send_message(
        &self,
        request: AnthropicRequest,
    ) -> Result<ProviderResponse, ProviderError>;

    /// Send a streaming message request to the provider
    /// Returns a stream of raw bytes (SSE format) along with headers to forward
    async fn send_message_stream(
        &self,
        request: AnthropicRequest,
    ) -> Result<StreamResponse, ProviderError>;

    /// Count tokens for a request
    /// Provider-specific implementation (tiktoken for OpenAI, etc.)
    async fn count_tokens(
        &self,
        request: CountTokensRequest,
    ) -> Result<CountTokensResponse, ProviderError>;

    /// Check if provider supports a specific model
    fn supports_model(&self, model: &str) -> bool;

    /// Return the provider's base URL for connection warmup.
    /// Override to enable pre-warming TLS connections on startup.
    fn base_url(&self) -> Option<&str> {
        None
    }
}

/// Common parameters shared across all provider constructors.
pub struct ProviderParams {
    pub name: String,
    pub api_key: String,
    pub base_url: Option<String>,
    pub models: Vec<String>,
    pub oauth_provider: Option<String>,
    pub token_store: Option<TokenStore>,
    pub api_timeout: Duration,
    pub connect_timeout: Duration,
}

/// Authentication type for providers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum AuthType {
    /// API key authentication
    #[default]
    ApiKey,
    /// OAuth 2.0 authentication
    OAuth,
}

/// Provider configuration from TOML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub name: String,
    pub provider_type: String,

    /// Authentication type (default: api_key)
    #[serde(default)]
    pub auth_type: AuthType,

    /// API key (required for auth_type = "apikey")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// OAuth provider ID (required for auth_type = "oauth")
    /// References a token stored in TokenStore
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_provider: Option<String>,

    /// Google Cloud Project ID (for Vertex AI provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,

    /// Location/Region (for Vertex AI provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    pub base_url: Option<String>,

    /// Custom HTTP headers (e.g., {"X-Novita-Source": "grob"})
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    pub models: Vec<String>,
    pub enabled: Option<bool>,

    /// Per-provider monthly budget in USD (optional, overrides global)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_usd: Option<f64>,

    /// Provider region for GDPR filtering (e.g., "eu", "us", "global")
    /// None defaults to "global" (no restriction)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

impl ProviderConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

pub use anthropic_compatible::AnthropicCompatibleProvider;
pub use openai::OpenAIProvider;
pub use registry::ProviderRegistry;
