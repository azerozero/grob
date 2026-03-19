//! Shared provider fields and helper methods.
//!
//! Eliminates field and method duplication across OpenAI, Gemini,
//! and Anthropic-compatible providers.

use super::{build_provider_client, error::ProviderError, key_pool::KeyPool, ProviderParams};
use crate::auth::{OAuthConfig, TokenStore};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;

/// Common fields shared across all LLM providers.
/// Embed in provider structs to eliminate field and method duplication.
pub(crate) struct ProviderBase {
    pub name: String,
    pub api_key: SecretString,
    pub base_url: String,
    pub client: Client,
    pub models: Vec<String>,
    pub custom_headers: Vec<(String, String)>,
    pub oauth_provider: Option<String>,
    pub token_store: Option<TokenStore>,
    pub api_timeout: Duration,
    pub pass_through: bool,
    pub key_pool: Option<Arc<KeyPool>>,
}

impl ProviderBase {
    /// Creates a ProviderBase from standard constructor parameters.
    pub fn new(params: ProviderParams, custom_headers: Vec<(String, String)>) -> Self {
        let client =
            build_provider_client(params.connect_timeout, params.tls_identity, params.tls_ca);
        Self {
            name: params.name,
            api_key: params.api_key,
            base_url: params.base_url.unwrap_or_default(),
            client,
            models: params.models,
            custom_headers,
            oauth_provider: params.oauth_provider,
            token_store: params.token_store,
            api_timeout: params.api_timeout,
            pass_through: params.pass_through,
            key_pool: params.key_pool,
        }
    }

    /// Returns true if OAuth authentication is configured.
    pub fn is_oauth(&self) -> bool {
        self.oauth_provider.is_some() && self.token_store.is_some()
    }

    /// Checks if the provider supports the given model (case-insensitive).
    pub fn supports_model(&self, model: &str) -> bool {
        self.pass_through || self.models.iter().any(|m| m.eq_ignore_ascii_case(model))
    }

    /// Resolves the auth token: OAuth refresh if configured, key pool if
    /// available, otherwise the primary API key.
    pub async fn resolve_auth(
        &self,
        config_fn: fn() -> OAuthConfig,
    ) -> Result<String, ProviderError> {
        // When a key pool is configured, use its current key instead of the
        // static api_key field. Round-robin pools advance on every call.
        let effective_key: String = if let Some(ref pool) = self.key_pool {
            if *pool.strategy() == crate::cli::PoolStrategy::RoundRobin {
                pool.advance();
            }
            pool.current_key().expose_secret().to_string()
        } else {
            self.api_key.expose_secret().to_string()
        };

        super::auth::resolve_access_token(
            self.oauth_provider.as_deref(),
            self.token_store.as_ref(),
            config_fn,
            &effective_key,
        )
        .await
    }

    /// Appends custom headers to a request builder.
    pub fn apply_headers(&self, mut builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        for (key, value) in &self.custom_headers {
            builder = builder.header(key, value);
        }
        builder
    }
}
