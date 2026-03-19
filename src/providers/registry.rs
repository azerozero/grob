use super::gemini::GeminiProvider;
use super::{
    error::ProviderError, AnthropicCompatibleProvider, LlmProvider, OpenAIProvider, ProviderConfig,
    ProviderParams,
};
use crate::auth::TokenStore;
use crate::cli::{ModelConfig, TimeoutConfig};
use secrecy::SecretString;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Default base URL for OpenAI-compatible API
const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";

/// GitHub repository URL (used in HTTP-Referer headers)
const REPO_URL: &str = "https://github.com/azerozero/grob";

/// Shared context for building providers (timeout + auth settings).
struct ProviderBuildContext {
    token_store: Option<TokenStore>,
    api_timeout: Duration,
    connect_timeout: Duration,
}

/// Provider registry that manages all configured providers
pub struct ProviderRegistry {
    /// Map of provider name -> provider instance
    providers: HashMap<String, Arc<dyn LlmProvider>>,
    /// Map of model name -> provider name for fast lookup
    model_to_provider: HashMap<String, String>,
}

impl ProviderRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            model_to_provider: HashMap::new(),
        }
    }

    /// Build standard ProviderParams from a config entry.
    ///
    /// When `GROB_MOCK_BACKEND` is set, overrides the base URL so all
    /// providers route traffic to the harness mock backend.
    fn build_params(
        config: &ProviderConfig,
        api_key: SecretString,
        default_base_url: &str,
        build_ctx: &ProviderBuildContext,
    ) -> ProviderParams {
        let base_url = if let Ok(mock_url) = std::env::var("GROB_MOCK_BACKEND") {
            mock_url
        } else {
            config
                .base_url
                .clone()
                .unwrap_or_else(|| default_base_url.to_string())
        };

        // Load mTLS identity (cert + key) if both paths are configured.
        let tls_identity = match (&config.tls_cert, &config.tls_key) {
            (Some(cert_path), Some(key_path)) => {
                let cert_pem = std::fs::read(cert_path).unwrap_or_else(|e| {
                    tracing::warn!("Failed to read TLS cert '{}': {}", cert_path, e);
                    Vec::new()
                });
                let key_pem = std::fs::read(key_path).unwrap_or_else(|e| {
                    tracing::warn!("Failed to read TLS key '{}': {}", key_path, e);
                    Vec::new()
                });
                if cert_pem.is_empty() || key_pem.is_empty() {
                    None
                } else {
                    let mut combined = cert_pem;
                    combined.extend_from_slice(&key_pem);
                    match reqwest::Identity::from_pem(&combined) {
                        Ok(id) => Some(id),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to load mTLS identity for '{}': {}",
                                config.name,
                                e
                            );
                            None
                        }
                    }
                }
            }
            _ => None,
        };

        // Load custom CA certificate if configured.
        let tls_ca = config
            .tls_ca
            .as_ref()
            .and_then(|ca_path| match std::fs::read(ca_path) {
                Ok(ca_pem) => match reqwest::Certificate::from_pem(&ca_pem) {
                    Ok(cert) => Some(cert),
                    Err(e) => {
                        tracing::warn!("Failed to parse CA cert for '{}': {}", config.name, e);
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read CA cert '{}': {}", ca_path, e);
                    None
                }
            });

        ProviderParams {
            name: config.name.clone(),
            api_key,
            base_url: Some(base_url),
            models: config.models.clone(),
            oauth_provider: config.oauth_provider.clone(),
            token_store: build_ctx.token_store.clone(),
            api_timeout: build_ctx.api_timeout,
            connect_timeout: build_ctx.connect_timeout,
            pass_through: config.pass_through.unwrap_or(false),
            tls_identity,
            tls_ca,
        }
    }

    /// Resolve the API key from a provider config.
    fn resolve_api_key(config: &ProviderConfig) -> Result<SecretString, ProviderError> {
        match &config.auth_type {
            super::AuthType::ApiKey => config.api_key.clone().ok_or_else(|| {
                ProviderError::ConfigError(format!(
                    "Provider '{}' requires api_key for ApiKey auth",
                    config.name
                ))
            }),
            super::AuthType::OAuth => Ok(SecretString::new(
                config
                    .oauth_provider
                    .clone()
                    .unwrap_or_else(|| config.name.clone()),
            )),
        }
    }

    /// Create a provider instance based on provider type.
    fn create_provider(
        config: &ProviderConfig,
        api_key: SecretString,
        build_ctx: &ProviderBuildContext,
    ) -> Result<Box<dyn LlmProvider>, ProviderError> {
        match config.provider_type.as_str() {
            "openai" => {
                let headers: Vec<(String, String)> = config
                    .headers
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let params =
                    Self::build_params(config, api_key, DEFAULT_OPENAI_BASE_URL, build_ctx);
                Ok(Box::new(OpenAIProvider::with_headers(params, headers)))
            }

            "openrouter" => {
                let params =
                    Self::build_params(config, api_key, "https://openrouter.ai/api/v1", build_ctx);
                Ok(Box::new(OpenAIProvider::with_headers(
                    params,
                    vec![
                        ("HTTP-Referer".to_string(), REPO_URL.to_string()),
                        ("X-Title".to_string(), "Claude Code Mux".to_string()),
                    ],
                )))
            }

            "anthropic" => {
                let params =
                    Self::build_params(config, api_key, "https://api.anthropic.com", build_ctx);
                Ok(Box::new(AnthropicCompatibleProvider::new(params)))
            }

            "z.ai" | "minimax" | "zenmux" | "kimi-coding" => {
                let base_url = match config.provider_type.as_str() {
                    "z.ai" => "https://api.z.ai/api/anthropic",
                    "minimax" => "https://api.minimax.io/anthropic",
                    "zenmux" => "https://zenmux.ai/api/anthropic",
                    "kimi-coding" => "https://api.kimi.com/coding",
                    _ => unreachable!(),
                };
                let params = Self::build_params(config, api_key, base_url, build_ctx);
                Ok(Box::new(AnthropicCompatibleProvider::named(
                    &config.provider_type,
                    base_url,
                    params,
                )))
            }

            "gemini" => {
                let gemini_api_key = if config.auth_type == super::AuthType::ApiKey {
                    api_key
                } else {
                    SecretString::new(String::new())
                };
                let mut params = Self::build_params(config, gemini_api_key, "", build_ctx);
                // build_params sets base_url to Some("") — override with config's value
                params.base_url = config.base_url.clone();
                Ok(Box::new(GeminiProvider::new(
                    params,
                    HashMap::new(),
                    None,
                    None,
                )))
            }

            "vertex-ai" => {
                let mut params =
                    Self::build_params(config, SecretString::new(String::new()), "", build_ctx);
                params.base_url = config.base_url.clone();
                params.oauth_provider = None;
                Ok(Box::new(GeminiProvider::new(
                    params,
                    HashMap::new(),
                    config.project_id.clone(),
                    config.location.clone(),
                )))
            }

            other => Err(ProviderError::ConfigError(format!(
                "Unknown provider type: {}",
                other
            ))),
        }
    }

    /// Load providers from configuration with model mappings
    pub fn from_configs_with_models(
        configs: &[ProviderConfig],
        token_store: Option<TokenStore>,
        models: &[ModelConfig],
        timeouts: &TimeoutConfig,
    ) -> Result<Self, ProviderError> {
        let mut registry = Self::new();
        let build_ctx = ProviderBuildContext {
            token_store,
            api_timeout: Duration::from_millis(timeouts.api_timeout_ms),
            connect_timeout: Duration::from_millis(timeouts.connect_timeout_ms),
        };

        for config in configs {
            if !config.is_enabled() {
                continue;
            }

            let api_key = Self::resolve_api_key(config)?;
            let provider = Self::create_provider(config, api_key, &build_ctx)?;

            registry
                .providers
                .insert(config.name.clone(), Arc::from(provider));
        }

        for model in models {
            if let Some(first_mapping) = model.mappings.first() {
                registry
                    .model_to_provider
                    .insert(model.name.clone(), first_mapping.provider.clone());
            }
        }

        Ok(registry)
    }

    /// Get a provider by name
    pub fn provider(&self, name: &str) -> Option<Arc<dyn LlmProvider>> {
        self.providers.get(name).cloned()
    }

    /// Get a provider for a specific model
    pub fn provider_for_model(&self, model: &str) -> Result<Arc<dyn LlmProvider>, ProviderError> {
        // First, check if we have a direct model → provider mapping
        if let Some(provider_name) = self.model_to_provider.get(model) {
            if let Some(provider) = self.providers.get(provider_name) {
                return Ok(provider.clone());
            }
        }

        // If no direct mapping, search through all providers
        self.providers
            .values()
            .find(|p| p.supports_model(model))
            .cloned()
            .ok_or_else(|| ProviderError::ModelNotSupported(model.to_string()))
    }

    /// List all available models
    pub fn list_models(&self) -> Vec<String> {
        self.model_to_provider.keys().cloned().collect()
    }

    /// List all providers
    pub fn list_providers(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }

    /// Pre-warm TLS connections to all providers (fire-and-forget).
    /// Spawns a background task per provider to open a TCP+TLS connection.
    pub fn warmup_connections(self: &Arc<Self>) {
        let warmup_client = super::build_provider_client(Duration::from_secs(5), None, None);

        for (name, provider) in &self.providers {
            if let Some(base_url) = provider.base_url() {
                let url = base_url.to_string();
                let name = name.clone();
                let client = warmup_client.clone();
                tokio::spawn(async move {
                    match client.head(&url).send().await {
                        Ok(_) => tracing::debug!("Warmed up connection to {}", name),
                        Err(e) => {
                            tracing::debug!("Warmup to {} failed (non-fatal): {}", name, e)
                        }
                    }
                });
            }
        }
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_registry() {
        let registry = ProviderRegistry::new();
        assert!(registry.list_models().is_empty());
        assert!(registry.list_providers().is_empty());
    }

    #[test]
    fn test_provider_for_model_not_found() {
        let registry = ProviderRegistry::new();
        let result = registry.provider_for_model("gpt-4");
        assert!(result.is_err());
    }

    #[test]
    fn test_model_counting_with_configs() {
        use crate::providers::{AuthType, ProviderConfig};

        let providers = vec![
            ProviderConfig {
                name: "provider-a".to_string(),
                provider_type: "anthropic".to_string(),
                auth_type: AuthType::ApiKey,
                api_key: Some(SecretString::new("test-key-1".to_string())),
                base_url: None,
                models: vec![],
                enabled: Some(true),
                oauth_provider: None,
                project_id: None,
                location: None,
                headers: None,
                budget_usd: None,
                region: None,
                pass_through: None,
                tls_cert: None,
                tls_key: None,
                tls_ca: None,
            },
            ProviderConfig {
                name: "provider-b".to_string(),
                provider_type: "anthropic".to_string(),
                auth_type: AuthType::ApiKey,
                api_key: Some(SecretString::new("test-key-2".to_string())),
                base_url: None,
                models: vec![],
                enabled: Some(true),
                oauth_provider: None,
                project_id: None,
                location: None,
                headers: None,
                budget_usd: None,
                region: None,
                pass_through: None,
                tls_cert: None,
                tls_key: None,
                tls_ca: None,
            },
        ];

        let models = vec![
            crate::cli::ModelConfig {
                name: "model-1".to_string(),
                mappings: vec![crate::cli::ModelMapping {
                    priority: 1,
                    provider: "provider-a".to_string(),
                    actual_model: "actual-model-1".to_string(),
                    inject_continuation_prompt: false,
                }],
                budget_usd: None,
                strategy: Default::default(),
                fan_out: None,
                deprecated: None,
            },
            crate::cli::ModelConfig {
                name: "model-2".to_string(),
                mappings: vec![crate::cli::ModelMapping {
                    priority: 1,
                    provider: "provider-b".to_string(),
                    actual_model: "actual-model-2".to_string(),
                    inject_continuation_prompt: false,
                }],
                budget_usd: None,
                strategy: Default::default(),
                fan_out: None,
                deprecated: None,
            },
        ];

        // Actually test the method we implemented
        let registry = ProviderRegistry::from_configs_with_models(
            &providers,
            None, // token_store
            &models,
            &TimeoutConfig::default(),
        )
        .unwrap();

        assert_eq!(registry.list_models().len(), 2);
        assert!(registry.list_models().contains(&"model-1".to_string()));
        assert!(registry.list_models().contains(&"model-2".to_string()));
        assert_eq!(registry.list_providers().len(), 2);
    }
}
