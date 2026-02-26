use super::gemini::GeminiProvider;
use super::{
    error::ProviderError, AnthropicCompatibleProvider, AnthropicProvider, OpenAIProvider,
    ProviderConfig,
};
use crate::auth::TokenStore;
use crate::cli::ModelConfig;
use std::collections::HashMap;
use std::sync::Arc;

/// Default base URL for OpenAI-compatible API
const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";

/// GitHub repository URL (used in HTTP-Referer headers)
const REPO_URL: &str = "https://github.com/azerozero/grob";

/// Provider registry that manages all configured providers
pub struct ProviderRegistry {
    /// Map of provider name -> provider instance
    providers: HashMap<String, Arc<dyn AnthropicProvider>>,
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

    /// Load providers from configuration with model mappings
    pub fn from_configs_with_models(
        configs: &[ProviderConfig],
        token_store: Option<TokenStore>,
        models: &[ModelConfig],
    ) -> Result<Self, ProviderError> {
        let mut registry = Self::new();

        for config in configs {
            // Skip disabled providers
            if !config.is_enabled() {
                continue;
            }

            // Get API key - required for API key auth, skipped for OAuth
            let api_key = match &config.auth_type {
                super::AuthType::ApiKey => config.api_key.clone().ok_or_else(|| {
                    ProviderError::ConfigError(format!(
                        "Provider '{}' requires api_key for ApiKey auth",
                        config.name
                    ))
                })?,
                super::AuthType::OAuth => {
                    // OAuth providers will handle authentication differently
                    // For now, use a placeholder - will be replaced with token
                    config
                        .oauth_provider
                        .clone()
                        .unwrap_or_else(|| config.name.clone())
                }
            };

            // Create provider instance based on type
            let provider: Box<dyn AnthropicProvider> = match config.provider_type.as_str() {
                // OpenAI-compatible providers (unified with custom headers support)
                "openai" => {
                    let base_url = config
                        .base_url
                        .clone()
                        .unwrap_or_else(|| DEFAULT_OPENAI_BASE_URL.to_string());
                    let custom_headers: Vec<(String, String)> = config
                        .headers
                        .clone()
                        .unwrap_or_default()
                        .into_iter()
                        .collect();

                    Box::new(OpenAIProvider::with_headers(
                        config.name.clone(),
                        api_key,
                        base_url,
                        config.models.clone(),
                        custom_headers,
                        config.oauth_provider.clone(),
                        token_store.clone(),
                    ))
                }

                // OpenRouter (OpenAI-compatible)
                // Note: OpenRouter's Anthropic-compatible endpoint only supports Claude models,
                // so we use the OpenAI endpoint to support all models (Kimi, DeepSeek, etc.)
                "openrouter" => Box::new(OpenAIProvider::with_headers(
                    config.name.clone(),
                    api_key,
                    config
                        .base_url
                        .clone()
                        .unwrap_or_else(|| "https://openrouter.ai/api/v1".to_string()),
                    config.models.clone(),
                    vec![
                        ("HTTP-Referer".to_string(), REPO_URL.to_string()),
                        ("X-Title".to_string(), "Claude Code Mux".to_string()),
                    ],
                    config.oauth_provider.clone(),
                    token_store.clone(),
                )),

                // Anthropic-compatible providers
                "anthropic" => Box::new(AnthropicCompatibleProvider::new(
                    config.name.clone(),
                    api_key,
                    config
                        .base_url
                        .clone()
                        .unwrap_or_else(|| "https://api.anthropic.com".to_string()),
                    config.models.clone(),
                    config.oauth_provider.clone(),
                    token_store.clone(),
                )),
                "z.ai" => Box::new(AnthropicCompatibleProvider::zai(
                    api_key,
                    config.models.clone(),
                    token_store.clone(),
                )),
                "minimax" => Box::new(AnthropicCompatibleProvider::minimax(
                    api_key,
                    config.models.clone(),
                    token_store.clone(),
                )),
                "zenmux" => Box::new(AnthropicCompatibleProvider::zenmux(
                    api_key,
                    config.models.clone(),
                    token_store.clone(),
                )),
                "kimi-coding" => Box::new(AnthropicCompatibleProvider::kimi_coding(
                    api_key,
                    config.models.clone(),
                    token_store.clone(),
                )),

                // Google Gemini (supports OAuth, API Key, Vertex AI)
                "gemini" => {
                    let api_key_opt = if config.auth_type == super::AuthType::ApiKey {
                        Some(api_key.clone())
                    } else {
                        None
                    };

                    Box::new(GeminiProvider::new(
                        config.name.clone(),
                        api_key_opt,
                        config.base_url.clone(),
                        config.models.clone(),
                        HashMap::new(), // custom headers
                        config.oauth_provider.clone(),
                        token_store.clone(),
                        None, // No project_id/location for Gemini (AI Studio/OAuth only)
                        None,
                    ))
                }

                "vertex-ai" => {
                    // Vertex AI provider (separate from Gemini)
                    // Uses Google Cloud Vertex AI with ADC authentication
                    Box::new(GeminiProvider::new(
                        config.name.clone(),
                        None, // No API key for Vertex AI (uses ADC)
                        config.base_url.clone(),
                        config.models.clone(),
                        HashMap::new(), // custom headers
                        None,           // No OAuth for Vertex AI
                        token_store.clone(),
                        config.project_id.clone(), // GCP project ID
                        config.location.clone(),   // GCP location
                    ))
                }

                other => {
                    return Err(ProviderError::ConfigError(format!(
                        "Unknown provider type: {}",
                        other
                    )));
                }
            };

            // NOTE: models field in provider config is deprecated
            // Model mappings are now defined in [[models]] section
            // We only register the provider by name

            // Add provider to registry
            registry
                .providers
                .insert(config.name.clone(), Arc::from(provider));
        }

        // Populate model_to_provider mappings from model configurations
        for model in models {
            // Map each model name to its first (highest priority) provider
            if let Some(first_mapping) = model.mappings.first() {
                registry
                    .model_to_provider
                    .insert(model.name.clone(), first_mapping.provider.clone());
            }
        }

        Ok(registry)
    }

    /// Get a provider by name
    pub fn get_provider(&self, name: &str) -> Option<Arc<dyn AnthropicProvider>> {
        self.providers.get(name).cloned()
    }

    /// Get a provider for a specific model
    pub fn get_provider_for_model(
        &self,
        model: &str,
    ) -> Result<Arc<dyn AnthropicProvider>, ProviderError> {
        // First, check if we have a direct model → provider mapping
        if let Some(provider_name) = self.model_to_provider.get(model) {
            if let Some(provider) = self.providers.get(provider_name) {
                return Ok(provider.clone());
            }
        }

        // If no direct mapping, search through all providers
        for provider in self.providers.values() {
            if provider.supports_model(model) {
                return Ok(provider.clone());
            }
        }

        Err(ProviderError::ModelNotSupported(model.to_string()))
    }

    /// List all available models
    pub fn list_models(&self) -> Vec<String> {
        self.model_to_provider.keys().cloned().collect()
    }

    /// List all providers
    pub fn list_providers(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
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
    fn test_get_provider_for_model_not_found() {
        let registry = ProviderRegistry::new();
        let result = registry.get_provider_for_model("gpt-4");
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
                api_key: Some("test-key-1".to_string()),
                base_url: None,
                models: vec![],
                enabled: Some(true),
                oauth_provider: None,
                project_id: None,
                location: None,
                headers: None,
                budget_usd: None,
                region: None,
            },
            ProviderConfig {
                name: "provider-b".to_string(),
                provider_type: "anthropic".to_string(),
                auth_type: AuthType::ApiKey,
                api_key: Some("test-key-2".to_string()),
                base_url: None,
                models: vec![],
                enabled: Some(true),
                oauth_provider: None,
                project_id: None,
                location: None,
                headers: None,
                budget_usd: None,
                region: None,
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
            &providers, None, // token_store
            &models,
        )
        .unwrap();

        assert_eq!(registry.list_models().len(), 2);
        assert!(registry.list_models().contains(&"model-1".to_string()));
        assert!(registry.list_models().contains(&"model-2".to_string()));
        assert_eq!(registry.list_providers().len(), 2);
    }
}
