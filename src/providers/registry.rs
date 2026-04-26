use super::gemini::GeminiProvider;
use super::key_pool::KeyPool;
use super::{
    error::ProviderError, AnthropicCompatibleProvider, LlmProvider, OpenAIProvider, ProviderConfig,
    ProviderParams,
};
use crate::auth::TokenStore;
use crate::cli::{ModelConfig, TimeoutConfig};
use crate::routing::{
    CircuitBreaker, CircuitBreakerConfig, EndpointId, HealthCheckConfig, HealthChecker,
    HealthStatus,
};
use dashmap::DashMap;
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
    /// Per-provider circuit breaker template used to lazily mint endpoint breakers.
    ///
    /// Populated from each provider's `[providers.circuit_breaker]` TOML
    /// section. A provider with no section maps to
    /// [`CircuitBreakerConfig::default`] (disabled, Caddy parity).
    cb_templates: HashMap<String, CircuitBreakerConfig>,
    /// Per-endpoint passive circuit breakers (RE-1a, ADR-0018).
    ///
    /// Keyed by `(provider_name, actual_model)`. Entries are created
    /// lazily on the first hit from the provider loop, so configs with
    /// hundreds of models do not allocate hundreds of unused breakers.
    endpoint_breakers: DashMap<EndpointId, Arc<CircuitBreaker>>,
    /// Per-provider active health checkers (RE-1b, ADR-0018).
    ///
    /// Keyed by provider name. Populated eagerly at build time so the
    /// probe starts ticking before the first dispatch lands. Dropping the
    /// registry aborts every spawned probe (see [`HealthChecker::drop`]).
    health_checkers: HashMap<String, Arc<HealthChecker>>,
}

impl ProviderRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            model_to_provider: HashMap::new(),
            cb_templates: HashMap::new(),
            endpoint_breakers: DashMap::new(),
            health_checkers: HashMap::new(),
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

        // Build key pool when pool config is present.
        let key_pool = config.pool.as_ref().map(|pool_cfg| {
            let mut all_keys = vec![api_key.clone()];
            for raw in &pool_cfg.keys {
                let resolved = if let Some(env_var) = raw.strip_prefix('$') {
                    std::env::var(env_var).unwrap_or_else(|_| {
                        tracing::warn!(
                            "Pool key env var ${} not set for provider '{}'",
                            env_var,
                            config.name
                        );
                        String::new()
                    })
                } else {
                    raw.clone()
                };
                if !resolved.is_empty() {
                    all_keys.push(SecretString::new(resolved));
                }
            }
            Arc::new(KeyPool::new(all_keys, pool_cfg.strategy.clone()))
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
            key_pool,
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

            "openai_compatible" => {
                let headers: Vec<(String, String)> = config
                    .headers
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let base = config
                    .base_url
                    .as_deref()
                    .unwrap_or(DEFAULT_OPENAI_BASE_URL);
                let params = Self::build_params(config, api_key, base, build_ctx);
                Ok(Box::new(OpenAIProvider::with_headers(params, headers)))
            }

            "anthropic_compatible" => {
                let base = config
                    .base_url
                    .as_deref()
                    .unwrap_or("https://api.anthropic.com");
                let params = Self::build_params(config, api_key, base, build_ctx);
                Ok(Box::new(AnthropicCompatibleProvider::named(
                    "anthropic_compatible",
                    base,
                    params,
                )))
            }

            other => Err(ProviderError::ConfigError(format!(
                "Unknown provider type: {}",
                other
            ))),
        }
    }

    /// Load providers from configuration with model mappings.
    ///
    /// Resolves `secret:<name>` and `$ENV_VAR` placeholders in each
    /// provider's `api_key` through the supplied [`SecretBackend`] before
    /// building the underlying client. This is the single entry point used
    /// by `server::init`, the CLI `validate` command, and every hot-reload
    /// path; making the backend a required parameter prevents the recurring
    /// class of bug where a caller forgot the resolution step and the
    /// literal placeholder ended up as the bearer token (PR #280, PR #284).
    ///
    /// Callers that have no secrets to resolve — typically tests using
    /// literal keys — can pass [`storage::secrets::EnvBackend`], which is
    /// stateless and a no-op for non-`secret:` / non-`$` strings.
    ///
    /// # Errors
    ///
    /// Returns a `ProviderError` when any provider's underlying client
    /// cannot be built or when an OAuth-typed provider is missing its
    /// `oauth_provider` reference.
    pub fn from_configs_with_models(
        configs: &[ProviderConfig],
        secret_backend: &dyn crate::storage::secrets::SecretBackend,
        token_store: Option<TokenStore>,
        models: &[ModelConfig],
        timeouts: &TimeoutConfig,
    ) -> Result<Self, ProviderError> {
        let resolved = crate::storage::secrets::resolve_provider_secrets(configs, secret_backend);
        let configs = &resolved;

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

            // Materialise the circuit-breaker template for this provider. Lazy
            // endpoint registration happens on the first call — this only
            // stores the config shape (cheap clone).
            if let Some(cb_cfg) = config.circuit_breaker.as_ref() {
                match cb_cfg.to_runtime() {
                    Ok(runtime) => {
                        registry.cb_templates.insert(config.name.clone(), runtime);
                    }
                    Err(e) => {
                        tracing::warn!(
                            provider = %config.name,
                            "invalid circuit_breaker config, using disabled defaults: {}",
                            e
                        );
                    }
                }
            }

            // RE-1b: spawn the active health checker eagerly so the first
            // probe lands before the first real request. Disabled configs
            // (no `health_uri`) are cheap — no task spawned.
            if let Some(hc_cfg) = config.health_check.as_ref() {
                match hc_cfg.to_runtime() {
                    Ok(runtime) if runtime.uri.is_some() => {
                        let checker = HealthChecker::new(config.name.clone(), runtime);
                        registry
                            .health_checkers
                            .insert(config.name.clone(), checker);
                    }
                    Ok(_) => {
                        tracing::debug!(
                            provider = %config.name,
                            "health_check section present but health_uri empty, checker disabled"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            provider = %config.name,
                            "invalid health_check config, checker disabled: {}",
                            e
                        );
                    }
                }
            }
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

    /// Gets a provider for a specific model.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::ModelNotSupported`] if no registered
    /// provider handles the given model name.
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

    /// Returns the circuit-breaker template configured for a provider.
    ///
    /// When no `[providers.circuit_breaker]` section was supplied for the
    /// provider, returns the disabled default (Caddy parity).
    fn cb_template_for(&self, provider: &str) -> CircuitBreakerConfig {
        self.cb_templates.get(provider).cloned().unwrap_or_default()
    }

    /// Looks up (or lazily creates) the passive circuit breaker for an endpoint.
    ///
    /// The endpoint identity is the `(provider, actual_model)` tuple —
    /// two models served by the same provider own independent breakers.
    pub fn endpoint_breaker(&self, provider: &str, model: &str) -> Arc<CircuitBreaker> {
        let key: EndpointId = (provider.to_string(), model.to_string());
        if let Some(cb) = self.endpoint_breakers.get(&key) {
            return Arc::clone(cb.value());
        }
        let label = format!("{provider}/{model}");
        let cfg = self.cb_template_for(provider);
        let cb = CircuitBreaker::new(label, cfg);
        // NOTE: `entry().or_insert_with` handles the race where two callers mint at once.
        self.endpoint_breakers
            .entry(key)
            .or_insert_with(|| cb)
            .value()
            .clone()
    }

    /// Returns the active-health-check status for a provider.
    ///
    /// Returns [`HealthStatus::NotConfigured`] when no
    /// `[providers.health_check]` section was supplied. The AND gate in
    /// [`is_endpoint_healthy`](Self::is_endpoint_healthy) consumes this.
    pub fn provider_health_status(&self, provider: &str) -> HealthStatus {
        match self.health_checkers.get(provider) {
            Some(hc) => hc.status(),
            None => HealthStatus::NotConfigured,
        }
    }

    /// Returns the health checker for a provider, if one is configured.
    ///
    /// Exposed mainly for testing and observability endpoints.
    pub fn health_checker(&self, provider: &str) -> Option<Arc<HealthChecker>> {
        self.health_checkers.get(provider).cloned()
    }

    /// Returns the runtime health-check config for a provider, if any.
    ///
    /// Exposed so the CLI/RPC surface can report the configured knobs
    /// without exposing the checker internals.
    pub fn health_check_config(&self, provider: &str) -> Option<&HealthCheckConfig> {
        self.health_checkers.get(provider).map(|hc| hc.config())
    }

    /// Returns whether an endpoint is currently healthy (ADR-0018 AND gate).
    ///
    /// Combines the passive circuit breaker (RE-1a) with the active
    /// health checker (RE-1b): the endpoint is healthy only when *both*
    /// signals agree. Each signal short-circuits to "healthy" when not
    /// configured, so a registry with neither section behaves exactly as
    /// before this module existed.
    pub fn is_endpoint_healthy(&self, provider: &str, model: &str) -> bool {
        // RE-1b active health check: if configured and reporting Down,
        // the endpoint is out regardless of the passive breaker.
        if self.provider_health_status(provider) == HealthStatus::Down {
            return false;
        }
        // RE-1a passive circuit breaker: fast path when no template.
        if !self.cb_templates.contains_key(provider) {
            return true;
        }
        self.endpoint_breaker(provider, model).is_healthy()
    }

    /// Records a successful dispatch against the endpoint breaker.
    ///
    /// No-op when no breaker template was configured for the provider.
    pub fn record_endpoint_success(&self, provider: &str, model: &str) {
        if !self.cb_templates.contains_key(provider) {
            return;
        }
        self.endpoint_breaker(provider, model).record_success();
    }

    /// Records a failed dispatch against the endpoint breaker.
    ///
    /// No-op when no breaker template was configured for the provider.
    pub fn record_endpoint_failure(&self, provider: &str, model: &str) {
        if !self.cb_templates.contains_key(provider) {
            return;
        }
        self.endpoint_breaker(provider, model).record_failure();
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
                pool: None,
                circuit_breaker: None,

                health_check: None,
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
                pool: None,
                circuit_breaker: None,

                health_check: None,
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

        // Test fixtures use literal API keys (no `secret:` / `$` prefix),
        // so any backend is a no-op here. Use `EnvBackend` because it is
        // stateless and avoids creating a temporary `GrobStore`.
        let backend = crate::storage::secrets::EnvBackend;
        let registry = ProviderRegistry::from_configs_with_models(
            &providers,
            &backend,
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

    #[test]
    fn from_configs_routes_resolution_through_backend() {
        // Regression guard for the class of bug fixed by PR #280, #284, and
        // this refactor. Three reload paths previously bypassed the secret
        // resolution step and shipped the literal `secret:openrouter` as
        // the upstream bearer token. Now `from_configs_with_models`
        // requires a `&dyn SecretBackend` and applies resolution
        // internally — any future caller that compiles also resolves.
        //
        // The `LlmProvider` trait does not expose the resolved api_key for
        // inspection (security: zeroize on drop, secrecy crate). We therefore
        // verify the integration by counting how many times the backend's
        // `get` is invoked: exactly once for our single `secret:`-prefixed
        // provider. A future caller forgetting to call this function would
        // surface as a zero-call counter even before reaching production.
        use crate::providers::AuthType;
        use crate::storage::secrets::SecretBackend;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingBackend {
            calls: AtomicUsize,
        }
        impl SecretBackend for CountingBackend {
            fn get(&self, name: &str) -> Option<SecretString> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if name == "openrouter" {
                    Some(SecretString::new("sk-resolved-real-key".into()))
                } else {
                    None
                }
            }
            fn label(&self) -> &'static str {
                "counting"
            }
        }

        let backend = CountingBackend {
            calls: AtomicUsize::new(0),
        };
        let providers = vec![ProviderConfig {
            name: "openrouter".to_string(),
            provider_type: "openrouter".to_string(),
            auth_type: AuthType::ApiKey,
            api_key: Some(SecretString::new("secret:openrouter".to_string())),
            base_url: None,
            models: vec![],
            enabled: Some(true),
            oauth_provider: None,
            project_id: None,
            location: None,
            headers: None,
            budget_usd: None,
            region: None,
            pass_through: Some(true),
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            pool: None,
            circuit_breaker: None,
            health_check: None,
        }];

        let registry = ProviderRegistry::from_configs_with_models(
            &providers,
            &backend,
            None,
            &[],
            &TimeoutConfig::default(),
        )
        .expect("registry build");

        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            1,
            "secret: prefix must trigger exactly one backend lookup; \
             zero would mean the resolution step was skipped"
        );
        assert!(
            registry.provider("openrouter").is_some(),
            "registry must contain the resolved provider"
        );
    }
}
