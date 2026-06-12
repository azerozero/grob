//! Top-level application configuration.
//!
//! [`AppConfig`](crate::config::AppConfig) aggregates every config section, including feature config
//! structs (`DlpConfig`, `McpConfig`, `PledgeConfig`, `TapConfig`,
//! `PolicyConfig`). Because those feature modules import core types from
//! `crate::models`, this aggregator must sit ABOVE both `models` and
//! `features` in the dependency graph: it is a top-level module
//! (`crate::config`), NOT a child of `crate::models`. Housing it under
//! `models` closed a `models → features → models` cycle. See the
//! `crate::pricing` leaf for the same anti-cycle pattern.
//!
//! Sub-configs (`ServerConfig`, `RouterConfig`, `ProviderConfig`, ...)
//! remain in `crate::cli::config` and are re-imported here.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::auth::jwt::AuthConfig;
#[cfg(feature = "harness")]
use crate::cli::HarnessConfig;
use crate::cli::{
    BudgetConfig, CacheConfig, ComplianceConfig, ConfigSource, FipsConfig, LogExportConfig,
    MetricsConfig, ModelConfig, ModelStrategy, OtelConfig, PresetConfig, PricingConfig,
    ProjectConfig, ProviderConfig, RouterConfig, SecurityConfig, ServerConfig, TeeConfig,
    TierConfig, ToolLayerConfig, UserConfig,
};
use crate::features::dlp::config::DlpConfig;
#[cfg(feature = "mcp")]
use crate::features::mcp::config::McpConfig;
use crate::features::pledge::config::PledgeConfig;
use crate::features::tap::TapConfig;

/// Application configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Config schema version (for forward compatibility)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// HTTP server settings (port, host, TLS, timeouts)
    #[serde(default)]
    pub server: ServerConfig,
    /// Request routing rules and model assignments
    pub router: RouterConfig,
    /// Configured LLM provider backends
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    /// Model definitions with provider mappings
    #[serde(default)]
    pub models: Vec<ModelConfig>,
    /// Declarative tier-to-provider mappings (opt-in complexity routing)
    #[serde(default)]
    pub tiers: Vec<TierConfig>,
    /// Complexity classifier scoring weights and thresholds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier: Option<crate::routing::classify::ScoringConfig>,
    /// Preset management and sync settings
    #[serde(default)]
    pub presets: PresetConfig,
    /// Monthly spend budget and warning thresholds
    #[serde(default)]
    pub budget: BudgetConfig,
    /// Price source (OpenRouter vs hardcoded) and token-accounting mode
    #[serde(default)]
    pub pricing: PricingConfig,
    /// Data loss prevention pipeline settings
    #[serde(default)]
    pub dlp: DlpConfig,
    /// Authentication and authorization configuration
    #[serde(default)]
    pub auth: AuthConfig,
    /// Webhook event tap configuration
    #[serde(default)]
    pub tap: TapConfig,
    /// Security middleware settings (rate limits, circuit breaker)
    #[serde(default)]
    pub security: SecurityConfig,
    /// LLM response cache configuration
    #[serde(default)]
    pub cache: CacheConfig,
    /// Secrets backend selection (local_encrypted | env | file)
    #[serde(default)]
    pub secrets: crate::cli::SecretsConfig,
    /// EU AI Act compliance configuration
    #[serde(default)]
    pub compliance: ComplianceConfig,
    /// Universal tool layer (injection, aliasing, capability gating)
    #[serde(default)]
    pub tool_layer: ToolLayerConfig,
    /// MCP tool matrix configuration
    #[cfg(feature = "mcp")]
    #[serde(default)]
    pub mcp: McpConfig,
    /// User-defined section preserved across preset applies
    #[serde(default)]
    pub user: UserConfig,
    /// OpenTelemetry distributed tracing export
    #[serde(default)]
    pub otel: OtelConfig,
    /// `/metrics` endpoint protection (optional bearer-token auth)
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// External log sink configuration for structured request/response export
    #[serde(default)]
    pub log_export: LogExportConfig,
    /// Pledge filter: structurally removes tools from LLM payloads.
    #[serde(default)]
    pub pledge: PledgeConfig,
    /// Inbound tool well-formedness validation (strip malformed, or reject 400).
    #[serde(default)]
    pub tool_validation: crate::features::tool_validation::ToolValidationConfig,
    /// Trusted Execution Environment (TEE) attestation and key sealing.
    #[serde(default)]
    pub tee: TeeConfig,
    /// FIPS 140-3 compliance enforcement.
    #[serde(default)]
    pub fips: FipsConfig,
    /// Policy engine rules for per-tenant/zone/compliance evaluation.
    #[serde(default)]
    pub policies: Vec<crate::features::policies::config::PolicyConfig>,
    /// Record-and-replay harness configuration (opt-in, `harness` feature).
    #[cfg(feature = "harness")]
    #[serde(default)]
    pub harness: HarnessConfig,
}

impl AppConfig {
    /// Returns `true` if the config file does not exist (first-run scenario).
    pub fn needs_first_run(path: &Path) -> bool {
        !path.exists()
    }

    /// Returns the default config file path (`~/.grob/config.toml`).
    ///
    /// # Errors
    ///
    /// Returns an error if the home directory cannot be determined
    /// or the config directory cannot be created.
    pub fn default_path() -> Result<PathBuf> {
        let config_dir =
            crate::grob_home().context("Failed to get home directory (set GROB_HOME)")?;
        std::fs::create_dir_all(&config_dir).with_context(|| {
            format!(
                "Failed to create config directory: {}",
                config_dir.display()
            )
        })?;
        Ok(config_dir.join("config.toml"))
    }

    /// Loads configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, the TOML content
    /// is malformed, or config validation fails.
    pub fn from_file(path: &Path) -> Result<Self> {
        // Check if file exists, if not create a default one
        if !path.exists() {
            Self::create_default_config(path)?;
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        Self::from_content(&content, &format!("{}", path.display()))
    }

    /// Loads configuration from a [`ConfigSource`] (file path or URL).
    ///
    /// # Errors
    ///
    /// Returns an error if the file/URL cannot be read, the HTTP
    /// request fails, or the TOML content is invalid.
    pub async fn from_source(source: &ConfigSource) -> Result<Self> {
        match source {
            ConfigSource::File(path) => Self::from_file(path),
            ConfigSource::Url(url) => {
                let content = reqwest::get(url)
                    .await
                    .with_context(|| format!("Failed to fetch config from {}", url))?
                    .error_for_status()
                    .with_context(|| format!("HTTP error fetching config from {}", url))?
                    .text()
                    .await
                    .with_context(|| format!("Failed to read config body from {}", url))?;
                Self::from_content(&content, url)
            }
        }
    }

    /// Parses configuration from a TOML content string.
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML cannot be deserialized, environment
    /// variable resolution fails, or config validation fails.
    pub fn from_content(content: &str, source_label: &str) -> Result<Self> {
        let mut config: AppConfig = toml::from_str(content)
            .with_context(|| format!("Failed to parse config from {}", source_label))?;

        config.resolve_env_vars()?;
        config.validate()?;

        Ok(config)
    }

    /// Resolves `$ENV_VAR` references in provider API keys.
    ///
    /// Missing env vars disable the provider with a warning instead of
    /// crashing, so the proxy can still serve traffic through the
    /// remaining providers. Only fails if *all* providers end up disabled.
    fn resolve_env_vars(&mut self) -> Result<()> {
        use secrecy::{ExposeSecret, SecretString};

        // Resolve server API key
        if let Some(ref key) = self.server.api_key {
            if let Some(env_var) = key.expose_secret().strip_prefix('$') {
                self.server.api_key = std::env::var(env_var).ok().map(SecretString::new);
            }
        }

        let mut disabled_for_missing: Vec<(String, String)> = Vec::new();

        // Resolve provider API keys (only for enabled providers)
        for provider in &mut self.providers {
            if !provider.is_enabled() {
                continue;
            }

            // Only resolve env vars for API key auth
            if let Some(ref api_key) = provider.api_key {
                if let Some(env_var) = api_key.expose_secret().strip_prefix('$') {
                    if let Ok(value) = std::env::var(env_var) {
                        provider.api_key = Some(SecretString::new(value));
                    } else if std::env::var("GROB_MOCK_BACKEND").is_ok() {
                        provider.api_key = Some(SecretString::new("mock-key".to_string()));
                    } else {
                        // Gracefully disable instead of crashing.
                        disabled_for_missing.push((provider.name.clone(), env_var.to_string()));
                        provider.enabled = Some(false);
                    }
                }
            }

            // Resolve $ENV_VAR references in pool keys.
            if let Some(ref mut pool) = provider.pool {
                for key in &mut pool.keys {
                    if let Some(env_var) = key.strip_prefix('$') {
                        if let Ok(value) = std::env::var(env_var) {
                            *key = value;
                        } else if std::env::var("GROB_MOCK_BACKEND").is_ok() {
                            *key = "mock-pool-key".to_string();
                        } else {
                            eprintln!(
                                "Warning: pool key ${} not set for provider '{}'",
                                env_var, provider.name
                            );
                            *key = String::new();
                        }
                    }
                }
                // Remove empty keys (unresolved env vars).
                pool.keys.retain(|k| !k.is_empty());
            }
        }

        if !disabled_for_missing.is_empty() {
            let still_active = self.providers.iter().filter(|p| p.is_enabled()).count();

            for (name, var) in &disabled_for_missing {
                eprintln!("Warning: ${} not set — provider '{}' disabled", var, name);
            }

            if still_active == 0 {
                eprintln!();
                eprintln!("No providers left. Fix with one of:");
                for (name, var) in &disabled_for_missing {
                    eprintln!("  export {}=your-api-key-here", var);
                    eprintln!("  grob connect {}", name);
                }
                anyhow::bail!("All providers disabled due to missing API keys");
            }

            eprintln!("Continuing with {} active provider(s)", still_active);
            eprintln!();
        }

        Ok(())
    }

    /// Create a default configuration file or migrate existing one
    pub(crate) fn create_default_config(path: &Path) -> Result<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        // Check for existing config in old location (config/default.toml)
        let old_config_path = PathBuf::from("config/default.toml");
        if old_config_path.exists() {
            // Migrate existing config
            eprintln!(
                "📦 Migrating existing config from {} to {}",
                old_config_path.display(),
                path.display()
            );

            std::fs::copy(&old_config_path, path).with_context(|| {
                format!(
                    "Failed to migrate config from {} to {}",
                    old_config_path.display(),
                    path.display()
                )
            })?;

            eprintln!("✅ Migration complete! Your existing configuration has been preserved.");
            eprintln!("   Old location: {}", old_config_path.display());
            eprintln!("   New location: {}", path.display());
            eprintln!();
            eprintln!("💡 You can safely delete the old config file if you want:");
            eprintln!("   rm {}", old_config_path.display());
        } else {
            // Generate default config content
            let default_config = Self::default_config_content();

            // Write to file
            std::fs::write(path, default_config).with_context(|| {
                format!("Failed to write default config file: {}", path.display())
            })?;

            eprintln!("Created default config file at: {}", path.display());
            eprintln!("Please edit the config file to add your providers and models.");
            eprintln!("Run 'grob preset list' to see presets, then 'grob preset apply <name>'.");
        }

        Ok(())
    }

    /// Generate default configuration content as TOML string
    pub(crate) fn default_config_content() -> String {
        r#"# Grob Configuration
#
# This is a minimal default configuration.
# Edit this file or run 'grob preset apply <name>' for quick setup.
# See: grob preset list

[server]
host = "::1"
port = 13456
log_level = "info"

[server.timeouts]
api_timeout_ms = 600000      # 10 minutes
connect_timeout_ms = 10000   # 10 seconds

# Message tracing for debugging (logs full request/response to JSONL)
# [server.tracing]
# enabled = true
# path = "~/.grob/trace.jsonl"
# omit_system_prompt = true

[presets]
sync_url = "https://raw.githubusercontent.com/azerozero/grob/main/presets/"
[router]
# Default model to use when no routing conditions are met
# You MUST configure at least one provider and model before using Grob
default = "placeholder-model"

# Optional: Model for background tasks (e.g., "glm-4.5-air")
# background = ""

# Optional: Model for thinking/reasoning tasks (e.g., "claude-opus-4-6")
# think = ""

# Optional: Model for web search tasks (e.g., "glm-4.6")
# websearch = ""

# Optional: Regex pattern for auto-mapping models (e.g., "^claude-")
# auto_map_regex = ""

# Optional: Regex pattern for detecting background tasks (e.g., "(?i)claude.*haiku")
# background_regex = ""

# Optional: Prompt-based routing rules (first match wins)
# Routes to specific models when patterns match user prompt content
# [[router.prompt_rules]]
# pattern = "(?i)commit.*changes"   # Regex pattern to match
# model = "fast-model"              # Model to route to
# strip_match = false               # Strip matched phrase from prompt (default: false)

# Providers configuration
# Add providers below or use 'grob preset apply <name>'
# Example:
# [[providers]]
# name = "my-provider"
# provider_type = "anthropic"  # or "openai", "openrouter", etc.
# auth_type = "apikey"          # or "oauth"
# api_key = "your-api-key-here"
# enabled = true
# models = []

# Models configuration
# Add models below or use 'grob preset apply <name>'
# Example:
# [[models]]
# name = "my-model"
#
# [[models.mappings]]
# provider = "my-provider"
# actual_model = "claude-sonnet-4-6"
# priority = 1
"#
        .to_string()
    }

    /// Validates configuration for common errors.
    ///
    /// Runs each per-section validator in a fixed order; the first failing
    /// section determines the returned error (validation short-circuits on the
    /// first hard error, matching the original single-function behaviour).
    ///
    /// # Errors
    ///
    /// Returns an error if model mappings reference unknown providers,
    /// enabled providers lack required auth credentials, or configured
    /// regex patterns fail to compile.
    pub fn validate(&self) -> Result<()> {
        use std::collections::HashSet;

        // Built once and shared by reference with the section validators to keep
        // the hot validation path allocation-equivalent with the original.
        let provider_names: HashSet<&str> =
            self.providers.iter().map(|p| p.name.as_str()).collect();
        let model_names: HashSet<&str> = self.models.iter().map(|m| m.name.as_str()).collect();

        // Order is load-bearing: callers rely on the first hard error surfacing,
        // so the section sequence below must not be reordered.
        Self::validate_model_mappings(&self.models, &provider_names)?;
        Self::validate_provider_auth(&self.providers)?;
        Self::validate_router_regexes(&self.router)?;
        Self::warn_unknown_router_models(&self.router, &model_names);
        Self::validate_acme(&self.server)?;
        Self::validate_auth_mode(&self.auth)?;
        Self::validate_fan_out(&self.models, &model_names)?;
        Self::validate_tiers(&self.tiers, &provider_names, &model_names)?;
        Self::validate_pledge_profiles(&self.pledge)?;

        Ok(())
    }

    /// Rejects pledge configs that reference an unknown profile name.
    ///
    /// Fail-closed at load: a typo'd `default_profile` or rule profile (which
    /// would otherwise resolve to `none`/strip-all at runtime) is surfaced as a
    /// startup error instead, so the operator notices before deploying.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first profile reference that resolves to
    /// neither a config-defined nor a built-in profile.
    fn validate_pledge_profiles(pledge: &PledgeConfig) -> Result<()> {
        use crate::features::pledge::profiles::is_known;

        if is_known(pledge, &pledge.default_profile) {
            // ok
        } else {
            anyhow::bail!(
                "pledge.default_profile '{}' is not a known profile (built-in or [[pledge.profiles]])",
                pledge.default_profile
            );
        }
        for rule in &pledge.rules {
            if !is_known(pledge, &rule.profile) {
                anyhow::bail!(
                    "pledge rule references unknown profile '{}' (built-in or [[pledge.profiles]])",
                    rule.profile
                );
            }
        }
        // Validate every custom profile's glob patterns compile, so an invalid
        // pattern is a startup error rather than a silently-dropped (never-match)
        // pattern at runtime.
        for profile in &pledge.profiles {
            for pattern in &profile.allowed_tool_patterns {
                globset::Glob::new(pattern).map_err(|e| {
                    anyhow::anyhow!(
                        "pledge profile '{}' has an invalid tool pattern '{}': {}",
                        profile.name,
                        pattern,
                        e
                    )
                })?;
            }
        }
        Ok(())
    }

    /// Verifies every model mapping references a declared provider.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first mapping whose provider is unknown.
    fn validate_model_mappings(
        models: &[ModelConfig],
        provider_names: &std::collections::HashSet<&str>,
    ) -> Result<()> {
        for model in models {
            for mapping in &model.mappings {
                if !provider_names.contains(mapping.provider.as_str()) {
                    anyhow::bail!(
                        "Model '{}' references unknown provider '{}'. Available: {:?}",
                        model.name,
                        mapping.provider,
                        provider_names.iter().collect::<Vec<_>>()
                    );
                }
            }
        }
        Ok(())
    }

    /// Verifies every enabled provider carries the credentials its auth type needs.
    ///
    /// # Errors
    ///
    /// Returns an error for the first enabled provider missing an API key
    /// (except `vertex-ai`, which may use ADC) or an `oauth_provider`.
    fn validate_provider_auth(providers: &[ProviderConfig]) -> Result<()> {
        use crate::cli::AuthType;
        for provider in providers {
            if !provider.is_enabled() {
                continue;
            }
            match provider.auth_type {
                AuthType::ApiKey => {
                    let key_missing = provider.api_key.is_none();
                    if key_missing {
                        // Special case: gemini/vertex-ai may use ADC
                        if provider.provider_type != "vertex-ai" {
                            anyhow::bail!(
                                "Provider '{}' has auth_type=apikey but no api_key configured",
                                provider.name
                            );
                        }
                    }
                }
                AuthType::OAuth => {
                    if provider.oauth_provider.is_none() {
                        anyhow::bail!(
                            "Provider '{}' has auth_type=oauth but no oauth_provider configured",
                            provider.name
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Compiles every configured router regex to surface invalid patterns early.
    ///
    /// # Errors
    ///
    /// Returns an error if `auto_map_regex`, `background_regex`, or any
    /// `prompt_rules` pattern fails to compile.
    fn validate_router_regexes(router: &RouterConfig) -> Result<()> {
        if let Some(ref pattern) = router.auto_map_regex {
            if !pattern.is_empty() {
                regex::Regex::new(pattern)
                    .with_context(|| format!("Invalid auto_map_regex: '{}'", pattern))?;
            }
        }
        if let Some(ref pattern) = router.background_regex {
            if !pattern.is_empty() {
                regex::Regex::new(pattern)
                    .with_context(|| format!("Invalid background_regex: '{}'", pattern))?;
            }
        }
        for (i, rule) in router.prompt_rules.iter().enumerate() {
            regex::Regex::new(&rule.pattern).with_context(|| {
                format!("Invalid prompt_rule[{}] pattern: '{}'", i, rule.pattern)
            })?;
        }
        Ok(())
    }

    /// Warns (without failing) when a router model name is absent from `[[models]]`.
    fn warn_unknown_router_models(
        router: &RouterConfig,
        model_names: &std::collections::HashSet<&str>,
    ) {
        let check_router_model = |name: &str, field: &str| {
            if !model_names.contains(name) && !model_names.is_empty() {
                eprintln!(
                    "⚠️  Warning: router.{} = '{}' not found in [[models]]",
                    field, name
                );
            }
        };

        check_router_model(&router.default, "default");
        if let Some(ref m) = router.background {
            check_router_model(m, "background");
        }
        if let Some(ref m) = router.think {
            check_router_model(m, "think");
        }
        if let Some(ref m) = router.websearch {
            check_router_model(m, "websearch");
        }
    }

    /// Verifies ACME has domains and contacts whenever it is enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if ACME is enabled with empty `domains` or `contacts`.
    fn validate_acme(server: &ServerConfig) -> Result<()> {
        if server.tls.acme.enabled {
            if server.tls.acme.domains.is_empty() {
                anyhow::bail!(
                    "ACME is enabled but no domains configured. Set [server.tls.acme] domains = [\"example.com\"]"
                );
            }
            if server.tls.acme.contacts.is_empty() {
                anyhow::bail!(
                    "ACME is enabled but no contacts configured. Set [server.tls.acme] contacts = [\"admin@example.com\"]"
                );
            }
        }
        Ok(())
    }

    /// Verifies the inbound auth mode is one of the supported values.
    ///
    /// # Errors
    ///
    /// Returns an error if `auth.mode` is not `none`, `api_key`, or `jwt`.
    fn validate_auth_mode(auth: &AuthConfig) -> Result<()> {
        match auth.mode.as_str() {
            "none" | "api_key" | "jwt" => {}
            other => anyhow::bail!(
                "Invalid auth.mode '{}'. Must be one of: none, api_key, jwt",
                other
            ),
        }
        Ok(())
    }

    /// Verifies fan-out models carry a `[fan_out]` block and warns on unknown judges.
    ///
    /// # Errors
    ///
    /// Returns an error for the first `strategy=fan_out` model lacking a
    /// `[fan_out]` config block.
    fn validate_fan_out(
        models: &[ModelConfig],
        model_names: &std::collections::HashSet<&str>,
    ) -> Result<()> {
        for model in models {
            if model.strategy == ModelStrategy::FanOut && model.fan_out.is_none() {
                anyhow::bail!(
                    "Model '{}' has strategy=fan_out but no [fan_out] config block",
                    model.name
                );
            }
            // Warn if judge_model not in [[models]]
            if let Some(ref fo) = model.fan_out {
                if let Some(ref judge) = fo.judge_model {
                    if !model_names.contains(judge.as_str()) && !model_names.is_empty() {
                        eprintln!(
                            "⚠️  Warning: model '{}' fan_out.judge_model '{}' not found in [[models]]",
                            model.name, judge
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Verifies every tier references a declared provider; warns on unknown models.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first tier whose provider is unknown. An
    /// unknown `model` only warns — it may be a pass-through model forwarded
    /// verbatim to a `pass_through = true` provider and intentionally absent
    /// from `[[models]]` (mirrors [`Self::warn_unknown_router_models`]).
    fn validate_tiers(
        tiers: &[TierConfig],
        provider_names: &std::collections::HashSet<&str>,
        model_names: &std::collections::HashSet<&str>,
    ) -> Result<()> {
        // Skip when no providers are defined: an empty provider set means no
        // declared names to validate against, matching the original guard.
        if !provider_names.is_empty() {
            for tier in tiers {
                for prov in &tier.providers {
                    if !provider_names.contains(prov.as_str()) {
                        anyhow::bail!(
                            "Tier '{}' references unknown provider '{}'. Available: {:?}",
                            tier.name,
                            prov,
                            provider_names.iter().collect::<Vec<_>>()
                        );
                    }
                }
            }
        }
        // Unknown tier models are a warning, not a hard error: a tier may target
        // a pass-through model — forwarded verbatim to a `pass_through = true`
        // provider and intentionally absent from `[[models]]`. This matches
        // `warn_unknown_router_models` and `validate_fan_out`, which also only
        // warn. Providers (above) stay a hard error: a tier must reference a
        // declared `[[providers]]` entry.
        if !model_names.is_empty() {
            for tier in tiers {
                if let Some(model) = tier.model.as_deref() {
                    if !model_names.contains(model) {
                        eprintln!(
                            "⚠️  Warning: tier '{}' model '{}' not found in [[models]] (ok for pass-through)",
                            tier.name, model
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

/// Search for .grob.toml by walking up from CWD to home dir.
/// Returns the path if found.
pub fn find_project_config() -> Option<PathBuf> {
    let home = crate::home_dir()?;
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".grob.toml");
        if candidate.exists() {
            return Some(candidate);
        }
        if dir == home || !dir.pop() {
            break;
        }
    }
    None
}

/// Merge per-project .grob.toml overlay into the main config.
/// Searches CWD up to home for .grob.toml and overlays found values.
pub fn merge_project_config(mut config: AppConfig) -> AppConfig {
    let project_path = match find_project_config() {
        Some(p) => p,
        None => return config,
    };

    let content = match std::fs::read_to_string(&project_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("Could not read {}: {}", project_path.display(), e);
            return config;
        }
    };

    let project: ProjectConfig = match toml::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("⚠️  Failed to parse {}: {}", project_path.display(), e);
            return config;
        }
    };

    // Overlay router settings
    if let Some(router_overlay) = project.router {
        if let Some(default) = router_overlay.default {
            config.router.default = default;
        }
        if let Some(think) = router_overlay.think {
            config.router.think = Some(think);
        }
        if let Some(background) = router_overlay.background {
            config.router.background = Some(background);
        }
        if let Some(websearch) = router_overlay.websearch {
            config.router.websearch = Some(websearch);
        }
        if !router_overlay.prompt_rules.is_empty() {
            // Prepend project rules (higher priority)
            let mut merged = router_overlay.prompt_rules;
            merged.append(&mut config.router.prompt_rules);
            config.router.prompt_rules = merged;
        }
    }

    // Overlay budget
    if let Some(budget) = project.budget {
        config.budget = budget;
    }

    // Overlay preset name
    if let Some(presets) = project.presets {
        if presets.active.is_some() {
            config.presets.active = presets.active;
        }
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_toml_config() {
        let config_content = r#"
[server]
port = 3456
host = "::1"
log_level = "info"

[server.timeouts]
api_timeout_ms = 600000
connect_timeout_ms = 10000

[router]
default = "my-default-model"
think = "my-think-model"
        "#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();

        let config = AppConfig::from_file(temp_file.path()).unwrap();

        assert_eq!(config.server.port.value(), 3456);
        assert_eq!(config.router.default, "my-default-model");
        assert_eq!(config.router.think.as_deref(), Some("my-think-model"));
    }

    #[test]
    fn validate_tiers_accepts_pass_through_model_but_rejects_unknown_provider() {
        use std::collections::HashSet;
        let providers: HashSet<&str> = ["chatgpt-codex"].into_iter().collect();
        // Non-empty [[models]] that does NOT contain the tier's model.
        let models: HashSet<&str> = ["dev"].into_iter().collect();

        // A tier model absent from [[models]] is a pass-through target → warn,
        // not error (mirrors router/fan_out validation).
        let pass_through = vec![TierConfig {
            name: "medium".to_string(),
            model: Some("gpt-5.5-not-declared".to_string()),
            providers: vec!["chatgpt-codex".to_string()],
            fanout: false,
            match_conditions: None,
        }];
        assert!(AppConfig::validate_tiers(&pass_through, &providers, &models).is_ok());

        // An unknown provider stays a hard error.
        let bad_provider = vec![TierConfig {
            name: "medium".to_string(),
            model: None,
            providers: vec!["does-not-exist".to_string()],
            fanout: false,
            match_conditions: None,
        }];
        assert!(AppConfig::validate_tiers(&bad_provider, &providers, &models).is_err());
    }
}
