use crate::providers::ProviderConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

/// Where the configuration comes from: local file or remote URL
#[derive(Debug, Clone)]
pub enum ConfigSource {
    File(PathBuf),
    Url(String),
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSource::File(p) => write!(f, "{}", p.display()),
            ConfigSource::Url(u) => write!(f, "{}", u),
        }
    }
}

/// Budget configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BudgetConfig {
    /// Global monthly hard cap in USD (0 = unlimited)
    #[serde(default)]
    pub monthly_limit_usd: f64,
    /// Log warning at this percentage of budget (default: 80)
    #[serde(default = "default_warn_percent")]
    pub warn_at_percent: u32,
}

fn default_warn_percent() -> u32 {
    80
}

/// Application configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    pub router: RouterConfig,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub models: Vec<ModelConfig>,
    #[serde(default)]
    pub presets: PresetConfig,
    #[serde(default)]
    pub budget: BudgetConfig,
}

/// Preset configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PresetConfig {
    /// URL to sync presets from (HTTP raw URL or git repo URL)
    /// Examples:
    ///   "https://raw.githubusercontent.com/user/presets/main/"  (fetches index.toml)
    ///   "https://example.com/presets/perf.toml"                 (single file)
    ///   "git@github.com:user/presets.git"                       (git fallback)
    pub sync_url: Option<String>,
    /// Sync interval: "6h", "12h", "1d", "30m"
    pub sync_interval: Option<String>,
    /// Set to false to disable auto-sync even if sync_url is configured
    #[serde(default = "default_auto_sync")]
    pub auto_sync: bool,
    /// Currently active preset name
    pub active: Option<String>,
}

fn default_auto_sync() -> bool {
    true
}

/// Server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_host")]
    pub host: String,
    pub api_key: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    #[serde(default)]
    pub tracing: TracingConfig,
}

/// Message tracing configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tracing_path")]
    pub path: String,
    /// Omit system prompt from traces (default: true, since system prompts are huge)
    #[serde(default = "default_true")]
    pub omit_system_prompt: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_tracing_path(),
            omit_system_prompt: true,
        }
    }
}

fn default_tracing_path() -> String {
    "~/.grob/trace.jsonl".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: default_port(),
            host: default_host(),
            api_key: None,
            log_level: default_log_level(),
            timeouts: TimeoutConfig::default(),
            tracing: TracingConfig::default(),
        }
    }
}

fn default_port() -> u16 {
    13456
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Timeout configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TimeoutConfig {
    #[serde(default = "default_api_timeout")]
    pub api_timeout_ms: u64,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_ms: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            api_timeout_ms: default_api_timeout(),
            connect_timeout_ms: default_connect_timeout(),
        }
    }
}

fn default_api_timeout() -> u64 {
    600_000 // 10 minutes
}

fn default_connect_timeout() -> u64 {
    10_000 // 10 seconds
}

/// Router configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouterConfig {
    pub default: String,
    pub background: Option<String>,
    pub think: Option<String>,
    pub websearch: Option<String>,
    /// Regex pattern for auto-mapping models (e.g., "^claude-").
    /// If empty/null, defaults to Claude models only.
    pub auto_map_regex: Option<String>,
    /// Regex pattern for detecting background tasks (e.g., "(?i)claude.*haiku").
    /// If empty/null, defaults to claude-haiku pattern.
    pub background_regex: Option<String>,
    /// Prompt-based routing rules. Routes to specific models when patterns match user prompt.
    #[serde(default)]
    pub prompt_rules: Vec<PromptRule>,
}

/// Prompt-based routing rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromptRule {
    /// Regex pattern to match against user prompt content.
    /// Can include capture groups: (pattern) or named: (?P<name>pattern)
    pub pattern: String,
    /// Model to route to when pattern matches.
    /// Can reference capture groups: $1, $name, ${1}, ${name}, or mixed like "prefix-$1"
    pub model: String,
    /// Strip the matched phrase from the prompt (default: false)
    #[serde(default)]
    pub strip_match: bool,
}

/// Model configuration with 1:N provider mappings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelConfig {
    /// External model name (used in API requests)
    pub name: String,
    /// List of provider mappings with priorities (fallback support)
    pub mappings: Vec<ModelMapping>,
    /// Per-model monthly budget in USD (optional, overrides provider and global)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_usd: Option<f64>,
}

/// Model mapping to a specific provider
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelMapping {
    /// Priority for this mapping (1 = highest priority)
    pub priority: u32,
    /// Provider name
    pub provider: String,
    /// Actual model name to use with the provider
    pub actual_model: String,
    /// Inject continuation prompt after tool results (for models that stop prematurely)
    #[serde(default)]
    pub inject_continuation_prompt: bool,
}

impl ModelConfig {}

impl AppConfig {
    /// Get default config file path
    /// Returns ~/.grob/config.toml (cross-platform)
    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Failed to get home directory")?;
        let config_dir = home.join(".grob");
        std::fs::create_dir_all(&config_dir).with_context(|| {
            format!(
                "Failed to create config directory: {}",
                config_dir.display()
            )
        })?;
        Ok(config_dir.join("config.toml"))
    }

    /// Load configuration from a TOML file
    pub fn from_file(path: &PathBuf) -> Result<Self> {
        // Check if file exists, if not create a default one
        if !path.exists() {
            Self::create_default_config(path)?;
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        Self::from_content(&content, &format!("{}", path.display()))
    }

    /// Load configuration from a ConfigSource (file path or URL)
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

    /// Parse configuration from TOML content string
    pub fn from_content(content: &str, source_label: &str) -> Result<Self> {
        let mut config: AppConfig = toml::from_str(content)
            .with_context(|| format!("Failed to parse config from {}", source_label))?;

        config.resolve_env_vars()?;
        config.validate()?;

        Ok(config)
    }

    /// Validate configuration for common errors
    pub fn validate(&self) -> Result<()> {
        let provider_names: HashSet<&str> =
            self.providers.iter().map(|p| p.name.as_str()).collect();

        // Check model mappings reference existing providers
        for model in &self.models {
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

        // Check enabled providers have auth configured
        for provider in &self.providers {
            if !provider.is_enabled() {
                continue;
            }
            use crate::providers::AuthType;
            match provider.auth_type {
                AuthType::ApiKey => {
                    if provider.api_key.is_none() {
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

        // Validate regex patterns compile
        if let Some(ref pattern) = self.router.auto_map_regex {
            if !pattern.is_empty() {
                regex::Regex::new(pattern)
                    .with_context(|| format!("Invalid auto_map_regex: '{}'", pattern))?;
            }
        }
        if let Some(ref pattern) = self.router.background_regex {
            if !pattern.is_empty() {
                regex::Regex::new(pattern)
                    .with_context(|| format!("Invalid background_regex: '{}'", pattern))?;
            }
        }
        for (i, rule) in self.router.prompt_rules.iter().enumerate() {
            regex::Regex::new(&rule.pattern).with_context(|| {
                format!("Invalid prompt_rule[{}] pattern: '{}'", i, rule.pattern)
            })?;
        }

        // Warn if router models don't exist in [[models]]
        let model_names: HashSet<&str> = self.models.iter().map(|m| m.name.as_str()).collect();

        let check_router_model = |name: &str, field: &str| {
            if !model_names.contains(name) && !model_names.is_empty() {
                eprintln!(
                    "⚠️  Warning: router.{} = '{}' not found in [[models]]",
                    field, name
                );
            }
        };

        check_router_model(&self.router.default, "default");
        if let Some(ref m) = self.router.background {
            check_router_model(m, "background");
        }
        if let Some(ref m) = self.router.think {
            check_router_model(m, "think");
        }
        if let Some(ref m) = self.router.websearch {
            check_router_model(m, "websearch");
        }

        Ok(())
    }

    /// Create a default configuration file or migrate existing one
    fn create_default_config(path: &PathBuf) -> Result<()> {
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
            eprintln!("Run 'grob preset apply medium' for a quick multi-provider setup.");
        }

        Ok(())
    }

    /// Generate default configuration content as TOML string
    fn default_config_content() -> String {
        r#"# Grob Configuration
#
# This is a minimal default configuration.
# Edit this file or run 'grob preset apply <name>' for quick setup.
# See: grob preset list

[server]
host = "127.0.0.1"
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

    /// Resolve environment variables in configuration
    fn resolve_env_vars(&mut self) -> Result<()> {
        // Resolve server API key
        if let Some(ref key) = self.server.api_key {
            if let Some(env_var) = key.strip_prefix('$') {
                self.server.api_key = std::env::var(env_var).ok();
            }
        }

        // Resolve provider API keys (only for enabled providers)
        for provider in &mut self.providers {
            // Skip disabled providers
            if !provider.is_enabled() {
                continue;
            }

            // Only resolve env vars for API key auth
            if let Some(ref api_key) = provider.api_key {
                if let Some(env_var) = api_key.strip_prefix('$') {
                    if let Ok(value) = std::env::var(env_var) {
                        provider.api_key = Some(value);
                    } else {
                        anyhow::bail!(
                            "Environment variable {} not found for provider {}",
                            env_var,
                            provider.name
                        );
                    }
                }
            }
        }

        Ok(())
    }
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
host = "127.0.0.1"
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

        let config = AppConfig::from_file(&temp_file.path().to_path_buf()).unwrap();

        assert_eq!(config.server.port, 3456);
        assert_eq!(config.router.default, "my-default-model");
        assert_eq!(config.router.think.as_deref(), Some("my-think-model"));
    }
}
