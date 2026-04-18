//! CLI configuration, argument parsing, and validation.

/// CLI argument parsing and subcommand definitions.
pub mod args;
mod config;
mod defaults;
mod newtypes;
mod validation;

pub use crate::features::log_export::LogExportConfig;
pub use crate::features::tool_layer::config::ToolLayerConfig;
pub use config::parse_duration;
#[cfg(feature = "harness")]
pub use config::HarnessConfig;
pub use config::{
    AcmeConfig, AuthType, BudgetConfig, CacheConfig, CircuitBreakerProviderConfig,
    ComplianceConfig, EnforcementMode, FanOutConfig, FanOutMode, FipsConfig, ModelConfig,
    ModelMapping, ModelStrategy, OtelConfig, PoolConfig, PoolStrategy, PresetConfig, ProjectConfig,
    ProjectRouterOverlay, PromptRule, ProviderConfig, RouterConfig, SecurityConfig, ServerConfig,
    TeeConfig, TierConfig, TierMatchCondition, TimeoutConfig, TlsConfig, TracingConfig, UserConfig,
};
pub use newtypes::{BodySizeLimit, BudgetUsd, ConfigSource, Port};

use crate::auth::jwt::AuthConfig;
use crate::features::dlp::config::DlpConfig;
#[cfg(feature = "mcp")]
use crate::features::mcp::config::McpConfig;
use crate::features::pledge::config::PledgeConfig;
use crate::features::tap::TapConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Application configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
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
    pub classifier: Option<crate::router::classify::ScoringConfig>,
    /// Preset management and sync settings
    #[serde(default)]
    pub presets: PresetConfig,
    /// Monthly spend budget and warning thresholds
    #[serde(default)]
    pub budget: BudgetConfig,
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
    /// External log sink configuration for structured request/response export
    #[serde(default)]
    pub log_export: LogExportConfig,
    /// Pledge filter: structurally removes tools from LLM payloads.
    #[serde(default)]
    pub pledge: PledgeConfig,
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

/// Format a bind address with proper IPv6 bracket notation.
/// IPv6 hosts (containing `:`) are wrapped in brackets: `[::1]:13456`
/// IPv4 hosts are left as-is: `127.0.0.1:13456`
pub fn format_bind_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Format a base URL with proper IPv6 bracket notation.
/// IPv6 hosts: `http://[::1]:13456`
/// IPv4 hosts: `http://127.0.0.1:13456`
pub fn format_base_url(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("http://[{}]:{}", host, port)
    } else {
        format!("http://{}:{}", host, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_format_bind_addr_ipv6() {
        assert_eq!(format_bind_addr("::1", 13456), "[::1]:13456");
    }

    #[test]
    fn test_format_bind_addr_ipv4() {
        assert_eq!(format_bind_addr("127.0.0.1", 13456), "127.0.0.1:13456");
    }

    #[test]
    fn test_format_base_url_ipv6() {
        assert_eq!(format_base_url("::", 13456), "http://[::]:13456");
    }

    #[test]
    fn test_format_base_url_ipv4() {
        assert_eq!(
            format_base_url("127.0.0.1", 13456),
            "http://127.0.0.1:13456"
        );
    }

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
}
