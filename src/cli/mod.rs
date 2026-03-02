//! CLI configuration, argument parsing, and validation.

pub mod args;
mod config;
mod defaults;
mod newtypes;
mod validation;

pub use config::*;
pub use newtypes::*;

use crate::auth::jwt::AuthConfig;
use crate::features::dlp::config::DlpConfig;
use crate::features::tap::TapConfig;
use crate::providers::ProviderConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Application configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    /// Config schema version (for forward compatibility)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
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
    #[serde(default)]
    pub dlp: DlpConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub tap: TapConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    /// LLM response cache configuration
    #[serde(default)]
    pub cache: CacheConfig,
    /// EU AI Act compliance configuration
    #[serde(default)]
    pub compliance: ComplianceConfig,
    /// User-defined section preserved across preset applies
    #[serde(default)]
    pub user: UserConfig,
}

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
    pub fn from_file(path: &Path) -> Result<Self> {
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
                            "Environment variable ${} not set for provider '{}'\n\n\
                             Fix with one of:\n  \
                             export {}=your-api-key-here\n  \
                             grob connect {}\n  \
                             Set enabled = false for '{}' in config.toml",
                            env_var,
                            provider.name,
                            env_var,
                            provider.name,
                            provider.name
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
    let home = dirs::home_dir()?;
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
