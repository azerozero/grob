//! Centralized guard for configuration updates.
//!
//! Provides a deny-list to prevent credential leaks and security weakening,
//! and a unified persist-and-reload pipeline shared by the web config API
//! (`/api/config`) and the MCP self-tuning path (`grob_configure`).

#[cfg(feature = "mcp")]
use crate::features::mcp::server::types::ConfigSection;

use std::path::Path;
use std::sync::Arc;
use tracing::info;

/// Top-level TOML sections that are never writable via any config API.
const DENIED_SECTIONS: &[&str] = &["providers", "dlp"];

/// Per-section keys that are never writable via any config API.
const DENIED_KEYS: &[(&str, &str)] = &[
    ("router", "api_key"),
    ("budget", "api_key"),
    ("cache", "api_key"),
];

/// Checks whether a (section, key) pair is blocked by the deny-list.
///
/// Returns `true` when the write must be rejected:
/// - The entire `providers` section (contains API keys).
/// - The entire `dlp` section (security must not be weakened).
/// - Any `api_key` field in any section.
pub fn is_section_or_key_denied(section: &str, key: &str) -> bool {
    if DENIED_SECTIONS.contains(&section) {
        return true;
    }
    if key == "api_key" {
        return true;
    }
    DENIED_KEYS.iter().any(|(s, k)| *s == section && *k == key)
}

/// Validates a key update against the deny-list using [`ConfigSection`].
///
/// Delegates to [`is_section_or_key_denied`] after converting the enum to a
/// string. This keeps the MCP path backward-compatible.
#[cfg(feature = "mcp")]
pub fn is_key_denied(section: &ConfigSection, key: &str) -> bool {
    let section_str = match section {
        ConfigSection::Router => "router",
        ConfigSection::Budget => "budget",
        ConfigSection::Dlp => "dlp",
        ConfigSection::Cache => "cache",
    };
    is_section_or_key_denied(section_str, key)
}

/// Backs up the config file, writes new content, and triggers a hot-reload.
///
/// Both the web config API and MCP self-tuning path delegate here so that
/// backup, serialisation, and reload behaviour are identical regardless of
/// the mutation surface.
///
/// # Errors
///
/// Returns an error when the config source is a remote URL (read-only), the
/// backup copy fails, serialisation fails, disk write fails, or the
/// hot-reload (re-parse + provider rebuild) fails.
pub async fn persist_and_reload(
    state: &Arc<super::AppState>,
    config: &crate::cli::AppConfig,
) -> Result<(), super::AppError> {
    let config_path = match &state.config_source {
        crate::cli::ConfigSource::File(p) => p,
        crate::cli::ConfigSource::Url(_) => {
            return Err(super::AppError::ParseError(
                "Cannot save config: loaded from remote URL (read-only)".to_string(),
            ));
        }
    };

    // 1. Backup
    let backup_path = config_path.with_extension("toml.backup");
    tokio::fs::copy(config_path, &backup_path)
        .await
        .map_err(|e| super::AppError::ParseError(format!("Failed to create backup: {e}")))?;

    // 2. Serialise and write
    let toml_str = toml::to_string_pretty(config)
        .map_err(|e| super::AppError::ParseError(format!("Failed to serialize config: {e}")))?;

    tokio::fs::write(config_path, toml_str)
        .await
        .map_err(|e| super::AppError::ParseError(format!("Failed to write config: {e}")))?;

    // 3. Hot-reload: rebuild router + provider registry from the new config
    reload_state(state, config.clone(), config_path)?;

    Ok(())
}

/// Rebuilds [`ReloadableState`] from a validated config and atomically swaps it.
fn reload_state(
    state: &Arc<super::AppState>,
    config: crate::cli::AppConfig,
    _config_path: &Path,
) -> Result<(), super::AppError> {
    let new_router = crate::routing::classify::Router::new(config.clone());

    let new_registry = crate::providers::ProviderRegistry::from_configs_with_models(
        &config.providers,
        Some(state.token_store.clone()),
        &config.models,
        &config.server.timeouts,
    )
    .map_err(|e| {
        super::AppError::ProviderError(format!("Failed to rebuild provider registry: {e}"))
    })?;

    let new_inner = Arc::new(super::ReloadableState::new(
        config,
        new_router,
        Arc::new(new_registry),
    ));

    // Atomic swap
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner;

    info!("Configuration persisted and hot-reloaded");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_providers_section() {
        assert!(is_section_or_key_denied("providers", "anything"));
        assert!(is_section_or_key_denied("providers", "api_key"));
        assert!(is_section_or_key_denied("providers", "name"));
    }

    #[test]
    fn deny_dlp_section() {
        assert!(is_section_or_key_denied("dlp", "enabled"));
        assert!(is_section_or_key_denied("dlp", "scan_input"));
        assert!(is_section_or_key_denied("dlp", "scan_output"));
        assert!(is_section_or_key_denied("dlp", "no_builtins"));
        assert!(is_section_or_key_denied("dlp", "anything"));
    }

    #[test]
    fn deny_api_key_anywhere() {
        assert!(is_section_or_key_denied("router", "api_key"));
        assert!(is_section_or_key_denied("budget", "api_key"));
        assert!(is_section_or_key_denied("cache", "api_key"));
        assert!(is_section_or_key_denied("server", "api_key"));
    }

    #[test]
    fn allow_safe_keys() {
        assert!(!is_section_or_key_denied("router", "default"));
        assert!(!is_section_or_key_denied("router", "think"));
        assert!(!is_section_or_key_denied("budget", "monthly_limit_usd"));
        assert!(!is_section_or_key_denied("cache", "enabled"));
        assert!(!is_section_or_key_denied("cache", "ttl_secs"));
    }

    #[cfg(feature = "mcp")]
    mod mcp_compat {
        use super::*;
        use crate::features::mcp::server::types::ConfigSection;

        #[test]
        fn deny_dlp_via_enum() {
            assert!(is_key_denied(&ConfigSection::Dlp, "enabled"));
            assert!(is_key_denied(&ConfigSection::Dlp, "scan_input"));
        }

        #[test]
        fn deny_credentials_via_enum() {
            assert!(is_key_denied(&ConfigSection::Router, "api_key"));
            assert!(is_key_denied(&ConfigSection::Budget, "api_key"));
        }

        #[test]
        fn allow_safe_via_enum() {
            assert!(!is_key_denied(&ConfigSection::Router, "default"));
            assert!(!is_key_denied(&ConfigSection::Cache, "ttl_secs"));
        }
    }
}
