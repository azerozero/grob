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
///
/// Each entry is denied because hot-reloading it cannot be done safely
/// at runtime — either the data is sensitive (and must travel through a
/// dedicated secret API), or the code path that consumes it is set up
/// once at process start and not re-initialised on `/api/config/reload`:
///
/// | Section     | Reason                                                                                  |
/// |-------------|-----------------------------------------------------------------------------------------|
/// | `providers` | Contains API keys; mutate via `grob connect` / secret backend, not the config API.      |
/// | `dlp`       | Security policy must not be weakened by an authenticated control-plane caller.          |
/// | `tee`       | TEE attestation runs at startup; flipping the mode mid-flight bypasses the gate.        |
/// | `fips`      | FIPS mode is checked once on init; toggling at runtime gives a false sense of compliance. |
///
/// To change any of these the operator must edit `~/.grob/config.toml`
/// and restart the daemon.
const DENIED_SECTIONS: &[&str] = &["providers", "dlp", "tee", "fips"];

/// Per-section keys that are never writable via any config API.
///
/// These are individual fields whose host section is otherwise editable,
/// but the field itself is either credential material or wired into a
/// non-reloadable subsystem:
///
/// | Section.Key        | Reason                                                                          |
/// |--------------------|---------------------------------------------------------------------------------|
/// | `router.api_key`   | Credential material — never round-trip through the config API.                  |
/// | `budget.api_key`   | Same.                                                                           |
/// | `cache.api_key`    | Same.                                                                           |
/// | `server.tls`       | TLS listener is bound at startup; rebuilding it requires a daemon restart.      |
/// | `secrets.backend`  | The secret backend is constructed once and shared via `Arc`; swapping it at     |
/// |                    | runtime would orphan in-flight readers and change credential resolution semantics. |
const DENIED_KEYS: &[(&str, &str)] = &[
    ("router", "api_key"),
    ("budget", "api_key"),
    ("cache", "api_key"),
    ("server", "tls"),
    ("secrets", "backend"),
];

/// Checks whether a (section, key) pair is blocked by the deny-list.
///
/// Returns `true` when the write must be rejected. See [`DENIED_SECTIONS`]
/// and [`DENIED_KEYS`] for the rationale behind every entry. A denied
/// attempt is logged at INFO so the operator sees actionable guidance
/// (restart instead of expecting a silent reload to take effect).
pub fn is_section_or_key_denied(section: &str, key: &str) -> bool {
    if DENIED_SECTIONS.contains(&section) {
        info!(
            section = %section,
            "config hot-reload: section is on the deny-list; restart the daemon to apply changes"
        );
        return true;
    }
    if key == "api_key" {
        info!(
            section = %section,
            key = %key,
            "config hot-reload: api_key fields cannot be set via the config API; use `grob connect` or the secret backend"
        );
        return true;
    }
    if DENIED_KEYS.iter().any(|(s, k)| *s == section && *k == key) {
        info!(
            section = %section,
            key = %key,
            "config hot-reload: key is on the deny-list; restart the daemon to apply changes"
        );
        return true;
    }
    false
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
        ConfigSection::Classifier => "classifier",
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
    config: &crate::models::config::AppConfig,
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
///
/// Resolves `secret:<name>` and `$ENV_VAR` placeholders in `[[providers]]
/// api_key` before constructing the new registry. Without this step, a hot
/// reload that touches a provider declared with `api_key = "secret:foo"`
/// would push the literal placeholder back into the registry and every
/// upstream call would fail with 401 until the daemon is fully restarted.
/// Same code path as `server::init` and `preset::build_registry`.
fn reload_state(
    state: &Arc<super::AppState>,
    config: crate::models::config::AppConfig,
    _config_path: &Path,
) -> Result<(), super::AppError> {
    let new_router = crate::routing::classify::Router::new(config.clone());

    let secret_backend =
        crate::storage::secrets::build_backend(&config.secrets, state.grob_store.clone());

    let new_registry = crate::providers::ProviderRegistry::from_configs_with_models(
        &config.providers,
        secret_backend.as_ref(),
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

    #[test]
    fn deny_static_init_sections() {
        // tee and fips are checked once at startup; toggling them at runtime
        // would bypass the gate without the operator realising.
        assert!(is_section_or_key_denied("tee", "mode"));
        assert!(is_section_or_key_denied("tee", "sealed_keys"));
        assert!(is_section_or_key_denied("fips", "mode"));
        assert!(is_section_or_key_denied("fips", "anything"));
    }

    #[test]
    fn deny_static_init_keys() {
        // The TLS listener and secret backend are constructed once on
        // process start; both require a daemon restart to swap.
        assert!(is_section_or_key_denied("server", "tls"));
        assert!(is_section_or_key_denied("secrets", "backend"));
        // Sibling keys in the same sections must remain editable.
        assert!(!is_section_or_key_denied("server", "host"));
        assert!(!is_section_or_key_denied("server", "port"));
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
