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
/// | `metrics.bearer_token` | `/metrics` auth token is resolved once at startup into non-reloadable state; |
/// | `metrics.bearer_token_file` | hot-reloading it would leave `/metrics` on its old posture (false sense of security). |
const DENIED_KEYS: &[(&str, &str)] = &[
    ("router", "api_key"),
    ("budget", "api_key"),
    ("cache", "api_key"),
    ("server", "tls"),
    ("secrets", "backend"),
    ("metrics", "bearer_token"),
    ("metrics", "bearer_token_file"),
];

/// Message returned when a hot reload would change the `/metrics` bearer token.
///
/// The token is resolved once at startup into non-reloadable
/// [`super::ObservabilityState`], so a reload cannot re-apply it — surfacing this
/// instead of silently keeping the old posture avoids a false sense of security.
pub const METRICS_AUTH_RESTART_MSG: &str =
    "[metrics] bearer_token / bearer_token_file changes require a daemon restart — the token is \
     resolved once at startup, so /metrics auth was NOT changed by this reload";

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

/// Ensures a candidate config neither changes nor breaks the live `/metrics`
/// bearer token, which is resolved **once at startup** into non-reloadable
/// [`super::ObservabilityState`].
///
/// This is the single choke-point every reload path MUST call (HTTP
/// `/api/config` + `/api/config/reload`, RPC `grob/server/reload_config`, MCP
/// self-tuning) so none can silently keep the old `/metrics` posture. Comparison
/// uses the **resolved** tokens, so an inline change, a file-path change, and a
/// same-path file-content change are all caught.
///
/// A candidate whose `bearer_token_file` cannot be read is also rejected: masking
/// the read error as "no token" would let an operator who just pointed at a bad
/// path believe `/metrics` became gated when it actually stays public.
///
/// # Errors
///
/// Returns the user-facing "restart required" message when the resolved token
/// would change, or when a configured token source fails to resolve.
pub fn ensure_metrics_auth_reloadable(
    state: &Arc<super::AppState>,
    candidate: &crate::config::AppConfig,
) -> Result<(), String> {
    use secrecy::ExposeSecret;

    // A configured-but-unreadable source is a hard error, NOT silently "public":
    // the operator's intent (gate /metrics) cannot be honoured without a restart.
    let next = candidate.metrics.resolve_bearer_token().map_err(|e| {
        format!("{METRICS_AUTH_RESTART_MSG} (candidate [metrics] bearer_token_file could not be read: {e})")
    })?;

    let live = state
        .observability
        .metrics_bearer_token
        .as_ref()
        .map(|s| s.expose_secret().to_string());
    let next = next.map(|s| s.expose_secret().to_string());

    if live != next {
        return Err(METRICS_AUTH_RESTART_MSG.to_string());
    }
    Ok(())
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
    config: &crate::config::AppConfig,
) -> Result<(), super::RequestError> {
    let config_path = match &state.config_source {
        crate::cli::ConfigSource::File(p) => p,
        crate::cli::ConfigSource::Url(_) => {
            return Err(super::RequestError::BadRequest(
                "Cannot save config: loaded from remote URL (read-only)".to_string(),
            ));
        }
    };

    // Reject a `/metrics` token change BEFORE any persistence, so the on-disk
    // config and the running token never diverge (the token is resolved once at
    // startup and cannot be hot-applied).
    ensure_metrics_auth_reloadable(state, config).map_err(super::RequestError::BadRequest)?;

    // 1. Backup
    let backup_path = config_path.with_extension("toml.backup");
    tokio::fs::copy(config_path, &backup_path)
        .await
        .map_err(|e| {
            super::RequestError::Internal(anyhow::anyhow!("Failed to create backup: {e}"))
        })?;

    // 2. Serialise and write
    let toml_str = toml::to_string_pretty(config).map_err(|e| {
        super::RequestError::Internal(anyhow::anyhow!("Failed to serialize config: {e}"))
    })?;

    let config_path_for_write = config_path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::storage::atomic::write_atomic(&config_path_for_write, toml_str.as_bytes())
    })
    .await
    .map_err(|e| {
        super::RequestError::Internal(anyhow::anyhow!("Failed to join config write task: {e}"))
    })?
    .map_err(|e| super::RequestError::Internal(anyhow::anyhow!("Failed to write config: {e}")))?;

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
    config: crate::config::AppConfig,
    _config_path: &Path,
) -> Result<(), super::RequestError> {
    // NOTE: the `/metrics` token guard runs in `persist_and_reload` BEFORE any
    // write, so it is intentionally not repeated here (this is reached only after
    // that check has passed).

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
        super::RequestError::Internal(anyhow::anyhow!("Failed to rebuild provider registry: {e}"))
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

    #[test]
    fn deny_metrics_bearer_token_keys() {
        // The /metrics bearer token is resolved once at startup; changing it via
        // the JSON config API must be rejected (restart required).
        assert!(is_section_or_key_denied("metrics", "bearer_token"));
        assert!(is_section_or_key_denied("metrics", "bearer_token_file"));
    }

    // Helper: a minimal, parseable config with an optional extra `[metrics]`.
    #[cfg(test)]
    fn guard_config(extra: &str) -> crate::config::AppConfig {
        let base = r#"
[server]
host = "127.0.0.1"
port = 18098

[router]
default = "alpha"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"
"#;
        crate::cli::AppConfig::from_content(&format!("{base}{extra}"), "guard_test")
            .expect("config parses")
    }

    // The reload gap the review caught: changing/adding/removing the /metrics
    // token must be rejected by the shared guard (restart required).
    #[tokio::test]
    async fn metrics_auth_change_is_rejected() {
        use crate::providers::ProviderRegistry;

        let with_token = "\n[metrics]\nbearer_token = \"live-token\"\n";
        let live = crate::server::test_app_state(guard_config(with_token), ProviderRegistry::new());

        // Unchanged token → Ok (other sections may still reload).
        assert!(ensure_metrics_auth_reloadable(&live, &guard_config(with_token)).is_ok());
        // Different token → rejected with a restart-required message.
        let err = ensure_metrics_auth_reloadable(
            &live,
            &guard_config("\n[metrics]\nbearer_token = \"rotated\"\n"),
        )
        .expect_err("rotation must be rejected");
        assert!(
            err.contains("restart"),
            "message must mention restart: {err}"
        );
        // Token removed → rejected (would silently open /metrics).
        assert!(ensure_metrics_auth_reloadable(&live, &guard_config("")).is_err());

        // Public live state: ADDING a token is the exact gap — must be rejected.
        let public = crate::server::test_app_state(guard_config(""), ProviderRegistry::new());
        assert!(ensure_metrics_auth_reloadable(
            &public,
            &guard_config("\n[metrics]\nbearer_token = \"added\"\n")
        )
        .is_err());
        // Staying public → Ok (default reloads keep working).
        assert!(ensure_metrics_auth_reloadable(&public, &guard_config("")).is_ok());
    }

    // #2: a configured-but-unreadable bearer_token_file must NOT be masked as
    // "no token". From a public live state, pointing at a bad path is rejected
    // (not silently kept public).
    #[tokio::test]
    async fn metrics_unreadable_token_file_is_rejected_from_public() {
        use crate::providers::ProviderRegistry;

        let public = crate::server::test_app_state(guard_config(""), ProviderRegistry::new());
        let candidate =
            guard_config("\n[metrics]\nbearer_token_file = \"/no/such/grob-metrics-token\"\n");
        let err = ensure_metrics_auth_reloadable(&public, &candidate)
            .expect_err("unreadable token file must be rejected, not treated as public");
        assert!(
            err.contains("restart") || err.contains("could not be read"),
            "message must explain the rejection: {err}"
        );
    }

    // #3: persist_and_reload must reject a token change BEFORE persisting. The
    // test state's config_source points at a non-existent "test.toml", so if the
    // metrics check ran AFTER the backup we'd get an IO error instead of the
    // BadRequest restart message — proving the check runs first.
    #[tokio::test]
    async fn persist_and_reload_rejects_token_change_before_write() {
        use crate::providers::ProviderRegistry;

        let live = crate::server::test_app_state(
            guard_config("\n[metrics]\nbearer_token = \"live\"\n"),
            ProviderRegistry::new(),
        );
        let candidate = guard_config("\n[metrics]\nbearer_token = \"rotated\"\n");
        let err = persist_and_reload(&live, &candidate)
            .await
            .expect_err("token change must be rejected before any write");
        if let crate::server::RequestError::BadRequest(msg) = err {
            assert!(
                msg.contains("restart"),
                "must be the restart message: {msg}"
            );
        } else {
            panic!("expected BadRequest (pre-write guard), got an IO/other error");
        }
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
