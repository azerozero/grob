use crate::config::AppConfig;
use crate::providers::ProviderRegistry;
use crate::routing::classify::Router;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tracing::{error, info, warn};

use super::config_guard::is_section_or_key_denied;
use super::{AppState, ReloadableState, RequestError};

/// Get full configuration as JSON — API keys are redacted
pub(crate) async fn get_config_json(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let inner = state.snapshot();

    let providers = crate::config::redaction::redact(
        serde_json::to_value(&inner.config.providers).unwrap_or_default(),
    );

    Json(serde_json::json!({
        "server": {
            "host": inner.config.server.host,
            "port": inner.config.server.port,
        },
        "router": {
            "default": inner.config.router.default,
            "background": inner.config.router.background,
            "think": inner.config.router.think,
            "websearch": inner.config.router.websearch,
            "auto_map_regex": inner.config.router.auto_map_regex,
            "background_regex": inner.config.router.background_regex,
            "prompt_rules": inner.config.router.prompt_rules,
        },
        "providers": providers,
        "models": inner.config.models,
    }))
}

/// Update configuration via JSON
pub(crate) async fn update_config_json(
    State(state): State<Arc<AppState>>,
    Json(new_config): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, RequestError> {
    // Reject writes to denied sections or keys before touching disk.
    if let Some(obj) = new_config.as_object() {
        for (section, value) in obj {
            // Whole-section deny check (providers, dlp).
            if is_section_or_key_denied(section, "") {
                warn!(section = %section, "config API: denied write to protected section");
                return Err(RequestError::Forbidden(format!(
                    "denied: section '{}' cannot be modified via the config API",
                    section
                )));
            }
            // Per-key deny check within allowed sections.
            if let Some(inner) = value.as_object() {
                for key in inner.keys() {
                    if is_section_or_key_denied(section, key) {
                        warn!(section = %section, key = %key, "config API: denied write to protected key");
                        return Err(RequestError::Forbidden(format!(
                            "denied: {}.{} cannot be modified via the config API",
                            section, key
                        )));
                    }
                }
            }
        }
    }

    // Read-only guard: reject remote URL configs early.
    let config_path = match &state.config_source {
        crate::cli::ConfigSource::File(p) => p,
        crate::cli::ConfigSource::Url(_) => {
            return Err(RequestError::BadRequest(
                "Cannot save config: loaded from remote URL (read-only)".to_string(),
            ));
        }
    };

    // Read current config and merge the incoming JSON updates into it.
    let config_str = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| RequestError::Internal(anyhow::anyhow!("Failed to read config: {e}")))?;

    let mut config: toml::Value = toml::from_str(&config_str)
        .map_err(|e| RequestError::ParseError(format!("Failed to parse config: {e}")))?;

    let updates = new_config
        .as_object()
        .ok_or_else(|| RequestError::BadRequest("Config patch must be an object".into()))?;
    for (section, patch) in updates {
        match section.as_str() {
            "router" => {
                let fields = patch
                    .as_object()
                    .ok_or_else(|| RequestError::BadRequest("router must be an object".into()))?;
                let table = config
                    .get_mut("router")
                    .and_then(toml::Value::as_table_mut)
                    .ok_or_else(|| RequestError::BadRequest("Missing router table".into()))?;
                for (key, value) in fields {
                    if !matches!(
                        key.as_str(),
                        "default"
                            | "think"
                            | "websearch"
                            | "background"
                            | "auto_map_regex"
                            | "background_regex"
                            | "prompt_rules"
                    ) {
                        return Err(RequestError::BadRequest(format!(
                            "Unsupported router field: {key}"
                        )));
                    }
                    if value.is_null() {
                        if key == "default" {
                            return Err(RequestError::BadRequest(
                                "router.default cannot be null".into(),
                            ));
                        }
                        table.remove(key);
                    } else {
                        let value =
                            serde_json::from_value::<toml::Value>(value.clone()).map_err(|e| {
                                RequestError::BadRequest(format!("Invalid router.{key}: {e}"))
                            })?;
                        table.insert(key.clone(), value);
                    }
                }
            }
            "models" => {
                let models = serde_json::from_value::<toml::Value>(patch.clone())
                    .map_err(|e| RequestError::BadRequest(format!("Invalid models: {e}")))?;
                config
                    .as_table_mut()
                    .expect("parsed config is a table")
                    .insert(section.clone(), models);
            }
            _ => {
                return Err(RequestError::BadRequest(format!(
                    "Unsupported config section: {section}"
                )))
            }
        }
    }

    // Deserialise the merged TOML into AppConfig so we can validate and reload.
    let merged_toml_str = toml::to_string_pretty(&config)
        .map_err(|e| RequestError::Internal(anyhow::anyhow!("Failed to serialize config: {e}")))?;
    let merged_config: crate::config::AppConfig = toml::from_str(&merged_toml_str)
        .map_err(|e| RequestError::ParseError(format!("Invalid config after merge: {e}")))?;

    // Backup, write, and hot-reload via the shared pipeline.
    super::config_guard::persist_and_reload(&state, &merged_config).await?;

    info!("Configuration updated successfully via API");

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Configuration saved and reloaded"
    })))
}

/// Reload configuration without restarting the server.
///
/// Rejects invalid candidates and changes to startup-only config-derived
/// subsystems, leaving the live `inner` snapshot untouched. Accepted reloads
/// are **not** gated on live provider health, because a provider being
/// momentarily unreachable must not block a config swap. Health is still
/// observed: `validate_config`'s live probes run in a detached task that only
/// logs warnings on unhealthy mappings.
pub(crate) async fn reload_config(State(state): State<Arc<AppState>>) -> Response {
    use axum::http::StatusCode;

    info!("🔄 Configuration reload requested via UI");

    // 1. Read and parse new config from source
    let new_config: AppConfig = match AppConfig::from_source(&state.config_source).await {
        Ok(mut c) => {
            super::config_guard::preserve_startup_overrides(&state, &mut c);
            c
        }
        Err(e) => {
            error!("Failed to reload config: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "message": format!("Failed to reload config: {}", e),
                })),
            )
                .into_response();
        }
    };

    // 1b. Reject changes to config-derived subsystems that are initialized only
    //     at startup. This guard applies equally to API writes and direct edits of
    //     the config file followed by this endpoint.
    if let Err(msg) = super::config_guard::ensure_config_reloadable(&state, &new_config) {
        warn!("config reload rejected: {msg}");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": msg,
            })),
        )
            .into_response();
    }

    // 2. Build new router (compiles regexes)
    let new_router = Router::new(new_config.clone());

    // 3. Build new provider registry (reuse existing token_store).
    //    `from_configs_with_models` resolves `secret:<name>` and
    //    `$ENV_VAR` placeholders internally via the supplied backend, so
    //    a hot reload behaves the same as `grob start` and CLI `validate`.
    let secret_backend =
        crate::storage::secrets::build_backend(&new_config.secrets, state.grob_store.clone());
    let new_registry = match ProviderRegistry::from_configs_with_models(
        &new_config.providers,
        secret_backend.clone(),
        Some(state.token_store.clone()),
        &new_config.models,
        &new_config.server.timeouts,
    ) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            error!("Failed to init providers: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "error",
                    "message": format!("Failed to init providers: {}", e),
                })),
            )
                .into_response();
        }
    };

    // 4. Create new reloadable state and atomically swap (write lock held for
    //    microseconds). In-flight requests continue on the old snapshot because
    //    they hold an `Arc<ReloadableState>` taken before the swap.
    //
    //    The candidate is already structurally valid here: `from_source`
    //    re-parsed it and ran `AppConfig::validate()` (model→provider mappings,
    //    provider auth, router regexes), and `from_configs_with_models`
    //    confirmed the registry builds. We do NOT gate the swap on live
    //    provider health — a momentarily unreachable provider must not block a
    //    config reload.
    let new_inner = Arc::new(ReloadableState::new(
        new_config.clone(),
        new_router,
        new_registry.clone(),
    ));

    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner;

    // 5. Spawn a detached live-health probe purely as a signal. It sends a
    //    minimal request to each router mapping and logs warnings on unhealthy
    //    ones, mirroring the `validate_on_start` task in `server::init`. It runs
    //    after the swap and never blocks or reverts the reload.
    spawn_health_probe(new_config, new_registry);

    if active > 0 {
        info!(
            "✅ Configuration reloaded successfully ({} requests still using old config)",
            active
        );
    } else {
        info!("✅ Configuration reloaded successfully");
    }

    Json(serde_json::json!({
        "status": "success",
        "message": "Configuration reloaded",
        "active_requests": active,
    }))
    .into_response()
}

/// Spawns a detached live-health probe over a reloaded config's router models.
///
/// Sends a minimal request to every router mapping and logs warnings on
/// unhealthy ones. Runs as a fire-and-forget [`tokio::spawn`] **after** the
/// atomic swap, so it provides a health signal without ever blocking or
/// reverting the reload — a provider being momentarily unreachable does not
/// fail the swap. Mirrors the `validate_on_start` task in [`super::init`].
pub(crate) fn spawn_health_probe(config: AppConfig, registry: Arc<ProviderRegistry>) {
    tokio::spawn(async move {
        info!("🔍 Probing reloaded config provider health...");
        let results = crate::preset::validate_config(&config, &registry).await;
        crate::preset::log_validation_results(&results);

        let total = results.len();
        let healthy = results.iter().filter(|r| r.any_ok()).count();
        if healthy == total {
            info!("✅ Reload health probe: {healthy}/{total} models healthy");
        } else {
            let unhealthy = results
                .iter()
                .filter(|r| !r.any_ok())
                .map(|r| format!("{} [{}]", r.model_name, r.role))
                .collect::<Vec<_>>()
                .join(", ");
            warn!(
                "⚠️ Reload health probe: {healthy}/{total} models healthy — \
                 no healthy provider for: {unhealthy} (config still reloaded)"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::extract::State;

    fn config_toml(rate_limit_rps: u32, default_model: &str) -> String {
        format!(
            r#"
[server]
host = "127.0.0.1"
port = 18100

[router]
default = "{default_model}"

[security]
rate_limit_rps = {rate_limit_rps}

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha", "beta"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"

[[models]]
name = "beta"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "beta"
"#
        )
    }

    #[tokio::test]
    async fn reload_endpoint_rejects_direct_edit_to_startup_only_section() {
        use crate::cli::{AppConfig, ConfigSource};
        use crate::providers::ProviderRegistry;

        let live_config = AppConfig::from_content(&config_toml(10, "alpha"), "reload_live")
            .expect("live config parses");
        let file = tempfile::NamedTempFile::new().expect("temp config");
        std::fs::write(file.path(), config_toml(20, "beta")).expect("edit config directly");
        let state = crate::server::test_app_state_with_source(
            live_config,
            ProviderRegistry::new(),
            ConfigSource::File(file.path().to_path_buf()),
        );

        let response = reload_config(State(state.clone())).await;
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        assert!(
            String::from_utf8_lossy(&body).contains("[security]"),
            "response should identify the startup-only section"
        );
        assert_eq!(state.snapshot().config.router.default, "alpha");
    }
}
