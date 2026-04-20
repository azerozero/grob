use crate::cli::AppConfig;
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
use super::{AppError, AppState, ReloadableState};

/// Redact an API key for safe display (show first 4 + last 4 chars)
pub(crate) fn redact_api_key(key: &str) -> String {
    if key.starts_with('$') {
        return key.to_string(); // Environment variable reference, safe to show
    }
    if key.len() <= 12 {
        return "***".to_string();
    }
    format!("{}...{}", &key[..4], &key[key.len() - 4..])
}

/// Remove null values from JSON (TOML doesn't support null)
fn remove_null_values(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for (_, v) in map.iter_mut() {
                remove_null_values(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                remove_null_values(item);
            }
        }
        _ => {}
    }
}

/// Get full configuration as JSON — API keys are redacted
pub(crate) async fn get_config_json(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let inner = state.snapshot();

    // Redact API keys before serializing.
    // NOTE: serde serializes SecretString via expose_secret, so we must
    // immediately redact to avoid leaking the full key in the JSON response.
    let providers: Vec<serde_json::Value> = inner
        .config
        .providers
        .iter()
        .map(|p| {
            let mut v = serde_json::to_value(p).unwrap_or_default();
            if let Some(obj) = v.as_object_mut() {
                if let Some(key) = obj.get("api_key").and_then(|k| k.as_str()) {
                    obj.insert(
                        "api_key".to_string(),
                        serde_json::Value::String(redact_api_key(key)),
                    );
                }
            }
            v
        })
        .collect();

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
    Json(mut new_config): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Remove null values (TOML doesn't support null)
    remove_null_values(&mut new_config);

    // Reject writes to denied sections or keys before touching disk.
    if let Some(obj) = new_config.as_object() {
        for (section, value) in obj {
            // Whole-section deny check (providers, dlp).
            if is_section_or_key_denied(section, "") {
                warn!(section = %section, "config API: denied write to protected section");
                return Err(AppError::ParseError(format!(
                    "denied: section '{}' cannot be modified via the config API",
                    section
                )));
            }
            // Per-key deny check within allowed sections.
            if let Some(inner) = value.as_object() {
                for key in inner.keys() {
                    if is_section_or_key_denied(section, key) {
                        warn!(section = %section, key = %key, "config API: denied write to protected key");
                        return Err(AppError::ParseError(format!(
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
            return Err(AppError::ParseError(
                "Cannot save config: loaded from remote URL (read-only)".to_string(),
            ));
        }
    };

    // Read current config and merge the incoming JSON updates into it.
    let config_str = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| AppError::ParseError(format!("Failed to read config: {e}")))?;

    let mut config: toml::Value = toml::from_str(&config_str)
        .map_err(|e| AppError::ParseError(format!("Failed to parse config: {e}")))?;

    // Update providers section
    if let Some(providers) = new_config.get("providers") {
        let providers_toml: toml::Value = serde_json::from_str(&providers.to_string())
            .map_err(|e| AppError::ParseError(format!("Failed to convert providers: {e}")))?;

        if let Some(table) = config.as_table_mut() {
            table.insert("providers".to_string(), providers_toml);
        }
    }

    // Update models section
    if let Some(models) = new_config.get("models") {
        let models_toml: toml::Value = serde_json::from_str(&models.to_string())
            .map_err(|e| AppError::ParseError(format!("Failed to convert models: {e}")))?;

        if let Some(table) = config.as_table_mut() {
            table.insert("models".to_string(), models_toml);
        }
    }

    // Update router section if provided
    if let Some(router) = new_config.get("router") {
        if let Some(router_table) = config.get_mut("router").and_then(|v| v.as_table_mut()) {
            let update_field = |table: &mut toml::map::Map<String, toml::Value>,
                                key: &str,
                                value: Option<&serde_json::Value>| {
                if let Some(val) = value {
                    if let Some(s) = val.as_str() {
                        table.insert(key.to_string(), toml::Value::String(s.to_string()));
                    }
                } else {
                    table.remove(key);
                }
            };

            if let Some(default) = router.get("default") {
                if let Some(s) = default.as_str() {
                    router_table.insert("default".to_string(), toml::Value::String(s.to_string()));
                }
            }

            update_field(router_table, "think", router.get("think"));
            update_field(router_table, "websearch", router.get("websearch"));
            update_field(router_table, "background", router.get("background"));
            update_field(router_table, "auto_map_regex", router.get("auto_map_regex"));
            update_field(
                router_table,
                "background_regex",
                router.get("background_regex"),
            );
        }
    }

    // Deserialise the merged TOML into AppConfig so we can validate and reload.
    let merged_toml_str = toml::to_string_pretty(&config)
        .map_err(|e| AppError::ParseError(format!("Failed to serialize config: {e}")))?;
    let merged_config: crate::cli::AppConfig = toml::from_str(&merged_toml_str)
        .map_err(|e| AppError::ParseError(format!("Invalid config after merge: {e}")))?;

    // Backup, write, and hot-reload via the shared pipeline.
    super::config_guard::persist_and_reload(&state, &merged_config).await?;

    info!("Configuration updated successfully via API");

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Configuration saved and reloaded"
    })))
}

/// Reload configuration without restarting the server
pub(crate) async fn reload_config(State(state): State<Arc<AppState>>) -> Response {
    info!("🔄 Configuration reload requested via UI");

    // 1. Read and parse new config from source
    let new_config: AppConfig = match AppConfig::from_source(&state.config_source).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to reload config: {}", e);
            return Json(serde_json::json!({"status": "error", "message": format!("Failed to reload config: {}", e)})).into_response();
        }
    };

    // 2. Build new router (compiles regexes)
    let new_router = Router::new(new_config.clone());

    // 3. Build new provider registry (reuse existing token_store)
    let new_registry = match ProviderRegistry::from_configs_with_models(
        &new_config.providers,
        Some(state.token_store.clone()),
        &new_config.models,
        &new_config.server.timeouts,
    ) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            error!("Failed to init providers: {}", e);
            return Json(serde_json::json!({"status": "error", "message": format!("Failed to init providers: {}", e)})).into_response();
        }
    };

    // 4. Create new reloadable state
    let new_inner = Arc::new(ReloadableState::new(new_config, new_router, new_registry));

    // 5. Atomic swap (write lock held for microseconds)
    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner.clone();

    if active > 0 {
        info!(
            "✅ Configuration reloaded successfully ({} requests still using old config)",
            active
        );
    } else {
        info!("✅ Configuration reloaded successfully");
    }

    // 6. Validate new config in background (non-blocking)
    tokio::spawn(async move {
        info!("🔍 Validating reloaded config...");
        let results =
            crate::preset::validate_config(&new_inner.config, &new_inner.provider_registry).await;
        crate::preset::log_validation_results(&results);
    });

    Json(serde_json::json!({"status": "success", "message": "Configuration reloaded", "active_requests": active})).into_response()
}
