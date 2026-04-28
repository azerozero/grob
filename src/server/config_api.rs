use crate::models::config::AppConfig;
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
    let merged_config: crate::models::config::AppConfig = toml::from_str(&merged_toml_str)
        .map_err(|e| AppError::ParseError(format!("Invalid config after merge: {e}")))?;

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
/// The handler **awaits** validation against the candidate provider registry
/// before swapping the live config. A failure in any router model surfaces as
/// a 4xx response and the in-flight `inner` snapshot is left untouched, so
/// in-flight requests never see a half-validated config and a misconfigured
/// reload cannot temporarily serve traffic.
pub(crate) async fn reload_config(State(state): State<Arc<AppState>>) -> Response {
    use axum::http::StatusCode;

    info!("🔄 Configuration reload requested via UI");

    // 1. Read and parse new config from source
    let new_config: AppConfig = match AppConfig::from_source(&state.config_source).await {
        Ok(c) => c,
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
        secret_backend.as_ref(),
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

    // 4. Validate the candidate config BEFORE swapping. Awaiting here is
    // intentional — if validation fails we must surface the error and keep
    // the live snapshot intact, so in-flight requests never observe a
    // half-validated config.
    info!("🔍 Validating reloaded config...");
    let validation = crate::preset::validate_config(&new_config, &new_registry).await;
    crate::preset::log_validation_results(&validation);

    if let Some(rejection) = reject_if_validation_broken(&validation) {
        error!(
            "Configuration reload rejected: validation failed for {}",
            rejection.detail
        );
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "status": "error",
                "message": format!(
                    "Validation failed — config not reloaded. Models with no healthy provider: {}",
                    rejection.detail,
                ),
                "broken_models": rejection.broken_models,
            })),
        )
            .into_response();
    }

    // 5. Create new reloadable state and atomically swap (write lock held
    // for microseconds). In-flight requests continue on the old snapshot
    // because they hold an `Arc<ReloadableState>` from before the swap.
    let new_inner = Arc::new(ReloadableState::new(new_config, new_router, new_registry));

    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner;

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

/// Internal carrier for a validation rejection — feeds the 4xx response body.
///
/// Extracted so the rejection logic can be unit-tested without standing up an
/// `AppState` or a full `Router`.
struct ValidationRejection {
    detail: String,
    broken_models: Vec<serde_json::Value>,
}

/// Returns `Some(rejection)` when at least one router model has zero healthy
/// providers in the candidate registry; otherwise `None`.
///
/// The reload handler short-circuits on `Some(_)` and leaves the live config
/// untouched, satisfying the "in-flight requests keep using the old snapshot"
/// invariant.
fn reject_if_validation_broken(
    validation: &[crate::preset::ModelValidation],
) -> Option<ValidationRejection> {
    let broken: Vec<&crate::preset::ModelValidation> =
        validation.iter().filter(|m| !m.any_ok()).collect();
    if broken.is_empty() {
        return None;
    }
    let detail = broken
        .iter()
        .map(|m| format!("{} [{}]", m.model_name, m.role))
        .collect::<Vec<_>>()
        .join(", ");
    let broken_models = broken
        .iter()
        .map(|m| {
            serde_json::json!({
                "model": m.model_name,
                "role": m.role,
            })
        })
        .collect();
    Some(ValidationRejection {
        detail,
        broken_models,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preset::{MappingResult, ModelValidation};

    fn ok_mapping() -> MappingResult {
        MappingResult {
            priority: 1,
            provider: "p".into(),
            actual_model: "m".into(),
            ok: true,
            detail: "OK (12ms)".into(),
        }
    }

    fn broken_mapping(detail: &str) -> MappingResult {
        MappingResult {
            priority: 1,
            provider: "p".into(),
            actual_model: "m".into(),
            ok: false,
            detail: detail.into(),
        }
    }

    #[test]
    fn empty_validation_passes() {
        // No router models declared → nothing to validate → no rejection.
        // Preserves the prior "soft" reload contract for minimal configs.
        assert!(reject_if_validation_broken(&[]).is_none());
    }

    #[test]
    fn all_ok_validation_passes() {
        let results = vec![ModelValidation {
            model_name: "default".into(),
            role: "default".into(),
            mappings: vec![ok_mapping()],
        }];
        assert!(reject_if_validation_broken(&results).is_none());
    }

    #[test]
    fn at_least_one_healthy_mapping_passes() {
        // any_ok() — a single healthy mapping is enough; a fallback being
        // rate-limited at reload time should not block the reload.
        let results = vec![ModelValidation {
            model_name: "default".into(),
            role: "default".into(),
            mappings: vec![ok_mapping(), broken_mapping("429 - rate limited")],
        }];
        assert!(reject_if_validation_broken(&results).is_none());
    }

    #[test]
    fn rejects_when_any_router_model_has_zero_healthy_mappings() {
        // Regression guard for the race the parent fix targets: a config where
        // a router slot points at a model with no working provider must NOT
        // be swapped in.
        let results = vec![
            ModelValidation {
                model_name: "default".into(),
                role: "default".into(),
                mappings: vec![ok_mapping()],
            },
            ModelValidation {
                model_name: "missing-think-model".into(),
                role: "think".into(),
                mappings: vec![broken_mapping("Model not found in [[models]]")],
            },
        ];
        let rejection = reject_if_validation_broken(&results)
            .expect("expected rejection for the broken router model");
        assert!(rejection.detail.contains("missing-think-model [think]"));
        assert_eq!(rejection.broken_models.len(), 1);
        assert_eq!(rejection.broken_models[0]["model"], "missing-think-model");
        assert_eq!(rejection.broken_models[0]["role"], "think");
    }

    #[test]
    fn rejects_with_multiple_broken_models_in_detail() {
        let results = vec![
            ModelValidation {
                model_name: "default".into(),
                role: "default".into(),
                mappings: vec![broken_mapping("connection refused")],
            },
            ModelValidation {
                model_name: "think".into(),
                role: "think".into(),
                mappings: vec![broken_mapping("connection refused")],
            },
        ];
        let rejection =
            reject_if_validation_broken(&results).expect("expected rejection for broken models");
        assert!(rejection.detail.contains("default [default]"));
        assert!(rejection.detail.contains("think [think]"));
        assert_eq!(rejection.broken_models.len(), 2);
    }
}
