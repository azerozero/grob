//! Wizard MCP surface (ADR-0011) — first-run/setup helpers exposed as MCP tools.
//!
//! These tools mirror the `grob doctor` and config-edit flows for MCP-native
//! setup wizards: read sections, apply batched updates, run programmatic
//! health checks. Same deny-list and persistence pipeline as `grob_configure`.

use super::config::{apply_config_update, parse_section, read_config_section};
use crate::features::mcp::server::types::{ConfigSection, JsonRpcError, JsonRpcResponse};
use crate::server::config_guard::is_key_denied;
use crate::server::AppState;
use std::sync::Arc;

/// Handles `wizard_get_config` — returns the safe view of one or every section.
///
/// # Errors
///
/// Returns a JSON-RPC error when the optional `section` parameter is not a
/// recognized [`ConfigSection`].
pub async fn handle_wizard_get_config(
    state: &Arc<AppState>,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let section = parse_section(params.get("section"))
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e))?;

    let snapshot = state.snapshot();
    let config = &snapshot.config;

    let result = match section {
        Some(s) => {
            serde_json::json!({
                "section": s.to_string(),
                "config": read_config_section(config, &s),
            })
        }
        None => serde_json::json!({
            "router": read_config_section(config, &ConfigSection::Router),
            "budget": read_config_section(config, &ConfigSection::Budget),
            "dlp": read_config_section(config, &ConfigSection::Dlp),
            "cache": read_config_section(config, &ConfigSection::Cache),
            "classifier": read_config_section(config, &ConfigSection::Classifier),
        }),
    };

    tracing::info!("MCP: wizard_get_config");
    Ok(JsonRpcResponse::ok(id, result))
}

/// Handles `wizard_set_section` — applies a batch of key/value updates to a section.
///
/// # Errors
///
/// Returns a JSON-RPC error when `section` is missing or invalid, when
/// `values` is missing/empty/malformed, when any key is denied by the policy,
/// when a value type is invalid, or when persistence/hot-reload fails.
pub async fn handle_wizard_set_section(
    state: &Arc<AppState>,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let section: ConfigSection = serde_json::from_value(
        params
            .get("section")
            .cloned()
            .ok_or_else(|| JsonRpcError::invalid_params(id.clone(), "missing 'section'"))?,
    )
    .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    let values = params
        .get("values")
        .and_then(|v| v.as_object())
        .ok_or_else(|| JsonRpcError::invalid_params(id.clone(), "'values' must be an object"))?
        .clone();

    if values.is_empty() {
        return Err(JsonRpcError::invalid_params(
            id,
            "'values' must contain at least one key",
        ));
    }

    let mut new_config = state.snapshot().config.clone();
    let mut applied = Vec::with_capacity(values.len());

    for (key, value) in &values {
        if is_key_denied(&section, key) {
            return Err(JsonRpcError::invalid_params(
                id,
                &format!(
                    "denied: {}.{} cannot be modified via wizard surface",
                    section, key
                ),
            ));
        }
        apply_config_update(&mut new_config, &section, key, value)
            .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e))?;
        applied.push(key.clone());
    }

    crate::server::config_guard::persist_and_reload(state, &new_config)
        .await
        .map_err(|e| JsonRpcError::internal(id.clone(), &e.to_string()))?;

    tracing::info!(
        section = %section,
        count = applied.len(),
        "MCP: wizard_set_section applied + hot-reload"
    );

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "section": section.to_string(),
            "applied": applied,
            "status": "applied",
        }),
    ))
}

/// Handles `wizard_run_doctor` — programmatic doctor checks returning JSON.
///
/// # Errors
///
/// This handler does not currently produce JSON-RPC errors; the `Result` type
/// is preserved for symmetry with the other wizard handlers and for future
/// extensibility (e.g., privileged-only checks).
pub async fn handle_wizard_run_doctor(
    state: &Arc<AppState>,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let snapshot = state.snapshot();
    let config = &snapshot.config;

    let providers = &config.providers;
    let enabled = providers.iter().filter(|p| p.is_enabled()).count();
    let with_creds = providers
        .iter()
        .filter(|p| p.is_enabled() && (p.api_key.is_some() || p.oauth_provider.is_some()))
        .count();

    let mut missing_env: Vec<String> = Vec::new();
    for provider in providers {
        if !provider.is_enabled() {
            continue;
        }
        if let Some(ref key) = provider.api_key {
            if let Some(var) = secrecy::ExposeSecret::expose_secret(key).strip_prefix('$') {
                if std::env::var(var).is_err() {
                    missing_env.push(format!("{}:{}", provider.name, var));
                }
            }
        }
    }

    let checks = serde_json::json!({
        "providers": {
            "enabled": enabled,
            "with_credentials": with_creds,
            "status": if enabled == 0 { "error" }
                      else if with_creds < enabled { "warning" }
                      else { "ok" },
        },
        "models": {
            "count": config.models.len(),
            "status": if config.models.is_empty() { "error" } else { "ok" },
        },
        "missing_env_vars": missing_env,
        "dlp_enabled": config.dlp.enabled,
        "security_enabled": config.security.enabled,
    });

    let severity = if enabled == 0 || config.models.is_empty() || !missing_env.is_empty() {
        "error"
    } else if with_creds < enabled {
        "warning"
    } else {
        "ok"
    };

    tracing::info!(severity, "MCP: wizard_run_doctor");

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "severity": severity,
            "checks": checks,
        }),
    ))
}
