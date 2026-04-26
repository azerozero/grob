//! `grob_configure` and `grob_autotune` MCP tools — self-tuning configuration surface.
//!
//! Both tools share the same safety contract: any key flagged by
//! [`crate::server::config_guard::is_key_denied`] (credentials, security
//! settings, bind address, …) is rejected before mutation. Approved updates
//! are persisted and hot-reloaded via
//! [`crate::server::config_guard::persist_and_reload`].

use super::config::{apply_config_update, read_config_section};
use crate::features::mcp::server::types::{
    ConfigSection, ConfigureAction, ConfigureParams, JsonRpcError, JsonRpcResponse,
};
use crate::server::config_guard::is_key_denied;
use crate::server::AppState;
use std::sync::Arc;

/// Handles `grob_configure` — self-tuning configuration tool for MCP agents.
///
/// Agents can read safe config subsets and update whitelisted parameters.
/// Credential, security, and bind-address modifications are always rejected.
///
/// # Errors
///
/// Returns a JSON-RPC error when `params` cannot be deserialized into
/// [`ConfigureParams`], when the requested key is denied by the policy, when
/// the value type is invalid, or when persistence/hot-reload fails.
pub async fn handle_configure(
    state: &Arc<AppState>,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let p: ConfigureParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    match p.action {
        ConfigureAction::Read { ref section } => {
            let snapshot = state.snapshot();
            let data = read_config_section(&snapshot.config, section);

            tracing::info!(section = %section, "MCP: grob_configure read");

            Ok(JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "action": "read",
                    "section": section.to_string(),
                    "config": data,
                }),
            ))
        }
        ConfigureAction::Update {
            ref section,
            ref key,
            ref value,
        } => {
            if is_key_denied(section, key) {
                tracing::warn!(
                    section = %section,
                    key = %key,
                    "MCP: grob_configure denied update (security policy)"
                );
                return Err(JsonRpcError::invalid_params(
                    id,
                    &format!(
                        "denied: {}.{} cannot be modified via self-tuning",
                        section, key
                    ),
                ));
            }

            // Clone the current config, apply the change, then persist + reload.
            let mut new_config = {
                let snapshot = state.snapshot();
                snapshot.config.clone()
            };

            apply_config_update(&mut new_config, section, key, value)
                .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e))?;

            // Backup, write, and hot-reload via the shared pipeline.
            crate::server::config_guard::persist_and_reload(state, &new_config)
                .await
                .map_err(|e| JsonRpcError::internal(id.clone(), &e.to_string()))?;

            tracing::info!(
                section = %section,
                key = %key,
                "MCP: grob_configure applied update + hot-reload"
            );

            Ok(JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "action": "update",
                    "section": section.to_string(),
                    "key": key,
                    "status": "applied",
                }),
            ))
        }
    }
}

/// Handles `grob_autotune` — exposes the classifier as a batchable tuning surface.
///
/// `action=suggest` returns the current weights and thresholds with a no-op
/// proposed value (the MVP does not infer patches; future revisions will).
/// `action=apply` accepts a list of `{key, value}` patches and persists them
/// via the same pipeline as `grob_configure update section=classifier`.
///
/// # Errors
///
/// Returns a JSON-RPC error for unknown actions, missing/invalid `patches`,
/// denied classifier keys, or persistence/hot-reload failures.
pub async fn handle_autotune(
    state: &Arc<AppState>,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    use crate::routing::classify::autotune::{current_snapshot, AutotunePatch};

    let action = params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("suggest");

    match action {
        "suggest" => {
            let snapshot = state.snapshot();
            let cfg = snapshot.config.classifier.clone().unwrap_or_default();
            let suggestions = current_snapshot(&cfg);

            tracing::info!(count = suggestions.len(), "MCP: grob_autotune suggest");

            Ok(JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "action": "suggest",
                    "suggestions": suggestions,
                }),
            ))
        }
        "apply" => {
            let patches: Vec<AutotunePatch> = match params.get("patches") {
                Some(v) => serde_json::from_value(v.clone()).map_err(|e| {
                    JsonRpcError::invalid_params(id.clone(), &format!("invalid patches: {e}"))
                })?,
                None => {
                    return Err(JsonRpcError::invalid_params(
                        id,
                        "action=apply requires a 'patches' array",
                    ))
                }
            };

            if patches.is_empty() {
                return Err(JsonRpcError::invalid_params(
                    id,
                    "'patches' must contain at least one entry",
                ));
            }

            let mut new_config = state.snapshot().config.clone();
            for patch in &patches {
                if is_key_denied(&ConfigSection::Classifier, &patch.key) {
                    return Err(JsonRpcError::invalid_params(
                        id,
                        &format!("denied: classifier.{} cannot be modified", patch.key),
                    ));
                }
                apply_config_update(
                    &mut new_config,
                    &ConfigSection::Classifier,
                    &patch.key,
                    &serde_json::json!(patch.value),
                )
                .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e))?;
            }

            crate::server::config_guard::persist_and_reload(state, &new_config)
                .await
                .map_err(|e| JsonRpcError::internal(id.clone(), &e.to_string()))?;

            tracing::info!(
                applied = patches.len(),
                "MCP: grob_autotune apply + hot-reload"
            );

            Ok(JsonRpcResponse::ok(
                id,
                serde_json::json!({
                    "action": "apply",
                    "applied_count": patches.len(),
                    "status": "applied",
                }),
            ))
        }
        other => Err(JsonRpcError::invalid_params(
            id,
            &format!("unknown action '{other}' (expected 'suggest' or 'apply')"),
        )),
    }
}
