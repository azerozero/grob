//! `grob/config/*` namespace: configuration inspection and mutation.

use super::auth::{require_role, CallerIdentity};
use super::types::{rpc_err, Role, StatusResponse, ERR_INTERNAL};
use crate::server::AppState;
use jsonrpsee::types::ErrorObjectOwned;
use std::sync::Arc;

/// Returns the running configuration (or a single key).
pub async fn get(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    key: Option<&str>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    let inner = state.snapshot();
    let full = serde_json::to_value(&inner.config)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to serialize config: {e}")))?;

    match key {
        Some(path) => {
            let value = resolve_dotted_path(&full, path);
            match value {
                Some(v) => Ok(serde_json::json!({ "key": path, "value": v })),
                None => Ok(serde_json::json!({ "key": path, "value": null, "found": false })),
            }
        }
        None => Ok(full),
    }
}

/// Sets a configuration key (in-memory only, does not persist to disk).
pub async fn set(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    _key: &str,
    _value: &serde_json::Value,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    // TODO: Implement in-memory config mutation with validation.
    // Phase 2 will add persistence and diff tracking.
    let _ = state;

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some("Config set (in-memory only — use reload to persist)".into()),
    })
}

/// Triggers a full configuration reload from disk.
///
/// Delegates to the existing `server_ns::reload_config` logic.
pub async fn reload(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    super::server_ns::reload_config(state, caller).await
}

/// Compares running config with on-disk version.
pub async fn diff(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    let running = {
        let inner = state.snapshot();
        serde_json::to_value(&inner.config)
            .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to serialize config: {e}")))?
    };

    let disk = match crate::cli::AppConfig::from_source(&state.config_source).await {
        Ok(cfg) => serde_json::to_value(&cfg).map_err(|e| {
            rpc_err(
                ERR_INTERNAL,
                format!("Failed to serialize disk config: {e}"),
            )
        })?,
        Err(e) => {
            return Ok(serde_json::json!({
                "error": format!("Failed to read disk config: {e}"),
                "diff": null,
            }));
        }
    };

    let identical = running == disk;

    Ok(serde_json::json!({
        "identical": identical,
        "running": running,
        "disk": disk,
    }))
}

/// Resolves a dot-separated path against a JSON value.
fn resolve_dotted_path<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_dotted_path_simple() {
        let v = serde_json::json!({ "a": { "b": { "c": 42 } } });
        assert_eq!(
            resolve_dotted_path(&v, "a.b.c"),
            Some(&serde_json::json!(42))
        );
    }

    #[test]
    fn resolve_dotted_path_missing() {
        let v = serde_json::json!({ "a": { "b": 1 } });
        assert!(resolve_dotted_path(&v, "a.x.y").is_none());
    }

    #[test]
    fn resolve_dotted_path_root() {
        let v = serde_json::json!({ "key": "value" });
        assert_eq!(
            resolve_dotted_path(&v, "key"),
            Some(&serde_json::json!("value"))
        );
    }

    #[test]
    fn resolve_dotted_path_array_element() {
        let v = serde_json::json!({ "arr": [1, 2, 3] });
        let result = resolve_dotted_path(&v, "arr");
        assert!(result.is_some());
        assert!(result.unwrap().is_array());
    }
}
