//! `grob/tools/*` namespace: tool layer inspection and management.

use super::auth::{require_role, CallerIdentity};
use super::types::{Role, StatusResponse};
use crate::server::AppState;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Tool summary returned by `grob/tools/list`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Canonical tool name.
    pub name: String,
    /// Whether the tool is currently injected.
    pub injected: bool,
    /// Only inject when absent from client request.
    pub if_absent: bool,
}

/// Lists tools injected by the tool layer.
pub async fn list(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<Vec<ToolInfo>, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let inner = state.snapshot();
    let tool_cfg = &inner.config.tool_layer;

    if !tool_cfg.enabled {
        return Ok(vec![]);
    }

    let tools: Vec<ToolInfo> = tool_cfg
        .inject
        .iter()
        .map(|r| ToolInfo {
            name: r.tool.clone(),
            injected: true,
            if_absent: r.if_absent,
        })
        .collect();

    Ok(tools)
}

/// Enables a tool by name (in-memory only).
pub async fn enable(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    _tool: &str,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    // TODO(#228): Implement runtime tool enable with config mutation.
    let _ = state;

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some("Tool enabled (in-memory — reload to persist)".into()),
    })
}

/// Disables a tool by name (in-memory only).
pub async fn disable(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    _tool: &str,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    // TODO(#228): Implement runtime tool disable with config mutation.
    let _ = state;

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some("Tool disabled (in-memory — reload to persist)".into()),
    })
}

/// Returns the full tool catalog (inject rules + aliases + capabilities).
pub async fn catalog(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let inner = state.snapshot();
    let tool_cfg = &inner.config.tool_layer;

    let inject_rules: Vec<serde_json::Value> = tool_cfg
        .inject
        .iter()
        .map(|r| {
            serde_json::json!({
                "tool": r.tool,
                "if_absent": r.if_absent,
            })
        })
        .collect();

    let aliases: Vec<serde_json::Value> = tool_cfg
        .aliases
        .iter()
        .map(|a| {
            serde_json::json!({
                "from": a.from,
                "to": a.to,
            })
        })
        .collect();

    let capabilities: serde_json::Value = tool_cfg
        .capabilities
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                serde_json::json!({
                    "tools_supported": v.tools_supported,
                    "no_tool_models": v.no_tool_models,
                }),
            )
        })
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    Ok(serde_json::json!({
        "enabled": tool_cfg.enabled,
        "inject_rules": inject_rules,
        "aliases": aliases,
        "capabilities": capabilities,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_info_serialization() {
        let info = ToolInfo {
            name: "bash".into(),
            injected: true,
            if_absent: true,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["name"], "bash");
        assert_eq!(json["injected"], true);
        assert_eq!(json["if_absent"], true);
    }

    #[test]
    fn tool_info_roundtrip() {
        let info = ToolInfo {
            name: "grep".into(),
            injected: false,
            if_absent: false,
        };
        let json_str = serde_json::to_string(&info).unwrap();
        let parsed: ToolInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.name, "grep");
        assert!(!parsed.injected);
    }

    #[test]
    fn tool_info_if_absent_false() {
        let info = ToolInfo {
            name: "custom".into(),
            injected: true,
            if_absent: false,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["if_absent"], false);
    }
}
