//! `grob/tools/*` namespace: tool layer inspection and management.

use super::auth::{require_role, CallerIdentity};
use super::types::{rpc_err, Role, StatusResponse, ERR_INTERNAL};
use crate::features::tool_layer::config::InjectRule;
use crate::providers::ProviderRegistry;
use crate::routing::classify::Router;
use crate::server::{AppState, ReloadableState};
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
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

/// Enables a tool by name (adds an inject rule, in-memory only).
///
/// Appends `InjectRule { tool, if_absent: true }` to
/// `config.tool_layer.inject`, mirroring TOML-declared rules. Disk
/// persistence is out of scope (#228); the change reverts on next reload.
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` when the caller is below `Admin`.
/// Returns `INVALID_PARAMS_CODE` when `tool` is empty or already enabled.
/// Returns `ERR_INTERNAL` when the registry rebuild or atomic swap fails.
pub async fn enable(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    tool: &str,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;
    let mut new_config = state.snapshot().config.clone();
    apply_enable(&mut new_config, tool)?;
    swap_state(state, new_config, caller, &format!("enable tool '{tool}'"))?;
    Ok(StatusResponse {
        status: "ok".into(),
        message: Some(format!(
            "Tool '{tool}' enabled (in-memory only — change reverts on next disk reload)"
        )),
    })
}

/// Disables a tool by name (removes the inject rule, in-memory only).
///
/// All matching `InjectRule` entries are removed from
/// `config.tool_layer.inject`. Aliases that map TO the disabled tool are
/// kept in place so client requests still resolve through them. Disk
/// persistence is out of scope (#228); the change reverts on next reload.
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` when the caller is below `Admin`.
/// Returns `INVALID_PARAMS_CODE` when `tool` is empty or not currently enabled.
/// Returns `ERR_INTERNAL` when the registry rebuild or atomic swap fails.
pub async fn disable(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    tool: &str,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;
    let mut new_config = state.snapshot().config.clone();
    apply_disable(&mut new_config, tool)?;
    swap_state(state, new_config, caller, &format!("disable tool '{tool}'"))?;
    Ok(StatusResponse {
        status: "ok".into(),
        message: Some(format!(
            "Tool '{tool}' disabled (in-memory only — change reverts on next disk reload)"
        )),
    })
}

/// Pure mutation helper for `enable`. Validates the tool name and pushes
/// the new `InjectRule` into the supplied config. Separated from the
/// async handler so the validation logic is unit-testable without an
/// `AppState`.
fn apply_enable(
    config: &mut crate::models::config::AppConfig,
    tool: &str,
) -> Result<(), ErrorObjectOwned> {
    if tool.trim().is_empty() {
        return Err(rpc_err(INVALID_PARAMS_CODE, "tool name cannot be empty"));
    }
    if config.tool_layer.inject.iter().any(|r| r.tool == tool) {
        return Err(rpc_err(
            INVALID_PARAMS_CODE,
            format!("tool '{tool}' is already enabled"),
        ));
    }
    config.tool_layer.inject.push(InjectRule {
        tool: tool.to_string(),
        if_absent: true,
    });
    Ok(())
}

/// Pure mutation helper for `disable`. Removes any inject rule matching
/// `tool` from the supplied config. Separated for unit-testability.
fn apply_disable(
    config: &mut crate::models::config::AppConfig,
    tool: &str,
) -> Result<(), ErrorObjectOwned> {
    if tool.trim().is_empty() {
        return Err(rpc_err(INVALID_PARAMS_CODE, "tool name cannot be empty"));
    }
    let before = config.tool_layer.inject.len();
    config.tool_layer.inject.retain(|r| r.tool != tool);
    if config.tool_layer.inject.len() == before {
        return Err(rpc_err(
            INVALID_PARAMS_CODE,
            format!("tool '{tool}' is not enabled"),
        ));
    }
    Ok(())
}

/// Rebuilds reloadable state from a mutated config and atomically swaps
/// it. Mirrors the helper used by `config_ns::set` and `server_ns::reload_config`.
/// In-memory only — see [`tools/enable`] / [`tools/disable`] for rationale.
fn swap_state(
    state: &Arc<AppState>,
    new_config: crate::models::config::AppConfig,
    caller: &CallerIdentity,
    action: &str,
) -> Result<(), ErrorObjectOwned> {
    let new_router = Router::new(new_config.clone());
    let secret_backend =
        crate::storage::secrets::build_backend(&new_config.secrets, state.grob_store.clone());
    let new_registry = ProviderRegistry::from_configs_with_models(
        &new_config.providers,
        secret_backend.as_ref(),
        Some(state.token_store.clone()),
        &new_config.models,
        &new_config.server.timeouts,
    )
    .map(Arc::new)
    .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to rebuild providers: {e}")))?;

    let new_inner = Arc::new(ReloadableState::new(new_config, new_router, new_registry));
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner;

    tracing::info!(
        caller_ip = %caller.ip,
        action = action,
        "RPC tools/* applied (in-memory only)"
    );
    Ok(())
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
    use crate::models::config::AppConfig;
    use crate::server::rpc::types::ERR_FORBIDDEN;

    /// Minimal AppConfig for tool_layer mutation tests.
    fn fixture_config() -> AppConfig {
        let toml = r#"
[router]
default = "claude-sonnet-4-6"

[cache]
enabled = false
max_capacity = 100
ttl_secs = 60
max_entry_bytes = 8192

[tool_layer]
enabled = true

[[tool_layer.inject]]
tool = "bash"
if_absent = true
"#;
        toml::from_str(toml).expect("valid test TOML")
    }

    #[test]
    fn enable_appends_inject_rule() {
        let mut config = fixture_config();
        apply_enable(&mut config, "grep").expect("enable should succeed");
        assert_eq!(config.tool_layer.inject.len(), 2);
        let last = config.tool_layer.inject.last().unwrap();
        assert_eq!(last.tool, "grep");
        assert!(last.if_absent);
    }

    #[test]
    fn enable_rejects_empty_tool_name() {
        let mut config = fixture_config();
        let err = apply_enable(&mut config, "   ").unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[test]
    fn enable_rejects_duplicate() {
        let mut config = fixture_config();
        // `bash` is already in the fixture; enabling it again must error.
        let err = apply_enable(&mut config, "bash").unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert!(err.message().contains("already enabled"));
        // Config must not have grown.
        assert_eq!(config.tool_layer.inject.len(), 1);
    }

    #[test]
    fn disable_removes_inject_rule() {
        let mut config = fixture_config();
        apply_disable(&mut config, "bash").expect("disable should succeed");
        assert!(config.tool_layer.inject.is_empty());
    }

    #[test]
    fn disable_rejects_not_enabled() {
        let mut config = fixture_config();
        let err = apply_disable(&mut config, "grep").unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert!(err.message().contains("not enabled"));
    }

    #[test]
    fn disable_rejects_empty_tool_name() {
        let mut config = fixture_config();
        let err = apply_disable(&mut config, "").unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[test]
    fn require_role_denies_observer_for_admin_methods() {
        // Documents the role gate at the top of `enable` / `disable`. The
        // role check uses the same primitive as `config_ns::set` and is
        // covered end-to-end by the auth.rs tests; this case asserts the
        // contract surface for `tools/*`.
        let observer = CallerIdentity {
            role: Role::Observer,
            ip: "10.0.0.1".into(),
            tenant_id: String::new(),
        };
        let err = require_role(&observer, Role::Admin).unwrap_err();
        assert_eq!(err.code(), ERR_FORBIDDEN);
    }

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
