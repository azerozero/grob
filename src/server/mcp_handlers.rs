//! MCP JSON-RPC Axum handlers and self-tuning configuration logic.
//!
//! Moved here from `features/mcp/server/` to break the features -> server
//! dependency cycle. The pure MCP business logic (query, bench, calibrate,
//! report, tools/list) stays in `features::mcp::server::methods`.

use super::rpc::auth::CallerIdentity;
use super::rpc::types::Role;
use super::AppState;
use crate::features::mcp::server::methods;
use crate::features::mcp::server::types::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, RPC_INTERNAL_ERROR,
};
use axum::{extract::State, response::IntoResponse, Json};
use std::sync::Arc;

use crate::features::mcp::server::types::{
    ConfigSection, ConfigureAction, ConfigureParams, HintParams,
};

// ── Axum HTTP handlers ──────────────────────────────────────────────────────

/// Handles `POST /mcp` — dispatches on JSON-RPC `method` field.
pub async fn handle_mcp_rpc(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let mcp = match state.security.mcp.as_ref() {
        Some(m) => m,
        None => {
            return Json(to_json_value(Err(JsonRpcError::internal(
                req.id,
                "MCP not initialized",
            ))));
        }
    };

    let result = match req.method.as_str() {
        "tool_matrix/query" => methods::handle_query(mcp, req.params, req.id.clone()).await,
        "tool_matrix/bench" => methods::handle_bench(mcp, req.params, req.id.clone()).await,
        "tool_matrix/calibrate" => methods::handle_calibrate(mcp, req.params, req.id.clone()).await,
        "tool_matrix/report" => methods::handle_report(mcp, req.id.clone()).await,
        "grob_configure" => handle_configure(&state, req.params, req.id.clone()).await,
        "grob_hint" => handle_hint(&state, req.params, req.id.clone()).await,
        "grob_keys" => handle_control_tool(&state, "grob/keys", req.params, req.id.clone()).await,
        "grob_tools" => handle_control_tool(&state, "grob/tools", req.params, req.id.clone()).await,
        "grob_hit" => handle_control_tool(&state, "grob/hit", req.params, req.id.clone()).await,
        "grob_pledge" => {
            handle_control_tool(&state, "grob/pledge", req.params, req.id.clone()).await
        }
        "tools/list" => match methods::handle_tools_list(mcp, req.id.clone()).await {
            Ok(mut resp) => {
                inject_builtin_tools(&mut resp);
                Ok(resp)
            }
            Err(e) => Err(e),
        },
        _ => Err(JsonRpcError::method_not_found(req.id.clone(), &req.method)),
    };

    Json(to_json_value(result))
}

/// Handles `GET /api/tool-matrix` — REST endpoint for the full matrix report.
pub async fn handle_matrix_report(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.security.mcp.as_ref() {
        Some(mcp) => {
            let report = methods::build_matrix_report(mcp).await;
            Json(report)
        }
        None => Json(serde_json::json!({
            "error": "MCP not enabled",
            "tool_count": 0,
            "tools": [],
        })),
    }
}

/// Serializes a JSON-RPC result to a [`serde_json::Value`].
///
/// Both `JsonRpcResponse` and `JsonRpcError` are simple structs with only
/// string/numeric fields, so serialization cannot realistically fail. The
/// fallback exists purely to satisfy the type system without `unwrap()`.
fn to_json_value(result: Result<JsonRpcResponse, JsonRpcError>) -> serde_json::Value {
    let fallback = |e: serde_json::Error| {
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": RPC_INTERNAL_ERROR, "message": e.to_string()},
            "id": null
        })
    };
    match result {
        Ok(resp) => serde_json::to_value(resp).unwrap_or_else(fallback),
        Err(err) => serde_json::to_value(err).unwrap_or_else(fallback),
    }
}

// ── grob_hint ──────────────────────────────────────────────────────────────

/// Handles `grob_hint` — stores a one-shot complexity hint for the next dispatch.
///
/// The hint is consumed (taken) by the next dispatch call, then cleared.
/// Clients may also pass the hint inline via `X-Grob-Hint` header or
/// `metadata.grob_hint` in the request body — this MCP tool is the third
/// pathway, for MCP-native agents that cannot set custom HTTP headers.
async fn handle_hint(
    state: &Arc<AppState>,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let p: HintParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    // Store the hint for the next dispatch (one-shot).
    if let Ok(mut slot) = state.grob_hint.lock() {
        *slot = Some(p.complexity);
    }

    tracing::info!(complexity = %p.complexity, "MCP: grob_hint stored");

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "status": "accepted",
            "complexity": p.complexity.to_string(),
        }),
    ))
}

// ── Control plane bridge ───────────────────────────────────────────────────

/// Returns a privileged caller identity for MCP-originated control requests.
fn mcp_caller() -> CallerIdentity {
    CallerIdentity {
        role: Role::Admin,
        ip: "127.0.0.1".into(),
        tenant_id: "mcp".into(),
    }
}

/// Bridges an MCP tool call to the RPC control plane.
///
/// Extracts the `action` parameter, builds the full RPC method name
/// (e.g., `grob/keys/create`), and delegates to [`super::rpc::dispatch`].
async fn handle_control_tool(
    state: &Arc<AppState>,
    namespace: &str,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let action = params
        .get("action")
        .and_then(|a| a.as_str())
        .unwrap_or("")
        .to_string();

    if action.is_empty() {
        return Err(JsonRpcError::invalid_params(
            id,
            "missing required parameter: action",
        ));
    }

    let method = format!("{namespace}/{action}");
    let caller = mcp_caller();

    match super::rpc::dispatch(state, &caller, &method, Some(&params)).await {
        Ok(data) => {
            tracing::info!(
                namespace,
                action = action.as_str(),
                "MCP: control tool call"
            );
            Ok(JsonRpcResponse::ok(id, data))
        }
        Err(e) => Err(JsonRpcError::internal(id, e.message())),
    }
}

/// Appends built-in tools to the `tools/list` response.
fn inject_builtin_tools(resp: &mut JsonRpcResponse) {
    if let Some(tools) = resp.result.get_mut("tools").and_then(|v| v.as_array_mut()) {
        tools.push(serde_json::json!({
            "name": "grob_hint",
            "description": "Declare task complexity for routing heuristics (trivial/medium/complex). Stateless: consumed by the next request.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "complexity": {
                        "type": "string",
                        "enum": ["trivial", "medium", "complex"],
                        "description": "Task complexity level"
                    }
                },
                "required": ["complexity"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_configure",
            "description": "Read or update safe configuration sections (router, budget, cache). Credentials and security settings are denied.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "update"]
                    },
                    "section": {
                        "type": "string",
                        "enum": ["router", "budget", "dlp", "cache"]
                    },
                    "key": { "type": "string" },
                    "value": {}
                },
                "required": ["action", "section"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_keys",
            "description": "Manage virtual API keys: create, list, revoke, or rotate.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["create", "list", "revoke", "rotate"],
                        "description": "Key management operation"
                    },
                    "name": {
                        "type": "string",
                        "description": "Human-readable label (required for create)"
                    },
                    "key_id": {
                        "type": "string",
                        "description": "Key identifier (required for revoke/rotate)"
                    }
                },
                "required": ["action"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_tools",
            "description": "Inspect and toggle the tool layer: list active tools, enable/disable by name, or browse the full catalog.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "enable", "disable", "catalog"],
                        "description": "Tool layer operation"
                    },
                    "tool": {
                        "type": "string",
                        "description": "Tool name (required for enable/disable)"
                    }
                },
                "required": ["action"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_hit",
            "description": "Manage HIT (Human Intent Token) policies: list, get, set, or resolve which policy applies to a context.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list_policies", "get_policy", "set_policy", "resolve"],
                        "description": "HIT policy operation"
                    },
                    "name": {
                        "type": "string",
                        "description": "Policy name (required for get_policy/set_policy)"
                    },
                    "policy": {
                        "type": "object",
                        "description": "Policy definition (required for set_policy)"
                    },
                    "context": {
                        "type": "object",
                        "description": "Request context for policy resolution (required for resolve)"
                    }
                },
                "required": ["action"]
            }
        }));
        tools.push(serde_json::json!({
            "name": "grob_pledge",
            "description": "Manage pledge capability restrictions: activate a profile, clear to defaults, check status, or list available profiles.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["set", "clear", "status", "list_profiles"],
                        "description": "Pledge operation"
                    },
                    "profile": {
                        "type": "string",
                        "description": "Profile name (required for set)"
                    },
                    "source": {
                        "type": "string",
                        "description": "Optional source filter (for set)"
                    }
                },
                "required": ["action"]
            }
        }));
    }
}

// ── grob_configure self-tuning ──────────────────────────────────────────────

use super::config_guard::is_key_denied;

/// Returns a safe JSON view of the requested config section (no secrets).
fn read_config_section(
    config: &crate::cli::AppConfig,
    section: &ConfigSection,
) -> serde_json::Value {
    match section {
        ConfigSection::Router => serde_json::json!({
            "default": config.router.default,
            "background": config.router.background,
            "think": config.router.think,
            "websearch": config.router.websearch,
            "auto_map_regex": config.router.auto_map_regex,
            "background_regex": config.router.background_regex,
            "prompt_rules": config.router.prompt_rules,
            "gdpr": config.router.gdpr,
            "region": config.router.region,
        }),
        ConfigSection::Budget => serde_json::json!({
            "monthly_limit_usd": config.budget.monthly_limit_usd,
            "warn_at_percent": config.budget.warn_at_percent,
        }),
        ConfigSection::Dlp => serde_json::json!({
            "enabled": config.dlp.enabled,
            "scan_input": config.dlp.scan_input,
            "scan_output": config.dlp.scan_output,
            "entropy_enabled": config.dlp.entropy.enabled,
            "entropy_action": format!("{:?}", config.dlp.entropy.action),
            "pii_credit_cards": config.dlp.pii.credit_cards,
            "pii_iban": config.dlp.pii.iban,
            "pii_action": format!("{:?}", config.dlp.pii.action),
            "url_exfil_enabled": config.dlp.url_exfil.enabled,
            "prompt_injection_enabled": config.dlp.prompt_injection.enabled,
        }),
        ConfigSection::Cache => serde_json::json!({
            "enabled": config.cache.enabled,
            "max_capacity": config.cache.max_capacity,
            "ttl_secs": config.cache.ttl_secs,
            "max_entry_bytes": config.cache.max_entry_bytes,
        }),
    }
}

/// Applies an update to a config section, returning the modified config.
///
/// The caller is responsible for triggering the hot-reload after a successful update.
fn apply_config_update(
    config: &mut crate::cli::AppConfig,
    section: &ConfigSection,
    key: &str,
    value: &serde_json::Value,
) -> Result<(), String> {
    match section {
        ConfigSection::Router => match key {
            "default" => {
                config.router.default = value
                    .as_str()
                    .ok_or("expected string for router.default")?
                    .to_string();
            }
            "background" => {
                config.router.background = value.as_str().map(String::from);
            }
            "think" => {
                config.router.think = value.as_str().map(String::from);
            }
            "websearch" => {
                config.router.websearch = value.as_str().map(String::from);
            }
            "auto_map_regex" => {
                config.router.auto_map_regex = value.as_str().map(String::from);
            }
            "background_regex" => {
                config.router.background_regex = value.as_str().map(String::from);
            }
            "gdpr" => {
                config.router.gdpr = value.as_bool().ok_or("expected bool for router.gdpr")?;
            }
            "region" => {
                config.router.region = value.as_str().map(String::from);
            }
            _ => return Err(format!("unknown router key: {key}")),
        },
        ConfigSection::Budget => match key {
            "monthly_limit_usd" => {
                let v = value
                    .as_f64()
                    .ok_or("expected number for budget.monthly_limit_usd")?;
                config.budget.monthly_limit_usd =
                    crate::cli::BudgetUsd::new(v).map_err(|e| format!("invalid budget: {e}"))?;
            }
            "warn_at_percent" => {
                let v = value
                    .as_u64()
                    .ok_or("expected integer for budget.warn_at_percent")?;
                if v > 100 {
                    return Err("warn_at_percent must be 0-100".to_string());
                }
                config.budget.warn_at_percent = v as u32;
            }
            _ => return Err(format!("unknown budget key: {key}")),
        },
        ConfigSection::Dlp => {
            return Err("DLP section is read-only via self-tuning".to_string());
        }
        ConfigSection::Cache => match key {
            "enabled" => {
                config.cache.enabled = value.as_bool().ok_or("expected bool for cache.enabled")?;
            }
            "max_capacity" => {
                config.cache.max_capacity = value
                    .as_u64()
                    .ok_or("expected integer for cache.max_capacity")?;
            }
            "ttl_secs" => {
                config.cache.ttl_secs = value
                    .as_u64()
                    .ok_or("expected integer for cache.ttl_secs")?;
            }
            "max_entry_bytes" => {
                let v = value
                    .as_u64()
                    .ok_or("expected integer for cache.max_entry_bytes")?;
                config.cache.max_entry_bytes = v as usize;
            }
            _ => return Err(format!("unknown cache key: {key}")),
        },
    }
    Ok(())
}

// Disk persistence and hot-reload are handled by `config_guard::persist_and_reload`.

/// Handles `grob_configure` — self-tuning configuration tool for MCP agents.
///
/// Agents can read safe config subsets and update whitelisted parameters.
/// Credential, security, and bind-address modifications are always rejected.
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
            super::config_guard::persist_and_reload(state, &new_config)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_app_config() -> crate::cli::AppConfig {
        let toml_str = r#"
            [router]
            default = "claude-sonnet"
            think = "claude-opus"
            background = "claude-haiku"
            websearch = "claude-sonnet"
        "#;
        toml::from_str(toml_str).unwrap()
    }

    #[test]
    fn test_configure_read_router() {
        let config = test_app_config();
        let result = read_config_section(&config, &ConfigSection::Router);
        assert_eq!(result["default"], "claude-sonnet");
        assert_eq!(result["think"], "claude-opus");
        assert_eq!(result["background"], "claude-haiku");
    }

    #[test]
    fn test_configure_read_budget() {
        let config = test_app_config();
        let result = read_config_section(&config, &ConfigSection::Budget);
        assert_eq!(result["monthly_limit_usd"].as_f64().unwrap(), 0.0);
        assert!(result.get("warn_at_percent").is_some());
    }

    #[test]
    fn test_configure_read_dlp() {
        let config = test_app_config();
        let result = read_config_section(&config, &ConfigSection::Dlp);
        assert_eq!(result["enabled"], serde_json::json!(false));
        assert!(result.get("scan_input").is_some());
    }

    #[test]
    fn test_configure_read_cache() {
        let config = test_app_config();
        let result = read_config_section(&config, &ConfigSection::Cache);
        assert_eq!(result["enabled"], false);
        assert_eq!(result["ttl_secs"], 3600);
    }

    #[test]
    fn test_configure_update_routing_default() {
        let mut config = test_app_config();
        apply_config_update(
            &mut config,
            &ConfigSection::Router,
            "default",
            &serde_json::json!("gpt-4o"),
        )
        .unwrap();
        assert_eq!(config.router.default, "gpt-4o");
    }

    #[test]
    fn test_configure_update_routing_think() {
        let mut config = test_app_config();
        apply_config_update(
            &mut config,
            &ConfigSection::Router,
            "think",
            &serde_json::json!("o1-pro"),
        )
        .unwrap();
        assert_eq!(config.router.think.as_deref(), Some("o1-pro"));
    }

    #[test]
    fn test_configure_update_budget_limit() {
        let mut config = test_app_config();
        apply_config_update(
            &mut config,
            &ConfigSection::Budget,
            "monthly_limit_usd",
            &serde_json::json!(50.0),
        )
        .unwrap();
        assert_eq!(f64::from(config.budget.monthly_limit_usd), 50.0);
    }

    #[test]
    fn test_configure_update_cache_enabled() {
        let mut config = test_app_config();
        apply_config_update(
            &mut config,
            &ConfigSection::Cache,
            "enabled",
            &serde_json::json!(true),
        )
        .unwrap();
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_configure_update_cache_ttl() {
        let mut config = test_app_config();
        apply_config_update(
            &mut config,
            &ConfigSection::Cache,
            "ttl_secs",
            &serde_json::json!(7200),
        )
        .unwrap();
        assert_eq!(config.cache.ttl_secs, 7200);
    }

    #[test]
    fn test_configure_reject_dlp_update() {
        assert!(is_key_denied(&ConfigSection::Dlp, "enabled"));
        assert!(is_key_denied(&ConfigSection::Dlp, "scan_input"));
        assert!(is_key_denied(&ConfigSection::Dlp, "anything"));
    }

    #[test]
    fn test_configure_reject_credentials() {
        assert!(is_key_denied(&ConfigSection::Router, "api_key"));
        assert!(is_key_denied(&ConfigSection::Budget, "api_key"));
    }

    #[test]
    fn test_configure_reject_security_core() {
        assert!(is_key_denied(&ConfigSection::Dlp, "enabled"));
        assert!(is_key_denied(&ConfigSection::Dlp, "scan_input"));
        assert!(is_key_denied(&ConfigSection::Dlp, "scan_output"));
        assert!(is_key_denied(&ConfigSection::Dlp, "no_builtins"));
    }

    #[test]
    fn test_configure_allow_safe_keys() {
        assert!(!is_key_denied(&ConfigSection::Router, "default"));
        assert!(!is_key_denied(&ConfigSection::Router, "think"));
        assert!(!is_key_denied(&ConfigSection::Budget, "monthly_limit_usd"));
        assert!(!is_key_denied(&ConfigSection::Cache, "enabled"));
        assert!(!is_key_denied(&ConfigSection::Cache, "ttl_secs"));
    }

    #[test]
    fn test_configure_update_unknown_key_rejected() {
        let mut config = test_app_config();
        let result = apply_config_update(
            &mut config,
            &ConfigSection::Router,
            "nonexistent_key",
            &serde_json::json!("value"),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown router key"));
    }

    #[test]
    fn test_configure_update_wrong_type_rejected() {
        let mut config = test_app_config();
        let result = apply_config_update(
            &mut config,
            &ConfigSection::Router,
            "default",
            &serde_json::json!(42),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_configure_update_negative_budget_rejected() {
        let mut config = test_app_config();
        let result = apply_config_update(
            &mut config,
            &ConfigSection::Budget,
            "monthly_limit_usd",
            &serde_json::json!(-10.0),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_configure_update_warn_percent_over_100_rejected() {
        let mut config = test_app_config();
        let result = apply_config_update(
            &mut config,
            &ConfigSection::Budget,
            "warn_at_percent",
            &serde_json::json!(150),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_configure_params_deserialize_read() {
        let json = serde_json::json!({
            "action": "read",
            "section": "router"
        });
        let p: ConfigureParams = serde_json::from_value(json).unwrap();
        match p.action {
            ConfigureAction::Read { section } => assert_eq!(section, ConfigSection::Router),
            _ => panic!("expected Read action"),
        }
    }

    #[test]
    fn test_configure_params_deserialize_update() {
        let json = serde_json::json!({
            "action": "update",
            "section": "cache",
            "key": "ttl_secs",
            "value": 7200
        });
        let p: ConfigureParams = serde_json::from_value(json).unwrap();
        match p.action {
            ConfigureAction::Update {
                section,
                key,
                value,
            } => {
                assert_eq!(section, ConfigSection::Cache);
                assert_eq!(key, "ttl_secs");
                assert_eq!(value, 7200);
            }
            _ => panic!("expected Update action"),
        }
    }

    #[test]
    fn test_inject_builtin_tools_adds_all() {
        let mut resp =
            JsonRpcResponse::ok(serde_json::json!(1), serde_json::json!({ "tools": [] }));
        inject_builtin_tools(&mut resp);
        let tools = resp.result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 6);
        assert_eq!(tools[0]["name"], "grob_hint");
        assert_eq!(tools[1]["name"], "grob_configure");
        assert_eq!(tools[2]["name"], "grob_keys");
        assert_eq!(tools[3]["name"], "grob_tools");
        assert_eq!(tools[4]["name"], "grob_hit");
        assert_eq!(tools[5]["name"], "grob_pledge");
    }

    #[test]
    fn test_inject_builtin_tools_preserves_existing() {
        let mut resp = JsonRpcResponse::ok(
            serde_json::json!(1),
            serde_json::json!({
                "tools": [{"name": "web_search"}]
            }),
        );
        inject_builtin_tools(&mut resp);
        let tools = resp.result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 7);
        assert_eq!(tools[0]["name"], "web_search");
        assert_eq!(tools[1]["name"], "grob_hint");
    }

    #[test]
    fn test_inject_builtin_tools_schemas_valid() {
        let mut resp =
            JsonRpcResponse::ok(serde_json::json!(1), serde_json::json!({ "tools": [] }));
        inject_builtin_tools(&mut resp);
        let tools = resp.result["tools"].as_array().unwrap();
        for tool in tools {
            assert!(tool["name"].is_string(), "tool must have a name");
            assert!(
                tool["description"].is_string(),
                "tool must have a description"
            );
            let schema = &tool["inputSchema"];
            assert_eq!(schema["type"], "object", "schema must be an object");
            assert!(
                schema["properties"].is_object(),
                "schema must have properties"
            );
            assert!(
                schema["required"].is_array(),
                "schema must have required array"
            );
        }
    }

    #[test]
    fn test_mcp_caller_is_admin() {
        let caller = mcp_caller();
        assert_eq!(caller.role, Role::Admin);
        assert_eq!(caller.ip, "127.0.0.1");
        assert_eq!(caller.tenant_id, "mcp");
    }
}
