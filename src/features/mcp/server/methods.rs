//! MCP JSON-RPC method implementations: query, bench, calibrate, configure, report, tools/list.

use super::types::*;
use crate::features::mcp::McpState;
use crate::server::AppState;
use std::collections::HashMap;
use std::sync::Arc;

/// Sentinel epoch for tools that have never been benchmarked.
const NO_BENCH_EPOCH: u64 = 0;

/// Handles `tool_matrix/query` — returns scores for a tool, optionally filtered by provider.
pub async fn handle_query(
    mcp: &McpState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let p: QueryParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    let entry = mcp.matrix.query(&p.tool).ok_or_else(|| {
        JsonRpcError::invalid_params(id.clone(), &format!("Unknown tool: {}", p.tool))
    })?;

    let scorer = mcp.read_scorer().await;
    let runtime_scores = mcp.matrix.scores_handle();

    let mut providers: HashMap<String, serde_json::Value> = HashMap::new();
    for (prov, cap) in entry
        .providers
        .iter()
        .filter(|(prov, _)| p.provider.as_ref().is_none_or(|f| f == *prov))
    {
        let composite = scorer.composite_score(&p.tool, prov, Some(cap.reliability));
        let metrics = scorer.metric_breakdown(&p.tool, prov);
        let last_bench = runtime_scores
            .get(&p.tool, prov)
            .await
            .map(|s| s.last_bench_epoch)
            .unwrap_or(NO_BENCH_EPOCH);

        providers.insert(
            prov.clone(),
            serde_json::json!({
                "static_reliability": cap.reliability,
                "composite": composite,
                "last_bench_epoch": last_bench,
                "metrics": metrics,
            }),
        );
    }

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "tool": p.tool,
            "category": entry.category,
            "aliases": entry.aliases,
            "providers": providers,
        }),
    ))
}

/// Handles `tool_matrix/bench` — triggers an on-demand bench cycle (placeholder).
pub async fn handle_bench(
    _mcp: &McpState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let p: BenchParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    // NOTE: actual bench dispatch is handled by the bench engine;
    // here we acknowledge the request.
    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "status": "accepted",
            "tools": p.tools.unwrap_or_default(),
            "providers": p.providers.unwrap_or_default(),
        }),
    ))
}

/// Handles `tool_matrix/calibrate` — manual score override.
pub async fn handle_calibrate(
    mcp: &McpState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let p: CalibrateParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    if !(0.0..=1.0).contains(&p.score) {
        return Err(JsonRpcError::invalid_params(
            id,
            "score must be between 0.0 and 1.0",
        ));
    }

    mcp.matrix
        .update_score(&p.tool, &p.provider, p.score, HashMap::new())
        .await;

    tracing::info!(
        tool = %p.tool,
        provider = %p.provider,
        score = p.score,
        "MCP: manual calibration override"
    );

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "tool": p.tool,
            "provider": p.provider,
            "score": p.score,
        }),
    ))
}

/// Handles `tool_matrix/report` — returns the full matrix with all scores.
pub async fn handle_report(
    mcp: &McpState,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let report = build_matrix_report(mcp).await;
    Ok(JsonRpcResponse::ok(id, report))
}

/// Handles `tools/list` — MCP standard tool listing.
pub async fn handle_tools_list(
    mcp: &McpState,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let tools: Vec<McpToolInfo> = mcp
        .matrix
        .all_entries()
        .iter()
        .map(|entry| {
            let schema = serde_json::json!({
                "type": entry.schema.r#type,
                "properties": entry.schema.properties,
                "required": entry.schema.required,
            });
            McpToolInfo {
                name: entry.name.clone(),
                description: format!("{} tool (category: {})", entry.name, entry.category),
                input_schema: schema,
            }
        })
        .collect();

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({ "tools": tools }),
    ))
}

/// Builds the full matrix report (reused by both JSON-RPC and REST endpoints).
pub async fn build_matrix_report(mcp: &McpState) -> serde_json::Value {
    let scorer = mcp.read_scorer().await;
    let runtime_scores = mcp.matrix.scores_handle();

    let mut tools: Vec<serde_json::Value> = Vec::new();
    for entry in mcp.matrix.all_entries() {
        let mut providers: HashMap<String, serde_json::Value> = HashMap::new();
        for (prov, cap) in &entry.providers {
            let composite = scorer.composite_score(&entry.name, prov, Some(cap.reliability));
            let metrics = scorer.metric_breakdown(&entry.name, prov);
            let last_bench = runtime_scores
                .get(&entry.name, prov)
                .await
                .map(|s| s.last_bench_epoch)
                .unwrap_or(NO_BENCH_EPOCH);

            providers.insert(
                prov.clone(),
                serde_json::json!({
                    "static_reliability": cap.reliability,
                    "composite": composite,
                    "last_bench_epoch": last_bench,
                    "metrics": metrics,
                }),
            );
        }

        tools.push(serde_json::json!({
            "name": entry.name,
            "aliases": entry.aliases,
            "category": entry.category,
            "providers": providers,
        }));
    }

    serde_json::json!({
        "tool_count": mcp.matrix.tool_count(),
        "tools": tools,
        "config": {
            "filter_low_score_tools": mcp.config.routing.filter_low_score_tools,
            "min_score": mcp.config.routing.min_score,
            "bench_enabled": mcp.config.bench.enabled,
            "bench_interval_secs": mcp.config.bench.interval_secs,
        }
    })
}

// ── grob_configure self-tuning ──────────────────────────────────────────────

/// Keys that agents are never allowed to modify via `grob_configure`.
///
/// Covers credentials, security core switches, and audit — any field whose
/// modification could weaken the security posture or expose secrets.
const DENIED_KEYS: &[(&str, &str)] = &[
    ("router", "api_key"),
    ("budget", "api_key"),
    ("cache", "api_key"),
];

/// Validates that a key update is not on the deny-list.
fn is_key_denied(section: &ConfigSection, key: &str) -> bool {
    let section_str = match section {
        ConfigSection::Router => "router",
        ConfigSection::Budget => "budget",
        ConfigSection::Dlp => "dlp",
        ConfigSection::Cache => "cache",
    };

    // DLP section is fully read-only (security cannot be weakened via self-tuning)
    if section_str == "dlp" {
        return true;
    }

    DENIED_KEYS
        .iter()
        .any(|(s, k)| *s == section_str && *k == key)
}

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

            // Clone the current config, apply the change, then atomically swap
            let mut new_config = {
                let snapshot = state.snapshot();
                snapshot.config.clone()
            };

            apply_config_update(&mut new_config, section, key, value)
                .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e))?;

            // Rebuild reloadable state (same mechanism as /api/config/reload)
            let new_router = crate::router::Router::new(new_config.clone());
            let new_registry = crate::providers::ProviderRegistry::from_configs_with_models(
                &new_config.providers,
                Some(state.token_store.clone()),
                &new_config.models,
                &new_config.server.timeouts,
            )
            .map_err(|e| {
                JsonRpcError::internal(
                    id.clone(),
                    &format!("failed to rebuild provider registry: {e}"),
                )
            })?;

            let new_inner = Arc::new(crate::server::ReloadableState::new(
                new_config,
                new_router,
                Arc::new(new_registry),
            ));

            // Atomic swap
            *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner;

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
    use crate::features::mcp::config::McpConfig;
    use crate::features::mcp::matrix::{ProviderToolCapability, ToolEntry, ToolMatrix, ToolSchema};

    fn test_mcp_state() -> McpState {
        let entries = vec![ToolEntry {
            name: "web_search".to_string(),
            aliases: vec!["brave_search".to_string()],
            category: "retrieval".to_string(),
            schema: ToolSchema {
                r#type: "object".to_string(),
                properties: HashMap::from([(
                    "query".to_string(),
                    serde_json::json!({"type": "string"}),
                )]),
                required: vec!["query".to_string()],
            },
            providers: HashMap::from([(
                "anthropic".to_string(),
                ProviderToolCapability { reliability: 0.95 },
            )]),
        }];

        McpState::new(McpConfig::default(), ToolMatrix::from_entries(entries))
    }

    #[tokio::test]
    async fn test_handle_query() {
        let mcp = test_mcp_state();
        let params = serde_json::json!({"tool": "web_search"});
        let result = handle_query(&mcp, params, serde_json::json!(1))
            .await
            .unwrap();
        assert!(
            result.result["providers"]["anthropic"]["static_reliability"]
                .as_f64()
                .unwrap()
                > 0.9
        );
    }

    #[tokio::test]
    async fn test_handle_query_unknown_tool() {
        let mcp = test_mcp_state();
        let params = serde_json::json!({"tool": "nonexistent"});
        let err = handle_query(&mcp, params, serde_json::json!(1))
            .await
            .unwrap_err();
        assert_eq!(err.error.code, -32602);
    }

    #[tokio::test]
    async fn test_handle_calibrate() {
        let mcp = test_mcp_state();
        let params =
            serde_json::json!({"tool": "web_search", "provider": "anthropic", "score": 0.8});
        let result = handle_calibrate(&mcp, params, serde_json::json!(1))
            .await
            .unwrap();
        assert!((result.result["score"].as_f64().unwrap() - 0.8).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_handle_calibrate_invalid_score() {
        let mcp = test_mcp_state();
        let params =
            serde_json::json!({"tool": "web_search", "provider": "anthropic", "score": 1.5});
        let err = handle_calibrate(&mcp, params, serde_json::json!(1))
            .await
            .unwrap_err();
        assert_eq!(err.error.code, -32602);
    }

    #[tokio::test]
    async fn test_handle_report() {
        let mcp = test_mcp_state();
        let result = handle_report(&mcp, serde_json::json!(1)).await.unwrap();
        assert_eq!(result.result["tool_count"], 1);
    }

    #[tokio::test]
    async fn test_handle_tools_list() {
        let mcp = test_mcp_state();
        let result = handle_tools_list(&mcp, serde_json::json!(1)).await.unwrap();
        let tools = result.result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "web_search");
    }

    // ── grob_configure tests ────────────────────────────────────────────────

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
        // warn_at_percent present (value depends on Default impl vs serde default)
        assert!(result.get("warn_at_percent").is_some());
    }

    #[test]
    fn test_configure_read_dlp() {
        let config = test_app_config();
        let result = read_config_section(&config, &ConfigSection::Dlp);
        assert_eq!(result["enabled"], serde_json::json!(false));
        // scan_input defaults to false via Default derive (serde default_true only applies during deser)
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
}
