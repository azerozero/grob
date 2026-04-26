//! Unit tests for the MCP handler submodules.

use super::builtin_tools::inject_builtin_tools;
use super::config::{apply_config_update, parse_section, read_config_section};
use super::control_bridge::mcp_caller;
use crate::features::mcp::server::types::{
    ConfigSection, ConfigureAction, ConfigureParams, JsonRpcResponse,
};
use crate::server::config_guard::is_key_denied;
use crate::server::rpc::types::Role;

fn test_app_config() -> crate::models::config::AppConfig {
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
fn test_configure_read_classifier_defaults() {
    let config = test_app_config();
    let result = read_config_section(&config, &ConfigSection::Classifier);
    assert_eq!(result["weights"]["tools"].as_f64().unwrap(), 1.0);
    assert_eq!(result["weights"]["max_tokens"].as_f64().unwrap(), 1.0);
    assert_eq!(
        result["thresholds"]["medium_threshold"].as_f64().unwrap(),
        2.0
    );
    assert_eq!(
        result["thresholds"]["complex_threshold"].as_f64().unwrap(),
        5.0
    );
}

#[test]
fn test_configure_update_classifier_weight() {
    let mut config = test_app_config();
    apply_config_update(
        &mut config,
        &ConfigSection::Classifier,
        "weights.tools",
        &serde_json::json!(5.0),
    )
    .unwrap();
    assert_eq!(config.classifier.unwrap().weights.tools, 5.0);
}

#[test]
fn test_configure_update_classifier_threshold() {
    let mut config = test_app_config();
    apply_config_update(
        &mut config,
        &ConfigSection::Classifier,
        "thresholds.complex_threshold",
        &serde_json::json!(7.5),
    )
    .unwrap();
    assert_eq!(config.classifier.unwrap().thresholds.complex_threshold, 7.5);
}

#[test]
fn test_configure_update_classifier_unknown_key() {
    let mut config = test_app_config();
    let err = apply_config_update(
        &mut config,
        &ConfigSection::Classifier,
        "weights.bogus",
        &serde_json::json!(1.0),
    )
    .unwrap_err();
    assert!(err.contains("unknown classifier key"));
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
    let mut resp = JsonRpcResponse::ok(serde_json::json!(1), serde_json::json!({ "tools": [] }));
    inject_builtin_tools(&mut resp);
    let tools = resp.result["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(tools.len(), 10);
    assert_eq!(names[0], "grob_hint");
    assert_eq!(names[1], "grob_configure");
    assert_eq!(names[2], "grob_autotune");
    assert_eq!(names[3], "grob_keys");
    assert_eq!(names[4], "grob_tools");
    assert_eq!(names[5], "grob_hit");
    assert!(names.contains(&"wizard_get_config"));
    assert!(names.contains(&"wizard_set_section"));
    assert!(names.contains(&"wizard_run_doctor"));
    assert!(names.contains(&"grob_pledge"));
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
    assert_eq!(tools.len(), 11);
    assert_eq!(tools[0]["name"], "web_search");
    assert_eq!(tools[1]["name"], "grob_hint");
}

#[test]
fn test_inject_builtin_tools_schemas_valid() {
    let mut resp = JsonRpcResponse::ok(serde_json::json!(1), serde_json::json!({ "tools": [] }));
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
fn test_wizard_parse_section_none() {
    assert!(parse_section(None).unwrap().is_none());
    assert!(parse_section(Some(&serde_json::Value::Null))
        .unwrap()
        .is_none());
}

#[test]
fn test_wizard_parse_section_router() {
    let v = serde_json::json!("router");
    assert_eq!(
        parse_section(Some(&v)).unwrap(),
        Some(ConfigSection::Router)
    );
}

#[test]
fn test_wizard_parse_section_invalid() {
    let v = serde_json::json!("nonsense");
    assert!(parse_section(Some(&v)).is_err());
}

#[test]
fn test_mcp_caller_is_admin() {
    let caller = mcp_caller();
    assert_eq!(caller.role, Role::Admin);
    assert_eq!(caller.ip, "127.0.0.1");
    assert_eq!(caller.tenant_id, "mcp");
}
