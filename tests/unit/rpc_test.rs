use grob::server::rpc::auth::{method_required_role, require_role, resolve_caller, CallerIdentity};
use grob::server::rpc::types::{
    BudgetCurrent, Role, SpendBreakdown, StatusResponse, ERR_FORBIDDEN, ERR_UNAUTHORIZED,
};

// ── AuthN tests ──

#[test]
fn test_localhost_ipv4_is_superadmin() {
    let caller = resolve_caller("127.0.0.1", None, "api_key", None).unwrap();
    assert_eq!(caller.role, Role::Superadmin);
    assert_eq!(caller.ip, "127.0.0.1");
}

#[test]
fn test_localhost_ipv6_is_superadmin() {
    let caller = resolve_caller("::1", None, "jwt", None).unwrap();
    assert_eq!(caller.role, Role::Superadmin);
}

#[test]
fn test_remote_no_token_api_key_mode_rejected() {
    let err = resolve_caller("10.0.0.1", None, "api_key", None).unwrap_err();
    assert_eq!(err.code(), ERR_UNAUTHORIZED);
}

#[test]
fn test_remote_with_virtual_key_is_operator() {
    let caller = resolve_caller(
        "192.168.1.100",
        Some("grob_abcdef1234567890"),
        "api_key",
        None,
    )
    .unwrap();
    assert_eq!(caller.role, Role::Operator);
}

#[test]
fn test_auth_mode_none_grants_operator() {
    let caller = resolve_caller("8.8.8.8", None, "none", None).unwrap();
    assert_eq!(caller.role, Role::Operator);
}

#[test]
fn test_jwt_token_is_operator() {
    let caller = resolve_caller("10.0.0.1", Some("eyJhbGciOiJSUzI1NiJ9.xxx"), "jwt", None).unwrap();
    assert_eq!(caller.role, Role::Operator);
}

// ── AuthZ RBAC tests ──

#[test]
fn test_role_hierarchy_superadmin_has_all() {
    assert!(Role::Superadmin.has_at_least(Role::Superadmin));
    assert!(Role::Superadmin.has_at_least(Role::Admin));
    assert!(Role::Superadmin.has_at_least(Role::Operator));
    assert!(Role::Superadmin.has_at_least(Role::Observer));
}

#[test]
fn test_role_hierarchy_observer_minimal() {
    assert!(Role::Observer.has_at_least(Role::Observer));
    assert!(!Role::Observer.has_at_least(Role::Operator));
    assert!(!Role::Observer.has_at_least(Role::Admin));
    assert!(!Role::Observer.has_at_least(Role::Superadmin));
}

#[test]
fn test_require_role_observer_can_read() {
    let caller = CallerIdentity {
        role: Role::Observer,
        ip: "10.0.0.1".into(),
        tenant_id: String::new(),
    };
    assert!(require_role(&caller, Role::Observer).is_ok());
}

#[test]
fn test_require_role_observer_cannot_reload() {
    let caller = CallerIdentity {
        role: Role::Observer,
        ip: "10.0.0.1".into(),
        tenant_id: String::new(),
    };
    let err = require_role(&caller, Role::Operator).unwrap_err();
    assert_eq!(err.code(), ERR_FORBIDDEN);
}

#[test]
fn test_require_role_operator_can_reload() {
    let caller = CallerIdentity {
        role: Role::Operator,
        ip: "10.0.0.1".into(),
        tenant_id: String::new(),
    };
    assert!(require_role(&caller, Role::Operator).is_ok());
}

#[test]
fn test_operator_cannot_access_admin() {
    let caller = CallerIdentity {
        role: Role::Operator,
        ip: "10.0.0.1".into(),
        tenant_id: String::new(),
    };
    assert!(require_role(&caller, Role::Admin).is_err());
}

// ── Method-to-role mapping tests ──

#[test]
fn test_read_methods_are_observer() {
    let read_methods = [
        "grob/server/status",
        "grob/model/list",
        "grob/model/routing",
        "grob/provider/list",
        "grob/provider/score",
        "grob/budget/current",
        "grob/budget/breakdown",
    ];
    for method in &read_methods {
        assert_eq!(
            method_required_role(method),
            Role::Observer,
            "{method} should require Observer"
        );
    }
}

#[test]
fn test_reload_config_requires_operator() {
    assert_eq!(
        method_required_role("grob/server/reload_config"),
        Role::Operator
    );
}

#[test]
fn test_config_methods_require_admin() {
    assert_eq!(method_required_role("grob/config/update"), Role::Admin);
    assert_eq!(method_required_role("grob/keys/create"), Role::Admin);
}

#[test]
fn test_unknown_methods_require_superadmin() {
    assert_eq!(method_required_role("grob/unknown/foo"), Role::Superadmin);
}

// ── JSON-RPC serialization tests ──

#[test]
fn test_status_response_serialization() {
    let resp = StatusResponse {
        status: "ok".into(),
        message: Some("Config reloaded".into()),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["message"], "Config reloaded");
}

#[test]
fn test_status_response_without_message() {
    let resp = StatusResponse {
        status: "ok".into(),
        message: None,
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json.get("message").is_none());
}

#[test]
fn test_budget_current_serialization() {
    let budget = BudgetCurrent {
        total_usd: 42.50,
        budget_usd: 100.0,
        remaining_usd: 57.50,
    };
    let json = serde_json::to_value(&budget).unwrap();
    assert_eq!(json["total_usd"], 42.50);
    assert_eq!(json["budget_usd"], 100.0);
    assert_eq!(json["remaining_usd"], 57.50);
}

#[test]
fn test_spend_breakdown_serialization() {
    let entry = SpendBreakdown {
        provider: "anthropic".into(),
        spent_usd: 15.00,
        request_count: 42,
    };
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(json["provider"], "anthropic");
    assert_eq!(json["spent_usd"], 15.0);
    assert_eq!(json["request_count"], 42);
}

#[test]
fn test_role_serialization() {
    let json = serde_json::to_value(Role::Superadmin).unwrap();
    assert_eq!(json, "superadmin");

    let json = serde_json::to_value(Role::Observer).unwrap();
    assert_eq!(json, "observer");
}

#[test]
fn test_role_deserialization() {
    let role: Role = serde_json::from_str("\"operator\"").unwrap();
    assert_eq!(role, Role::Operator);
}

// ── JSON-RPC envelope format tests ──

#[test]
fn test_jsonrpc_success_envelope() {
    let result = serde_json::json!({"status": "ok"});
    let id = serde_json::json!(1);
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "result": result,
        "id": id
    });
    assert_eq!(envelope["jsonrpc"], "2.0");
    assert!(envelope.get("error").is_none());
    assert_eq!(envelope["id"], 1);
}

#[test]
fn test_jsonrpc_error_envelope() {
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": ERR_FORBIDDEN,
            "message": "Insufficient privileges"
        },
        "id": 1
    });
    assert_eq!(envelope["error"]["code"], ERR_FORBIDDEN);
    assert_eq!(envelope["error"]["message"], "Insufficient privileges");
}

#[test]
fn test_jsonrpc_parse_error() {
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": -32700, "message": "Parse error" },
        "id": serde_json::Value::Null
    });
    assert_eq!(envelope["error"]["code"], -32700);
    assert!(envelope["id"].is_null());
}
