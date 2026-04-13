//! Generic control engine: `(state, action) → result`.
//!
//! Pure dispatch layer shared by CLI, MCP, and UI adapters.
//! Adapters translate transport-specific inputs into [`Action`] variants
//! and convert [`ControlResponse`] back to their wire format.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Action catalog ──

/// Top-level action routed by the control engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "namespace", content = "action")]
pub enum Action {
    /// Server lifecycle operations.
    Server(ServerAction),
    /// Model listing and routing queries.
    Model(ModelAction),
    /// Provider listing and scoring queries.
    Provider(ProviderAction),
    /// Budget and spend tracking.
    Budget(BudgetAction),
    /// API key management.
    Keys(KeysAction),
    /// Configuration inspection and mutation.
    Config(ConfigAction),
    /// Tool layer management.
    Tools(ToolsAction),
    /// HIT policy management.
    Hit(HitAction),
    /// Pledge profile management.
    Pledge(PledgeAction),
}

/// Server lifecycle actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum ServerAction {
    /// Queries current server status.
    Status,
    /// Triggers atomic configuration reload.
    Reload,
}

/// Model query actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum ModelAction {
    /// Lists all configured models.
    List,
    /// Returns routing rules and prompt classification.
    Routing,
}

/// Provider query actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum ProviderAction {
    /// Lists all registered providers.
    List,
    /// Returns adaptive provider scores.
    Score,
}

/// Budget and spend actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum BudgetAction {
    /// Returns current month spend and limit.
    Current,
    /// Returns per-provider spend breakdown.
    Breakdown,
}

/// API key management actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum KeysAction {
    /// Creates a new virtual API key.
    Create {
        /// Human-readable key label.
        name: String,
    },
    /// Lists all virtual keys.
    List,
    /// Revokes a key by identifier.
    Revoke {
        /// Key identifier to revoke.
        key_id: String,
    },
    /// Rotates a key, issuing a new secret.
    Rotate {
        /// Key identifier to rotate.
        key_id: String,
    },
}

/// Configuration inspection and mutation actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum ConfigAction {
    /// Reads one or all configuration keys.
    Get {
        /// Dot-separated key path (e.g. `"server.bind"`). `None` returns all.
        key: Option<String>,
    },
    /// Sets a configuration key to a new value.
    Set {
        /// Dot-separated key path.
        key: String,
        /// New value.
        value: serde_json::Value,
    },
    /// Triggers a full configuration reload from disk.
    Reload,
    /// Compares running config with on-disk version.
    Diff,
}

/// Tool layer management actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum ToolsAction {
    /// Lists active tools for the current config.
    List,
    /// Enables a tool by name.
    Enable {
        /// Tool name to enable.
        tool: String,
    },
    /// Disables a tool by name.
    Disable {
        /// Tool name to disable.
        tool: String,
    },
    /// Returns the full tool catalog.
    Catalog,
}

/// HIT (Human-In-The-loop) policy actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum HitAction {
    /// Lists all configured HIT policies.
    ListPolicies,
    /// Creates or updates a named policy.
    SetPolicy {
        /// Policy name.
        name: String,
        /// Policy definition.
        policy: serde_json::Value,
    },
    /// Reads a single policy by name.
    GetPolicy {
        /// Policy name.
        name: String,
    },
    /// Resolves which policy applies to a given context.
    Resolve {
        /// Request context for policy resolution.
        context: serde_json::Value,
    },
}

/// Pledge capability restriction actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum PledgeAction {
    /// Activates a pledge profile.
    Set {
        /// Profile name to activate.
        profile: String,
        /// Optional source filter.
        source: Option<String>,
    },
    /// Clears the active pledge, restoring defaults.
    Clear,
    /// Returns current pledge status.
    Status,
    /// Lists all available pledge profiles.
    ListProfiles,
}

// ── Response ──

/// Unified response envelope from the control engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    /// Indicates whether the action succeeded.
    pub success: bool,
    /// Structured payload (action-specific).
    pub data: serde_json::Value,
}

impl ControlResponse {
    /// Builds a successful response with the given payload.
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            success: true,
            data,
        }
    }

    /// Builds a successful response for mutating operations.
    pub fn ok_message(message: impl Into<String>) -> Self {
        Self {
            success: true,
            data: serde_json::json!({ "status": "ok", "message": message.into() }),
        }
    }
}

// ── Error ──

/// Control engine error with structured code for adapter translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlError {
    /// Machine-readable error code.
    pub code: ControlErrorCode,
    /// Human-readable detail message.
    pub message: String,
}

/// Error code taxonomy for control operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    /// Caller lacks required role.
    Unauthorized,
    /// Insufficient privileges.
    Forbidden,
    /// Requested resource does not exist.
    NotFound,
    /// Operational failure.
    Internal,
    /// Budget limit exceeded.
    BudgetExceeded,
    /// Invalid action parameters.
    InvalidParams,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ControlError {}

impl ControlError {
    /// Creates an unauthorized error.
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            code: ControlErrorCode::Unauthorized,
            message: msg.into(),
        }
    }

    /// Creates a forbidden error.
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            code: ControlErrorCode::Forbidden,
            message: msg.into(),
        }
    }

    /// Creates a not-found error.
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            code: ControlErrorCode::NotFound,
            message: msg.into(),
        }
    }

    /// Creates an internal error.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            code: ControlErrorCode::Internal,
            message: msg.into(),
        }
    }

    /// Creates an invalid-params error.
    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self {
            code: ControlErrorCode::InvalidParams,
            message: msg.into(),
        }
    }
}

// ── Role requirement mapping (pure) ──

use crate::server::rpc::types::Role;

/// Returns the minimum [`Role`] required for the given action.
pub fn required_role(action: &Action) -> Role {
    match action {
        // Read-only queries
        Action::Server(ServerAction::Status)
        | Action::Model(ModelAction::List | ModelAction::Routing)
        | Action::Provider(ProviderAction::List | ProviderAction::Score)
        | Action::Budget(BudgetAction::Current | BudgetAction::Breakdown)
        | Action::Tools(ToolsAction::List | ToolsAction::Catalog)
        | Action::Hit(HitAction::ListPolicies | HitAction::GetPolicy { .. })
        | Action::Pledge(PledgeAction::Status | PledgeAction::ListProfiles) => Role::Observer,

        // Operational mutations
        Action::Server(ServerAction::Reload)
        | Action::Config(ConfigAction::Reload | ConfigAction::Diff | ConfigAction::Get { .. })
        | Action::Hit(HitAction::Resolve { .. }) => Role::Operator,

        // Administrative mutations
        Action::Keys(_)
        | Action::Config(ConfigAction::Set { .. })
        | Action::Tools(ToolsAction::Enable { .. } | ToolsAction::Disable { .. })
        | Action::Hit(HitAction::SetPolicy { .. })
        | Action::Pledge(PledgeAction::Set { .. } | PledgeAction::Clear) => Role::Admin,
    }
}

/// Maps an RPC method string to an [`Action`].
///
/// # Errors
///
/// Returns `None` if the method name is not recognized.
pub fn parse_method(method: &str, params: Option<&serde_json::Value>) -> Option<Action> {
    let empty = serde_json::Value::Null;
    let p = params.unwrap_or(&empty);

    Some(match method {
        // server
        "grob/server/status" => Action::Server(ServerAction::Status),
        "grob/server/reload_config" => Action::Server(ServerAction::Reload),
        // model
        "grob/model/list" => Action::Model(ModelAction::List),
        "grob/model/routing" => Action::Model(ModelAction::Routing),
        // provider
        "grob/provider/list" => Action::Provider(ProviderAction::List),
        "grob/provider/score" => Action::Provider(ProviderAction::Score),
        // budget
        "grob/budget/current" => Action::Budget(BudgetAction::Current),
        "grob/budget/breakdown" => Action::Budget(BudgetAction::Breakdown),
        // keys
        "grob/keys/create" => Action::Keys(KeysAction::Create {
            name: p
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        "grob/keys/list" => Action::Keys(KeysAction::List),
        "grob/keys/revoke" => Action::Keys(KeysAction::Revoke {
            key_id: p
                .get("key_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        "grob/keys/rotate" => Action::Keys(KeysAction::Rotate {
            key_id: p
                .get("key_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        // config
        "grob/config/get" => Action::Config(ConfigAction::Get {
            key: p.get("key").and_then(|v| v.as_str()).map(String::from),
        }),
        "grob/config/set" => Action::Config(ConfigAction::Set {
            key: p
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            value: p.get("value").cloned().unwrap_or(serde_json::Value::Null),
        }),
        "grob/config/reload" => Action::Config(ConfigAction::Reload),
        "grob/config/diff" => Action::Config(ConfigAction::Diff),
        // tools
        "grob/tools/list" => Action::Tools(ToolsAction::List),
        "grob/tools/enable" => Action::Tools(ToolsAction::Enable {
            tool: p
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        "grob/tools/disable" => Action::Tools(ToolsAction::Disable {
            tool: p
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        "grob/tools/catalog" => Action::Tools(ToolsAction::Catalog),
        // hit
        "grob/hit/list_policies" => Action::Hit(HitAction::ListPolicies),
        "grob/hit/set_policy" => Action::Hit(HitAction::SetPolicy {
            name: p
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            policy: p.get("policy").cloned().unwrap_or(serde_json::Value::Null),
        }),
        "grob/hit/get_policy" => Action::Hit(HitAction::GetPolicy {
            name: p
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        "grob/hit/resolve" => Action::Hit(HitAction::Resolve {
            context: p.get("context").cloned().unwrap_or(serde_json::Value::Null),
        }),
        // pledge
        "grob/pledge/set" => Action::Pledge(PledgeAction::Set {
            profile: p
                .get("profile")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            source: p.get("source").and_then(|v| v.as_str()).map(String::from),
        }),
        "grob/pledge/clear" => Action::Pledge(PledgeAction::Clear),
        "grob/pledge/status" => Action::Pledge(PledgeAction::Status),
        "grob/pledge/list_profiles" => Action::Pledge(PledgeAction::ListProfiles),

        _ => return None,
    })
}

/// All registered control engine method names.
pub const ALL_METHODS: &[&str] = &[
    // server
    "grob/server/status",
    "grob/server/reload_config",
    // model
    "grob/model/list",
    "grob/model/routing",
    // provider
    "grob/provider/list",
    "grob/provider/score",
    // budget
    "grob/budget/current",
    "grob/budget/breakdown",
    // keys
    "grob/keys/create",
    "grob/keys/list",
    "grob/keys/revoke",
    "grob/keys/rotate",
    // config
    "grob/config/get",
    "grob/config/set",
    "grob/config/reload",
    "grob/config/diff",
    // tools
    "grob/tools/list",
    "grob/tools/enable",
    "grob/tools/disable",
    "grob/tools/catalog",
    // hit
    "grob/hit/list_policies",
    "grob/hit/set_policy",
    "grob/hit/get_policy",
    "grob/hit/resolve",
    // pledge
    "grob/pledge/set",
    "grob/pledge/clear",
    "grob/pledge/status",
    "grob/pledge/list_profiles",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_methods_returns_some() {
        for method in ALL_METHODS {
            assert!(
                parse_method(method, None).is_some(),
                "parse_method should recognize {method}"
            );
        }
    }

    #[test]
    fn parse_unknown_method_returns_none() {
        assert!(parse_method("grob/unknown/method", None).is_none());
        assert!(parse_method("", None).is_none());
        assert!(parse_method("not_grob", None).is_none());
    }

    #[test]
    fn parse_keys_create_extracts_name() {
        let params = serde_json::json!({ "name": "my-key" });
        let action = parse_method("grob/keys/create", Some(&params)).unwrap();
        match action {
            Action::Keys(KeysAction::Create { name }) => assert_eq!(name, "my-key"),
            _ => panic!("expected Keys::Create"),
        }
    }

    #[test]
    fn parse_config_get_with_key() {
        let params = serde_json::json!({ "key": "server.bind" });
        let action = parse_method("grob/config/get", Some(&params)).unwrap();
        match action {
            Action::Config(ConfigAction::Get { key }) => {
                assert_eq!(key.as_deref(), Some("server.bind"));
            }
            _ => panic!("expected Config::Get"),
        }
    }

    #[test]
    fn parse_config_get_without_key() {
        let action = parse_method("grob/config/get", None).unwrap();
        match action {
            Action::Config(ConfigAction::Get { key }) => assert!(key.is_none()),
            _ => panic!("expected Config::Get"),
        }
    }

    #[test]
    fn required_role_read_is_observer() {
        let read_actions = [
            Action::Server(ServerAction::Status),
            Action::Model(ModelAction::List),
            Action::Provider(ProviderAction::Score),
            Action::Budget(BudgetAction::Current),
            Action::Tools(ToolsAction::List),
            Action::Hit(HitAction::ListPolicies),
            Action::Pledge(PledgeAction::Status),
        ];
        for action in &read_actions {
            assert_eq!(
                required_role(action),
                Role::Observer,
                "expected Observer for {action:?}"
            );
        }
    }

    #[test]
    fn required_role_mutate_is_admin() {
        let admin_actions = [
            Action::Keys(KeysAction::List),
            Action::Config(ConfigAction::Set {
                key: "k".into(),
                value: serde_json::Value::Null,
            }),
            Action::Tools(ToolsAction::Enable { tool: "t".into() }),
            Action::Hit(HitAction::SetPolicy {
                name: "p".into(),
                policy: serde_json::Value::Null,
            }),
            Action::Pledge(PledgeAction::Set {
                profile: "read_only".into(),
                source: None,
            }),
        ];
        for action in &admin_actions {
            assert_eq!(
                required_role(action),
                Role::Admin,
                "expected Admin for {action:?}"
            );
        }
    }

    #[test]
    fn required_role_reload_is_operator() {
        assert_eq!(
            required_role(&Action::Server(ServerAction::Reload)),
            Role::Operator
        );
        assert_eq!(
            required_role(&Action::Config(ConfigAction::Reload)),
            Role::Operator
        );
    }

    #[test]
    fn control_response_ok_message() {
        let resp = ControlResponse::ok_message("done");
        assert!(resp.success);
        assert_eq!(resp.data["status"], "ok");
        assert_eq!(resp.data["message"], "done");
    }

    #[test]
    fn control_error_display() {
        let err = ControlError::not_found("key xyz missing");
        assert!(err.to_string().contains("NotFound"));
        assert!(err.to_string().contains("key xyz missing"));
    }

    #[test]
    fn action_serde_roundtrip() {
        let action = Action::Keys(KeysAction::Create {
            name: "test".into(),
        });
        let json = serde_json::to_string(&action).unwrap();
        let parsed: Action = serde_json::from_str(&json).unwrap();
        match parsed {
            Action::Keys(KeysAction::Create { name }) => assert_eq!(name, "test"),
            _ => panic!("roundtrip failed"),
        }
    }

    #[test]
    fn parse_pledge_set_extracts_fields() {
        let params = serde_json::json!({ "profile": "read_only", "source": "mcp" });
        let action = parse_method("grob/pledge/set", Some(&params)).unwrap();
        match action {
            Action::Pledge(PledgeAction::Set { profile, source }) => {
                assert_eq!(profile, "read_only");
                assert_eq!(source.as_deref(), Some("mcp"));
            }
            _ => panic!("expected Pledge::Set"),
        }
    }

    #[test]
    fn parse_tools_enable_extracts_tool() {
        let params = serde_json::json!({ "tool": "bash" });
        let action = parse_method("grob/tools/enable", Some(&params)).unwrap();
        match action {
            Action::Tools(ToolsAction::Enable { tool }) => assert_eq!(tool, "bash"),
            _ => panic!("expected Tools::Enable"),
        }
    }

    #[test]
    fn parse_hit_resolve_extracts_context() {
        let ctx = serde_json::json!({ "tenant": "acme", "zone": "eu" });
        let params = serde_json::json!({ "context": ctx });
        let action = parse_method("grob/hit/resolve", Some(&params)).unwrap();
        match action {
            Action::Hit(HitAction::Resolve { context }) => {
                assert_eq!(context["tenant"], "acme");
            }
            _ => panic!("expected Hit::Resolve"),
        }
    }
}
