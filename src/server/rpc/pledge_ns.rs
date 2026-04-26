//! `grob/pledge/*` namespace: pledge profile inspection and management.

use super::auth::{require_role, CallerIdentity};
use super::types::{rpc_err, Role, StatusResponse, ERR_INTERNAL};
use crate::features::pledge::config::PledgeRule;
use crate::providers::ProviderRegistry;
use crate::routing::classify::Router;
use crate::server::{AppState, ReloadableState};
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Pledge profile summary returned by `grob/pledge/list_profiles`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PledgeProfileInfo {
    /// Profile name.
    pub name: String,
    /// Whether all tools are allowed (no filtering).
    pub allow_all: bool,
    /// Explicit tool allowlist (empty when `allow_all` is true).
    pub allowed_tools: Vec<String>,
}

/// Activates a pledge profile, in-memory only (#228 non-goal: persistence).
///
/// When `source` is `Some`, a new `PledgeRule { source, profile }` is
/// appended (or updated if a rule with the same source already exists).
/// When `source` is `None`, the active default profile is replaced and
/// the master switch flipped on.
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` when the caller is below `Admin`.
/// Returns `INVALID_PARAMS_CODE` when `profile` is empty or unknown to
/// the built-in catalogue (`read_only`, `execute`, `full`, `none`).
/// Returns `ERR_INTERNAL` when the registry rebuild or atomic swap fails.
pub async fn set(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    profile: &str,
    source: Option<&str>,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;
    let mut new_config = state.snapshot().config.clone();
    apply_set(&mut new_config, profile, source)?;
    swap_state(
        state,
        new_config,
        caller,
        &format!(
            "set pledge '{profile}' for source={}",
            source.unwrap_or("<default>")
        ),
    )?;
    let target = source.unwrap_or("<default>");
    Ok(StatusResponse {
        status: "ok".into(),
        message: Some(format!(
            "Pledge profile '{profile}' applied to {target} (in-memory only — change reverts on next disk reload)"
        )),
    })
}

/// Clears all runtime pledge rules and resets the default profile to
/// `full` (in-memory only).
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` when the caller is below `Admin`.
/// Returns `ERR_INTERNAL` when the registry rebuild or atomic swap fails.
pub async fn clear(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;
    let mut new_config = state.snapshot().config.clone();
    apply_clear(&mut new_config);
    swap_state(state, new_config, caller, "clear pledge rules")?;
    Ok(StatusResponse {
        status: "ok".into(),
        message: Some(
            "Pledge cleared — defaults restored (in-memory only — change reverts on next disk reload)"
                .into(),
        ),
    })
}

/// Pure mutation helper for `set`. Validates the profile name and
/// either upserts a per-source rule or updates the default profile.
fn apply_set(
    config: &mut crate::models::config::AppConfig,
    profile: &str,
    source: Option<&str>,
) -> Result<(), ErrorObjectOwned> {
    if profile.trim().is_empty() {
        return Err(rpc_err(INVALID_PARAMS_CODE, "profile name cannot be empty"));
    }
    if !is_known_profile(profile) {
        return Err(rpc_err(
            INVALID_PARAMS_CODE,
            format!("unknown profile '{profile}' (built-ins: read_only, execute, full, none)"),
        ));
    }

    config.pledge.enabled = true;

    match source {
        None => {
            config.pledge.default_profile = profile.to_string();
        }
        Some("") => {
            return Err(rpc_err(
                INVALID_PARAMS_CODE,
                "source cannot be empty (omit it to set the default profile)",
            ));
        }
        Some(src) => {
            // Upsert: replace any existing rule for this source.
            if let Some(existing) = config
                .pledge
                .rules
                .iter_mut()
                .find(|r| r.source.as_deref() == Some(src))
            {
                existing.profile = profile.to_string();
            } else {
                config.pledge.rules.push(PledgeRule {
                    source: Some(src.to_string()),
                    token_prefix: None,
                    profile: profile.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Pure mutation helper for `clear`. Drops all rules and resets the
/// default profile to the catalogue default (`full`).
fn apply_clear(config: &mut crate::models::config::AppConfig) {
    config.pledge.rules.clear();
    config.pledge.default_profile = "full".to_string();
}

/// Verifies that a profile name belongs to the built-in catalogue.
fn is_known_profile(name: &str) -> bool {
    matches!(name, "read_only" | "execute" | "full" | "none")
}

/// Rebuilds the reloadable state from a mutated config and atomic-swaps
/// it. Same primitive as `config_ns::set` and `tools_ns::*`.
fn swap_state(
    state: &Arc<AppState>,
    new_config: crate::models::config::AppConfig,
    caller: &CallerIdentity,
    action: &str,
) -> Result<(), ErrorObjectOwned> {
    let new_router = Router::new(new_config.clone());
    let new_registry = ProviderRegistry::from_configs_with_models(
        &new_config.providers,
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
        "RPC pledge/* applied (in-memory only)"
    );
    Ok(())
}

/// Returns the active pledge configuration, default profile, and per-rule bindings.
pub async fn status(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let inner = state.snapshot();
    let pledge_cfg = &inner.config.pledge;

    Ok(serde_json::json!({
        "enabled": pledge_cfg.enabled,
        "default_profile": pledge_cfg.default_profile,
        "rules_count": pledge_cfg.rules.len(),
        "rules": pledge_cfg.rules.iter().map(|r| {
            serde_json::json!({
                "source": r.source,
                "token_prefix": r.token_prefix,
                "profile": r.profile,
            })
        }).collect::<Vec<_>>(),
    }))
}

/// Lists all available built-in pledge profiles.
pub async fn list_profiles(
    _state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<Vec<PledgeProfileInfo>, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    use crate::features::pledge::profiles;

    let builtins = [
        &profiles::READ_ONLY,
        &profiles::EXECUTE,
        &profiles::FULL,
        &profiles::NONE,
    ];

    Ok(builtins
        .iter()
        .map(|p| PledgeProfileInfo {
            name: p.name.to_string(),
            allow_all: p.allow_all,
            allowed_tools: p.allowed_tools.iter().map(|s| (*s).to_string()).collect(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::config::AppConfig;
    use crate::server::rpc::types::ERR_FORBIDDEN;

    fn fixture_config() -> AppConfig {
        let toml = r#"
[router]
default = "claude-sonnet-4-6"

[cache]
enabled = false
max_capacity = 100
ttl_secs = 60
max_entry_bytes = 8192

[pledge]
enabled = false
default_profile = "full"
"#;
        toml::from_str(toml).expect("valid test TOML")
    }

    #[test]
    fn set_default_profile_with_no_source() {
        let mut config = fixture_config();
        apply_set(&mut config, "read_only", None).expect("set should succeed");
        assert!(config.pledge.enabled, "set must flip the master switch on");
        assert_eq!(config.pledge.default_profile, "read_only");
        assert!(config.pledge.rules.is_empty());
    }

    #[test]
    fn set_per_source_appends_rule() {
        let mut config = fixture_config();
        apply_set(&mut config, "execute", Some("mcp")).expect("set should succeed");
        assert!(config.pledge.enabled);
        assert_eq!(config.pledge.rules.len(), 1);
        let rule = &config.pledge.rules[0];
        assert_eq!(rule.source.as_deref(), Some("mcp"));
        assert_eq!(rule.profile, "execute");
    }

    #[test]
    fn set_per_source_upserts_existing() {
        // Setting a profile for a source that already has a rule must replace
        // the profile, not append a duplicate.
        let mut config = fixture_config();
        apply_set(&mut config, "read_only", Some("cli")).unwrap();
        apply_set(&mut config, "execute", Some("cli")).unwrap();
        assert_eq!(config.pledge.rules.len(), 1);
        assert_eq!(config.pledge.rules[0].profile, "execute");
    }

    #[test]
    fn set_rejects_unknown_profile() {
        let mut config = fixture_config();
        let err = apply_set(&mut config, "yolo", None).unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert!(err.message().contains("unknown profile"));
    }

    #[test]
    fn set_rejects_empty_profile() {
        let mut config = fixture_config();
        let err = apply_set(&mut config, "  ", None).unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[test]
    fn set_rejects_empty_source() {
        let mut config = fixture_config();
        let err = apply_set(&mut config, "full", Some("")).unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
        assert!(err.message().contains("omit it"));
    }

    #[test]
    fn clear_drops_rules_and_resets_default() {
        let mut config = fixture_config();
        // Seed a rule + non-default default to verify reset.
        apply_set(&mut config, "execute", Some("mcp")).unwrap();
        apply_set(&mut config, "read_only", None).unwrap();
        apply_clear(&mut config);
        assert!(config.pledge.rules.is_empty());
        assert_eq!(config.pledge.default_profile, "full");
    }

    #[test]
    fn require_role_denies_observer_for_admin_methods() {
        let observer = CallerIdentity {
            role: Role::Observer,
            ip: "10.0.0.1".into(),
            tenant_id: String::new(),
        };
        let err = require_role(&observer, Role::Admin).unwrap_err();
        assert_eq!(err.code(), ERR_FORBIDDEN);
    }

    #[test]
    fn pledge_profile_info_serialization() {
        let info = PledgeProfileInfo {
            name: "read_only".into(),
            allow_all: false,
            allowed_tools: vec!["grep".into(), "read_file".into()],
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["name"], "read_only");
        assert_eq!(json["allow_all"], false);
        assert_eq!(json["allowed_tools"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn pledge_profile_info_allow_all() {
        let info = PledgeProfileInfo {
            name: "full".into(),
            allow_all: true,
            allowed_tools: vec![],
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["allow_all"], true);
        assert!(json["allowed_tools"].as_array().unwrap().is_empty());
    }

    #[test]
    fn pledge_profile_info_roundtrip() {
        let info = PledgeProfileInfo {
            name: "none".into(),
            allow_all: false,
            allowed_tools: vec![],
        };
        let json_str = serde_json::to_string(&info).unwrap();
        let parsed: PledgeProfileInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.name, "none");
        assert!(!parsed.allow_all);
    }
}
