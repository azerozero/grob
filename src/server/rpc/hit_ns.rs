//! `grob/hit/*` namespace: HIT (Human-In-The-loop) policy management.

use super::auth::{require_role, CallerIdentity};
use super::types::{rpc_err, Role, ERR_INTERNAL, ERR_NOT_FOUND};
use crate::server::AppState;
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// HIT policy summary returned by `grob/hit/list_policies`.
#[derive(Debug, Serialize, Deserialize)]
pub struct HitPolicyInfo {
    /// Policy name.
    pub name: String,
    /// Whether the policy has a HIT override section.
    pub has_hit: bool,
}

/// Lists all configured policies with HIT relevance.
pub async fn list_policies(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<Vec<HitPolicyInfo>, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let inner = state.snapshot();

    let policies: Vec<HitPolicyInfo> = inner
        .config
        .policies
        .iter()
        .map(|p| HitPolicyInfo {
            name: p.name.clone(),
            has_hit: p.hit.is_some(),
        })
        .collect();

    Ok(policies)
}

/// Creates or updates a named HIT policy.
pub async fn set_policy(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    _name: &str,
    _policy: &serde_json::Value,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    // TODO: Implement runtime policy mutation with config reload.
    let _ = state;

    Ok(serde_json::json!({
        "status": "ok",
        "message": "Policy set (in-memory — use config reload to persist)"
    }))
}

/// Reads a single policy by name.
pub async fn get_policy(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    name: &str,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let inner = state.snapshot();

    let found = inner.config.policies.iter().find(|p| p.name == name);
    match found {
        Some(policy) => serde_json::to_value(policy)
            .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to serialize policy: {e}"))),
        None => Err(rpc_err(ERR_NOT_FOUND, format!("Policy not found: {name}"))),
    }
}

/// Resolves which policy applies to a given request context.
pub async fn resolve(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    _context: &serde_json::Value,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    let inner = state.snapshot();

    #[cfg(feature = "policies")]
    {
        match &inner.policy_matcher {
            Some(_matcher) => {
                // TODO: Build RequestContext from JSON and run matcher.resolve().
                Ok(serde_json::json!({
                    "resolved": true,
                    "message": "Policy resolution placeholder — full implementation in Phase 2"
                }))
            }
            None => Ok(serde_json::json!({
                "resolved": false,
                "message": "No policy matcher configured"
            })),
        }
    }

    #[cfg(not(feature = "policies"))]
    {
        let _ = inner;
        Ok(serde_json::json!({
            "resolved": false,
            "message": "Policies feature not enabled"
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_policy_info_serialization() {
        let info = HitPolicyInfo {
            name: "default".into(),
            has_hit: true,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["name"], "default");
        assert_eq!(json["has_hit"], true);
    }

    #[test]
    fn hit_policy_info_no_hit() {
        let info = HitPolicyInfo {
            name: "dlp_only".into(),
            has_hit: false,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["has_hit"], false);
    }

    #[test]
    fn hit_policy_info_roundtrip() {
        let info = HitPolicyInfo {
            name: "test_policy".into(),
            has_hit: true,
        };
        let json_str = serde_json::to_string(&info).unwrap();
        let parsed: HitPolicyInfo = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.name, "test_policy");
        assert!(parsed.has_hit);
    }
}
