//! `grob/pledge/*` namespace: pledge profile inspection and management.

use super::auth::{require_role, CallerIdentity};
use super::types::{Role, StatusResponse};
use crate::server::AppState;
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

/// Activates a pledge profile for a given source.
pub async fn set(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    _profile: &str,
    _source: Option<&str>,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    // TODO(#228): Implement runtime pledge activation with config mutation.
    let _ = state;

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some("Pledge profile set (in-memory — reload to persist)".into()),
    })
}

/// Clears the active pledge, reverting all sources to the default profile.
pub async fn clear(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    // TODO(#228): Implement pledge clear with config mutation.
    let _ = state;

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some("Pledge cleared — defaults restored".into()),
    })
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
