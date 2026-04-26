//! `grob/hit/*` namespace: HIT (Human-In-The-loop) policy management.

use super::auth::{require_role, CallerIdentity};
use super::types::{rpc_err, Role, ERR_INTERNAL, ERR_NOT_FOUND};
#[cfg(feature = "policies")]
use crate::features::policies::config::PolicyConfig;
#[cfg(feature = "policies")]
use crate::features::policies::context::RequestContext;
#[cfg(feature = "policies")]
use crate::providers::ProviderRegistry;
#[cfg(feature = "policies")]
use crate::routing::classify::Router;
use crate::server::AppState;
#[cfg(feature = "policies")]
use crate::server::ReloadableState;
#[cfg(feature = "policies")]
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
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

/// Upserts a named HIT policy in memory; the change reverts on the next
/// config reload from disk (#228 non-goal: persistence).
///
/// The `policy` JSON is deserialized into a [`PolicyConfig`]. The `name`
/// argument always wins over `policy.name` to keep the path-vs-payload
/// invariant. If a policy with the same name already exists in
/// `config.policies`, it is replaced; otherwise the policy is appended.
/// The policy matcher is rebuilt as part of the atomic state swap (this
/// happens inside `ReloadableState::new`), so the new policy takes effect
/// before this RPC returns.
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` when the caller is below `Admin`.
/// Returns `INVALID_PARAMS_CODE` when `name` is empty, the JSON cannot
/// be parsed into a `PolicyConfig`, or any glob in the policy is invalid.
/// Returns `ERR_INTERNAL` when the registry rebuild or atomic swap fails.
#[cfg(feature = "policies")]
pub async fn set_policy(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    name: &str,
    policy: &serde_json::Value,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    if name.trim().is_empty() {
        return Err(rpc_err(INVALID_PARAMS_CODE, "policy name cannot be empty"));
    }

    let mut parsed: PolicyConfig = serde_json::from_value(policy.clone())
        .map_err(|e| rpc_err(INVALID_PARAMS_CODE, format!("invalid policy JSON: {e}")))?;
    // Path-wins-over-payload: the URL/RPC name is the canonical identity.
    parsed.name = name.to_string();

    let mut new_config = state.snapshot().config.clone();
    let action = if let Some(existing) = new_config.policies.iter_mut().find(|p| p.name == name) {
        *existing = parsed;
        "replace"
    } else {
        new_config.policies.push(parsed);
        "create"
    };

    // Validate by attempting to compile the matcher BEFORE swapping. If a
    // glob is malformed, the new state is rejected and the running config
    // is left intact.
    crate::features::policies::matcher::PolicyMatcher::new(new_config.policies.clone())
        .map_err(|e| rpc_err(INVALID_PARAMS_CODE, format!("policy compiles fail: {e}")))?;

    swap_state(
        state,
        new_config,
        caller,
        &format!("hit/{action}_policy '{name}'"),
    )?;

    Ok(serde_json::json!({
        "status": "ok",
        "action": action,
        "policy_name": name,
        "message": format!(
            "Policy '{name}' {action}d (in-memory only — change reverts on next disk reload)"
        ),
    }))
}

/// Stub when the `policies` feature is disabled: `set_policy` is unavailable.
#[cfg(not(feature = "policies"))]
pub async fn set_policy(
    _state: &Arc<AppState>,
    caller: &CallerIdentity,
    _name: &str,
    _policy: &serde_json::Value,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;
    Err(rpc_err(
        ERR_INTERNAL,
        "policies feature is not enabled at compile time",
    ))
}

/// Rebuilds the reloadable state from a mutated config and atomic-swaps
/// it. The `ReloadableState::new` constructor recompiles the policy
/// matcher from `config.policies`, so HIT policy changes are visible
/// immediately after the swap.
#[cfg(feature = "policies")]
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
        "RPC hit/* applied (in-memory only)"
    );
    Ok(())
}

/// Returns the full policy JSON (including HIT overrides) for the given policy name.
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
///
/// The `context` JSON is parsed into a [`RequestContext`]; missing fields
/// fall back to defaults (`""` for required string fields, `None` for
/// optional ones). The matcher is invoked in evaluate mode; the merged
/// [`ResolvedPolicy`] is projected to JSON for the response.
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` when the caller is below `Operator`.
/// Returns `INVALID_PARAMS_CODE` when `context` is not a JSON object.
/// Returns no error when no matcher is configured — the response carries
/// `{ "resolved": false, "reason": "..." }` instead.
pub async fn resolve(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    context: &serde_json::Value,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    let inner = state.snapshot();

    #[cfg(feature = "policies")]
    {
        match &inner.policy_matcher {
            Some(matcher) => {
                let ctx = parse_request_context(context)?;
                let resolved = matcher.evaluate(&ctx);
                Ok(serialize_resolved_policy(&resolved))
            }
            None => Ok(serde_json::json!({
                "resolved": false,
                "reason": "no policy matcher configured (no [[policies]] in config)"
            })),
        }
    }

    #[cfg(not(feature = "policies"))]
    {
        let _ = inner;
        let _ = context;
        Ok(serde_json::json!({
            "resolved": false,
            "reason": "policies feature is not enabled at compile time"
        }))
    }
}

/// Parses a JSON object into a [`RequestContext`], with permissive defaults.
///
/// `RequestContext` does not derive `Deserialize` (it is built imperatively
/// in the dispatch path), so we project field-by-field here. Missing
/// optional fields stay `None`; missing required string fields fall back
/// to `""` so a partial probe ("just match on model") still works.
#[cfg(feature = "policies")]
fn parse_request_context(value: &serde_json::Value) -> Result<RequestContext, ErrorObjectOwned> {
    let obj = value
        .as_object()
        .ok_or_else(|| rpc_err(INVALID_PARAMS_CODE, "context must be a JSON object"))?;

    let str_opt = |k: &str| obj.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let str_req = |k: &str| {
        obj.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let bool_opt = |k: &str| obj.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
    let f64_opt = |k: &str| obj.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let str_vec = |k: &str| {
        obj.get(k)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };

    Ok(RequestContext {
        tenant: str_opt("tenant"),
        zone: str_opt("zone"),
        project: str_opt("project"),
        user: str_opt("user"),
        agent: str_opt("agent"),
        compliance: str_vec("compliance"),
        model: str_req("model"),
        provider: str_req("provider"),
        route_type: str_req("route_type"),
        dlp_triggered: bool_opt("dlp_triggered"),
        estimated_cost: f64_opt("estimated_cost"),
    })
}

/// Projects a [`ResolvedPolicy`] to JSON for transport. Each override
/// field is reported as present/absent; the precise override shape is
/// not currently part of the JSON-RPC contract (callers that need the
/// full HIT/DLP/budget/log shape go through `policies/get_policy`).
#[cfg(feature = "policies")]
fn serialize_resolved_policy(
    resolved: &crate::features::policies::resolved::ResolvedPolicy,
) -> serde_json::Value {
    serde_json::json!({
        "resolved": true,
        "matched": resolved.matched,
        "has_dlp_override": resolved.dlp.is_some(),
        "has_rate_limit_override": resolved.rate_limit.is_some(),
        "has_routing_override": resolved.routing.is_some(),
        "has_budget_override": resolved.budget.is_some(),
        "has_log_export_override": resolved.log_export.is_some(),
        "has_hit_override": resolved.hit.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::rpc::types::ERR_FORBIDDEN;

    #[cfg(feature = "policies")]
    #[test]
    fn parse_context_extracts_all_fields() {
        let json = serde_json::json!({
            "tenant": "acme",
            "zone": "eu-west",
            "project": "alpha",
            "user": "ludwig",
            "agent": "claude-code",
            "compliance": ["pii", "gdpr"],
            "model": "claude-sonnet-4-6",
            "provider": "anthropic",
            "route_type": "default",
            "dlp_triggered": true,
            "estimated_cost": 0.42,
        });
        let ctx = parse_request_context(&json).unwrap();
        assert_eq!(ctx.tenant.as_deref(), Some("acme"));
        assert_eq!(ctx.zone.as_deref(), Some("eu-west"));
        assert_eq!(ctx.compliance, vec!["pii".to_string(), "gdpr".to_string()]);
        assert_eq!(ctx.model, "claude-sonnet-4-6");
        assert!(ctx.dlp_triggered);
        assert!((ctx.estimated_cost - 0.42).abs() < f64::EPSILON);
    }

    #[cfg(feature = "policies")]
    #[test]
    fn parse_context_tolerates_missing_fields() {
        // A partial probe with only `model` should yield empty defaults
        // for the rest, not an error. Useful for "match on model alone".
        let json = serde_json::json!({ "model": "claude-haiku-4-5" });
        let ctx = parse_request_context(&json).unwrap();
        assert_eq!(ctx.model, "claude-haiku-4-5");
        assert_eq!(ctx.provider, "");
        assert!(ctx.tenant.is_none());
        assert!(ctx.compliance.is_empty());
        assert!(!ctx.dlp_triggered);
    }

    #[cfg(feature = "policies")]
    #[test]
    fn parse_context_rejects_non_object() {
        let err = parse_request_context(&serde_json::json!("scalar")).unwrap_err();
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[cfg(feature = "policies")]
    #[test]
    fn set_policy_rejects_invalid_json() {
        // The PolicyConfig deserializer rejects this — name is required.
        // Tests the INVALID_PARAMS_CODE path of `set_policy` without
        // needing an AppState. We exercise the same `from_value` call.
        use crate::features::policies::config::PolicyConfig;
        let bad: Result<PolicyConfig, _> =
            serde_json::from_value(serde_json::json!({ "wrong_field": 42 }));
        assert!(bad.is_err());
    }

    #[cfg(feature = "policies")]
    #[test]
    fn matcher_compile_rejects_invalid_glob() {
        // Documents the validation gate added by `set_policy`: a malformed
        // glob in match_rules must fail compilation BEFORE we swap state.
        use crate::features::policies::config::PolicyConfig;
        let toml = r#"
name = "bad"

[match]
tenant = "[invalid"
"#;
        let cfg: PolicyConfig = toml::from_str(toml).expect("toml parse ok");
        let result = crate::features::policies::matcher::PolicyMatcher::new(vec![cfg]);
        assert!(result.is_err(), "malformed glob must fail to compile");
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
    fn require_role_allows_operator_for_resolve() {
        let operator = CallerIdentity {
            role: Role::Operator,
            ip: "10.0.0.1".into(),
            tenant_id: String::new(),
        };
        // resolve() requires Operator, not Admin — operators can probe
        // policy resolution without being able to mutate.
        assert!(require_role(&operator, Role::Operator).is_ok());
    }

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
