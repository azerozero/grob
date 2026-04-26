//! `grob/config/*` namespace: configuration inspection and mutation.

use super::auth::{require_role, CallerIdentity};
use super::types::{rpc_err, Role, StatusResponse, ERR_INTERNAL};
use crate::models::config::AppConfig;
use crate::providers::ProviderRegistry;
use crate::routing::classify::Router;
use crate::server::config_guard::is_section_or_key_denied;
use crate::server::{AppState, ReloadableState};
use jsonrpsee::types::error::INVALID_PARAMS_CODE;
use jsonrpsee::types::ErrorObjectOwned;
use std::sync::Arc;

/// Returns the running configuration (or a single key).
pub async fn get(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    key: Option<&str>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    let inner = state.snapshot();
    let full = serde_json::to_value(&inner.config)
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to serialize config: {e}")))?;

    match key {
        Some(path) => {
            let value = resolve_dotted_path(&full, path);
            match value {
                Some(v) => Ok(serde_json::json!({ "key": path, "value": v })),
                None => Ok(serde_json::json!({ "key": path, "value": null, "found": false })),
            }
        }
        None => Ok(full),
    }
}

/// Applies a key/value mutation to the running config (in-memory only).
///
/// The change survives until the next config reload from disk.
/// Persistence is explicitly out of scope (#228).
///
/// # Errors
///
/// Returns `ERR_FORBIDDEN` (insufficient role) when the caller is below `Admin`.
/// Returns `INVALID_PARAMS_CODE` when `key` is malformed (no dot separator),
/// targets a denied section/key (`providers`, `dlp`, any `api_key`), or the
/// value type does not match the field.
/// Returns `ERR_INTERNAL` when the atomic config swap fails.
pub async fn set(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    key: &str,
    value: &serde_json::Value,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    // Clone the active config so a validation failure leaves the snapshot intact.
    let mut new_config = state.snapshot().config.clone();
    apply_runtime_update(&mut new_config, key, value)?;

    // Rebuild the reloadable state from the mutated config and swap atomically.
    // Mirrors the pattern in `server_ns::reload_config` and
    // `config_guard::reload_state`. We deliberately do NOT call
    // `config_guard::persist_and_reload`: persistence to disk is a non-goal
    // for #228 (in-memory mutation only).
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
        key = key,
        "RPC config/set applied (in-memory only)"
    );

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some(format!(
            "Set {key} (in-memory only — change reverts on next disk reload)"
        )),
    })
}

/// Triggers a full configuration reload from disk.
///
/// Delegates to the existing `server_ns::reload_config` logic.
pub async fn reload(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    super::server_ns::reload_config(state, caller).await
}

/// Compares running config with on-disk version.
pub async fn diff(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    let running = {
        let inner = state.snapshot();
        serde_json::to_value(&inner.config)
            .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to serialize config: {e}")))?
    };

    let disk = match crate::models::config::AppConfig::from_source(&state.config_source).await {
        Ok(cfg) => serde_json::to_value(&cfg).map_err(|e| {
            rpc_err(
                ERR_INTERNAL,
                format!("Failed to serialize disk config: {e}"),
            )
        })?,
        Err(e) => {
            return Ok(serde_json::json!({
                "error": format!("Failed to read disk config: {e}"),
                "diff": null,
            }));
        }
    };

    let identical = running == disk;

    Ok(serde_json::json!({
        "identical": identical,
        "running": running,
        "disk": disk,
    }))
}

/// Resolves a dot-separated path against a JSON value.
fn resolve_dotted_path<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Applies an in-memory mutation to `config` according to a dotted `key`.
///
/// Splits `key` at the first `.` into `(section, sub_key)`, validates the
/// pair against [`is_section_or_key_denied`], then writes the JSON `value`
/// into the matching field. The mutation contract mirrors
/// [`crate::server::mcp_handlers::config::apply_config_update`] so that the
/// MCP and JSON-RPC self-tuning surfaces stay aligned (per #228 plan).
///
/// Supported sections: `router`, `budget`, `cache`, `classifier`. The
/// `providers` and `dlp` sections, plus any `api_key` field, are rejected
/// up-front by the deny-list.
///
/// # Errors
///
/// Returns an `ErrorObjectOwned` with code `INVALID_PARAMS_CODE` when:
/// - `key` lacks a `.` separator,
/// - the resolved `(section, sub_key)` pair is on the deny-list,
/// - the section name is unknown,
/// - the sub-key is unknown for that section,
/// - the JSON `value` type does not match the destination field.
fn apply_runtime_update(
    config: &mut AppConfig,
    key: &str,
    value: &serde_json::Value,
) -> Result<(), ErrorObjectOwned> {
    let invalid = |msg: String| rpc_err(INVALID_PARAMS_CODE, msg);

    let (section, sub_key) = key.split_once('.').ok_or_else(|| {
        invalid(format!(
            "key must be in dotted form (e.g. 'router.default'); got '{key}'"
        ))
    })?;

    if is_section_or_key_denied(section, sub_key) {
        return Err(invalid(format!(
            "section/key '{section}.{sub_key}' is on the deny-list (security policy)"
        )));
    }

    match section {
        "router" => match sub_key {
            "default" => {
                config.router.default = value
                    .as_str()
                    .ok_or_else(|| invalid("expected string for router.default".into()))?
                    .to_string();
            }
            "background" => config.router.background = value.as_str().map(String::from),
            "think" => config.router.think = value.as_str().map(String::from),
            "websearch" => config.router.websearch = value.as_str().map(String::from),
            "auto_map_regex" => config.router.auto_map_regex = value.as_str().map(String::from),
            "background_regex" => config.router.background_regex = value.as_str().map(String::from),
            "gdpr" => {
                config.router.gdpr = value
                    .as_bool()
                    .ok_or_else(|| invalid("expected bool for router.gdpr".into()))?;
            }
            "region" => config.router.region = value.as_str().map(String::from),
            other => return Err(invalid(format!("unknown router key: {other}"))),
        },
        "budget" => match sub_key {
            "monthly_limit_usd" => {
                let v = value.as_f64().ok_or_else(|| {
                    invalid("expected number for budget.monthly_limit_usd".into())
                })?;
                config.budget.monthly_limit_usd = crate::cli::BudgetUsd::new(v)
                    .map_err(|e| invalid(format!("invalid budget: {e}")))?;
            }
            "warn_at_percent" => {
                let v = value
                    .as_u64()
                    .ok_or_else(|| invalid("expected integer for budget.warn_at_percent".into()))?;
                if v > 100 {
                    return Err(invalid("warn_at_percent must be 0-100".into()));
                }
                config.budget.warn_at_percent = v as u32;
            }
            other => return Err(invalid(format!("unknown budget key: {other}"))),
        },
        "cache" => match sub_key {
            "enabled" => {
                config.cache.enabled = value
                    .as_bool()
                    .ok_or_else(|| invalid("expected bool for cache.enabled".into()))?;
            }
            "max_capacity" => {
                config.cache.max_capacity = value
                    .as_u64()
                    .ok_or_else(|| invalid("expected integer for cache.max_capacity".into()))?;
            }
            "ttl_secs" => {
                config.cache.ttl_secs = value
                    .as_u64()
                    .ok_or_else(|| invalid("expected integer for cache.ttl_secs".into()))?;
            }
            "max_entry_bytes" => {
                let v = value
                    .as_u64()
                    .ok_or_else(|| invalid("expected integer for cache.max_entry_bytes".into()))?;
                config.cache.max_entry_bytes = v as usize;
            }
            other => return Err(invalid(format!("unknown cache key: {other}"))),
        },
        "classifier" => {
            let cfg = config.classifier.get_or_insert_with(Default::default);
            let v = value
                .as_f64()
                .ok_or_else(|| invalid(format!("expected number for classifier.{sub_key}")))?
                as f32;
            match sub_key {
                "weights.max_tokens" => cfg.weights.max_tokens = v,
                "weights.tools" => cfg.weights.tools = v,
                "weights.context_size" => cfg.weights.context_size = v,
                "weights.keywords" => cfg.weights.keywords = v,
                "weights.system_prompt" => cfg.weights.system_prompt = v,
                "thresholds.medium_threshold" => cfg.thresholds.medium_threshold = v,
                "thresholds.complex_threshold" => cfg.thresholds.complex_threshold = v,
                other => return Err(invalid(format!("unknown classifier key: {other}"))),
            }
        }
        other => return Err(invalid(format!("unknown config section: {other}"))),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::rpc::types::ERR_FORBIDDEN;

    /// Parses a minimal AppConfig from a TOML snippet (test fixture).
    fn fixture_config() -> AppConfig {
        let toml = r#"
[router]
default = "claude-sonnet-4-6"

[cache]
enabled = false
max_capacity = 100
ttl_secs = 60
max_entry_bytes = 8192
"#;
        toml::from_str(toml).expect("valid test TOML")
    }

    #[test]
    fn resolve_dotted_path_simple() {
        let v = serde_json::json!({ "a": { "b": { "c": 42 } } });
        assert_eq!(
            resolve_dotted_path(&v, "a.b.c"),
            Some(&serde_json::json!(42))
        );
    }

    #[test]
    fn resolve_dotted_path_missing() {
        let v = serde_json::json!({ "a": { "b": 1 } });
        assert!(resolve_dotted_path(&v, "a.x.y").is_none());
    }

    #[test]
    fn resolve_dotted_path_root() {
        let v = serde_json::json!({ "key": "value" });
        assert_eq!(
            resolve_dotted_path(&v, "key"),
            Some(&serde_json::json!("value"))
        );
    }

    #[test]
    fn resolve_dotted_path_array_element() {
        let v = serde_json::json!({ "arr": [1, 2, 3] });
        let result = resolve_dotted_path(&v, "arr");
        assert!(result.is_some());
        assert!(result.unwrap().is_array());
    }

    // ── apply_runtime_update — mutation path ─────────────────────────

    #[test]
    fn set_router_default_succeeds_for_admin() {
        // Mirrors the chef-spec test: an Admin caller setting `router.default`
        // results in the config field being mutated. The role check is verified
        // separately in `set_denies_for_observer`; here we exercise the mutation.
        let mut config = fixture_config();
        apply_runtime_update(
            &mut config,
            "router.default",
            &serde_json::json!("new-default"),
        )
        .expect("router.default update should succeed");
        assert_eq!(config.router.default, "new-default");
    }

    #[test]
    fn set_cache_ttl_succeeds() {
        let mut config = fixture_config();
        apply_runtime_update(&mut config, "cache.ttl_secs", &serde_json::json!(900))
            .expect("cache.ttl_secs update should succeed");
        assert_eq!(config.cache.ttl_secs, 900);
    }

    #[test]
    fn set_rejects_dlp_section() {
        // Bonus chef-spec test: dlp section is on the deny-list, even for Admin.
        let mut config = fixture_config();
        let err = apply_runtime_update(&mut config, "dlp.enabled", &serde_json::json!(true))
            .expect_err("dlp section is denied");
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[test]
    fn set_rejects_providers_section() {
        let mut config = fixture_config();
        let err = apply_runtime_update(
            &mut config,
            "providers.name",
            &serde_json::json!("anthropic"),
        )
        .expect_err("providers section is denied");
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[test]
    fn set_rejects_api_key_field() {
        let mut config = fixture_config();
        let err = apply_runtime_update(&mut config, "router.api_key", &serde_json::json!("secret"))
            .expect_err("api_key fields are denied");
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[test]
    fn set_rejects_malformed_key() {
        let mut config = fixture_config();
        let err = apply_runtime_update(&mut config, "noseparator", &serde_json::json!("x"))
            .expect_err("missing '.' separator should fail");
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[test]
    fn set_rejects_unknown_section() {
        let mut config = fixture_config();
        let err = apply_runtime_update(&mut config, "bogus.field", &serde_json::json!("x"))
            .expect_err("unknown section should fail");
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[test]
    fn set_rejects_unknown_router_key() {
        let mut config = fixture_config();
        let err = apply_runtime_update(&mut config, "router.bogus", &serde_json::json!("x"))
            .expect_err("unknown router key should fail");
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    #[test]
    fn set_rejects_wrong_value_type() {
        let mut config = fixture_config();
        let err = apply_runtime_update(&mut config, "router.default", &serde_json::json!(42))
            .expect_err("router.default expects a string");
        assert_eq!(err.code(), INVALID_PARAMS_CODE);
    }

    // ── role enforcement (the entry point of `set`) ──────────────────

    #[test]
    fn set_denies_for_observer() {
        // `set` calls `require_role(caller, Role::Admin)` before any state
        // access — so an Observer caller is rejected with `ERR_FORBIDDEN`
        // (the canonical "insufficient role" code in this repo) regardless of
        // the key/value. We assert the role-check contract directly to avoid
        // pulling a full `AppState` into a unit test.
        let observer = CallerIdentity {
            role: Role::Observer,
            ip: "10.0.0.1".into(),
            tenant_id: String::new(),
        };
        let err = require_role(&observer, Role::Admin).expect_err("Observer < Admin");
        assert_eq!(err.code(), ERR_FORBIDDEN);

        // Sanity: Operator is also below Admin.
        let operator = CallerIdentity {
            role: Role::Operator,
            ip: "10.0.0.1".into(),
            tenant_id: String::new(),
        };
        assert!(require_role(&operator, Role::Admin).is_err());
    }

    #[test]
    fn set_admin_passes_role_check() {
        let admin = CallerIdentity {
            role: Role::Admin,
            ip: "10.0.0.1".into(),
            tenant_id: String::new(),
        };
        assert!(require_role(&admin, Role::Admin).is_ok());
    }
}
