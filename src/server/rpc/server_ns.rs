//! `grob/server/*` namespace: status and config reload.

use super::auth::{require_role, CallerIdentity};
use super::types::{rpc_err, Role, StatusResponse, ERR_INTERNAL};
use crate::server::AppState;
use jsonrpsee::types::ErrorObjectOwned;
use std::sync::Arc;

/// Returns server status (mirrors `/health`).
pub async fn status(
    state: &Arc<AppState>,
    _caller: &CallerIdentity,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(_caller, Role::Observer)?;

    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    let spend_total = {
        let tracker = state.observability.spend_tracker.lock().await;
        tracker.total()
    };
    let inner = state.snapshot();
    let budget_limit = inner.config.budget.monthly_limit_usd.value();

    Ok(serde_json::json!({
        "status": "ok",
        "service": "grob",
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "started_at": state.started_at.to_rfc3339(),
        "active_requests": active,
        "spend": {
            "total_usd": spend_total,
            "budget_usd": budget_limit,
        }
    }))
}

/// Triggers an atomic configuration reload.
///
/// Rejects only **structurally** invalid candidates (parse error,
/// `AppConfig::validate()` failure, or provider-registry build failure) as a
/// JSON-RPC error, leaving the in-flight `inner` snapshot untouched. A
/// structurally-valid candidate is always swapped in — the reload is **not**
/// gated on live provider health. The same contract the HTTP
/// `/api/config/reload` endpoint enforces.
pub async fn reload_config(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    use crate::config::AppConfig;
    use crate::providers::ProviderRegistry;
    use crate::routing::classify::Router;
    use crate::server::ReloadableState;

    tracing::info!(
        caller_ip = %caller.ip,
        "RPC reload_config requested"
    );

    let new_config = AppConfig::from_source(&state.config_source)
        .await
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to reload config: {e}")))?;

    // Same shared guard as the HTTP reload path: a `/metrics` bearer-token change
    // cannot be hot-applied (resolved once at startup), so reject it here too
    // instead of silently keeping the old posture.
    crate::server::config_guard::ensure_metrics_auth_reloadable(state, &new_config)
        .map_err(|msg| rpc_err(ERR_INTERNAL, msg))?;

    let new_router = Router::new(new_config.clone());

    // `from_configs_with_models` resolves `secret:<name>` and `$ENV_VAR`
    // placeholders internally via the supplied backend.
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
    .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to init providers: {e}")))?;

    // The candidate is already structurally valid: `from_source` re-parsed it
    // and ran `AppConfig::validate()`, and `from_configs_with_models` confirmed
    // the registry builds. We do NOT gate the swap on live provider health — a
    // momentarily unreachable provider must not block a config reload.
    // In-flight requests continue on the old snapshot via their cached
    // `Arc<ReloadableState>`.
    let new_inner = Arc::new(ReloadableState::new(
        new_config.clone(),
        new_router,
        new_registry.clone(),
    ));

    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner;

    // Detached live-health probe as a signal only: logs warnings on unhealthy
    // router mappings after the swap, never blocking or reverting the reload.
    crate::server::config_api::spawn_health_probe(new_config, new_registry);

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some(format!(
            "Configuration reloaded ({active} requests still using old config)"
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn config_toml(metrics: &str) -> String {
        format!(
            r#"
[server]
host = "127.0.0.1"
port = 18100

[router]
default = "alpha"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"
{metrics}
"#
        )
    }

    fn operator() -> CallerIdentity {
        CallerIdentity {
            role: Role::Operator,
            ip: "127.0.0.1".to_string(),
            tenant_id: String::new(),
        }
    }

    // #1: the RPC reload path must enforce the same /metrics guard as HTTP.
    // Live state has a token; the on-disk config the RPC re-reads rotates it →
    // the reload must be rejected (restart required), not silently swapped.
    #[tokio::test]
    async fn rpc_reload_rejects_metrics_token_change() {
        use crate::cli::{AppConfig, ConfigSource};
        use crate::providers::ProviderRegistry;

        // On-disk config rotates the token to a different value.
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        write!(
            file,
            "{}",
            config_toml("\n[metrics]\nbearer_token = \"rotated\"\n")
        )
        .expect("write config");

        // Live state resolved its token from the ORIGINAL ("live") config.
        let live_config = AppConfig::from_content(
            &config_toml("\n[metrics]\nbearer_token = \"live\"\n"),
            "rpc_reload_test",
        )
        .expect("config parses");
        let state = crate::server::test_app_state_with_source(
            live_config,
            ProviderRegistry::new(),
            ConfigSource::File(file.path().to_path_buf()),
        );

        let err = reload_config(&state, &operator())
            .await
            .expect_err("RPC reload must reject a /metrics token change");
        assert!(
            err.message().contains("restart"),
            "RPC error must carry the restart-required message: {}",
            err.message()
        );
    }

    // An unchanged token does not block the RPC reload of other sections.
    #[tokio::test]
    async fn rpc_reload_allows_unchanged_metrics_token() {
        use crate::cli::{AppConfig, ConfigSource};
        use crate::providers::ProviderRegistry;

        let same = config_toml("\n[metrics]\nbearer_token = \"live\"\n");
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        write!(file, "{same}").expect("write config");

        let live_config = AppConfig::from_content(&same, "rpc_reload_ok_test").expect("parses");
        let state = crate::server::test_app_state_with_source(
            live_config,
            ProviderRegistry::new(),
            ConfigSource::File(file.path().to_path_buf()),
        );

        reload_config(&state, &operator())
            .await
            .expect("unchanged token must allow the RPC reload");
    }
}
