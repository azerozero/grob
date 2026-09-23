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
/// Rejects invalid candidates and changes to startup-only config-derived
/// subsystems as a JSON-RPC error, leaving the in-flight `inner` snapshot
/// untouched. Accepted reloads are **not** gated on live provider health. The
/// same contract the HTTP `/api/config/reload` endpoint enforces.
pub async fn reload_config(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Admin)?;

    use crate::config::AppConfig;

    tracing::info!(
        caller_ip = %caller.ip,
        "RPC reload_config requested"
    );

    let mut new_config = AppConfig::from_source(&state.config_source)
        .await
        .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to reload config: {e}")))?;
    // Same reason as the HTTP path: without this a container-mode reload is
    // rejected for a `server.host` the operator never wrote.
    crate::server::config_guard::preserve_startup_overrides(state, &mut new_config);

    let new_inner = crate::server::config_guard::prepare_state(state, new_config)
        .map_err(|e| rpc_err(ERR_INTERNAL, e.to_string()))?;
    let probe_config = new_inner.config.clone();
    let probe_registry = new_inner.provider_registry.clone();

    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner;

    // Detached live-health probe as a signal only: logs warnings on unhealthy
    // router mappings after the swap, never blocking or reverting the reload.
    crate::server::config_api::spawn_health_probe(probe_config, probe_registry);

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
    use crate::providers::ProviderRegistry;
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

    fn admin() -> CallerIdentity {
        CallerIdentity {
            role: Role::Admin,
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

        let err = reload_config(&state, &admin())
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

        let same = config_toml("\n[metrics]\nbearer_token = \"live\"\n");
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        write!(file, "{same}").expect("write config");

        let live_config = AppConfig::from_content(&same, "rpc_reload_ok_test").expect("parses");
        let state = crate::server::test_app_state_with_source(
            live_config,
            ProviderRegistry::new(),
            ConfigSource::File(file.path().to_path_buf()),
        );

        reload_config(&state, &admin())
            .await
            .expect("unchanged token must allow the RPC reload");
    }
}
