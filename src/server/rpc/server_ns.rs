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
pub async fn reload_config(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<StatusResponse, ErrorObjectOwned> {
    require_role(caller, Role::Operator)?;

    use crate::models::config::AppConfig;
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

    let new_router = Router::new(new_config.clone());

    // Resolve `secret:<name>` and `$ENV_VAR` placeholders so the JSON-RPC
    // reload path sees the same authenticated registry as `grob start`,
    // `validate`, and the HTTP `/api/config/reload` endpoint.
    let secret_backend =
        crate::storage::secrets::build_backend(&new_config.secrets, state.grob_store.clone());
    let resolved_providers = crate::storage::secrets::resolve_provider_secrets(
        &new_config.providers,
        secret_backend.as_ref(),
    );

    let new_registry = ProviderRegistry::from_configs_with_models(
        &resolved_providers,
        Some(state.token_store.clone()),
        &new_config.models,
        &new_config.server.timeouts,
    )
    .map(Arc::new)
    .map_err(|e| rpc_err(ERR_INTERNAL, format!("Failed to init providers: {e}")))?;

    let new_inner = Arc::new(ReloadableState::new(new_config, new_router, new_registry));

    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner.clone();

    // Background validation (non-blocking)
    tokio::spawn(async move {
        let results =
            crate::preset::validate_config(&new_inner.config, &new_inner.provider_registry).await;
        crate::preset::log_validation_results(&results);
    });

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some(format!(
            "Configuration reloaded ({active} requests still using old config)"
        )),
    })
}
