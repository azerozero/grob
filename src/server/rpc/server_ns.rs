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
/// Awaits validation against the candidate registry **before** swapping
/// the live snapshot. A failure surfaces as a JSON-RPC error and the
/// in-flight `inner` snapshot stays untouched — the same contract the
/// HTTP `/api/config/reload` endpoint enforces.
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

    // Awaited validation BEFORE swap so a misconfigured reload cannot
    // briefly serve traffic. In-flight requests continue on the old
    // snapshot via their cached `Arc<ReloadableState>`.
    let validation = crate::preset::validate_config(&new_config, &new_registry).await;
    crate::preset::log_validation_results(&validation);
    let broken: Vec<&crate::preset::ModelValidation> =
        validation.iter().filter(|m| !m.any_ok()).collect();
    if !broken.is_empty() {
        let detail = broken
            .iter()
            .map(|m| format!("{} [{}]", m.model_name, m.role))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(rpc_err(
            ERR_INTERNAL,
            format!(
                "Validation failed — config not reloaded. Models with no healthy provider: {detail}"
            ),
        ));
    }

    let new_inner = Arc::new(ReloadableState::new(new_config, new_router, new_registry));

    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner;

    Ok(StatusResponse {
        status: "ok".into(),
        message: Some(format!(
            "Configuration reloaded ({active} requests still using old config)"
        )),
    })
}
