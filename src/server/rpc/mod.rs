//! Unified JSON-RPC 2.0 Control Plane for Grob.
//!
//! Exposes server management, model routing, provider scoring, and budget
//! tracking through a single `POST /rpc` endpoint. Authentication and
//! authorization are resolved per-request from transport credentials.

pub mod auth;
pub(crate) mod budget_ns;
pub(crate) mod model_ns;
pub(crate) mod provider_ns;
pub(crate) mod server_ns;
pub mod types;

use crate::server::AppState;
use auth::CallerIdentity;
use std::sync::Arc;

/// Dispatches a JSON-RPC method call to the appropriate namespace handler.
///
/// Returns a `serde_json::Value` result or an `ErrorObjectOwned` on failure.
/// The caller identity has already been resolved by the axum handler.
pub async fn dispatch(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
    method: &str,
    _params: Option<&serde_json::Value>,
) -> Result<serde_json::Value, jsonrpsee::types::ErrorObjectOwned> {
    match method {
        // ── grob/server/* ──
        "grob/server/status" => server_ns::status(state, caller).await,
        "grob/server/reload_config" => {
            let r = server_ns::reload_config(state, caller).await?;
            serde_json::to_value(r).map_err(|e| types::rpc_err(types::ERR_INTERNAL, e.to_string()))
        }

        // ── grob/model/* ──
        "grob/model/list" => model_ns::list(state, caller).await,
        "grob/model/routing" => model_ns::routing(state, caller).await,

        // ── grob/provider/* ──
        "grob/provider/list" => {
            let r = provider_ns::list(state, caller).await?;
            serde_json::to_value(r).map_err(|e| types::rpc_err(types::ERR_INTERNAL, e.to_string()))
        }
        "grob/provider/score" => provider_ns::score(state, caller).await,

        // ── grob/budget/* ──
        "grob/budget/current" => {
            let r = budget_ns::current(state, caller).await?;
            serde_json::to_value(r).map_err(|e| types::rpc_err(types::ERR_INTERNAL, e.to_string()))
        }
        "grob/budget/breakdown" => {
            let r = budget_ns::breakdown(state, caller).await?;
            serde_json::to_value(r).map_err(|e| types::rpc_err(types::ERR_INTERNAL, e.to_string()))
        }

        _ => Err(jsonrpsee::types::ErrorObjectOwned::owned(
            jsonrpsee::types::error::METHOD_NOT_FOUND_CODE,
            format!("Method not found: {method}"),
            None::<()>,
        )),
    }
}

/// All registered JSON-RPC method names (for introspection / Phase 2 CLI).
#[allow(dead_code)]
pub const METHODS: &[&str] = &[
    "grob/server/status",
    "grob/server/reload_config",
    "grob/model/list",
    "grob/model/routing",
    "grob/provider/list",
    "grob/provider/score",
    "grob/budget/current",
    "grob/budget/breakdown",
];
