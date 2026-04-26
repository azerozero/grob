//! MCP JSON-RPC Axum handlers and self-tuning configuration logic.
//!
//! Moved here from `features/mcp/server/` to break the features -> server
//! dependency cycle. The pure MCP business logic (query, bench, calibrate,
//! report, tools/list) stays in `features::mcp::server::methods`.
//!
//! # Submodules
//!
//! - [`builtin_tools`] — descriptors injected into `tools/list`
//! - [`config`] — read/apply helpers for safe config sections
//! - [`configure`] — `grob_configure` and `grob_autotune` handlers
//! - [`control_bridge`] — MCP → RPC control-plane bridge (`grob_keys`, `grob_pledge`, …)
//! - [`hint`] — `grob_hint` one-shot complexity hint
//! - [`wizard`] — `wizard_*` setup/doctor surface (ADR-0011)

mod builtin_tools;
mod config;
mod configure;
mod control_bridge;
mod hint;
mod wizard;

#[cfg(test)]
mod tests;

use crate::features::mcp::server::methods;
use crate::features::mcp::server::types::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, RPC_INTERNAL_ERROR,
};
use crate::server::AppState;
use axum::{extract::State, response::IntoResponse, Json};
use std::sync::Arc;

// Re-export the configuration handlers so external/internal callers that
// previously referenced `mcp_handlers::handle_configure` (etc.) keep working.
pub use configure::{handle_autotune, handle_configure};
pub use wizard::{handle_wizard_get_config, handle_wizard_run_doctor, handle_wizard_set_section};

// ── Axum HTTP handlers ──────────────────────────────────────────────────────

/// Handles `POST /mcp` — dispatches on JSON-RPC `method` field.
pub async fn handle_mcp_rpc(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let mcp = match state.security.mcp.as_ref() {
        Some(m) => m,
        None => {
            return Json(to_json_value(Err(JsonRpcError::internal(
                req.id,
                "MCP not initialized",
            ))));
        }
    };

    let result = match req.method.as_str() {
        "tool_matrix/query" => methods::handle_query(mcp, req.params, req.id.clone()).await,
        "tool_matrix/bench" => methods::handle_bench(mcp, req.params, req.id.clone()).await,
        "tool_matrix/calibrate" => methods::handle_calibrate(mcp, req.params, req.id.clone()).await,
        "tool_matrix/report" => methods::handle_report(mcp, req.id.clone()).await,
        "grob_configure" => handle_configure(&state, req.params, req.id.clone()).await,
        "grob_autotune" => handle_autotune(&state, req.params, req.id.clone()).await,
        "grob_hint" => hint::handle_hint(&state, req.params, req.id.clone()).await,
        "grob_keys" => {
            control_bridge::handle_control_tool(&state, "grob/keys", req.params, req.id.clone())
                .await
        }
        "grob_tools" => {
            control_bridge::handle_control_tool(&state, "grob/tools", req.params, req.id.clone())
                .await
        }
        "grob_hit" => {
            control_bridge::handle_control_tool(&state, "grob/hit", req.params, req.id.clone())
                .await
        }
        "grob_pledge" => {
            control_bridge::handle_control_tool(&state, "grob/pledge", req.params, req.id.clone())
                .await
        }
        "wizard_get_config" => handle_wizard_get_config(&state, req.params, req.id.clone()).await,
        "wizard_set_section" => handle_wizard_set_section(&state, req.params, req.id.clone()).await,
        "wizard_run_doctor" => handle_wizard_run_doctor(&state, req.id.clone()).await,
        "tools/list" => match methods::handle_tools_list(mcp, req.id.clone()).await {
            Ok(mut resp) => {
                builtin_tools::inject_builtin_tools(&mut resp);
                Ok(resp)
            }
            Err(e) => Err(e),
        },
        _ => Err(JsonRpcError::method_not_found(req.id.clone(), &req.method)),
    };

    Json(to_json_value(result))
}

/// Handles `GET /api/tool-matrix` — REST endpoint for the full matrix report.
pub async fn handle_matrix_report(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.security.mcp.as_ref() {
        Some(mcp) => {
            let report = methods::build_matrix_report(mcp).await;
            Json(report)
        }
        None => Json(serde_json::json!({
            "error": "MCP not enabled",
            "tool_count": 0,
            "tools": [],
        })),
    }
}

/// Serializes a JSON-RPC result to a [`serde_json::Value`].
///
/// Both `JsonRpcResponse` and `JsonRpcError` are simple structs with only
/// string/numeric fields, so serialization cannot realistically fail. The
/// fallback exists purely to satisfy the type system without `unwrap()`.
fn to_json_value(result: Result<JsonRpcResponse, JsonRpcError>) -> serde_json::Value {
    let fallback = |e: serde_json::Error| {
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": RPC_INTERNAL_ERROR, "message": e.to_string()},
            "id": null
        })
    };
    match result {
        Ok(resp) => serde_json::to_value(resp).unwrap_or_else(fallback),
        Err(err) => serde_json::to_value(err).unwrap_or_else(fallback),
    }
}
