//! MCP JSON-RPC server: routes `POST /mcp` and `GET /api/tool-matrix`.

pub mod methods;
pub mod types;

use crate::server::AppState;
use axum::{extract::State, response::IntoResponse, Json};
use std::sync::Arc;
use types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};

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
        "grob_configure" => methods::handle_configure(&state, req.params, req.id.clone()).await,
        "tools/list" => methods::handle_tools_list(mcp, req.id.clone()).await,
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
            "error": {"code": types::RPC_INTERNAL_ERROR, "message": e.to_string()},
            "id": null
        })
    };
    match result {
        Ok(resp) => serde_json::to_value(resp).unwrap_or_else(fallback),
        Err(err) => serde_json::to_value(err).unwrap_or_else(fallback),
    }
}
