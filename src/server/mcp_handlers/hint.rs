//! `grob_hint` MCP tool — one-shot complexity hint for the next dispatch.

use crate::features::mcp::server::types::{HintParams, JsonRpcError, JsonRpcResponse};
use crate::server::AppState;
use std::sync::Arc;

/// Handles `grob_hint` — stores a one-shot complexity hint for the next dispatch.
///
/// The hint is consumed (taken) by the next dispatch call, then cleared.
/// Clients may also pass the hint inline via `X-Grob-Hint` header or
/// `metadata.grob_hint` in the request body — this MCP tool is the third
/// pathway, for MCP-native agents that cannot set custom HTTP headers.
///
/// # Errors
///
/// Returns a JSON-RPC error when `params` cannot be deserialized into
/// [`HintParams`].
pub(super) async fn handle_hint(
    state: &Arc<AppState>,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let p: HintParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    // Store the hint for the next dispatch (one-shot).
    if let Ok(mut slot) = state.grob_hint.lock() {
        *slot = Some(p.complexity);
    }

    tracing::info!(complexity = %p.complexity, "MCP: grob_hint stored");

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "status": "accepted",
            "complexity": p.complexity.to_string(),
        }),
    ))
}
