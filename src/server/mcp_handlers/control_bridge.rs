//! Bridge from MCP tool calls to the RPC control plane (`grob/keys`, `grob/tools`, etc.).
//!
//! MCP tools like `grob_keys` and `grob_pledge` are thin wrappers that forward
//! to the same JSON-RPC namespaces exposed via `POST /rpc`. The bridge
//! materializes a privileged caller identity, builds the fully-qualified RPC
//! method name from `namespace + params.action`, and delegates to
//! [`crate::server::rpc::dispatch`].

use crate::features::mcp::server::types::{JsonRpcError, JsonRpcResponse};
use crate::server::rpc::auth::CallerIdentity;
use crate::server::rpc::types::Role;
use crate::server::AppState;
use std::sync::Arc;

/// Returns a privileged caller identity for MCP-originated control requests.
pub(super) fn mcp_caller() -> CallerIdentity {
    CallerIdentity {
        role: Role::Admin,
        ip: "127.0.0.1".into(),
        tenant_id: "mcp".into(),
    }
}

/// Bridges an MCP tool call to the RPC control plane.
///
/// Extracts the `action` parameter, builds the full RPC method name
/// (e.g., `grob/keys/create`), and delegates to [`crate::server::rpc::dispatch`].
///
/// # Errors
///
/// Returns a JSON-RPC error when the `action` parameter is missing, or when
/// the underlying RPC dispatch fails.
pub(super) async fn handle_control_tool(
    state: &Arc<AppState>,
    namespace: &str,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let action = params
        .get("action")
        .and_then(|a| a.as_str())
        .unwrap_or("")
        .to_string();

    if action.is_empty() {
        return Err(JsonRpcError::invalid_params(
            id,
            "missing required parameter: action",
        ));
    }

    let method = format!("{namespace}/{action}");
    let caller = mcp_caller();

    match crate::server::rpc::dispatch(state, &caller, &method, Some(&params)).await {
        Ok(data) => {
            tracing::info!(
                namespace,
                action = action.as_str(),
                "MCP: control tool call"
            );
            Ok(JsonRpcResponse::ok(id, data))
        }
        Err(e) => Err(JsonRpcError::internal(id, e.message())),
    }
}
