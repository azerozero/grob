//! JSON-RPC 2.0 request/response types for the MCP server.

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 protocol version string.
const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC 2.0 standard error code: method not found.
const RPC_METHOD_NOT_FOUND: i32 = -32601;

/// JSON-RPC 2.0 standard error code: invalid parameters.
const RPC_INVALID_PARAMS: i32 = -32602;

/// JSON-RPC 2.0 standard error code: internal error.
pub(crate) const RPC_INTERNAL_ERROR: i32 = -32603;

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

impl std::fmt::Display for JsonRpcRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\" (id={})", self.method, self.id)
    }
}

/// JSON-RPC 2.0 success response.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub result: serde_json::Value,
    pub id: serde_json::Value,
}

impl std::fmt::Display for JsonRpcResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ok (id={})", self.id)
    }
}

/// JSON-RPC 2.0 error response.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub jsonrpc: &'static str,
    pub error: RpcError,
    pub id: serde_json::Value,
}

/// JSON-RPC error object.
#[derive(Debug, Clone, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl JsonRpcResponse {
    /// Creates a success response.
    pub fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            result,
            id,
        }
    }
}

impl JsonRpcError {
    /// Creates a method-not-found error.
    pub fn method_not_found(id: serde_json::Value, method: &str) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            error: RpcError {
                code: RPC_METHOD_NOT_FOUND,
                message: format!("Method not found: {}", method),
            },
            id,
        }
    }

    /// Creates an invalid-params error.
    pub fn invalid_params(id: serde_json::Value, msg: &str) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            error: RpcError {
                code: RPC_INVALID_PARAMS,
                message: msg.to_string(),
            },
            id,
        }
    }

    /// Creates an internal error.
    pub fn internal(id: serde_json::Value, msg: &str) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            error: RpcError {
                code: RPC_INTERNAL_ERROR,
                message: msg.to_string(),
            },
            id,
        }
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "JSON-RPC error {}: {}",
            self.error.code, self.error.message
        )
    }
}

impl std::error::Error for JsonRpcError {}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

/// Parameters for `tool_matrix/query`.
#[derive(Debug, Clone, Deserialize)]
pub struct QueryParams {
    pub tool: String,
    pub provider: Option<String>,
}

impl std::fmt::Display for QueryParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "query tool={}", self.tool)
    }
}

/// Parameters for `tool_matrix/bench`.
#[derive(Debug, Clone, Deserialize)]
pub struct BenchParams {
    pub tools: Option<Vec<String>>,
    pub providers: Option<Vec<String>>,
}

impl std::fmt::Display for BenchParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let t = self.tools.as_ref().map_or(0, |v| v.len());
        let p = self.providers.as_ref().map_or(0, |v| v.len());
        write!(f, "bench {} tools, {} providers", t, p)
    }
}

/// Parameters for `tool_matrix/calibrate`.
#[derive(Debug, Clone, Deserialize)]
pub struct CalibrateParams {
    pub tool: String,
    pub provider: String,
    pub score: f64,
}

impl std::fmt::Display for CalibrateParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "calibrate {}/{} score={}",
            self.tool, self.provider, self.score
        )
    }
}

/// MCP `tools/list` response entry.
#[derive(Debug, Clone, Serialize)]
pub struct McpToolInfo {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

impl std::fmt::Display for McpToolInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rpc_request() {
        let json = r#"{
            "jsonrpc": "2.0",
            "method": "tool_matrix/query",
            "params": {"tool": "web_search"},
            "id": 1
        }"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "tool_matrix/query");
    }

    #[test]
    fn test_serialize_success_response() {
        let resp = JsonRpcResponse::ok(serde_json::json!(1), serde_json::json!({"score": 0.95}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"score\":0.95"));
    }

    #[test]
    fn test_serialize_error_response() {
        let resp = JsonRpcError::method_not_found(serde_json::json!(1), "foo/bar");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("-32601"));
        assert!(json.contains("foo/bar"));
    }
}
