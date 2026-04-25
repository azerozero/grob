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
    /// Protocol version, always `"2.0"`.
    pub jsonrpc: String,
    /// RPC method name (e.g. `"tool_matrix/query"`).
    pub method: String,
    /// Method parameters, defaults to `null` if absent.
    #[serde(default)]
    pub params: serde_json::Value,
    /// Caller-assigned request identifier for correlation.
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
    /// Protocol version, always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Successful method return value.
    pub result: serde_json::Value,
    /// Request identifier echoed back to the caller.
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
    /// Protocol version, always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Structured error object with code and message.
    pub error: RpcError,
    /// Request identifier echoed back to the caller.
    pub id: serde_json::Value,
}

/// JSON-RPC error object.
#[derive(Debug, Clone, Serialize)]
pub struct RpcError {
    /// Numeric error code per the JSON-RPC 2.0 specification.
    pub code: i32,
    /// Human-readable error description.
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
    /// Tool name to look up in the matrix.
    pub tool: String,
    /// Optional provider filter to narrow the query.
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
    /// Subset of tools to benchmark; benchmarks all if `None`.
    pub tools: Option<Vec<String>>,
    /// Subset of providers to benchmark; benchmarks all if `None`.
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
    /// Tool name to calibrate.
    pub tool: String,
    /// Provider whose score is being overridden.
    pub provider: String,
    /// New capability score between 0.0 and 1.0.
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

/// Client-declared task complexity for routing heuristics.
///
/// Consumed once by the dispatch pipeline (stateless, single-request scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplexityHint {
    /// Fast-path: simple lookup, short answer.
    Trivial,
    /// Default: standard reasoning task.
    Medium,
    /// Deep reasoning, multi-step, or creative task.
    Complex,
}

impl std::fmt::Display for ComplexityHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplexityHint::Trivial => f.write_str("trivial"),
            ComplexityHint::Medium => f.write_str("medium"),
            ComplexityHint::Complex => f.write_str("complex"),
        }
    }
}

/// Parameters for `grob_hint`.
#[derive(Debug, Clone, Deserialize)]
pub struct HintParams {
    /// Task complexity declared by the client.
    pub complexity: ComplexityHint,
}

impl std::fmt::Display for HintParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hint complexity={}", self.complexity)
    }
}

/// Configurable sections exposed by the `grob_configure` self-tuning tool.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSection {
    /// Request routing rules and model assignments.
    Router,
    /// Monthly spend budget and warning thresholds.
    Budget,
    /// DLP pipeline settings (read-only severity/action fields).
    Dlp,
    /// LLM response cache settings.
    Cache,
    /// Complexity classifier scoring weights and tier thresholds.
    Classifier,
}

impl std::fmt::Display for ConfigSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSection::Router => f.write_str("router"),
            ConfigSection::Budget => f.write_str("budget"),
            ConfigSection::Dlp => f.write_str("dlp"),
            ConfigSection::Cache => f.write_str("cache"),
            ConfigSection::Classifier => f.write_str("classifier"),
        }
    }
}

/// Actions supported by the `grob_configure` self-tuning tool.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ConfigureAction {
    /// Reads the current value of a config section (safe subset only).
    Read {
        /// Config section to read.
        section: ConfigSection,
    },
    /// Updates a single key within a config section.
    Update {
        /// Config section containing the key.
        section: ConfigSection,
        /// Dot-separated key path within the section (e.g. `"default"`, `"monthly_limit_usd"`).
        key: String,
        /// New value to set.
        value: serde_json::Value,
    },
}

impl std::fmt::Display for ConfigureAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigureAction::Read { section } => write!(f, "read {section}"),
            ConfigureAction::Update { section, key, .. } => {
                write!(f, "update {section}.{key}")
            }
        }
    }
}

/// Parameters for `grob_configure`.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigureParams {
    /// The action to perform (read or update).
    #[serde(flatten)]
    pub action: ConfigureAction,
}

impl std::fmt::Display for ConfigureParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configure {}", self.action)
    }
}

/// MCP `tools/list` response entry.
#[derive(Debug, Clone, Serialize)]
pub struct McpToolInfo {
    /// Unique tool identifier exposed to MCP clients.
    pub name: String,
    /// Human-readable summary of the tool's purpose.
    pub description: String,
    /// JSON Schema describing the tool's expected input.
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

    #[test]
    fn test_complexity_hint_deserialize() {
        let cases = [
            ("\"trivial\"", ComplexityHint::Trivial),
            ("\"medium\"", ComplexityHint::Medium),
            ("\"complex\"", ComplexityHint::Complex),
        ];
        for (json, expected) in cases {
            let hint: ComplexityHint = serde_json::from_str(json).unwrap();
            assert_eq!(hint, expected);
        }
    }

    #[test]
    fn test_complexity_hint_display() {
        assert_eq!(ComplexityHint::Trivial.to_string(), "trivial");
        assert_eq!(ComplexityHint::Medium.to_string(), "medium");
        assert_eq!(ComplexityHint::Complex.to_string(), "complex");
    }

    #[test]
    fn test_hint_params_deserialize() {
        let json = serde_json::json!({"complexity": "complex"});
        let p: HintParams = serde_json::from_value(json).unwrap();
        assert_eq!(p.complexity, ComplexityHint::Complex);
    }
}
