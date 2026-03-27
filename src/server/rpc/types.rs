//! Shared types for the JSON-RPC 2.0 Control Plane.

use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};

// ── Error codes (JSON-RPC application range: -32000 to -32099) ──

/// Authentication failure (missing or invalid credentials).
pub const ERR_UNAUTHORIZED: i32 = -32001;
/// Insufficient privileges for the requested method.
pub const ERR_FORBIDDEN: i32 = -32002;
/// Requested resource does not exist (Phase 2).
#[allow(dead_code)]
pub const ERR_NOT_FOUND: i32 = -32003;
/// Operation failed at the backend.
pub const ERR_INTERNAL: i32 = -32004;
/// Budget limit exceeded (Phase 2).
#[allow(dead_code)]
pub const ERR_BUDGET_EXCEEDED: i32 = -32005;

/// Builds a typed JSON-RPC error.
pub fn rpc_err(code: i32, msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, msg.into(), None::<()>)
}

// ── RBAC role hierarchy ──

/// Access role derived from transport credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read-only: list endpoints and budget queries.
    Observer = 0,
    /// Operational: server control, routing changes.
    Operator = 1,
    /// Administrative: config and key management.
    Admin = 2,
    /// Unrestricted: localhost-only, full access.
    Superadmin = 3,
}

impl Role {
    /// Returns `true` if this role has at least the given privilege level.
    pub fn has_at_least(self, required: Role) -> bool {
        (self as u8) >= (required as u8)
    }
}

// ── Common response envelopes ──

/// Lightweight status response for mutating operations.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Outcome indicator (`"ok"` or `"error"`).
    pub status: String,
    /// Human-readable detail message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Provider summary returned by `grob/provider/list`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderInfo {
    /// Provider identifier (e.g. `"anthropic"`, `"openai"`).
    pub name: String,
    /// Models registered under this provider.
    pub models: Vec<String>,
}

/// Model routing rule returned by `grob/model/routing`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RoutingRule {
    /// Regex pattern that triggers this rule.
    pub pattern: String,
    /// Target model name.
    pub model: String,
}

/// Provider score entry returned by `grob/provider/score`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProviderScore {
    /// Provider identifier.
    pub provider: String,
    /// Composite score (0.0–1.0).
    pub score: f64,
    /// Exponentially weighted moving average latency in milliseconds.
    pub latency_ewma_ms: f64,
    /// Success rate (0.0–1.0).
    pub success_rate: f64,
}

/// Budget snapshot returned by `grob/budget/current`.
#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetCurrent {
    /// Total spent this month in USD.
    pub total_usd: f64,
    /// Monthly budget limit in USD (0 = unlimited).
    pub budget_usd: f64,
    /// Remaining budget in USD.
    pub remaining_usd: f64,
}

/// Per-provider spend breakdown entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct SpendBreakdown {
    /// Provider identifier.
    pub provider: String,
    /// Total spent via this provider in USD.
    pub spent_usd: f64,
    /// Number of requests routed to this provider.
    pub request_count: u64,
}
