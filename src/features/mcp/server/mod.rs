//! MCP JSON-RPC business logic: types and method implementations.
//!
//! The Axum HTTP handlers that previously lived here have been moved to
//! `server::mcp_handlers` to eliminate the features -> server dependency cycle.

pub mod methods;
pub mod types;
