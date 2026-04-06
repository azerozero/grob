//! Feature modules: DLP, TAP streaming, token pricing, MCP tool matrix, log export, policies, pledge, and live watch.

pub mod dlp;
#[cfg(feature = "harness")]
pub mod harness;
pub mod log_backend;
pub mod log_export;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod pledge;
pub mod policies;
pub mod tap;
pub mod token_pricing;
pub mod tool_layer;
pub mod watch;
