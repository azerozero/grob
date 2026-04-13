//! Generic control engine for unified CLI / MCP / UI dispatch.
//!
//! Translates [`Action`] variants into state reads or mutation commands.
//! Adapters (JSON-RPC, CLI args, MCP tools) convert their wire format
//! into actions and render [`ControlResponse`] back to the caller.

pub mod engine;

pub use engine::{
    Action, BudgetAction, ConfigAction, ControlError, ControlErrorCode, ControlResponse, HitAction,
    KeysAction, ModelAction, PledgeAction, ProviderAction, ServerAction, ToolsAction, ALL_METHODS,
};
