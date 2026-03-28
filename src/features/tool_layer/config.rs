//! Configuration types for the universal tool layer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level tool layer configuration (`[tool_layer]` in `grob.toml`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolLayerConfig {
    /// Master switch (default: false — zero overhead when disabled).
    #[serde(default)]
    pub enabled: bool,
    /// Static capability overrides keyed by provider name.
    #[serde(default)]
    pub capabilities: HashMap<String, CapabilityEntry>,
    /// Rules for injecting tools the client did not provide.
    #[serde(default)]
    pub inject: Vec<InjectRule>,
    /// Alias mappings: alternative name → canonical tool name.
    #[serde(default)]
    pub aliases: Vec<AliasRule>,
}

/// Declares whether a provider/model supports tool use.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CapabilityEntry {
    /// Whether this provider supports function calling.
    #[serde(default = "default_true")]
    pub tools_supported: bool,
    /// Optional set of model prefixes that lack tool support (e.g. `["o1"]`).
    #[serde(default)]
    pub no_tool_models: Vec<String>,
}

/// Injects a tool definition when the client request lacks it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InjectRule {
    /// Canonical tool name to inject (must exist in the embedded catalog).
    pub tool: String,
    /// Only inject when no tool with this name is already present.
    #[serde(default = "default_true")]
    pub if_absent: bool,
}

/// Maps an alternative tool name to its canonical equivalent.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AliasRule {
    /// Name used by the client (e.g. "execute_command").
    pub from: String,
    /// Canonical name in the catalog (e.g. "bash").
    pub to: String,
}

fn default_true() -> bool {
    true
}
