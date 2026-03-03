//! MCP Tool Matrix configuration, mapped from `[mcp]` in TOML.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level MCP configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpConfig {
    /// Master switch for the MCP tool matrix feature.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the tool matrix TOML catalogue. Default: `~/.grob/tool_matrix.toml`.
    #[serde(default = "default_matrix_path")]
    pub matrix_path: PathBuf,
    /// MCP JSON-RPC server settings.
    #[serde(default)]
    pub server: McpServerConfig,
    /// Continuous benchmarking settings.
    #[serde(default)]
    pub bench: BenchConfig,
    /// Tool routing / filtering settings.
    #[serde(default)]
    pub routing: ToolRoutingConfig,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            matrix_path: default_matrix_path(),
            server: McpServerConfig::default(),
            bench: BenchConfig::default(),
            routing: ToolRoutingConfig::default(),
        }
    }
}

fn default_matrix_path() -> PathBuf {
    PathBuf::from("~/.grob/tool_matrix.toml")
}

/// MCP JSON-RPC server configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpServerConfig {
    /// Enable the `/mcp` JSON-RPC endpoint.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Continuous bench engine configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BenchConfig {
    /// Enable the background bench engine.
    #[serde(default)]
    pub enabled: bool,
    /// Bench cycle interval in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// Max concurrent bench requests. Default: 2.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// Per-request timeout in milliseconds. Default: 30000.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_interval_secs(),
            concurrency: default_concurrency(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

/// Default bench cycle interval: 1 hour balances freshness vs. API cost.
const DEFAULT_BENCH_INTERVAL_SECS: u64 = 3600;

/// Default concurrency: 2 avoids overwhelming providers during bench runs.
const DEFAULT_BENCH_CONCURRENCY: usize = 2;

/// Default per-request timeout: 30s accommodates slow model endpoints.
const DEFAULT_BENCH_TIMEOUT_MS: u64 = 30_000;

fn default_interval_secs() -> u64 {
    DEFAULT_BENCH_INTERVAL_SECS
}

fn default_concurrency() -> usize {
    DEFAULT_BENCH_CONCURRENCY
}

fn default_timeout_ms() -> u64 {
    DEFAULT_BENCH_TIMEOUT_MS
}

/// Tool routing and filtering configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolRoutingConfig {
    /// Minimum composite score for a tool to remain in the request. Default: 0.5.
    #[serde(default = "default_min_score")]
    pub min_score: f64,
    /// Remove tools below `min_score` from requests. Default: false.
    #[serde(default, alias = "filter_unreliable_tools")]
    pub filter_low_score_tools: bool,
    /// Per-tool fallback chains.
    #[serde(default)]
    pub chains: Vec<ToolChain>,
}

impl Default for ToolRoutingConfig {
    fn default() -> Self {
        Self {
            min_score: default_min_score(),
            filter_low_score_tools: false,
            chains: Vec::new(),
        }
    }
}

/// Default minimum composite score: 0.5 is the "coin-flip" floor below which a
/// tool is considered unreliable.
const DEFAULT_MIN_SCORE: f64 = 0.5;

fn default_min_score() -> f64 {
    DEFAULT_MIN_SCORE
}

/// Per-tool provider fallback chain.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolChain {
    /// Canonical tool name.
    pub tool: String,
    /// Override minimum score for this tool.
    #[serde(default = "default_min_score")]
    pub min_score: f64,
    /// Provider fallback order.
    pub providers: Vec<String>,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let config = McpConfig::default();
        assert!(!config.enabled);
        assert_eq!(
            config.matrix_path,
            PathBuf::from("~/.grob/tool_matrix.toml")
        );
        assert!(config.server.enabled);
        assert!(!config.bench.enabled);
        assert_eq!(config.bench.interval_secs, 3600);
        assert!(!config.routing.filter_low_score_tools);
        assert!((config.routing.min_score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
enabled = true
matrix_path = "/custom/path.toml"

[bench]
enabled = true
interval_secs = 1800

[routing]
min_score = 0.7
filter_low_score_tools = true

[[routing.chains]]
tool = "web_search"
min_score = 0.8
providers = ["anthropic", "openai"]
        "#;
        let config: McpConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.matrix_path, PathBuf::from("/custom/path.toml"));
        assert!(config.bench.enabled);
        assert_eq!(config.bench.interval_secs, 1800);
        assert!(config.routing.filter_low_score_tools);
        assert_eq!(config.routing.chains.len(), 1);
        assert_eq!(config.routing.chains[0].tool, "web_search");
    }
}
