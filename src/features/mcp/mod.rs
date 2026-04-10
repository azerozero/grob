//! MCP Tool Matrix: tool-calling capability catalogue, scoring, and calibration.
//!
//! Three layers:
//! 1. **Tool Matrix** — static TOML catalogue of tools with per-provider reliability
//! 2. **Bench Engine** — continuous scoring via automated tool-calling tests
//! 3. **MCP Server** — JSON-RPC endpoints for query, bench, calibrate, report

pub mod bench;
pub mod calibration;
pub mod config;
pub mod matrix;
pub mod scorer;
pub mod server;

use config::McpConfig;
use matrix::ToolMatrix;
use scorer::ToolScorer;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default rolling window size for the tool scorer.
///
/// Matches the window size used by [`crate::security::provider_scorer::ScorerConfig`]
/// default. 50 samples provide a good balance between responsiveness and stability.
const DEFAULT_SCORER_WINDOW: usize = 50;

/// Shared MCP state threaded through the application.
pub struct McpState {
    /// MCP configuration loaded at startup.
    pub config: McpConfig,
    /// Static tool capability catalogue.
    pub matrix: ToolMatrix,
    scorer: Arc<RwLock<ToolScorer>>,
}

impl std::fmt::Debug for McpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpState")
            .field("config", &self.config)
            .field("matrix_tool_count", &self.matrix.tool_count())
            .finish_non_exhaustive()
    }
}

impl McpState {
    /// Creates a new MCP state from config and a loaded matrix.
    pub fn new(config: McpConfig, matrix: ToolMatrix) -> Self {
        let scorer = Arc::new(RwLock::new(ToolScorer::new(DEFAULT_SCORER_WINDOW)));
        Self {
            config,
            matrix,
            scorer,
        }
    }

    /// Returns a cloned `Arc` handle to the scorer for the bench engine.
    pub(crate) fn scorer(&self) -> Arc<RwLock<ToolScorer>> {
        self.scorer.clone()
    }

    /// Returns a read-locked reference to the scorer.
    pub async fn read_scorer(&self) -> tokio::sync::RwLockReadGuard<'_, ToolScorer> {
        self.scorer.read().await
    }

    /// Returns a handle to the runtime scores for the bench engine.
    pub(crate) fn matrix_handle(&self) -> matrix::RuntimeScores {
        self.matrix.scores_handle()
    }
}
