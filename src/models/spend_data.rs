//! Shared spend data types used by the storage and pricing modules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Persistent spend data (serialized to JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendData {
    /// Current month (e.g., "2026-02").
    pub month: String,
    /// Total spend in USD.
    pub total: f64,
    /// Spend by provider name.
    pub by_provider: HashMap<String, f64>,
    /// Spend by model name.
    pub by_model: HashMap<String, f64>,
    /// Request count by provider name.
    #[serde(default)]
    pub by_provider_count: HashMap<String, u64>,
}

impl Default for SpendData {
    fn default() -> Self {
        Self {
            month: current_month(),
            total: 0.0,
            by_provider: HashMap::new(),
            by_model: HashMap::new(),
            by_provider_count: HashMap::new(),
        }
    }
}

/// Returns the current year-month as a "YYYY-MM" string.
pub fn current_month() -> String {
    chrono::Local::now().format("%Y-%m").to_string()
}
