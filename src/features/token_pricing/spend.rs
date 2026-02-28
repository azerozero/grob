// Grob - Spend Tracking
// Copyright (c) 2025 a00 SAS
// License: Elastic License v2.0
// See LICENSE for details

//! Persistent monthly spend tracking
//! Stores spend data in ~/.grob/spend.json, auto-resets on new month

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Budget check error
#[derive(Debug, Clone)]
pub struct BudgetError {
    pub message: String,
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BudgetError {}

/// Persistent spend data (serialized to JSON)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendData {
    /// Current month (e.g., "2026-02")
    pub month: String,
    /// Total spend in USD
    pub total: f64,
    /// Spend by provider name
    pub by_provider: HashMap<String, f64>,
    /// Spend by model name
    pub by_model: HashMap<String, f64>,
}

impl Default for SpendData {
    fn default() -> Self {
        Self {
            month: current_month(),
            total: 0.0,
            by_provider: HashMap::new(),
            by_model: HashMap::new(),
        }
    }
}

/// Spend tracker with periodic persistence.
/// Thin wrapper around `GrobStore` for backward compatibility.
pub struct SpendTracker {
    store: Option<std::sync::Arc<crate::storage::GrobStore>>,
    /// Standalone data (used when no store is provided, e.g. tests or CLI)
    data: SpendData,
    path: PathBuf,
    request_count: AtomicU64,
}

impl SpendTracker {
    /// Create a SpendTracker backed by a GrobStore.
    pub fn with_store(store: std::sync::Arc<crate::storage::GrobStore>) -> Self {
        let data = store.load_spend(None);
        Self {
            store: Some(store),
            data,
            path: PathBuf::new(),
            request_count: AtomicU64::new(0),
        }
    }

    /// Load spend data from disk (legacy mode, no GrobStore).
    pub fn load(path: PathBuf) -> Self {
        let data = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<SpendData>(&content) {
                    Ok(mut data) => {
                        let now = current_month();
                        if data.month != now {
                            tracing::info!(
                                "New month detected ({} -> {}), resetting spend tracker",
                                data.month,
                                now
                            );
                            data = SpendData::default();
                        }
                        data
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse spend.json: {}, starting fresh", e);
                        SpendData::default()
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read spend.json: {}, starting fresh", e);
                    SpendData::default()
                }
            }
        } else {
            SpendData::default()
        };

        Self {
            store: None,
            data,
            path,
            request_count: AtomicU64::new(0),
        }
    }

    /// Default path: ~/.grob/spend.json
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".grob")
            .join("spend.json")
    }

    /// Record spend for a request
    pub fn record(&mut self, provider: &str, model: &str, cost: f64) {
        if let Some(ref store) = self.store {
            store.record_spend(None, cost, provider, model);
            self.data = store.load_spend(None);
        } else {
            self.reset_if_new_month();
            self.data.total += cost;
            *self
                .data
                .by_provider
                .entry(provider.to_string())
                .or_default() += cost;
            *self.data.by_model.entry(model.to_string()).or_default() += cost;

            let count = self.request_count.fetch_add(1, Ordering::Relaxed);
            if count.is_multiple_of(10) {
                self.save();
            }
        }
    }

    /// Record spend for a specific tenant
    pub fn record_tenant(&mut self, tenant: &str, provider: &str, model: &str, cost: f64) {
        if let Some(ref store) = self.store {
            store.record_spend(Some(tenant), cost, provider, model);
        }
        // Also record to global
        self.record(provider, model, cost);
    }

    /// Get total spend for current month
    pub fn total(&self) -> f64 {
        self.data.total
    }

    /// Get spend for a specific provider
    pub fn provider_spend(&self, provider: &str) -> f64 {
        self.data.by_provider.get(provider).copied().unwrap_or(0.0)
    }

    /// Get spend for a specific model
    pub fn model_spend(&self, model: &str) -> f64 {
        self.data.by_model.get(model).copied().unwrap_or(0.0)
    }

    /// Load spend for a specific tenant
    #[allow(dead_code)]
    pub fn tenant_spend(&self, tenant: &str) -> SpendData {
        if let Some(ref store) = self.store {
            store.load_spend(Some(tenant))
        } else {
            SpendData::default()
        }
    }

    /// Persist spend data to disk
    pub fn save(&self) {
        if let Some(ref store) = self.store {
            store.flush_spend();
            return;
        }

        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(&self.data) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.path, json) {
                    tracing::error!("Failed to write spend.json: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to serialize spend data: {}", e);
            }
        }
    }

    fn reset_if_new_month(&mut self) {
        let now = current_month();
        if self.data.month != now {
            tracing::info!(
                "New month detected ({} -> {}), resetting spend tracker",
                self.data.month,
                now
            );
            self.data = SpendData::default();
            self.save();
        }
    }

    /// Check if a request should be allowed given budget limits.
    pub fn check_budget(
        &self,
        provider: &str,
        model: &str,
        global_limit: f64,
        provider_limit: Option<f64>,
        model_limit: Option<f64>,
    ) -> Result<(), BudgetError> {
        if let Some(limit) = model_limit {
            let spend = self.model_spend(model);
            if spend >= limit {
                return Err(BudgetError {
                    message: format!(
                        "Monthly budget for model '{}' reached: ${:.2}/${:.2}",
                        model, spend, limit
                    ),
                });
            }
        }

        if let Some(limit) = provider_limit {
            let spend = self.provider_spend(provider);
            if spend >= limit {
                return Err(BudgetError {
                    message: format!(
                        "Monthly budget for provider '{}' reached: ${:.2}/${:.2}",
                        provider, spend, limit
                    ),
                });
            }
        }

        if global_limit > 0.0 {
            let total = self.total();
            if total >= global_limit {
                return Err(BudgetError {
                    message: format!(
                        "Monthly global budget reached: ${:.2}/${:.2}",
                        total, global_limit
                    ),
                });
            }
        }

        Ok(())
    }

    /// Check budget limits and log warnings when approaching limits.
    pub fn check_warnings(
        &self,
        provider: &str,
        model: &str,
        global_limit: f64,
        provider_limit: Option<f64>,
        model_limit: Option<f64>,
        warn_at_percent: u32,
    ) -> Option<String> {
        let threshold = warn_at_percent as f64 / 100.0;

        if let Some(limit) = model_limit {
            let spend = self.model_spend(model);
            if spend >= limit * threshold && spend < limit {
                return Some(format!(
                    "Model '{}' at {:.0}% of ${:.2} budget",
                    model,
                    (spend / limit) * 100.0,
                    limit
                ));
            }
        }

        if let Some(limit) = provider_limit {
            let spend = self.provider_spend(provider);
            if spend >= limit * threshold && spend < limit {
                return Some(format!(
                    "Provider '{}' at {:.0}% of ${:.2} budget",
                    provider,
                    (spend / limit) * 100.0,
                    limit
                ));
            }
        }

        if global_limit > 0.0 {
            let total = self.total();
            if total >= global_limit * threshold && total < global_limit {
                return Some(format!(
                    "Global spend at {:.0}% of ${:.2} budget",
                    (total / global_limit) * 100.0,
                    global_limit
                ));
            }
        }

        None
    }
}

/// Load spend data from the default path (for CLI commands, no tracker needed)
pub fn load_spend_data() -> SpendData {
    let path = SpendTracker::default_path();
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<SpendData>(&content) {
                Ok(data) => {
                    let now = current_month();
                    if data.month == now {
                        return data;
                    }
                    // Different month, return empty
                    SpendData::default()
                }
                Err(_) => SpendData::default(),
            },
            Err(_) => SpendData::default(),
        }
    } else {
        SpendData::default()
    }
}

pub fn current_month() -> String {
    chrono::Local::now().format("%Y-%m").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spend_tracker_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.json");
        let mut tracker = SpendTracker::load(path);

        tracker.record("openrouter", "claude-sonnet", 0.05);
        tracker.record("openrouter", "claude-opus", 0.15);
        tracker.record("anthropic", "claude-sonnet", 0.0);

        assert!((tracker.total() - 0.20).abs() < 0.001);
        assert!((tracker.provider_spend("openrouter") - 0.20).abs() < 0.001);
        assert!((tracker.provider_spend("anthropic") - 0.0).abs() < 0.001);
        assert!((tracker.model_spend("claude-sonnet") - 0.05).abs() < 0.001);
        assert!((tracker.model_spend("claude-opus") - 0.15).abs() < 0.001);
    }

    #[test]
    fn test_budget_check_global() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.json");
        let mut tracker = SpendTracker::load(path);

        tracker.record("openrouter", "model-a", 5.0);

        // Under limit
        assert!(tracker
            .check_budget("openrouter", "model-a", 10.0, None, None)
            .is_ok());

        // At limit
        tracker.record("openrouter", "model-a", 5.0);
        assert!(tracker
            .check_budget("openrouter", "model-a", 10.0, None, None)
            .is_err());
    }

    #[test]
    fn test_budget_check_provider() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.json");
        let mut tracker = SpendTracker::load(path);

        tracker.record("openrouter", "model-a", 4.0);

        // Provider limit exceeded
        assert!(tracker
            .check_budget("openrouter", "model-a", 100.0, Some(3.0), None)
            .is_err());

        // Other provider still under
        assert!(tracker
            .check_budget("anthropic", "model-a", 100.0, Some(3.0), None)
            .is_ok());
    }

    #[test]
    fn test_budget_check_model() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.json");
        let mut tracker = SpendTracker::load(path);

        tracker.record("openrouter", "expensive-model", 2.5);

        // Model limit exceeded (most specific wins)
        assert!(tracker
            .check_budget(
                "openrouter",
                "expensive-model",
                100.0,
                Some(100.0),
                Some(2.0)
            )
            .is_err());
    }

    #[test]
    fn test_budget_unlimited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.json");
        let mut tracker = SpendTracker::load(path);

        tracker.record("openrouter", "model-a", 1000.0);

        // 0 = unlimited
        assert!(tracker
            .check_budget("openrouter", "model-a", 0.0, None, None)
            .is_ok());
    }

    #[test]
    fn test_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.json");

        {
            let mut tracker = SpendTracker::load(path.clone());
            tracker.record("openrouter", "model-a", 3.50);
            tracker.save();
        }

        // Reload
        let tracker = SpendTracker::load(path);
        assert!((tracker.total() - 3.50).abs() < 0.001);
    }

    #[test]
    fn test_warnings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.json");
        let mut tracker = SpendTracker::load(path);

        tracker.record("openrouter", "model-a", 8.5);

        // At 85% of $10 → should warn at 80%
        let warning = tracker.check_warnings("openrouter", "model-a", 10.0, None, None, 80);
        assert!(warning.is_some());

        // At 85% but threshold is 90% → no warning
        let warning = tracker.check_warnings("openrouter", "model-a", 10.0, None, None, 90);
        assert!(warning.is_none());
    }
}
