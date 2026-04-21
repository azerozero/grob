//! Security, compliance, TEE and FIPS configuration.

use serde::{Deserialize, Serialize};

use crate::cli::BodySizeLimit;

use super::default_true;

/// Security configuration (wired into middleware stack)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// Master switch for security middleware
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Rate limit: requests per second per tenant/IP
    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_rps: u32,
    /// Rate limit: burst capacity
    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,
    /// Maximum request body size in bytes (default: 10MB)
    #[serde(default)]
    pub max_body_size: BodySizeLimit,
    /// Apply OWASP security headers to all responses
    #[serde(default = "default_true")]
    pub security_headers: bool,
    /// Enable circuit breaker for provider calls
    #[serde(default = "default_true")]
    pub circuit_breaker: bool,
    /// Directory for signed audit logs (empty = disabled)
    #[serde(default)]
    pub audit_dir: String,
    /// Audit log signing algorithm: "ecdsa-p256" (default) or "hmac-sha256"
    #[serde(default)]
    pub audit_signing_algorithm: String,
    /// Path to HMAC key file (only for hmac-sha256 algorithm; default: <audit_dir>/audit_hmac.key)
    #[serde(default)]
    pub audit_hmac_key_path: String,
    /// Entries per Merkle batch (1 = per-entry signing, >1 = batch)
    #[serde(default = "default_batch_size")]
    pub audit_batch_size: usize,
    /// Max milliseconds before flushing an incomplete batch
    #[serde(default = "default_flush_interval_ms")]
    pub audit_flush_interval_ms: u64,
    /// Include Merkle inclusion proof in each batch entry
    #[serde(default)]
    pub audit_include_merkle_proof: bool,
    /// Enable adaptive provider scoring (opt-in, default false)
    #[serde(default)]
    pub adaptive_scoring: bool,
    /// EWMA alpha for latency smoothing (0.0–1.0, default 0.3)
    #[serde(default = "default_scoring_latency_alpha")]
    pub scoring_latency_alpha: f64,
    /// Rolling window size for success rate calculation (default 50)
    #[serde(default = "default_scoring_window_size")]
    pub scoring_window_size: usize,
    /// Decay rate per second of inactivity (default 0.001)
    #[serde(default = "default_scoring_decay_rate")]
    pub scoring_decay_rate: f64,
    /// Persist scores across restarts (default false)
    #[serde(default)]
    pub scoring_persist: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit_rps: default_rate_limit_rps(),
            rate_limit_burst: default_rate_limit_burst(),
            max_body_size: BodySizeLimit::default(),
            security_headers: true,
            circuit_breaker: true,
            audit_dir: String::new(),
            audit_signing_algorithm: String::new(),
            audit_hmac_key_path: String::new(),
            audit_batch_size: default_batch_size(),
            audit_flush_interval_ms: default_flush_interval_ms(),
            audit_include_merkle_proof: false,
            adaptive_scoring: false,
            scoring_latency_alpha: default_scoring_latency_alpha(),
            scoring_window_size: default_scoring_window_size(),
            scoring_decay_rate: default_scoring_decay_rate(),
            scoring_persist: false,
        }
    }
}

fn default_batch_size() -> usize {
    1
}

fn default_flush_interval_ms() -> u64 {
    5000
}

// NOTE: 100 rps sustains ~10 concurrent Claude Code sessions (each bursting
// ~10 req/s during tool-use loops) while protecting providers from runaway clients.
fn default_rate_limit_rps() -> u32 {
    100
}

// NOTE: 2x sustained rate allows short tool-use bursts without 429s.
fn default_rate_limit_burst() -> u32 {
    200
}

// NOTE: 0.3 gives ~70% weight to recent latency, ~30% to history. Standard
// EWMA smoothing factor — higher values react faster but amplify noise.
fn default_scoring_latency_alpha() -> f64 {
    0.3
}

// NOTE: 50-request window balances responsiveness (detects degradation within
// ~1 min at typical traffic) vs stability (no jitter from single outliers).
fn default_scoring_window_size() -> usize {
    50
}

// NOTE: 0.001/s means idle providers lose ~3.5% score per hour, preventing
// stale high scores while keeping recently-active providers competitive.
fn default_scoring_decay_rate() -> f64 {
    0.001
}

/// EU AI Act compliance configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ComplianceConfig {
    /// Enable EU AI Act compliance features
    #[serde(default)]
    pub enabled: bool,
    /// Add transparency headers (X-AI-Provider, X-AI-Model, X-AI-Generated, X-Grob-Audit-Id)
    #[serde(default)]
    pub transparency_headers: bool,
    /// Record model name in audit entries (Article 12)
    #[serde(default)]
    pub audit_model_name: bool,
    /// Record token counts in audit entries (Article 12)
    #[serde(default)]
    pub audit_token_counts: bool,
    /// Enable risk classification (Article 14)
    #[serde(default)]
    pub risk_classification: bool,
    /// Minimum risk level to trigger escalation (low, medium, high, critical)
    #[serde(default = "default_escalation_threshold")]
    pub escalation_threshold: String,
    /// Optional webhook URL for risk escalation notifications
    #[serde(default)]
    pub escalation_webhook: Option<String>,
}

fn default_escalation_threshold() -> String {
    "high".to_string()
}

/// Enforcement policy for security features that can warn or block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Feature disabled entirely.
    #[default]
    Off,
    /// Log a warning at startup but allow the server to run.
    Warn,
    /// Refuse to start if the requirement is not met.
    Enforce,
}

/// Trusted Execution Environment (TEE) configuration.
///
/// Controls whether grob requires, recommends, or ignores TEE attestation.
/// When enabled, grob checks for AMD SEV-SNP at startup and can derive
/// hardware-bound keys for secret sealing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeeConfig {
    /// Whether TEE presence is off, warned, or enforced.
    #[serde(default)]
    pub mode: EnforcementMode,
    /// Publish an attestation report in the audit log on startup.
    #[serde(default = "default_true")]
    pub attestation_audit: bool,
    /// Derive encryption keys from TEE hardware (SNP_GET_DERIVED_KEY)
    /// instead of random filesystem keys.
    #[serde(default)]
    pub sealed_keys: bool,
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Off,
            attestation_audit: true,
            sealed_keys: false,
        }
    }
}

/// FIPS 140-3 compliance configuration.
///
/// When enabled, grob verifies that the crypto backend operates in FIPS
/// mode (e.g. OpenSSL FIPS provider or SymCrypt) and restricts algorithms
/// to FIPS-approved ones.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FipsConfig {
    /// Whether FIPS mode is off, warned, or enforced.
    #[serde(default)]
    pub mode: EnforcementMode,
}

impl Default for FipsConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::Off,
        }
    }
}
