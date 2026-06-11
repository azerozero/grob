//! Message tracing and OpenTelemetry export configuration.

use serde::{Deserialize, Serialize};

use super::default_true;

/// Message tracing configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    /// Enable request/response tracing to file
    #[serde(default)]
    pub enabled: bool,
    /// File path for trace output (default: ~/.grob/trace.jsonl)
    #[serde(default = "default_tracing_path")]
    pub path: String,
    /// Omit system prompt from traces (default: true, since system prompts are huge)
    #[serde(default = "default_true")]
    pub omit_system_prompt: bool,
    /// Maximum trace file size in MB before rotation (default: 50)
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    /// Number of rotated files to keep (default: 3)
    #[serde(default = "default_max_files")]
    pub max_files: usize,
    /// Compress rotated files with zstd (default: false)
    #[serde(default)]
    pub compress: bool,
    /// Encrypt trace entries with AES-256-GCM at rest (default: false)
    #[serde(default)]
    pub encrypt: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_tracing_path(),
            omit_system_prompt: true,
            max_size_mb: default_max_size_mb(),
            max_files: default_max_files(),
            compress: false,
            encrypt: false,
        }
    }
}

fn default_max_size_mb() -> u64 {
    50
}

fn default_max_files() -> usize {
    3
}

fn default_tracing_path() -> String {
    "~/.grob/trace.jsonl".to_string()
}

/// OpenTelemetry export configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OtelConfig {
    /// Enable OpenTelemetry trace export
    #[serde(default)]
    pub enabled: bool,
    /// OTLP endpoint (default: http://localhost:4317)
    #[serde(default = "default_otel_endpoint")]
    pub endpoint: String,
    /// Service name reported in traces (default: "grob")
    #[serde(default = "default_otel_service_name")]
    pub service_name: String,
    /// Export metrics over OTLP in addition to the always-on Prometheus
    /// `/metrics` surface. Requires the `otel` build feature; reuses `endpoint`
    /// and `service_name`. The single `metrics` recorder is fanned out to both
    /// backends, so no call site is instrumented twice. Default: false.
    #[serde(default)]
    pub metrics: bool,
    /// Push interval in seconds for the OTLP metrics `PeriodicReader`
    /// (default: 60). Ignored unless `metrics` is true.
    #[serde(default = "default_otel_metrics_interval_secs")]
    pub metrics_interval_secs: u64,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otel_endpoint(),
            service_name: default_otel_service_name(),
            metrics: false,
            metrics_interval_secs: default_otel_metrics_interval_secs(),
        }
    }
}

fn default_otel_metrics_interval_secs() -> u64 {
    60
}

fn default_otel_endpoint() -> String {
    "http://localhost:4317".to_string()
}

fn default_otel_service_name() -> String {
    "grob".to_string()
}
