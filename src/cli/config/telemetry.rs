//! Message tracing and OpenTelemetry export configuration.

use secrecy::SecretString;
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
    /// Export `tracing` events as OTLP logs (the 3rd OTel signal) alongside the
    /// always-on stdout fmt layer. Requires the `otel` build feature and
    /// `enabled = true`; reuses `endpoint` and `service_name` over gRPC/tonic.
    /// Default: false.
    #[serde(default)]
    pub logs: bool,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otel_endpoint(),
            service_name: default_otel_service_name(),
            metrics: false,
            metrics_interval_secs: default_otel_metrics_interval_secs(),
            logs: false,
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

/// `/metrics` endpoint protection.
///
/// `/metrics` is **unauthenticated by default** (the Prometheus convention is
/// to rely on network policy / TLS). Because the endpoint carries spend, budget,
/// and tenant labels, an operator can opt into bearer-token auth: set a token
/// and `/metrics` then requires `Authorization: Bearer <token>` (compared in
/// constant time). The `/health`, `/live`, and `/ready` probes always stay
/// public so liveness/readiness checks keep working, and TLS remains the job of
/// the existing TLS/ACME layer (not re-implemented here).
///
/// Matching Prometheus scrape config (file-based credential, recommended):
///
/// ```yaml
/// scrape_configs:
///   - job_name: grob
///     scheme: https
///     authorization:
///       type: Bearer
///       credentials_file: /etc/prometheus/grob-metrics-token
///     static_configs:
///       - targets: ["grob:13456"]
/// ```
///
/// Or, with `prometheus-operator`, a `ServiceMonitor` `bearerTokenSecret`.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MetricsConfig {
    /// Inline bearer token required to scrape `/metrics`. Unset/empty leaves the
    /// endpoint public. Prefer [`MetricsConfig::bearer_token_file`] so the secret
    /// never lives in the main config file.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::auth::token_store::serialize_secret_opt",
        deserialize_with = "crate::auth::token_store::deserialize_secret_opt"
    )]
    pub bearer_token: Option<SecretString>,
    /// Path to a file holding the bearer token. Takes precedence over
    /// [`MetricsConfig::bearer_token`]; read once at startup and trimmed of
    /// surrounding whitespace/newlines (so a trailing `\n` from `echo` or a
    /// mounted Secret is harmless).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer_token_file: Option<String>,
}

impl MetricsConfig {
    /// Resolves the effective bearer token, or `None` when `/metrics` is public.
    ///
    /// [`MetricsConfig::bearer_token_file`] wins over
    /// [`MetricsConfig::bearer_token`]; the file is read once and trimmed of
    /// surrounding whitespace/newlines. A blank result (empty file, or neither
    /// field set) yields `None` so the endpoint stays public.
    ///
    /// # Errors
    ///
    /// Returns an error if `bearer_token_file` is set but cannot be read.
    pub fn resolve_bearer_token(&self) -> std::io::Result<Option<SecretString>> {
        use secrecy::ExposeSecret;

        if let Some(path) = self.bearer_token_file.as_deref().filter(|p| !p.is_empty()) {
            let raw = std::fs::read_to_string(path)?;
            let trimmed = raw.trim();
            return Ok((!trimmed.is_empty()).then(|| SecretString::new(trimmed.to_string())));
        }
        Ok(self
            .bearer_token
            .as_ref()
            .map(|s| s.expose_secret().to_string())
            .filter(|t| !t.is_empty())
            .map(SecretString::new))
    }

    /// Returns true when a token source is configured, even if it resolves empty.
    ///
    /// Lets startup warn about a configured-but-blank token (which would
    /// silently leave `/metrics` public) without re-reading the file.
    pub fn token_source_configured(&self) -> bool {
        self.bearer_token.is_some()
            || self
                .bearer_token_file
                .as_deref()
                .is_some_and(|p| !p.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::io::Write;

    #[test]
    fn metrics_default_is_public() {
        let cfg = MetricsConfig::default();
        assert!(!cfg.token_source_configured());
        assert!(cfg.resolve_bearer_token().expect("resolves").is_none());
    }

    #[test]
    fn metrics_inline_token_resolves() {
        let cfg = MetricsConfig {
            bearer_token: Some(SecretString::new("inline-secret".to_string())),
            bearer_token_file: None,
        };
        let resolved = cfg.resolve_bearer_token().expect("resolves").expect("some");
        assert_eq!(resolved.expose_secret(), "inline-secret");
    }

    #[test]
    fn metrics_file_token_takes_precedence_and_is_trimmed() {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        // Trailing newline + spaces must be trimmed (mounted Secrets often add one).
        writeln!(f, "  file-secret").expect("write");
        let cfg = MetricsConfig {
            bearer_token: Some(SecretString::new("inline-loses".to_string())),
            bearer_token_file: Some(f.path().to_string_lossy().into_owned()),
        };
        let resolved = cfg.resolve_bearer_token().expect("resolves").expect("some");
        assert_eq!(resolved.expose_secret(), "file-secret");
    }

    #[test]
    fn metrics_blank_file_resolves_public() {
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(f, "\n   ").expect("write");
        let cfg = MetricsConfig {
            bearer_token: None,
            bearer_token_file: Some(f.path().to_string_lossy().into_owned()),
        };
        // A configured-but-blank file is treated as "no token" (stays public),
        // but the source is still reported as configured so startup can warn.
        assert!(cfg.token_source_configured());
        assert!(cfg.resolve_bearer_token().expect("resolves").is_none());
    }

    #[test]
    fn metrics_missing_file_errors() {
        let cfg = MetricsConfig {
            bearer_token: None,
            bearer_token_file: Some("/no/such/grob-metrics-token".to_string()),
        };
        assert!(cfg.resolve_bearer_token().is_err());
    }
}
