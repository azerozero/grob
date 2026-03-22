//! External log sinks for structured request/response log export.
//!
//! Exports structured [`LogEntry`] records to configurable destinations
//! (stdout JSON, JSONL file, HTTP endpoint) alongside the existing tap system.
//! Supports encrypted content export via age envelope encryption.

pub mod access_policy;
pub mod encryption;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Structured log entry emitted after each completed request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unique identifier for the request.
    pub request_id: String,
    /// ISO-8601 timestamp of request completion.
    pub timestamp: String,
    /// Model name requested by the client.
    pub model: String,
    /// Provider that served the request.
    pub provider: String,
    /// Number of input tokens consumed.
    pub input_tokens: u32,
    /// Number of output tokens produced.
    pub output_tokens: u32,
    /// End-to-end latency in milliseconds.
    pub latency_ms: u64,
    /// Estimated cost in USD.
    pub cost_usd: f64,
    /// Request outcome: "success" or "error".
    pub status: String,
    /// DLP actions applied during the request.
    pub dlp_actions: Vec<String>,
    /// Tenant identifier (multi-tenant deployments).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Age-encrypted request/response content (base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<String>,
    /// Named auditor recipients who can decrypt the content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_recipients: Option<Vec<String>>,
}

/// Content export mode.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ContentMode {
    /// Do not export content (default).
    #[default]
    None,
    /// Export content in plaintext.
    Plaintext,
    /// Export content encrypted with age.
    Encrypted,
}

/// Log export configuration (deserialized from TOML).
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LogExportConfig {
    /// Master switch for log export.
    #[serde(default)]
    pub enabled: bool,
    /// Configured sink destinations.
    #[serde(default)]
    pub sinks: Vec<LogSinkConfig>,
    /// Content export mode.
    #[serde(default)]
    pub content: ContentMode,
    /// Named auditors with their age public keys.
    #[serde(default)]
    pub auditors: HashMap<String, String>,
    /// Access policies controlling which auditors see which sessions.
    #[serde(default)]
    pub access_policies: Vec<access_policy::AccessPolicyConfig>,
}

/// Sink destination for log entries.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LogSinkConfig {
    /// Emit JSON to stdout (for piping to Fluentd/Vector/Logstash).
    Stdout,
    /// Append JSONL to a file.
    File {
        /// Path to the output file.
        path: String,
    },
    /// POST JSON to an HTTP endpoint.
    Http {
        /// Destination URL.
        url: String,
        /// Extra headers to include in the POST request.
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

/// Manages configured log sinks and dispatches entries to all of them.
pub struct LogExporter {
    sinks: Vec<LogSinkConfig>,
    /// Shared HTTP client for HTTP sinks (avoids per-request allocation).
    http_client: reqwest::Client,
    /// Per-file mutex to serialize writes (one per File sink, keyed by index).
    file_locks: Vec<Arc<Mutex<()>>>,
}

impl LogExporter {
    /// Creates a new exporter from the given sink configurations.
    pub fn new(sinks: Vec<LogSinkConfig>) -> Self {
        let file_locks: Vec<Arc<Mutex<()>>> =
            sinks.iter().map(|_| Arc::new(Mutex::new(()))).collect();

        Self {
            sinks,
            http_client: reqwest::Client::new(),
            file_locks,
        }
    }

    /// Emits a log entry to all configured sinks (fire-and-forget).
    pub fn emit(&self, entry: &LogEntry) {
        for (idx, sink) in self.sinks.iter().enumerate() {
            match sink {
                LogSinkConfig::Stdout => {
                    if let Ok(json) = serde_json::to_string(entry) {
                        println!("{}", json);
                    }
                }
                LogSinkConfig::File { path } => {
                    let path = path.clone();
                    let lock = self.file_locks[idx].clone();
                    let line = match serde_json::to_string(entry) {
                        Ok(j) => j,
                        Err(_) => continue,
                    };
                    tokio::spawn(async move {
                        let _guard = lock.lock().await;
                        if let Err(e) = append_line(&path, &line).await {
                            tracing::warn!("Log export file write failed: {}", e);
                        }
                    });
                }
                LogSinkConfig::Http { url, headers } => {
                    let client = self.http_client.clone();
                    let url = url.clone();
                    let headers = headers.clone();
                    let entry = entry.clone();
                    tokio::spawn(async move {
                        let mut req = client.post(&url).json(&entry);
                        for (k, v) in &headers {
                            req = req.header(k, v);
                        }
                        if let Err(e) = req.send().await {
                            tracing::warn!("Log export HTTP sink failed: {}", e);
                        }
                    });
                }
            }
        }
    }
}

/// Appends a single JSONL line to the given file path.
async fn append_line(path: &str, line: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    Ok(())
}

/// Initializes the log exporter if enabled. Returns `None` when disabled or no sinks configured.
pub fn init_log_exporter(config: &LogExportConfig) -> Option<Arc<LogExporter>> {
    if !config.enabled || config.sinks.is_empty() {
        return None;
    }

    let exporter = Arc::new(LogExporter::new(config.sinks.clone()));
    tracing::info!("Log export enabled with {} sink(s)", config.sinks.len());
    Some(exporter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = LogExportConfig::default();
        assert!(!config.enabled);
        assert!(config.sinks.is_empty());
    }

    #[test]
    fn test_sink_config_serde_stdout() {
        let json = r#"{"type":"stdout"}"#;
        let sink: LogSinkConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(sink, LogSinkConfig::Stdout));
    }

    #[test]
    fn test_sink_config_serde_file() {
        let json = r#"{"type":"file","path":"/tmp/grob.jsonl"}"#;
        let sink: LogSinkConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(sink, LogSinkConfig::File { path } if path == "/tmp/grob.jsonl"));
    }

    #[test]
    fn test_sink_config_serde_http() {
        let json = r#"{"type":"http","url":"https://example.com/logs","headers":{"Authorization":"Bearer tok"}}"#;
        let sink: LogSinkConfig = serde_json::from_str(json).unwrap();
        match sink {
            LogSinkConfig::Http { url, headers } => {
                assert_eq!(url, "https://example.com/logs");
                assert_eq!(headers.get("Authorization").unwrap(), "Bearer tok");
            }
            _ => panic!("Expected Http sink"),
        }
    }

    #[test]
    fn test_init_disabled() {
        let config = LogExportConfig::default();
        assert!(init_log_exporter(&config).is_none());
    }

    #[test]
    fn test_init_enabled_no_sinks() {
        let config = LogExportConfig {
            enabled: true,
            sinks: vec![],
            ..Default::default()
        };
        assert!(init_log_exporter(&config).is_none());
    }

    #[test]
    fn test_log_entry_serialization() {
        let entry = LogEntry {
            request_id: "req-1".to_string(),
            timestamp: "2026-03-18T00:00:00Z".to_string(),
            model: "claude-opus-4-6".to_string(),
            provider: "anthropic".to_string(),
            input_tokens: 100,
            output_tokens: 200,
            latency_ms: 1500,
            cost_usd: 0.015,
            status: "success".to_string(),
            dlp_actions: vec![],
            tenant_id: None,
            encrypted_content: None,
            content_recipients: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("req-1"));
        assert!(!json.contains("tenant_id"));
        assert!(!json.contains("encrypted_content"));
    }
}
