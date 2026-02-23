//! Message tracing for debugging
//!
//! Logs full request/response messages to a JSONL file for debugging purposes.

use crate::cli::TracingConfig;
use crate::models::{AnthropicRequest, RouteType};
use crate::providers::ProviderResponse;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

/// Message tracer that writes to JSONL file
pub struct MessageTracer {
    config: TracingConfig,
    file: Option<Mutex<File>>,
}

/// A trace entry for a request
#[derive(Serialize)]
struct RequestTrace {
    ts: DateTime<Utc>,
    dir: &'static str,
    id: String,
    model: String,
    provider: String,
    route_type: String,
    is_stream: bool,
    tool_count: usize,
    messages: serde_json::Value,
}

/// A trace entry for a response
#[derive(Serialize)]
struct ResponseTrace {
    ts: DateTime<Utc>,
    dir: &'static str,
    id: String,
    latency_ms: u64,
    stop_reason: String,
    input_tokens: u32,
    output_tokens: u32,
    content: serde_json::Value,
}

/// A trace entry for an error
#[derive(Serialize)]
struct ErrorTrace {
    ts: DateTime<Utc>,
    dir: &'static str,
    id: String,
    error: String,
}

impl MessageTracer {
    /// Create a new tracer from config
    pub fn new(config: TracingConfig) -> Self {
        if !config.enabled {
            return Self { config, file: None };
        }

        // Expand ~ in path
        let path = expand_tilde(&config.path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!("Failed to create tracing directory: {}", e);
                return Self { config, file: None };
            }
        }

        // Open file for appending
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                tracing::info!("📝 Message tracing enabled: {}", path.display());
                Self {
                    config,
                    file: Some(Mutex::new(file)),
                }
            }
            Err(e) => {
                tracing::error!("Failed to open trace file: {}", e);
                Self { config, file: None }
            }
        }
    }

    /// Generate a new trace ID
    pub fn new_trace_id(&self) -> String {
        if self.file.is_some() {
            Uuid::new_v4().to_string()[..8].to_string()
        } else {
            String::new()
        }
    }

    /// Trace an incoming request
    pub fn trace_request(
        &self,
        id: &str,
        request: &AnthropicRequest,
        provider: &str,
        route_type: &RouteType,
        is_stream: bool,
    ) {
        let Some(ref file_mutex) = self.file else {
            return;
        };

        // Build messages JSON, optionally omitting system prompt
        let messages = if self.config.omit_system_prompt {
            // Clone request and clear system prompt
            let mut req_clone = request.clone();
            req_clone.system = None;
            serde_json::to_value(&req_clone.messages).unwrap_or_default()
        } else {
            serde_json::to_value(&request.messages).unwrap_or_default()
        };

        let trace = RequestTrace {
            ts: Utc::now(),
            dir: "req",
            id: id.to_string(),
            model: request.model.clone(),
            provider: provider.to_string(),
            route_type: route_type.to_string(),
            is_stream,
            tool_count: request.tools.as_ref().map_or(0, |t| t.len()),
            messages,
        };

        self.write_trace(&trace, file_mutex);
    }

    /// Trace a response
    pub fn trace_response(&self, id: &str, response: &ProviderResponse, latency_ms: u64) {
        let Some(ref file_mutex) = self.file else {
            return;
        };

        let trace = ResponseTrace {
            ts: Utc::now(),
            dir: "res",
            id: id.to_string(),
            latency_ms,
            stop_reason: response.stop_reason.clone().unwrap_or_default(),
            input_tokens: response.usage.input_tokens,
            output_tokens: response.usage.output_tokens,
            content: serde_json::to_value(&response.content).unwrap_or_default(),
        };

        self.write_trace(&trace, file_mutex);
    }

    /// Trace an error
    pub fn trace_error(&self, id: &str, error: &str) {
        let Some(ref file_mutex) = self.file else {
            return;
        };

        let trace = ErrorTrace {
            ts: Utc::now(),
            dir: "err",
            id: id.to_string(),
            error: error.to_string(),
        };

        self.write_trace(&trace, file_mutex);
    }

    fn write_trace<T: Serialize>(&self, trace: &T, file_mutex: &Mutex<File>) {
        let Ok(json) = serde_json::to_string(trace) else {
            return;
        };

        if let Ok(mut file) = file_mutex.lock() {
            let _ = writeln!(file, "{}", json);
        }
    }
}

/// Expand ~ to home directory
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}
