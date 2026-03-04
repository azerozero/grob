//! Tape format for recording and replaying HTTP exchanges.
//!
//! Each exchange is a [`TapeEntry`] stored as one JSON line in a `.tape.jsonl` file.
//! The format is HTTP-level and format-agnostic: it captures raw paths, headers,
//! and bodies without coupling to Anthropic or OpenAI request types.

use axum::body::Body;
use axum::http::{Request, Response};
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tower::{Layer, Service};
use tracing::warn;

/// Single recorded HTTP exchange (format-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapeEntry {
    /// Short trace identifier.
    pub id: String,
    /// Timestamp of the exchange.
    pub ts: DateTime<Utc>,
    /// Raw HTTP request as received by grob.
    pub request: TapeRequest,
    /// Raw HTTP response (None on transport error).
    pub response: Option<TapeResponse>,
    /// Error message if the exchange failed.
    pub error: Option<String>,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u64,
}

/// Raw HTTP request as received by grob (Anthropic or OpenAI format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapeRequest {
    /// HTTP method (e.g. "POST").
    pub method: String,
    /// Request path (e.g. "/v1/messages" or "/v1/chat/completions").
    pub path: String,
    /// Sanitized headers (auth values redacted).
    pub headers: HashMap<String, String>,
    /// Raw JSON body.
    pub body: serde_json::Value,
}

/// Raw HTTP response as returned by grob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapeResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: HashMap<String, String>,
    /// JSON body (for non-streaming responses).
    pub body: serde_json::Value,
    /// SSE chunks (for streaming responses).
    pub sse_chunks: Option<Vec<String>>,
}

/// Loads a tape file (JSONL) into a vector of entries.
pub async fn load_tape(path: &Path) -> anyhow::Result<Vec<TapeEntry>> {
    let file = tokio::fs::File::open(path).await?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();
    let mut entries = Vec::new();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<TapeEntry>(&line) {
            Ok(entry) => entries.push(entry),
            Err(e) => warn!(error = %e, "Skipping malformed tape line"),
        }
    }

    Ok(entries)
}

// ── TapeRecorder (write side) ──

/// Shared writer for appending tape entries to a JSONL file.
#[derive(Clone)]
pub struct TapeWriter {
    file: Arc<Mutex<tokio::fs::File>>,
}

impl TapeWriter {
    /// Opens (or creates) the output file for appending.
    pub async fn new(path: &Path) -> anyhow::Result<Self> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }

    /// Serializes and appends one entry. Errors are logged, not propagated.
    pub async fn write(&self, entry: &TapeEntry) {
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, "Failed to serialize tape entry");
                return;
            }
        };

        let mut line = json;
        line.push('\n');

        let mut f = self.file.lock().await;
        if let Err(e) = f.write_all(line.as_bytes()).await {
            warn!(error = %e, "Failed to write tape entry");
        }
    }
}

/// Tower [`Layer`] that wraps handlers to record HTTP exchanges.
#[derive(Clone)]
pub struct TapeRecorderLayer {
    writer: TapeWriter,
}

impl TapeRecorderLayer {
    /// Creates a new layer writing to the given tape file.
    pub fn new(writer: TapeWriter) -> Self {
        Self { writer }
    }
}

impl<S> Layer<S> for TapeRecorderLayer {
    type Service = TapeRecorderService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TapeRecorderService {
            inner,
            writer: self.writer.clone(),
        }
    }
}

/// Tower [`Service`] that intercepts requests/responses for recording.
#[derive(Clone)]
pub struct TapeRecorderService<S> {
    inner: S,
    writer: TapeWriter,
}

impl<S> Service<Request<Body>> for TapeRecorderService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display + Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let writer = self.writer.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let id = uuid::Uuid::new_v4().to_string()[..8].to_string();
            let method = req.method().to_string();
            let path = req.uri().path().to_string();

            // Only record LLM endpoints.
            let should_record = path == "/v1/messages" || path == "/v1/chat/completions";

            if !should_record {
                return inner.call(req).await;
            }

            let headers = sanitize_headers(req.headers());

            // Buffer the request body so we can record it and forward it.
            let (parts, body) = req.into_parts();
            let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
                .await
                .unwrap_or_default();

            let body_json: serde_json::Value =
                serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);

            let tape_request = TapeRequest {
                method,
                path,
                headers,
                body: body_json,
            };

            // Reconstruct the request with the buffered body.
            let new_req = Request::from_parts(parts, Body::from(body_bytes));

            let start = std::time::Instant::now();
            let result = inner.call(new_req).await;
            let latency_ms = start.elapsed().as_millis() as u64;

            match result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let resp_headers = sanitize_headers(resp.headers());

                    // Buffer response body for recording, then reconstruct.
                    let (resp_parts, resp_body) = resp.into_parts();
                    let resp_bytes = axum::body::to_bytes(resp_body, 10 * 1024 * 1024)
                        .await
                        .unwrap_or_default();

                    let resp_json: serde_json::Value =
                        serde_json::from_slice(&resp_bytes).unwrap_or(serde_json::Value::Null);

                    // Detect SSE streaming by content-type.
                    let is_sse = resp_parts
                        .headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.contains("text/event-stream"))
                        .unwrap_or(false);

                    let sse_chunks = if is_sse {
                        let text = String::from_utf8_lossy(&resp_bytes);
                        Some(
                            text.lines()
                                .filter(|l| !l.is_empty())
                                .map(String::from)
                                .collect(),
                        )
                    } else {
                        None
                    };

                    let tape_response = TapeResponse {
                        status,
                        headers: resp_headers,
                        body: resp_json,
                        sse_chunks,
                    };

                    let entry = TapeEntry {
                        id,
                        ts: Utc::now(),
                        request: tape_request,
                        response: Some(tape_response),
                        error: None,
                        latency_ms,
                    };

                    writer.write(&entry).await;

                    Ok(Response::from_parts(resp_parts, Body::from(resp_bytes)))
                }
                Err(e) => {
                    let entry = TapeEntry {
                        id,
                        ts: Utc::now(),
                        request: tape_request,
                        response: None,
                        error: Some(e.to_string()),
                        latency_ms,
                    };

                    writer.write(&entry).await;

                    Err(e)
                }
            }
        })
    }
}

/// Extracts headers into a map, redacting auth-sensitive values.
fn sanitize_headers(headers: &axum::http::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            let key = k.as_str().to_lowercase();
            let value = if key == "authorization" || key == "x-api-key" || key == "cookie" {
                "[REDACTED]".to_string()
            } else {
                v.to_str().unwrap_or("[non-utf8]").to_string()
            };
            (key, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tape_entry_roundtrip() {
        let entry = TapeEntry {
            id: "abc12345".into(),
            ts: Utc::now(),
            request: TapeRequest {
                method: "POST".into(),
                path: "/v1/messages".into(),
                headers: HashMap::new(),
                body: serde_json::json!({"model": "claude-sonnet-4-20250514"}),
            },
            response: Some(TapeResponse {
                status: 200,
                headers: HashMap::new(),
                body: serde_json::json!({"content": []}),
                sse_chunks: None,
            }),
            error: None,
            latency_ms: 42,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TapeEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "abc12345");
        assert_eq!(parsed.latency_ms, 42);
    }

    #[test]
    fn sanitize_headers_redacts_auth() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer sk-secret".parse().unwrap());
        headers.insert("x-api-key", "key123".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        let sanitized = sanitize_headers(&headers);
        assert_eq!(sanitized["authorization"], "[REDACTED]");
        assert_eq!(sanitized["x-api-key"], "[REDACTED]");
        assert_eq!(sanitized["content-type"], "application/json");
    }
}
