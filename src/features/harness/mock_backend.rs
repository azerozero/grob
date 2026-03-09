//! Mock backend that serves recorded responses to grob.
//!
//! Starts an axum server on an ephemeral port, impersonating the upstream
//! provider (Anthropic / OpenAI). Grob sends requests here instead of the
//! real provider; the mock matches them to tape entries and returns the
//! recorded response (with optional latency and error injection).

use super::tape::{TapeEntry, TapeResponse};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Response, StatusCode};
use axum::routing::post;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, info};

/// Configuration for the mock backend.
#[derive(Debug, Clone)]
pub struct MockConfig {
    /// Port to bind on (0 = ephemeral).
    pub port: u16,
    /// Simulated response latency in milliseconds.
    pub latency_ms: u64,
    /// Fraction of requests that return 503 (0.0–1.0).
    pub error_rate: f64,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            port: 0,
            latency_ms: 50,
            error_rate: 0.0,
        }
    }
}

/// Running mock backend server.
pub struct MockBackend {
    port: u16,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
}

impl MockBackend {
    /// Starts the mock backend, indexing tape entries for fast lookup.
    pub async fn start(tape: &[TapeEntry], config: MockConfig) -> anyhow::Result<Self> {
        let index = build_response_index(tape);
        let fallback: Vec<TapeResponse> = tape.iter().filter_map(|e| e.response.clone()).collect();

        let bind_port = config.port;
        let state = Arc::new(MockState {
            index,
            fallback,
            fallback_cursor: AtomicUsize::new(0),
            config,
        });

        let app = Router::new()
            .route("/v1/messages", post(handle_mock))
            .route("/v1/chat/completions", post(handle_mock))
            .with_state(state);

        let listener = TcpListener::bind(("127.0.0.1", bind_port)).await?;
        let port = listener.local_addr()?.port();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                })
                .await
                .ok();
        });

        info!(port, "Mock backend started");
        Ok(Self {
            port,
            shutdown_tx,
            handle,
        })
    }

    /// Returns the base URL (e.g. "http://127.0.0.1:19432").
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Returns the bound port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Shuts down the mock backend gracefully.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        self.handle.await.ok();
        info!("Mock backend shut down");
    }
}

// ── Internal state and handler ──

struct MockState {
    /// Fingerprint → recorded responses.
    index: HashMap<String, Vec<TapeResponse>>,
    /// Round-robin fallback pool.
    fallback: Vec<TapeResponse>,
    fallback_cursor: AtomicUsize,
    config: MockConfig,
}

/// Handles a mock provider request: match by fingerprint, return recorded response.
async fn handle_mock(State(state): State<Arc<MockState>>, body: Bytes) -> Response<Body> {
    // Error injection.
    if state.config.error_rate > 0.0 {
        let roll: f64 = rand::random();
        if roll < state.config.error_rate {
            debug!("Injecting error (roll={roll:.3})");
            return error_response(if roll < state.config.error_rate / 2.0 {
                503
            } else {
                429
            });
        }
    }

    // Simulated latency.
    if state.config.latency_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(state.config.latency_ms)).await;
    }

    let fingerprint = compute_fingerprint(&body);
    debug!(fingerprint, "Mock request received");

    let tape_response = state
        .index
        .get(&fingerprint)
        .and_then(|v| v.first())
        .or_else(|| {
            if state.fallback.is_empty() {
                None
            } else {
                let idx =
                    state.fallback_cursor.fetch_add(1, Ordering::Relaxed) % state.fallback.len();
                Some(&state.fallback[idx])
            }
        });

    match tape_response {
        Some(tr) => build_response(tr),
        None => error_response(500),
    }
}

/// Builds a fingerprint from model + first user content in the JSON body.
fn compute_fingerprint(body: &[u8]) -> String {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);

    let model = parsed.get("model").and_then(|v| v.as_str()).unwrap_or("");

    // Anthropic format: messages[].content
    // OpenAI format: messages[].content
    let first_user = parsed
        .get("messages")
        .and_then(|m| m.as_array())
        .and_then(|msgs| {
            msgs.iter()
                .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("user"))
        })
        .and_then(|m| m.get("content"))
        .map(|c| {
            // Content can be a string or an array of blocks.
            if let Some(s) = c.as_str() {
                s.to_string()
            } else {
                // Serialize the first 200 chars for fingerprinting.
                let s = c.to_string();
                s[..s.len().min(200)].to_string()
            }
        })
        .unwrap_or_default();

    let mut hasher = Sha256::new();
    hasher.update(model.as_bytes());
    hasher.update(first_user.as_bytes());
    hex::encode(hasher.finalize())[..16].to_string()
}

/// Builds the response index from tape entries.
fn build_response_index(tape: &[TapeEntry]) -> HashMap<String, Vec<TapeResponse>> {
    let mut index: HashMap<String, Vec<TapeResponse>> = HashMap::new();

    for entry in tape {
        if let Some(ref resp) = entry.response {
            let body_bytes = serde_json::to_vec(&entry.request.body).unwrap_or_default();
            let fp = compute_fingerprint(&body_bytes);
            index.entry(fp).or_default().push(resp.clone());
        }
    }

    index
}

/// Reconstructs an HTTP response from a [`TapeResponse`].
fn build_response(tr: &TapeResponse) -> Response<Body> {
    // SSE streaming replay.
    if let Some(ref chunks) = tr.sse_chunks {
        let body_text = chunks.join("\n") + "\n";
        let mut builder = Response::builder()
            .status(tr.status)
            .header("content-type", "text/event-stream");

        for (k, v) in &tr.headers {
            if k != "content-type" && k != "content-length" && k != "transfer-encoding" {
                builder = builder.header(k.as_str(), v.as_str());
            }
        }

        return builder
            .body(Body::from(body_text))
            .unwrap_or_else(|_| error_response(500));
    }

    // Non-streaming JSON response.
    let body_bytes = serde_json::to_vec(&tr.body).unwrap_or_default();

    let mut builder = Response::builder()
        .status(tr.status)
        .header("content-type", "application/json");

    for (k, v) in &tr.headers {
        if k != "content-type" && k != "content-length" && k != "transfer-encoding" {
            builder = builder.header(k.as_str(), v.as_str());
        }
    }

    builder
        .body(Body::from(body_bytes))
        .unwrap_or_else(|_| error_response(500))
}

/// Returns a minimal JSON error response.
fn error_response(status: u16) -> Response<Body> {
    let body = serde_json::json!({
        "type": "error",
        "error": {"type": "server_error", "message": "mock injected error"}
    });

    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap_or_default()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_deterministic() {
        let body = serde_json::json!({
            "model": "claude-sonnet-4-20250514",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let fp1 = compute_fingerprint(&bytes);
        let fp2 = compute_fingerprint(&bytes);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
    }

    #[test]
    fn fingerprint_differs_by_model() {
        let body1 =
            serde_json::json!({"model": "a", "messages": [{"role": "user", "content": "x"}]});
        let body2 =
            serde_json::json!({"model": "b", "messages": [{"role": "user", "content": "x"}]});
        let fp1 = compute_fingerprint(&serde_json::to_vec(&body1).unwrap());
        let fp2 = compute_fingerprint(&serde_json::to_vec(&body2).unwrap());
        assert_ne!(fp1, fp2);
    }
}
