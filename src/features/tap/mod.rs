pub mod stream;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Tap configuration (deserialized from TOML)
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TapConfig {
    /// Enable the webhook tap
    #[serde(default)]
    pub enabled: bool,
    /// POST destination URL
    #[serde(default)]
    pub webhook_url: String,
    /// mpsc channel capacity (drops events if full)
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    /// HTTP POST timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Include request body in the tap payload
    #[serde(default = "default_true")]
    pub include_request: bool,
}

fn default_buffer_size() -> usize {
    256
}

fn default_timeout_ms() -> u64 {
    5000
}

fn default_true() -> bool {
    true
}

/// Events sent through the tap channel
pub enum TapEvent {
    /// A new request is starting
    Request {
        request_id: String,
        tenant_id: Option<String>,
        model: String,
        body: String,
    },
    /// A chunk of streaming data
    StreamChunk { request_id: String, data: Bytes },
    /// The stream has ended
    StreamEnd { request_id: String },
}

/// Non-blocking sender for tap events.
/// Uses `try_send` to avoid blocking the hot path — drops events silently if the channel is full.
#[derive(Clone)]
pub struct TapSender {
    tx: mpsc::Sender<TapEvent>,
}

impl TapSender {
    /// Try to send an event. Drops silently if the channel is full.
    pub fn try_send(&self, event: TapEvent) {
        let _ = self.tx.try_send(event);
    }
}

/// Payload sent to the webhook
#[derive(Serialize)]
struct TapPayload {
    request_id: String,
    tenant_id: Option<String>,
    model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body: Option<String>,
    response_body: String,
}

/// Initialize the tap system: returns a TapSender and spawns the background worker.
/// Returns None if tap is disabled.
pub fn init_tap(config: &TapConfig) -> Option<Arc<TapSender>> {
    if !config.enabled || config.webhook_url.is_empty() {
        return None;
    }

    let (tx, rx) = mpsc::channel(config.buffer_size);
    let sender = Arc::new(TapSender { tx });

    tokio::spawn(tap_worker(rx, config.clone()));

    tracing::info!("📡 Webhook tap enabled → {}", config.webhook_url);

    Some(sender)
}

/// Background worker that accumulates stream chunks per request_id and POSTs
/// the complete payload to the webhook URL when the stream ends.
async fn tap_worker(mut rx: mpsc::Receiver<TapEvent>, config: TapConfig) {
    let client = reqwest::Client::new();

    // Accumulator: request_id → (metadata, chunks)
    struct RequestAcc {
        tenant_id: Option<String>,
        model: String,
        request_body: Option<String>,
        chunks: Vec<Bytes>,
    }

    let mut pending: HashMap<String, RequestAcc> = HashMap::new();

    while let Some(event) = rx.recv().await {
        match event {
            TapEvent::Request {
                request_id,
                tenant_id,
                model,
                body,
            } => {
                let request_body = if config.include_request {
                    Some(body)
                } else {
                    None
                };
                pending.insert(
                    request_id,
                    RequestAcc {
                        tenant_id,
                        model,
                        request_body,
                        chunks: Vec::new(),
                    },
                );
            }
            TapEvent::StreamChunk { request_id, data } => {
                if let Some(acc) = pending.get_mut(&request_id) {
                    acc.chunks.push(data);
                }
            }
            TapEvent::StreamEnd { request_id } => {
                if let Some(acc) = pending.remove(&request_id) {
                    // Assemble full response body
                    let total_len: usize = acc.chunks.iter().map(|c| c.len()).sum();
                    let mut response_body = String::with_capacity(total_len);
                    for chunk in &acc.chunks {
                        if let Ok(s) = std::str::from_utf8(chunk) {
                            response_body.push_str(s);
                        }
                    }

                    let payload = TapPayload {
                        request_id,
                        tenant_id: acc.tenant_id,
                        model: acc.model,
                        request_body: acc.request_body,
                        response_body,
                    };

                    // Fire-and-forget POST
                    let client = client.clone();
                    let url = config.webhook_url.clone();
                    let timeout_ms = config.timeout_ms;
                    tokio::spawn(async move {
                        let result = client
                            .post(&url)
                            .json(&payload)
                            .timeout(std::time::Duration::from_millis(timeout_ms))
                            .send()
                            .await;

                        match result {
                            Ok(resp) if !resp.status().is_success() => {
                                tracing::warn!("Tap webhook returned {}: {}", resp.status(), url);
                            }
                            Err(e) => {
                                tracing::warn!("Tap webhook failed: {}", e);
                            }
                            _ => {}
                        }
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_try_send_drops_when_full() {
        // Channel of capacity 1
        let (tx, mut rx) = mpsc::channel(1);
        let sender = TapSender { tx };

        // First send should succeed
        sender.try_send(TapEvent::StreamEnd {
            request_id: "req-1".to_string(),
        });

        // Second send should silently drop (channel full)
        sender.try_send(TapEvent::StreamEnd {
            request_id: "req-2".to_string(),
        });

        // Only first event should be receivable
        let event = rx.recv().await.unwrap();
        assert!(matches!(event, TapEvent::StreamEnd { request_id } if request_id == "req-1"));

        // Channel should be empty now (second was dropped)
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_config_defaults() {
        let config = TapConfig::default();
        assert!(!config.enabled);
        assert!(config.webhook_url.is_empty());
    }
}
