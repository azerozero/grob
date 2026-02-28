//! LLM response cache for temperature=0 deterministic requests.
//!
//! Uses moka concurrent cache with SHA-256 keyed entries.
//! Per-tenant isolation via key prefixing.

use moka::future::Cache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// A cached LLM response with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    /// The full response body (JSON bytes)
    pub body: Vec<u8>,
    /// Content-Type header
    pub content_type: String,
    /// Provider name that generated this response
    pub provider: String,
    /// Model name used
    pub model: String,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub skipped_too_large: u64,
    pub entry_count: u64,
}

/// LLM response cache backed by moka.
pub struct ResponseCache {
    inner: Cache<String, CachedResponse>,
    max_entry_bytes: usize,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: std::sync::Arc<AtomicU64>,
    skipped_too_large: AtomicU64,
}

impl ResponseCache {
    /// Create a new response cache from config.
    pub fn new(max_capacity: u64, ttl_secs: u64, max_entry_bytes: usize) -> Self {
        let evictions = std::sync::Arc::new(AtomicU64::new(0));
        let evictions_clone = evictions.clone();

        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(ttl_secs))
            .eviction_listener(move |_key, _value, _cause| {
                evictions_clone.fetch_add(1, Ordering::Relaxed);
            })
            .build();

        Self {
            inner: cache,
            max_entry_bytes,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions,
            skipped_too_large: AtomicU64::new(0),
        }
    }

    /// Compute a cache key from request parameters.
    /// Returns `None` if the request is not cacheable (temperature != 0).
    #[cfg(test)]
    pub fn compute_key(
        tenant_id: &str,
        model: &str,
        messages: &serde_json::Value,
        system: Option<&serde_json::Value>,
        tools: Option<&serde_json::Value>,
        max_tokens: Option<u64>,
        temperature: Option<f64>,
    ) -> Option<String> {
        // Only cache deterministic requests (temperature == 0 or absent)
        if let Some(temp) = temperature {
            if temp != 0.0 {
                return None;
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(tenant_id.as_bytes());
        hasher.update(b"|");
        hasher.update(model.as_bytes());
        hasher.update(b"|");
        hasher.update(messages.to_string().as_bytes());
        hasher.update(b"|");
        if let Some(sys) = system {
            hasher.update(sys.to_string().as_bytes());
        }
        hasher.update(b"|");
        if let Some(t) = tools {
            hasher.update(t.to_string().as_bytes());
        }
        hasher.update(b"|");
        if let Some(mt) = max_tokens {
            hasher.update(mt.to_string().as_bytes());
        }

        Some(hex::encode(hasher.finalize()))
    }

    /// Compute a cache key directly from an AnthropicRequest.
    ///
    /// Streams each request field (tenant, model, messages, system, tools, max_tokens)
    /// through a SHA-256 hasher via `Sha256Writer`, separated by `|` delimiters.
    /// This avoids allocating an intermediate String or serde_json::Value — the JSON
    /// bytes flow directly into the digest. Returns `None` for non-deterministic
    /// requests (temperature != 0).
    pub fn compute_key_from_request(
        tenant_id: &str,
        request: &crate::models::AnthropicRequest,
    ) -> Option<String> {
        use std::io::Write as _;

        // Only cache deterministic requests (temperature == 0 or absent)
        if request.temperature.map(|t| t != 0.0).unwrap_or(false) {
            return None;
        }

        let mut hasher = Sha256Writer(Sha256::new());
        let _ = hasher.write_all(tenant_id.as_bytes());
        let _ = hasher.write_all(b"|");
        let _ = hasher.write_all(request.model.as_bytes());
        let _ = hasher.write_all(b"|");
        let _ = serde_json::to_writer(&mut hasher, &request.messages);
        let _ = hasher.write_all(b"|");
        if let Some(ref s) = request.system {
            let _ = serde_json::to_writer(&mut hasher, s);
        }
        let _ = hasher.write_all(b"|");
        if let Some(ref t) = request.tools {
            let _ = serde_json::to_writer(&mut hasher, t);
        }
        let _ = hasher.write_all(b"|");
        let _ = write!(hasher, "{}", request.max_tokens);

        Some(hex::encode(hasher.0.finalize()))
    }
}

/// `io::Write` adapter that feeds all bytes into a SHA-256 hasher.
///
/// This lets `serde_json::to_writer` serialize directly into the digest
/// without buffering the serialized JSON in memory first.
struct Sha256Writer(Sha256);

impl std::io::Write for Sha256Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ResponseCache {
    /// Try to get a cached response.
    pub async fn get(&self, key: &str) -> Option<CachedResponse> {
        match self.inner.get(key).await {
            Some(resp) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                metrics::counter!("grob_cache_hits_total").increment(1);
                Some(resp)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                metrics::counter!("grob_cache_misses_total").increment(1);
                None
            }
        }
    }

    /// Store a response in the cache. Skips if too large.
    pub async fn put(&self, key: String, response: CachedResponse) {
        if response.body.len() > self.max_entry_bytes {
            self.skipped_too_large.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("grob_cache_skipped_too_large_total").increment(1);
            return;
        }
        self.inner.insert(key, response).await;
    }

    /// Invalidate all entries.
    pub fn invalidate_all(&self) {
        self.inner.invalidate_all();
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            skipped_too_large: self.skipped_too_large.load(Ordering::Relaxed),
            entry_count: self.inner.entry_count(),
        }
    }
}

/// Synthesize an Anthropic SSE stream from a cached non-streaming response.
#[allow(dead_code)] // public API for streaming cache hit path
pub fn synthesize_anthropic_sse_from_cached(cached: &CachedResponse) -> Vec<u8> {
    // Parse the cached response to extract text content
    let mut output = Vec::new();

    if let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&cached.body) {
        let model = resp
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let msg_id = resp
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("msg_cached");

        // message_start
        let start = serde_json::json!({
            "type": "message_start",
            "message": {
                "id": msg_id,
                "type": "message",
                "role": "assistant",
                "model": model,
                "content": [],
                "stop_reason": null,
            }
        });
        output.extend_from_slice(format!("event: message_start\ndata: {}\n\n", start).as_bytes());

        // content_block_start + delta for each content block
        if let Some(content) = resp.get("content").and_then(|v| v.as_array()) {
            for (i, block) in content.iter().enumerate() {
                let block_start = serde_json::json!({
                    "type": "content_block_start",
                    "index": i,
                    "content_block": { "type": "text", "text": "" }
                });
                output.extend_from_slice(
                    format!("event: content_block_start\ndata: {}\n\n", block_start).as_bytes(),
                );

                if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                    let delta = serde_json::json!({
                        "type": "content_block_delta",
                        "index": i,
                        "delta": { "type": "text_delta", "text": text }
                    });
                    output.extend_from_slice(
                        format!("event: content_block_delta\ndata: {}\n\n", delta).as_bytes(),
                    );
                }

                let block_stop = serde_json::json!({
                    "type": "content_block_stop",
                    "index": i,
                });
                output.extend_from_slice(
                    format!("event: content_block_stop\ndata: {}\n\n", block_stop).as_bytes(),
                );
            }
        }

        // message_delta + message_stop
        let stop_reason = resp
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("end_turn");
        let msg_delta = serde_json::json!({
            "type": "message_delta",
            "delta": { "stop_reason": stop_reason },
            "usage": resp.get("usage").cloned().unwrap_or(serde_json::json!({}))
        });
        output
            .extend_from_slice(format!("event: message_delta\ndata: {}\n\n", msg_delta).as_bytes());
        output.extend_from_slice(
            format!(
                "event: message_stop\ndata: {}\n\n",
                serde_json::json!({"type": "message_stop"})
            )
            .as_bytes(),
        );
    }

    output
}

/// Synthesize an OpenAI SSE stream from a cached non-streaming response.
#[allow(dead_code)] // public API for streaming cache hit path
pub fn synthesize_openai_sse_from_cached(cached: &CachedResponse) -> Vec<u8> {
    let mut output = Vec::new();

    if let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&cached.body) {
        let id = resp
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("chatcmpl-cached");
        let model = resp
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Extract first choice content
        let content = resp
            .get("choices")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Single delta chunk with full content
        let chunk = serde_json::json!({
            "id": id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{
                "index": 0,
                "delta": { "role": "assistant", "content": content },
                "finish_reason": null
            }]
        });
        output.extend_from_slice(format!("data: {}\n\n", chunk).as_bytes());

        // Final chunk with finish_reason
        let done = serde_json::json!({
            "id": id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }]
        });
        output.extend_from_slice(format!("data: {}\n\n", done).as_bytes());
        output.extend_from_slice(b"data: [DONE]\n\n");
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_put_get() {
        let cache = ResponseCache::new(100, 60, 1024 * 1024);
        let key = "test-key".to_string();
        let resp = CachedResponse {
            body: b"hello".to_vec(),
            content_type: "application/json".to_string(),
            provider: "test".to_string(),
            model: "test-model".to_string(),
        };
        cache.put(key.clone(), resp).await;
        let got = cache.get(&key).await.unwrap();
        assert_eq!(got.body, b"hello");
        assert_eq!(got.provider, "test");
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = ResponseCache::new(100, 60, 1024 * 1024);
        assert!(cache.get("nonexistent").await.is_none());
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn test_cache_skip_too_large() {
        let cache = ResponseCache::new(100, 60, 10); // 10 byte limit
        let key = "big".to_string();
        let resp = CachedResponse {
            body: vec![0u8; 100],
            content_type: "application/json".to_string(),
            provider: "test".to_string(),
            model: "test-model".to_string(),
        };
        cache.put(key.clone(), resp).await;
        assert!(cache.get(&key).await.is_none()); // not stored
        assert_eq!(cache.stats().skipped_too_large, 1);
    }

    #[test]
    fn test_compute_key_cacheable() {
        let messages = serde_json::json!([{"role": "user", "content": "hello"}]);
        let key = ResponseCache::compute_key(
            "tenant",
            "model",
            &messages,
            None,
            None,
            Some(1024),
            Some(0.0),
        );
        assert!(key.is_some());
        assert_eq!(key.as_ref().unwrap().len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_compute_key_not_cacheable() {
        let messages = serde_json::json!([{"role": "user", "content": "hello"}]);
        let key =
            ResponseCache::compute_key("tenant", "model", &messages, None, None, None, Some(0.7));
        assert!(key.is_none());
    }

    #[test]
    fn test_compute_key_no_temp_is_cacheable() {
        let messages = serde_json::json!([{"role": "user", "content": "hello"}]);
        let key = ResponseCache::compute_key("tenant", "model", &messages, None, None, None, None);
        assert!(key.is_some());
    }

    #[test]
    fn test_invalidate_all() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let cache = ResponseCache::new(100, 60, 1024 * 1024);
            let resp = CachedResponse {
                body: b"data".to_vec(),
                content_type: "application/json".to_string(),
                provider: "test".to_string(),
                model: "model".to_string(),
            };
            cache.put("k1".to_string(), resp).await;
            cache.invalidate_all();
            // moka invalidate_all is lazy, need run_pending_tasks
            cache.inner.run_pending_tasks().await;
            assert!(cache.get("k1").await.is_none());
        });
    }

    #[test]
    fn test_synthesize_anthropic_sse() {
        let cached = CachedResponse {
            body: serde_json::to_vec(&serde_json::json!({
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "model": "test-model",
                "content": [{"type": "text", "text": "Hello world"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 5}
            }))
            .unwrap(),
            content_type: "application/json".to_string(),
            provider: "test".to_string(),
            model: "test-model".to_string(),
        };
        let sse = synthesize_anthropic_sse_from_cached(&cached);
        let text = String::from_utf8(sse).unwrap();
        assert!(text.contains("event: message_start"));
        assert!(text.contains("Hello world"));
        assert!(text.contains("event: message_stop"));
    }

    #[test]
    fn test_synthesize_openai_sse() {
        let cached = CachedResponse {
            body: serde_json::to_vec(&serde_json::json!({
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "model": "gpt-4",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"}, "finish_reason": "stop"}]
            }))
            .unwrap(),
            content_type: "application/json".to_string(),
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
        };
        let sse = synthesize_openai_sse_from_cached(&cached);
        let text = String::from_utf8(sse).unwrap();
        assert!(text.contains("data: "));
        assert!(text.contains("Hi"));
        assert!(text.contains("[DONE]"));
    }
}
