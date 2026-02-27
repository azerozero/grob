//! Response cache hit/miss tests
//!
//! Verifies that the response cache correctly stores and retrieves
//! non-streaming responses, including cache key computation.

use grob::cache::{CachedResponse, ResponseCache};
use grob::models::{AnthropicRequest, Message, MessageContent};

fn test_request(model: &str, text: &str) -> AnthropicRequest {
    AnthropicRequest {
        model: model.to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text(text.to_string()),
        }],
        max_tokens: 1024,
        thinking: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop_sequences: None,
        stream: None,
        metadata: None,
        system: None,
        tools: None,
        tool_choice: None,
    }
}

#[tokio::test]
async fn test_cache_miss_then_hit() {
    let cache = ResponseCache::new(100, 60, 1_000_000);
    let request = test_request("claude-3-5-sonnet", "Hello");

    let key =
        ResponseCache::compute_key_from_request("tenant-1", &request).expect("should compute key");

    // First access: cache miss
    let miss = cache.get(&key).await;
    assert!(miss.is_none(), "First access should be a cache miss");

    // Store response
    let cached = CachedResponse {
        body: br#"{"content":"Hello!"}"#.to_vec(),
        content_type: "application/json".to_string(),
        provider: "anthropic".to_string(),
        model: "claude-3-5-sonnet-20241022".to_string(),
    };
    cache.put(key.clone(), cached.clone()).await;

    // Second access: cache hit
    let hit = cache.get(&key).await;
    assert!(hit.is_some(), "Second access should be a cache hit");
    let hit = hit.unwrap();
    assert_eq!(hit.body, cached.body);
    assert_eq!(hit.provider, "anthropic");
    assert_eq!(hit.model, "claude-3-5-sonnet-20241022");
}

#[tokio::test]
async fn test_cache_different_tenants_independent() {
    let cache = ResponseCache::new(100, 60, 1_000_000);
    let request = test_request("claude-3-5-sonnet", "Hello");

    let key_a =
        ResponseCache::compute_key_from_request("tenant-a", &request).expect("should compute key");
    let key_b =
        ResponseCache::compute_key_from_request("tenant-b", &request).expect("should compute key");

    assert_ne!(
        key_a, key_b,
        "Different tenants should have different cache keys"
    );

    // Store for tenant A only
    cache
        .put(
            key_a.clone(),
            CachedResponse {
                body: b"response-a".to_vec(),
                content_type: "application/json".to_string(),
                provider: "anthropic".to_string(),
                model: "claude-3-5-sonnet".to_string(),
            },
        )
        .await;

    assert!(cache.get(&key_a).await.is_some(), "Tenant A should hit");
    assert!(cache.get(&key_b).await.is_none(), "Tenant B should miss");
}

#[tokio::test]
async fn test_cache_different_prompts_independent() {
    let _cache = ResponseCache::new(100, 60, 1_000_000);
    let req1 = test_request("claude-3-5-sonnet", "Hello");
    let req2 = test_request("claude-3-5-sonnet", "Goodbye");

    let key1 =
        ResponseCache::compute_key_from_request("tenant", &req1).expect("should compute key");
    let key2 =
        ResponseCache::compute_key_from_request("tenant", &req2).expect("should compute key");

    assert_ne!(
        key1, key2,
        "Different prompts should have different cache keys"
    );
}

#[tokio::test]
async fn test_cache_invalidate_all() {
    let cache = ResponseCache::new(100, 60, 1_000_000);
    let request = test_request("claude-3-5-sonnet", "Hello");
    let key =
        ResponseCache::compute_key_from_request("tenant", &request).expect("should compute key");

    cache
        .put(
            key.clone(),
            CachedResponse {
                body: b"response".to_vec(),
                content_type: "application/json".to_string(),
                provider: "anthropic".to_string(),
                model: "claude-3-5-sonnet".to_string(),
            },
        )
        .await;

    assert!(
        cache.get(&key).await.is_some(),
        "Should hit before invalidate"
    );

    cache.invalidate_all();

    assert!(
        cache.get(&key).await.is_none(),
        "Should miss after invalidate"
    );
}

#[tokio::test]
async fn test_cache_hit_miss_counters() {
    let cache = ResponseCache::new(100, 60, 1_000_000);

    let request = test_request("claude-3-5-sonnet", "Hello");
    let key =
        ResponseCache::compute_key_from_request("tenant", &request).expect("should compute key");

    // Miss
    let _ = cache.get(&key).await;
    let stats = cache.stats();
    assert_eq!(stats.misses, 1, "Should have 1 miss");
    assert_eq!(stats.hits, 0, "Should have 0 hits");

    // Put
    cache
        .put(
            key.clone(),
            CachedResponse {
                body: b"response".to_vec(),
                content_type: "application/json".to_string(),
                provider: "anthropic".to_string(),
                model: "claude-3-5-sonnet".to_string(),
            },
        )
        .await;

    // Hit
    let _ = cache.get(&key).await;
    let stats = cache.stats();
    assert_eq!(stats.misses, 1, "Should still have 1 miss");
    assert_eq!(stats.hits, 1, "Should have 1 hit");
}
