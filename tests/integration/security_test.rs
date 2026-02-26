// Security integration tests
// Tests for rate limiting, security headers, body size limits, request ID, circuit breaker

use grob::security::{
    CircuitBreakerRegistry, CircuitState, RateLimitConfig, RateLimitKey,
    RateLimiter, SecurityHeadersConfig, apply_security_headers,
};
use std::time::Duration;

#[tokio::test]
async fn test_rate_limiting_returns_429_after_burst() {
    let limiter = RateLimiter::new(RateLimitConfig {
        requests_per_second: 10,
        burst: 5,
        _window: Duration::from_secs(60),
    });

    let key = RateLimitKey::Tenant("test-tenant".to_string());

    // Exhaust burst
    for _ in 0..5 {
        let (allowed, _, _) = limiter.check(&key).await;
        assert!(allowed, "Should allow requests within burst");
    }

    // Next request should be rejected
    let (allowed, remaining, reset_after) = limiter.check(&key).await;
    assert!(!allowed, "Should reject after burst exhausted");
    assert_eq!(remaining, 0);
    assert!(reset_after.is_some(), "Should include retry-after duration");
}

#[test]
fn test_security_headers_present_in_api_mode() {
    let config = SecurityHeadersConfig::api_mode();
    let response = axum::http::Response::builder()
        .status(200)
        .body(axum::body::Body::empty())
        .unwrap();

    let response = apply_security_headers(response, &config);
    let headers = response.headers();

    assert!(
        headers.contains_key("strict-transport-security"),
        "Should include HSTS header"
    );
    assert!(
        headers.contains_key("x-frame-options"),
        "Should include X-Frame-Options"
    );
    assert!(
        headers.contains_key("x-content-type-options"),
        "Should include X-Content-Type-Options"
    );
    assert!(
        headers.contains_key("referrer-policy"),
        "Should include Referrer-Policy"
    );
    assert!(
        headers.contains_key("cache-control"),
        "Should include Cache-Control"
    );
}

#[tokio::test]
async fn test_circuit_breaker_opens_after_threshold() {
    let registry = CircuitBreakerRegistry::new();

    let provider = "test-provider";

    // Initially closed
    assert!(registry.can_execute(provider).await);

    // Record failures to open circuit (default threshold is 5)
    for _ in 0..5 {
        registry.record_failure(provider).await;
    }

    // Circuit should be open
    assert!(!registry.can_execute(provider).await);

    // Verify via all_states
    let states = registry.all_states().await;
    assert_eq!(states.get(provider), Some(&CircuitState::Open));
}

#[tokio::test]
async fn test_circuit_breaker_per_provider_isolation() {
    let registry = CircuitBreakerRegistry::new();

    // Open circuit for provider A (default threshold is 5)
    for _ in 0..5 {
        registry.record_failure("provider-a").await;
    }
    assert!(!registry.can_execute("provider-a").await);

    // Provider B should be unaffected
    assert!(registry.can_execute("provider-b").await);
}

#[tokio::test]
async fn test_rate_limit_per_tenant_isolation() {
    let limiter = RateLimiter::new(RateLimitConfig {
        requests_per_second: 10,
        burst: 3,
        _window: Duration::from_secs(60),
    });

    let tenant_a = RateLimitKey::Tenant("tenant-a".to_string());
    let tenant_b = RateLimitKey::Tenant("tenant-b".to_string());

    // Exhaust tenant A's burst
    for _ in 0..3 {
        let (allowed, _, _) = limiter.check(&tenant_a).await;
        assert!(allowed);
    }
    let (allowed, _, _) = limiter.check(&tenant_a).await;
    assert!(!allowed, "Tenant A should be rate limited");

    // Tenant B should still have full burst
    let (allowed, _, _) = limiter.check(&tenant_b).await;
    assert!(allowed, "Tenant B should not be affected");
}
