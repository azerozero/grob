//! Snapshot tests for error response formats.
//!
//! Each [`RequestError`] variant produces a JSON response with a specific HTTP
//! status code and error structure. These snapshots detect unintended changes
//! to the error API contract.

use axum::response::IntoResponse;
use grob::server::RequestError;

// ── Helpers ─────────────────────────────────────────────────────

/// Extracts status code and parsed JSON body from a `RequestError`.
async fn error_snapshot(error: RequestError) -> String {
    let response = error.into_response();
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("invariant: in-memory body collection cannot fail");
    let json: serde_json::Value = serde_json::from_slice(&body_bytes)
        .expect("invariant: RequestError always produces valid JSON");
    format!("status={} body={}", status.as_u16(), json)
}

// ── Snapshot Tests ──────────────────────────────────────────────

#[tokio::test]
async fn snapshot_budget_exceeded_error() {
    let snap = error_snapshot(RequestError::BudgetExceeded {
        limit_usd: 50.0,
        actual_usd: 50.0,
    })
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_routing_error() {
    let snap = error_snapshot(RequestError::RoutingError(
        "no matching model: gpt-unknown".to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_provider_error() {
    let snap = error_snapshot(RequestError::ProviderUpstream {
        provider: "openai".to_string(),
        status: 502,
        body: Some("upstream timeout after 30s".to_string()),
    })
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_parse_error() {
    let snap = error_snapshot(RequestError::ParseError(
        "invalid JSON at line 1, column 42".to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_dlp_blocked_error() {
    let snap = error_snapshot(RequestError::DlpBlocked(
        "secret detected in prompt: sk-***".to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_rate_limited_error() {
    let snap = error_snapshot(RequestError::RateLimited {
        provider: "anthropic".to_string(),
        retry_after_ms: Some(2500),
    })
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_unauthorized_error() {
    let snap = error_snapshot(RequestError::Unauthorized).await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_forbidden_error() {
    let snap = error_snapshot(RequestError::Forbidden(
        "policy denies model 'claude-opus-4-7' for tenant 'public'".to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_auth_revoked_error() {
    let snap = error_snapshot(RequestError::AuthRevoked(
        "OAuth token for provider 'anthropic' revoked. Run: grob connect --force-reauth"
            .to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}
