//! Snapshot tests for error response formats.
//!
//! Each [`AppError`] variant produces a JSON response with a specific HTTP
//! status code and error structure. These snapshots detect unintended changes
//! to the error API contract.

use axum::response::IntoResponse;
use grob::server::AppError;

// ── Helpers ─────────────────────────────────────────────────────

/// Extracts status code and parsed JSON body from an AppError.
async fn error_snapshot(error: AppError) -> String {
    let response = error.into_response();
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("invariant: in-memory body collection cannot fail");
    let json: serde_json::Value = serde_json::from_slice(&body_bytes)
        .expect("invariant: AppError always produces valid JSON");
    format!("status={} body={}", status.as_u16(), json)
}

// ── Snapshot Tests ──────────────────────────────────────────────

#[tokio::test]
async fn snapshot_budget_exceeded_error() {
    let snap = error_snapshot(AppError::BudgetExceeded(
        "Monthly global budget reached: $50.00/$50.00".to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_routing_error() {
    let snap = error_snapshot(AppError::RoutingError(
        "no matching model: gpt-unknown".to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_provider_error() {
    let snap = error_snapshot(AppError::ProviderError(
        "upstream timeout after 30s".to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_parse_error() {
    let snap = error_snapshot(AppError::ParseError(
        "invalid JSON at line 1, column 42".to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}

#[tokio::test]
async fn snapshot_dlp_blocked_error() {
    let snap = error_snapshot(AppError::DlpBlocked(
        "secret detected in prompt: sk-***".to_string(),
    ))
    .await;
    insta::assert_snapshot!(snap);
}
