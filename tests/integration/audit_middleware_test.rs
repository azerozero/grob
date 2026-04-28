//! Integration tests for the audit-log middleware.
//!
//! Exercises [`emit_request_processed`] over a representative cross-section
//! of HTTP statuses (2xx/4xx/5xx) and verifies:
//!
//! * One audit entry is written per request when the dispatch pipeline did
//!   not already log.
//! * No entry is written when the response carries the [`AuditedAlready`]
//!   marker (de-duplication invariant).
//! * Provider/model headers and error variant tags are preserved in the
//!   audit entry.

use axum::http::{HeaderValue, Method, Request, Response, StatusCode};
use grob::security::audit_log::{AuditConfig, AuditEntry, AuditEvent, AuditLog, SigningAlgorithm};
use grob::server::{
    capture_audit_input, emit_request_processed, AuditMiddlewareCapture, AuditedAlready,
};
use tempfile::TempDir;

fn build_audit_log() -> (TempDir, AuditLog) {
    let dir = TempDir::new().expect("tempdir");
    let log = AuditLog::new(AuditConfig {
        log_dir: dir.path().to_path_buf(),
        sign_key_path: None,
        signing_algorithm: SigningAlgorithm::default(),
        hmac_key_path: None,
        batch_size: 1,
        flush_interval_ms: 5000,
        include_merkle_proof: false,
    })
    .expect("audit log");
    (dir, log)
}

fn read_entries(dir: &TempDir) -> Vec<AuditEntry> {
    let path = dir.path().join("current.jsonl");
    if !path.exists() {
        return vec![];
    }
    std::fs::read_to_string(&path)
        .expect("read jsonl")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("parse audit entry"))
        .collect()
}

fn make_capture() -> AuditMiddlewareCapture {
    AuditMiddlewareCapture {
        method: Method::POST,
        path: "/v1/messages".to_string(),
        request_id: "req-test-001".to_string(),
        tenant_id: "tenant-alpha".to_string(),
        client_ip: "10.0.0.1".to_string(),
        started_at: std::time::Instant::now(),
    }
}

fn build_response(status: StatusCode) -> Response<axum::body::Body> {
    Response::builder()
        .status(status)
        .body(axum::body::Body::empty())
        .expect("build response")
}

#[test]
fn audit_middleware_emits_one_entry_per_request_lifecycle() {
    let (dir, audit) = build_audit_log();

    // Simulate five requests with different outcomes.
    let cases = [
        StatusCode::OK,                    // 200
        StatusCode::BAD_REQUEST,           // 400
        StatusCode::UNAUTHORIZED,          // 401
        StatusCode::TOO_MANY_REQUESTS,     // 429
        StatusCode::INTERNAL_SERVER_ERROR, // 500
    ];

    for status in cases {
        let capture = make_capture();
        let response = build_response(status);
        let written = emit_request_processed(&audit, &capture, &response);
        assert!(
            written,
            "audit middleware must emit an entry for {}",
            status
        );
    }

    let entries = read_entries(&dir);
    assert_eq!(
        entries.len(),
        cases.len(),
        "expected one audit entry per request"
    );
    for entry in &entries {
        assert!(matches!(entry.action, AuditEvent::RequestProcessed));
        assert_eq!(entry.tenant_id, "tenant-alpha");
        assert_eq!(entry.ip_source, "10.0.0.1");
    }
}

#[test]
fn audit_middleware_skips_when_handler_already_audited() {
    let (dir, audit) = build_audit_log();

    let capture = make_capture();
    let mut response = build_response(StatusCode::OK);
    response.extensions_mut().insert(AuditedAlready);

    let written = emit_request_processed(&audit, &capture, &response);
    assert!(
        !written,
        "audit middleware must not double-log when handler already logged"
    );

    let entries = read_entries(&dir);
    assert!(
        entries.is_empty(),
        "expected zero audit entries from middleware when AuditedAlready is set, got {}",
        entries.len()
    );
}

#[test]
fn audit_middleware_captures_provider_from_response_header() {
    let (dir, audit) = build_audit_log();

    let capture = make_capture();
    let mut response = build_response(StatusCode::OK);
    response
        .headers_mut()
        .insert("x-ai-provider", HeaderValue::from_static("anthropic"));
    response
        .headers_mut()
        .insert("x-ai-model", HeaderValue::from_static("claude-opus-4-7"));

    let written = emit_request_processed(&audit, &capture, &response);
    assert!(written);

    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].backend_routed, "anthropic");
    assert_eq!(
        entries[0].model_name.as_deref(),
        Some("claude-opus-4-7"),
        "model name should be captured from x-ai-model header"
    );
}

#[test]
fn audit_middleware_includes_error_variant_tag_in_dlp_rules_field() {
    let (dir, audit) = build_audit_log();

    let capture = make_capture();
    let mut response = build_response(StatusCode::PAYMENT_REQUIRED);
    response
        .extensions_mut()
        .insert(grob::server::ErrorVariantTag("budget_exceeded".to_string()));

    let written = emit_request_processed(&audit, &capture, &response);
    assert!(written);

    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert!(entries[0]
        .dlp_rules_triggered
        .iter()
        .any(|r| r.contains("budget_exceeded") && r.contains("status=402")));
}

#[test]
fn audit_middleware_emits_low_risk_for_2xx() {
    let (dir, audit) = build_audit_log();
    let capture = make_capture();
    let response = build_response(StatusCode::OK);
    emit_request_processed(&audit, &capture, &response);
    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].risk_level,
        Some(grob::security::audit_log::RiskLevel::Low)
    );
}

#[test]
fn audit_middleware_emits_medium_risk_for_4xx() {
    let (dir, audit) = build_audit_log();
    let capture = make_capture();
    let response = build_response(StatusCode::BAD_REQUEST);
    emit_request_processed(&audit, &capture, &response);
    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].risk_level,
        Some(grob::security::audit_log::RiskLevel::Medium)
    );
}

#[test]
fn audit_middleware_emits_high_risk_for_5xx() {
    let (dir, audit) = build_audit_log();
    let capture = make_capture();
    let response = build_response(StatusCode::INTERNAL_SERVER_ERROR);
    emit_request_processed(&audit, &capture, &response);
    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].risk_level,
        Some(grob::security::audit_log::RiskLevel::High)
    );
}

#[test]
fn audit_middleware_falls_back_to_client_ip_when_tenant_missing() {
    let (dir, audit) = build_audit_log();
    let mut capture = make_capture();
    capture.tenant_id = String::new();
    let response = build_response(StatusCode::OK);
    emit_request_processed(&audit, &capture, &response);
    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].tenant_id, "10.0.0.1",
        "anonymous request should be tagged by client IP"
    );
}

#[test]
fn capture_audit_input_picks_up_request_id_from_extensions() {
    let mut request: Request<axum::body::Body> = Request::builder()
        .method(Method::GET)
        .uri("/v1/models")
        .body(axum::body::Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(grob::server::RequestId("rid-abc-123".to_string()));

    let capture = capture_audit_input(&request);
    assert_eq!(capture.request_id, "rid-abc-123");
    assert_eq!(capture.method, Method::GET);
    assert_eq!(capture.path, "/v1/models");
}
