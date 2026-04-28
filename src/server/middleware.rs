use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tracing::{debug, error};

use crate::security::{apply_security_headers, RateLimitKey, SecurityHeadersConfig};

use super::AppState;

/// Constant-time string comparison to prevent timing side-channel attacks.
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Extract client IP from headers (X-Forwarded-For or fallback to "unknown").
pub(crate) fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Apply EU AI Act transparency headers to a response.
pub(crate) fn apply_transparency_headers(
    headers: &mut HeaderMap,
    provider: &str,
    model: &str,
    audit_id: &str,
) {
    if let Ok(v) = HeaderValue::from_str(provider) {
        headers.insert("x-ai-provider", v);
    }
    if let Ok(v) = HeaderValue::from_str(model) {
        headers.insert("x-ai-model", v);
    }
    if let Ok(v) = HeaderValue::from_str(audit_id) {
        headers.insert("x-grob-audit-id", v);
    }
    headers.insert("x-ai-generated", HeaderValue::from_static("true"));
}

/// Returns true when EU AI Act transparency headers should be added.
pub(crate) fn should_apply_transparency(config: &crate::models::config::AppConfig) -> bool {
    config.compliance.enabled && config.compliance.transparency_headers
}

/// Extract API credential from request headers (Bearer token or x-api-key).
pub(crate) fn extract_api_credential(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
}

/// Builds a 401 JSON error response with the given message.
pub(crate) fn auth_error_response(message: &str) -> Response {
    let body = Json(serde_json::json!({
        "error": {
            "type": "authentication_error",
            "message": message
        }
    }));
    (StatusCode::UNAUTHORIZED, body).into_response()
}

/// Stored in request extensions for correlation
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Auth middleware: supports three modes:
/// - "none" (default): all requests pass
/// - "api_key": checks Bearer token or x-api-key against configured key
/// - "jwt": validates JWT, extracts tenant_id, injects GrobClaims into request extensions
///
/// Skips auth for health/metrics/oauth paths.
pub(crate) async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if matches!(
        path,
        "/health" | "/live" | "/ready" | "/metrics" | "/auth/callback" | "/api/oauth/callback"
    ) {
        return next.run(request).await;
    }

    let inner = state.snapshot();
    let auth_mode = inner.config.auth.mode.as_str();

    let effective_mode = if auth_mode == "none" {
        // SAFETY: expose_secret() used only for emptiness check, value is never logged.
        let legacy_key = inner
            .config
            .server
            .api_key
            .as_ref()
            .map(|s| secrecy::ExposeSecret::expose_secret(s).as_str())
            .unwrap_or("");
        if legacy_key.is_empty() {
            "none"
        } else {
            "api_key"
        }
    } else {
        auth_mode
    };

    match effective_mode {
        "none" => next.run(request).await,
        "api_key" => {
            // SAFETY: expose_secret() used only for constant-time comparison,
            // value is never logged or included in any tracing output.
            let api_key = inner
                .config
                .auth
                .api_key
                .as_ref()
                .map(|s| secrecy::ExposeSecret::expose_secret(s).as_str())
                .filter(|k| !k.is_empty())
                .or_else(|| {
                    inner
                        .config
                        .server
                        .api_key
                        .as_ref()
                        .map(|s| secrecy::ExposeSecret::expose_secret(s).as_str())
                })
                .unwrap_or("");

            if api_key.is_empty() {
                return next.run(request).await;
            }

            let token = extract_api_credential(request.headers());
            match token {
                Some(t) if constant_time_eq(t, api_key) => next.run(request).await,
                Some(t) => {
                    // Static key didn't match — try virtual key lookup.
                    match resolve_virtual_key(&state, t) {
                        Some(vk_ctx) => {
                            debug!("Virtual key auth: tenant={}, key={}", vk_ctx.tenant_id, vk_ctx.name);
                            request.extensions_mut().insert(vk_ctx);
                            next.run(request).await
                        }
                        None => auth_error_response("Invalid or missing API key. Provide via Authorization: Bearer <key> or x-api-key header."),
                    }
                }
                None => auth_error_response("Invalid or missing API key. Provide via Authorization: Bearer <key> or x-api-key header."),
            }
        }
        "jwt" => {
            let Some(validator) = &state.security.jwt_validator else {
                error!("JWT auth mode configured but no validator initialized");
                return auth_error_response(
                    "Server misconfiguration: JWT validator not initialized",
                );
            };

            let Some(token) = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
            else {
                return auth_error_response(&crate::auth::jwt::AuthError::MissingToken.to_string());
            };

            match validator.validate(token) {
                Ok(claims) => {
                    debug!("JWT auth: tenant_id={}", claims.tenant_id());
                    request.extensions_mut().insert(claims);
                    next.run(request).await
                }
                Err(e) => auth_error_response(&format!("JWT validation failed: {}", e)),
            }
        }
        other => {
            error!("Unknown auth mode: {}", other);
            auth_error_response(&format!("Unknown auth mode: {}", other))
        }
    }
}

/// Resolves a bearer token as a virtual API key.
///
/// Hashes the token with SHA-256, looks up the record in storage,
/// and returns a [`VirtualKeyContext`] if the key is valid (not revoked, not expired).
fn resolve_virtual_key(
    state: &Arc<AppState>,
    token: &str,
) -> Option<crate::auth::virtual_keys::VirtualKeyContext> {
    use sha2::{Digest, Sha256};

    // Only attempt lookup for tokens with the grob_ prefix.
    if !token.starts_with("grob_") {
        return None;
    }

    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    let record = state.grob_store.lookup_virtual_key(&hash)?;

    if record.revoked {
        debug!("Virtual key {} is revoked", record.prefix);
        return None;
    }

    if let Some(expires_at) = record.expires_at {
        if chrono::Utc::now() >= expires_at {
            debug!("Virtual key {} is expired", record.prefix);
            return None;
        }
    }

    Some(crate::auth::virtual_keys::VirtualKeyContext {
        key_id: record.id,
        tenant_id: record.tenant_id,
        name: record.name,
        budget_usd: record.budget_usd,
        rate_limit_rps: record.rate_limit_rps,
        allowed_models: record.allowed_models,
    })
}

/// Request ID middleware: reads X-Request-Id header or generates UUID v4.
/// Stores in request extensions and echoes in response header.
pub(crate) async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    let mut response = next.run(request).await;
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }
    response
}

/// Rate limiting middleware: checks rate limiter before processing.
/// Returns 429 with Retry-After header when rate exceeded.
pub(crate) async fn rate_limit_check_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if matches!(path, "/health" | "/metrics" | "/live" | "/ready") {
        return next.run(request).await;
    }

    let limiter = match &state.security.rate_limiter {
        Some(l) => l,
        None => return next.run(request).await,
    };

    let key = if let Some(vk) = request
        .extensions()
        .get::<crate::auth::virtual_keys::VirtualKeyContext>()
    {
        RateLimitKey::Tenant(format!("vk:{}", vk.key_id))
    } else if let Some(claims) = request.extensions().get::<crate::auth::GrobClaims>() {
        RateLimitKey::Tenant(claims.tenant_id().to_string())
    } else if let Some(credential) = extract_api_credential(request.headers()) {
        RateLimitKey::Tenant(credential.to_string())
    } else {
        RateLimitKey::Ip("anonymous".to_string())
    };

    let (allowed, _remaining, reset_after) = limiter.check(&key).await;

    if !allowed {
        metrics::counter!("grob_ratelimit_rejected_total").increment(1);
        let retry_after = reset_after
            .map(|d| d.as_secs().max(1).to_string())
            .unwrap_or_else(|| "1".to_string());
        return Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Retry-After", &retry_after)
            .header("X-RateLimit-Remaining", "0")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"error":{"type":"rate_limit_error","message":"Rate limit exceeded. Please slow down."}}"#,
            ))
            // All header values are static ASCII; builder cannot fail here.
            .unwrap_or_else(|_| {
                Response::new(Body::from(r#"{"error":{"type":"rate_limit_error","message":"Rate limit exceeded."}}"#))
            });
    }

    next.run(request).await
}

/// Security headers middleware: applies OWASP security headers to all responses.
pub(crate) async fn security_headers_response_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    let config = SecurityHeadersConfig::api_mode();
    apply_security_headers(response, &config)
}

/// Marker inserted into response extensions by handlers that already wrote
/// an audit entry. The audit middleware skips logging when present so that
/// the dispatch pipeline (which audits with rich DLP and token-count context)
/// is the source of truth for request-lifecycle entries on the hot path.
///
/// Endpoints that bypass dispatch entirely (oauth handlers, config API,
/// errors raised in middleware before dispatch) leave this marker absent
/// and are audited centrally by the middleware.
#[derive(Clone, Debug)]
pub struct AuditedAlready;

/// Inputs captured by the audit middleware before the handler runs.
///
/// Stored on the request side so post-handler audit emission can rebuild
/// the entry without re-reading consumed request state.
pub struct AuditMiddlewareCapture {
    /// HTTP method of the request.
    pub method: axum::http::Method,
    /// Path component of the request URI.
    pub path: String,
    /// Correlation ID resolved from the `RequestId` extension.
    pub request_id: String,
    /// Tenant identifier from JWT / virtual key, or empty.
    pub tenant_id: String,
    /// Client IP from `X-Forwarded-For` or `"unknown"`.
    pub client_ip: String,
    /// Wall-clock instant the middleware observed the request.
    pub started_at: std::time::Instant,
}

/// Pulls the captured request context that `audit_log_layer` snapshots
/// before the handler runs.
pub fn capture_audit_input(request: &Request<Body>) -> AuditMiddlewareCapture {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();

    let tenant_id = if let Some(vk) = request
        .extensions()
        .get::<crate::auth::virtual_keys::VirtualKeyContext>()
    {
        vk.tenant_id.clone()
    } else if let Some(claims) = request.extensions().get::<crate::auth::GrobClaims>() {
        claims.tenant_id().to_string()
    } else {
        String::new()
    };

    AuditMiddlewareCapture {
        method: request.method().clone(),
        path: request.uri().path().to_string(),
        request_id,
        tenant_id,
        client_ip: extract_client_ip(request.headers()),
        started_at: std::time::Instant::now(),
    }
}

/// Emits an `AuditEvent::RequestProcessed` entry from the captured request
/// context plus the post-handler response. Returns `true` when an entry
/// was written, `false` when the response carried [`AuditedAlready`] (in
/// which case the dispatch pipeline already wrote a richer entry).
///
/// Extracted from [`audit_log_layer`] so it can be unit-tested without
/// constructing a full `AppState`.
pub fn emit_request_processed(
    audit_log: &crate::security::AuditLog,
    capture: &AuditMiddlewareCapture,
    response: &Response,
) -> bool {
    if response.extensions().get::<AuditedAlready>().is_some() {
        return false;
    }

    let status = response.status();
    let duration_ms = capture.started_at.elapsed().as_millis() as u64;

    let provider = response
        .headers()
        .get("x-ai-provider")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let model = response
        .headers()
        .get("x-ai-model")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let error_variant = response
        .extensions()
        .get::<super::error::ErrorVariantTag>()
        .map(|tag| tag.0.clone());

    let backend = if !provider.is_empty() {
        provider
    } else if let Some(ref tag) = error_variant {
        format!("ERROR:{}:{}", tag, status.as_u16())
    } else if status.is_success() {
        format!("{} {}", capture.method, capture.path)
    } else {
        format!("STATUS:{}", status.as_u16())
    };

    let tenant_for_entry = if capture.tenant_id.is_empty() {
        capture.client_ip.as_str()
    } else {
        capture.tenant_id.as_str()
    };

    let mut builder = super::AuditEntryBuilder::new(
        tenant_for_entry,
        crate::security::audit_log::AuditEvent::RequestProcessed,
        &backend,
        &capture.client_ip,
        duration_ms,
    );

    if !model.is_empty() {
        builder = builder.model(model);
    }

    // Risk level: low for 2xx, medium for 4xx, high for 5xx — matches
    // the EU AI Act Article 14 escalation threshold defaults.
    let risk = if status.is_server_error() {
        crate::security::audit_log::RiskLevel::High
    } else if status.is_client_error() {
        crate::security::audit_log::RiskLevel::Medium
    } else {
        crate::security::audit_log::RiskLevel::Low
    };
    builder = builder.risk(risk);

    if let Some(tag) = error_variant {
        builder = builder.dlp_rules(vec![format!(
            "request_error:{}:status={}",
            tag,
            status.as_u16()
        )]);
    }

    if let Err(e) = audit_log.write(builder.build()) {
        tracing::error!(
            error = %e,
            request_id = %capture.request_id,
            "audit middleware: write failed"
        );
    }
    true
}

/// Audit-log middleware: emits `AuditEvent::RequestProcessed` for every HTTP
/// request that flows through the server.
///
/// Wraps every endpoint, including the OAuth, config, and health surfaces
/// that previously bypassed audit entirely. Captures request method, path,
/// status, latency, error variant tag (when 4xx/5xx), tenant identifier
/// (from JWT claims or virtual key context), client IP, and the upstream
/// provider name when set on the response by the dispatch pipeline.
///
/// Skips logging when the dispatch pipeline has already written a richer
/// audit entry (signalled by the [`AuditedAlready`] marker in response
/// extensions). Health and metrics endpoints are excluded to avoid
/// flooding the journal with unauthenticated probe traffic.
pub(crate) async fn audit_log_layer(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if matches!(path, "/health" | "/live" | "/ready" | "/metrics") {
        return next.run(request).await;
    }

    let capture = capture_audit_input(&request);
    let response = next.run(request).await;

    if let Some(ref audit_log) = state.security.audit_log {
        emit_request_processed(audit_log, &capture, &response);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_same() {
        assert!(constant_time_eq("secret", "secret"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq("secret", "other"));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        assert!(!constant_time_eq("short", "longer_string"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_extract_client_ip_from_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), "1.2.3.4");
    }

    #[test]
    fn test_extract_client_ip_single() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), "10.0.0.1");
    }

    #[test]
    fn test_extract_client_ip_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_client_ip(&headers), "unknown");
    }

    #[test]
    fn test_extract_api_credential_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-test-key".parse().unwrap());
        assert_eq!(extract_api_credential(&headers), Some("sk-test-key"));
    }

    #[test]
    fn test_extract_api_credential_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "my-key".parse().unwrap());
        assert_eq!(extract_api_credential(&headers), Some("my-key"));
    }

    #[test]
    fn test_extract_api_credential_bearer_takes_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer bearer-key".parse().unwrap());
        headers.insert("x-api-key", "api-key".parse().unwrap());
        assert_eq!(extract_api_credential(&headers), Some("bearer-key"));
    }

    #[test]
    fn test_extract_api_credential_no_headers() {
        let headers = HeaderMap::new();
        assert_eq!(extract_api_credential(&headers), None);
    }

    #[test]
    fn test_apply_transparency_headers() {
        let mut headers = HeaderMap::new();
        apply_transparency_headers(&mut headers, "anthropic", "claude-3", "req-123");
        assert_eq!(headers.get("x-ai-provider").unwrap(), "anthropic");
        assert_eq!(headers.get("x-ai-model").unwrap(), "claude-3");
        assert_eq!(headers.get("x-grob-audit-id").unwrap(), "req-123");
        assert_eq!(headers.get("x-ai-generated").unwrap(), "true");
    }
}
