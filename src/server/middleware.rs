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

pub(crate) fn should_apply_transparency(config: &crate::cli::AppConfig) -> bool {
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
pub(crate) struct RequestId(pub String);

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
        let legacy_key = inner.config.server.api_key.as_deref().unwrap_or("");
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
            let api_key = inner
                .config
                .auth
                .api_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .or_else(|| inner.config.server.api_key.as_deref())
                .unwrap_or("");

            if api_key.is_empty() {
                return next.run(request).await;
            }

            let token = extract_api_credential(request.headers());
            match token {
                Some(t) if constant_time_eq(t, api_key) => next.run(request).await,
                _ => auth_error_response("Invalid or missing API key. Provide via Authorization: Bearer <key> or x-api-key header."),
            }
        }
        "jwt" => {
            let Some(validator) = &state.jwt_validator else {
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

    let limiter = match &state.rate_limiter {
        Some(l) => l,
        None => return next.run(request).await,
    };

    let key = if let Some(claims) = request.extensions().get::<crate::auth::GrobClaims>() {
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
            .expect("rate limit response");
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
