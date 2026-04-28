//! Unified request-level error taxonomy.
//!
//! Single source of truth for HTTP error responses. Replaces the old
//! `AppError` + `ProviderError` split that masked upstream HTTP status codes
//! behind a generic `502 Bad Gateway` body.
//!
//! Every variant maps to a precise HTTP status; the ECMA RFC-9457 inspired
//! body shape is `{ "error": { "type": ..., "message": ..., ...extras } }`.
//!
//! `is_retryable()` is the authoritative classifier for retry/backoff
//! logic — `dispatch/retry.rs` and the provider loop must consult this
//! single method rather than re-implement status-code matching.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Unified error type for the request pipeline.
///
/// Carries the upstream HTTP status when applicable so the client sees the
/// exact failure mode (`Bad Gateway`, `Service Unavailable`, …) rather than
/// an opaque "Provider error" string.
#[derive(Debug)]
pub enum RequestError {
    /// Indicates a malformed or invalid request payload (HTTP 400).
    BadRequest(String),
    /// Indicates the caller failed authentication (HTTP 401).
    Unauthorized,
    /// Indicates the caller is authenticated but the action is forbidden (HTTP 403).
    Forbidden(String),
    /// Indicates the requested resource does not exist (HTTP 404).
    NotFound,
    /// Indicates a JSON parse or schema validation failure (HTTP 400).
    ParseError(String),
    /// Indicates routing could not resolve a model or provider (HTTP 400).
    RoutingError(String),
    /// Indicates the upstream provider rate-limited the request (HTTP 429).
    RateLimited {
        /// Provider that emitted the 429 (or the resolved alias).
        provider: String,
        /// Server-side hint for when to retry, when known.
        retry_after_ms: Option<u64>,
    },
    /// Indicates the upstream provider returned a non-success status.
    ///
    /// The original status is forwarded verbatim so the client sees the
    /// actual failure mode (502/503/504/etc.) instead of a flattened error.
    ProviderUpstream {
        /// Provider name (e.g. `"anthropic"`).
        provider: String,
        /// Verbatim upstream HTTP status code.
        status: u16,
        /// Optional upstream body excerpt for diagnostics.
        body: Option<String>,
    },
    /// Indicates a budget cap (global, provider, or model) was exceeded (HTTP 402).
    BudgetExceeded {
        /// Configured monthly limit in USD.
        limit_usd: f64,
        /// Actual recorded spend in USD at the time of the check.
        actual_usd: f64,
    },
    /// Indicates the DLP pipeline blocked the request (HTTP 400).
    DlpBlocked(String),
    /// Indicates an upstream OAuth credential was revoked (HTTP 401).
    ///
    /// Surfaces a terminal authentication error — the user must run
    /// `grob connect --force-reauth`. Distinct from `Unauthorized`, which
    /// covers the inbound caller's credential rather than an upstream's.
    AuthRevoked(String),
    /// Indicates an internal server failure (HTTP 500).
    Internal(anyhow::Error),
}

impl RequestError {
    /// Returns `true` when the error is transient and the dispatch loop should
    /// retry (with exponential backoff) before falling back to the next provider.
    ///
    /// This is the SINGLE source of truth for retry classification — both the
    /// retry loop and the rate-limit detector must call this method rather than
    /// duplicate the status-code matching logic.
    ///
    /// Notably **excludes** `AuthRevoked` (a permanent 401 requires operator
    /// action) but **includes** `RateLimited` and 5xx upstream failures.
    pub fn is_retryable(&self) -> bool {
        match self {
            RequestError::RateLimited { .. } => true,
            RequestError::ProviderUpstream { status, .. } => {
                matches!(*status, 429 | 500 | 502 | 503 | 504)
            }
            // Network/transport failures bubble up here too; treat as retryable
            // when the underlying error chain wraps a `reqwest::Error`.
            RequestError::Internal(err) => err.downcast_ref::<reqwest::Error>().is_some(),
            _ => false,
        }
    }

    /// Returns the HTTP status code, error type tag, and message for this variant.
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            RequestError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                msg.clone(),
            ),
            RequestError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                "Missing or invalid credentials".to_string(),
            ),
            RequestError::Forbidden(msg) => {
                (StatusCode::FORBIDDEN, "permission_error", msg.clone())
            }
            RequestError::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found_error",
                "Resource not found".to_string(),
            ),
            RequestError::ParseError(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                msg.clone(),
            ),
            RequestError::RoutingError(msg) => (StatusCode::BAD_REQUEST, "error", msg.clone()),
            RequestError::RateLimited { provider, .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limit_error",
                format!("Provider '{}' rate-limited the request", provider),
            ),
            RequestError::ProviderUpstream {
                provider,
                status,
                body,
            } => {
                // Forward the upstream status verbatim so the client sees the
                // exact failure mode. Default to 502 for unmapped non-success codes.
                let status_code = StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY);
                let msg = body
                    .clone()
                    .unwrap_or_else(|| format!("Provider '{}' returned HTTP {}", provider, status));
                (status_code, "error", msg)
            }
            RequestError::BudgetExceeded {
                limit_usd,
                actual_usd,
            } => (
                StatusCode::PAYMENT_REQUIRED,
                "budget_exceeded",
                format!(
                    "Budget exceeded: ${:.4} spent of ${:.4} limit",
                    actual_usd, limit_usd
                ),
            ),
            RequestError::DlpBlocked(msg) => (StatusCode::BAD_REQUEST, "dlp_block", msg.clone()),
            RequestError::AuthRevoked(msg) => (
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                msg.clone(),
            ),
            RequestError::Internal(err) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "error", err.to_string())
            }
        }
    }

    /// Returns a stable string tag for the error variant — used in audit logs
    /// and metrics labels (low-cardinality alternative to the message).
    pub fn variant_tag(&self) -> &'static str {
        match self {
            RequestError::BadRequest(_) => "bad_request",
            RequestError::Unauthorized => "unauthorized",
            RequestError::Forbidden(_) => "forbidden",
            RequestError::NotFound => "not_found",
            RequestError::ParseError(_) => "parse_error",
            RequestError::RoutingError(_) => "routing_error",
            RequestError::RateLimited { .. } => "rate_limited",
            RequestError::ProviderUpstream { .. } => "provider_upstream",
            RequestError::BudgetExceeded { .. } => "budget_exceeded",
            RequestError::DlpBlocked(_) => "dlp_blocked",
            RequestError::AuthRevoked(_) => "auth_revoked",
            RequestError::Internal(_) => "internal",
        }
    }
}

impl IntoResponse for RequestError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = self.parts();

        let mut body_obj = serde_json::json!({
            "error": {
                "type": error_type,
                "message": message,
            }
        });

        // Attach variant-specific extras (retry-after for rate limits,
        // budget figures for budget overruns, upstream provider for 5xx).
        match &self {
            RequestError::RateLimited {
                provider,
                retry_after_ms,
            } => {
                if let Some(error) = body_obj.get_mut("error").and_then(|v| v.as_object_mut()) {
                    error.insert(
                        "provider".to_string(),
                        serde_json::Value::String(provider.clone()),
                    );
                    if let Some(ms) = retry_after_ms {
                        error.insert("retry_after_ms".to_string(), serde_json::Value::from(*ms));
                    }
                }
            }
            RequestError::ProviderUpstream {
                provider, status, ..
            } => {
                if let Some(error) = body_obj.get_mut("error").and_then(|v| v.as_object_mut()) {
                    error.insert(
                        "provider".to_string(),
                        serde_json::Value::String(provider.clone()),
                    );
                    error.insert(
                        "upstream_status".to_string(),
                        serde_json::Value::from(*status),
                    );
                }
            }
            RequestError::BudgetExceeded {
                limit_usd,
                actual_usd,
            } => {
                if let Some(error) = body_obj.get_mut("error").and_then(|v| v.as_object_mut()) {
                    error.insert("limit_usd".to_string(), serde_json::Value::from(*limit_usd));
                    error.insert(
                        "actual_usd".to_string(),
                        serde_json::Value::from(*actual_usd),
                    );
                }
            }
            _ => {}
        }

        let mut response = (status, Json(body_obj)).into_response();
        // Mark response so the audit middleware can pick up the variant
        // without re-parsing the body.
        response
            .extensions_mut()
            .insert(ErrorVariantTag(self.variant_tag().to_string()));

        // Forward Retry-After header on 429 when known.
        if let RequestError::RateLimited {
            retry_after_ms: Some(ms),
            ..
        } = &self
        {
            // RFC 7231 Retry-After is in seconds; round up so we never advise
            // a delay shorter than the upstream actually requested.
            let secs = ms.div_ceil(1000).max(1);
            if let Ok(value) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert("retry-after", value);
            }
        }

        response
    }
}

/// Marker stored in response extensions so middleware can read the error
/// variant tag without parsing the body. Value is the lowercase variant tag.
#[derive(Clone, Debug)]
pub struct ErrorVariantTag(pub String);

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (_, _, message) = self.parts();
        write!(f, "{}: {}", self.variant_tag(), message)
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RequestError::Internal(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for RequestError {
    fn from(err: anyhow::Error) -> Self {
        RequestError::Internal(err)
    }
}

impl From<crate::providers::error::ProviderError> for RequestError {
    fn from(err: crate::providers::error::ProviderError) -> Self {
        use crate::providers::error::ProviderError;
        match err {
            ProviderError::ApiError { status, message } => match status {
                429 => RequestError::RateLimited {
                    provider: "upstream".to_string(),
                    retry_after_ms: None,
                },
                401 => {
                    if super::budget::is_rate_limit_payload(&message) {
                        // Anthropic emits `rate_limit_error` with HTTP 401 — treat
                        // as a transient rate-limit, not a revoked credential.
                        RequestError::RateLimited {
                            provider: "upstream".to_string(),
                            retry_after_ms: None,
                        }
                    } else {
                        RequestError::AuthRevoked(message)
                    }
                }
                _ => RequestError::ProviderUpstream {
                    provider: "upstream".to_string(),
                    status,
                    body: Some(message),
                },
            },
            ProviderError::HttpError(e) => {
                RequestError::Internal(anyhow::Error::new(e).context("HTTP request failed"))
            }
            ProviderError::SerializationError(e) => {
                RequestError::ParseError(format!("serialization failed: {}", e))
            }
            ProviderError::ModelNotSupported(model) => RequestError::RoutingError(format!(
                "Model '{}' is not configured. Add a [[models]] entry or set pass_through = true on a provider.",
                model
            )),
            ProviderError::ConfigError(msg) => {
                RequestError::Internal(anyhow::anyhow!("Provider config error: {}", msg))
            }
            ProviderError::AuthError(msg) => RequestError::AuthRevoked(msg),
            ProviderError::NoProviderAvailable => {
                RequestError::RoutingError("No provider available for this request".to_string())
            }
            ProviderError::AllProvidersFailed(msg) => RequestError::ProviderUpstream {
                provider: "all".to_string(),
                status: 502,
                body: Some(msg),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extracts status code and parsed JSON body from a `RequestError` response.
    async fn error_response_parts(error: RequestError) -> (StatusCode, serde_json::Value) {
        let response = error.into_response();
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("invariant: in-memory body collection cannot fail");
        let json: serde_json::Value = serde_json::from_slice(&body_bytes)
            .expect("invariant: RequestError always produces valid JSON");
        (status, json)
    }

    #[tokio::test]
    async fn parse_error_returns_400_with_invalid_request_type() {
        let err = RequestError::ParseError("invalid JSON at line 1".to_string());
        let (status, json) = error_response_parts(err).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["type"], "invalid_request_error");
        assert_eq!(json["error"]["message"], "invalid JSON at line 1");
    }

    #[tokio::test]
    async fn bad_request_returns_400() {
        let err = RequestError::BadRequest("missing required field 'model'".to_string());
        let (status, json) = error_response_parts(err).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["type"], "invalid_request_error");
    }

    #[tokio::test]
    async fn unauthorized_returns_401() {
        let err = RequestError::Unauthorized;
        let (status, json) = error_response_parts(err).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"]["type"], "authentication_error");
    }

    #[tokio::test]
    async fn forbidden_returns_403() {
        let err = RequestError::Forbidden("policy denies model access".to_string());
        let (status, json) = error_response_parts(err).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json["error"]["type"], "permission_error");
    }

    #[tokio::test]
    async fn not_found_returns_404() {
        let err = RequestError::NotFound;
        let (status, _) = error_response_parts(err).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn routing_error_returns_400_with_error_type() {
        let err = RequestError::RoutingError("no matching model: gpt-unknown".to_string());
        let (status, json) = error_response_parts(err).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["type"], "error");
        assert_eq!(json["error"]["message"], "no matching model: gpt-unknown");
    }

    #[tokio::test]
    async fn rate_limited_returns_429_with_retry_after() {
        let err = RequestError::RateLimited {
            provider: "anthropic".to_string(),
            retry_after_ms: Some(2500),
        };
        let response = err.into_response();
        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json["error"]["type"], "rate_limit_error");
        assert_eq!(json["error"]["provider"], "anthropic");
        assert_eq!(json["error"]["retry_after_ms"], 2500);
        // 2500ms rounds up to 3 seconds.
        assert_eq!(retry_after.as_deref(), Some("3"));
    }

    #[tokio::test]
    async fn provider_upstream_502_forwards_status() {
        let err = RequestError::ProviderUpstream {
            provider: "openai".to_string(),
            status: 502,
            body: Some("upstream gateway timeout".to_string()),
        };
        let (status, json) = error_response_parts(err).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(json["error"]["upstream_status"], 502);
        assert_eq!(json["error"]["provider"], "openai");
    }

    #[tokio::test]
    async fn provider_upstream_503_forwards_status() {
        let err = RequestError::ProviderUpstream {
            provider: "openai".to_string(),
            status: 503,
            body: None,
        };
        let (status, _) = error_response_parts(err).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn budget_exceeded_returns_402_with_figures() {
        let err = RequestError::BudgetExceeded {
            limit_usd: 100.0,
            actual_usd: 105.5,
        };
        let (status, json) = error_response_parts(err).await;

        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(json["error"]["type"], "budget_exceeded");
        assert_eq!(json["error"]["limit_usd"], 100.0);
        assert_eq!(json["error"]["actual_usd"], 105.5);
    }

    #[tokio::test]
    async fn dlp_blocked_returns_400_with_dlp_block_type() {
        let err = RequestError::DlpBlocked("secret detected in prompt".to_string());
        let (status, json) = error_response_parts(err).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["type"], "dlp_block");
        assert_eq!(json["error"]["message"], "secret detected in prompt");
    }

    #[tokio::test]
    async fn auth_revoked_returns_401() {
        let err = RequestError::AuthRevoked(
            "OAuth token for provider 'anthropic' revoked. Run: grob connect --force-reauth"
                .to_string(),
        );
        let (status, json) = error_response_parts(err).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"]["type"], "authentication_error");
        assert!(json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("grob connect --force-reauth"));
    }

    #[tokio::test]
    async fn internal_returns_500() {
        let err = RequestError::Internal(anyhow::anyhow!("disk full"));
        let (status, _) = error_response_parts(err).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── is_retryable() table-driven tests ──

    #[test]
    fn rate_limited_is_retryable() {
        let err = RequestError::RateLimited {
            provider: "x".to_string(),
            retry_after_ms: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn upstream_500_is_retryable() {
        let err = RequestError::ProviderUpstream {
            provider: "x".to_string(),
            status: 500,
            body: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn upstream_502_is_retryable() {
        let err = RequestError::ProviderUpstream {
            provider: "x".to_string(),
            status: 502,
            body: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn upstream_503_is_retryable() {
        let err = RequestError::ProviderUpstream {
            provider: "x".to_string(),
            status: 503,
            body: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn upstream_504_is_retryable() {
        let err = RequestError::ProviderUpstream {
            provider: "x".to_string(),
            status: 504,
            body: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn upstream_429_is_retryable() {
        let err = RequestError::ProviderUpstream {
            provider: "x".to_string(),
            status: 429,
            body: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn upstream_400_is_not_retryable() {
        let err = RequestError::ProviderUpstream {
            provider: "x".to_string(),
            status: 400,
            body: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn upstream_401_is_not_retryable() {
        let err = RequestError::ProviderUpstream {
            provider: "x".to_string(),
            status: 401,
            body: None,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn auth_revoked_is_not_retryable() {
        let err = RequestError::AuthRevoked("revoked".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn unauthorized_is_not_retryable() {
        let err = RequestError::Unauthorized;
        assert!(!err.is_retryable());
    }

    #[test]
    fn forbidden_is_not_retryable() {
        let err = RequestError::Forbidden("nope".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn parse_error_is_not_retryable() {
        let err = RequestError::ParseError("bad".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn routing_error_is_not_retryable() {
        let err = RequestError::RoutingError("no model".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn budget_exceeded_is_not_retryable() {
        let err = RequestError::BudgetExceeded {
            limit_usd: 100.0,
            actual_usd: 200.0,
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn dlp_blocked_is_not_retryable() {
        let err = RequestError::DlpBlocked("secret".to_string());
        assert!(!err.is_retryable());
    }

    #[test]
    fn internal_without_reqwest_is_not_retryable() {
        let err = RequestError::Internal(anyhow::anyhow!("logic bug"));
        assert!(!err.is_retryable());
    }

    #[test]
    fn variant_tags_are_stable() {
        assert_eq!(
            RequestError::BadRequest("x".to_string()).variant_tag(),
            "bad_request"
        );
        assert_eq!(RequestError::Unauthorized.variant_tag(), "unauthorized");
        assert_eq!(
            RequestError::Forbidden("x".to_string()).variant_tag(),
            "forbidden"
        );
        assert_eq!(RequestError::NotFound.variant_tag(), "not_found");
        assert_eq!(
            RequestError::ParseError("x".to_string()).variant_tag(),
            "parse_error"
        );
        assert_eq!(
            RequestError::RoutingError("x".to_string()).variant_tag(),
            "routing_error"
        );
        assert_eq!(
            RequestError::RateLimited {
                provider: "x".to_string(),
                retry_after_ms: None
            }
            .variant_tag(),
            "rate_limited"
        );
        assert_eq!(
            RequestError::ProviderUpstream {
                provider: "x".to_string(),
                status: 502,
                body: None
            }
            .variant_tag(),
            "provider_upstream"
        );
        assert_eq!(
            RequestError::BudgetExceeded {
                limit_usd: 1.0,
                actual_usd: 2.0,
            }
            .variant_tag(),
            "budget_exceeded"
        );
        assert_eq!(
            RequestError::DlpBlocked("x".to_string()).variant_tag(),
            "dlp_blocked"
        );
        assert_eq!(
            RequestError::AuthRevoked("x".to_string()).variant_tag(),
            "auth_revoked"
        );
        assert_eq!(
            RequestError::Internal(anyhow::anyhow!("x")).variant_tag(),
            "internal"
        );
    }

    #[test]
    fn provider_error_429_converts_to_rate_limited() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 429,
            message: "slow down".to_string(),
        };
        let req_err: RequestError = err.into();
        assert!(matches!(req_err, RequestError::RateLimited { .. }));
        assert!(req_err.is_retryable());
    }

    #[test]
    fn provider_error_500_converts_to_upstream() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 500,
            message: "boom".to_string(),
        };
        let req_err: RequestError = err.into();
        match &req_err {
            RequestError::ProviderUpstream { status, .. } => assert_eq!(*status, 500),
            other => panic!("unexpected variant: {:?}", other),
        }
        assert!(req_err.is_retryable());
    }

    #[test]
    fn provider_error_401_with_rate_limit_payload_converts_to_rate_limited() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 401,
            message: r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow"}}"#
                .to_string(),
        };
        let req_err: RequestError = err.into();
        assert!(matches!(req_err, RequestError::RateLimited { .. }));
    }

    #[test]
    fn provider_error_401_authentication_converts_to_auth_revoked() {
        let err = crate::providers::error::ProviderError::ApiError {
            status: 401,
            message: r#"{"type":"error","error":{"type":"authentication_error","message":"bad"}}"#
                .to_string(),
        };
        let req_err: RequestError = err.into();
        assert!(matches!(req_err, RequestError::AuthRevoked(_)));
        assert!(!req_err.is_retryable());
    }

    #[test]
    fn display_includes_variant_tag() {
        let err = RequestError::ParseError("bad input".to_string());
        let s = err.to_string();
        assert!(s.contains("parse_error"));
        assert!(s.contains("bad input"));
    }
}
