use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Application error types — all variants carry a user-facing message string.
#[derive(Debug)]
pub enum AppError {
    /// Indicates no matching route or model for the request.
    RoutingError(String),
    /// Indicates a malformed or invalid request payload.
    ParseError(String),
    /// Indicates an upstream provider returned an error.
    ProviderError(String),
    /// Indicates the monthly spend budget has been exceeded.
    BudgetExceeded(String),
    /// Indicates the DLP pipeline blocked the request.
    DlpBlocked(String),
    /// Indicates an upstream OAuth token is revoked or invalid (401 authentication_error).
    ///
    /// Surfaced to the client as a terminal 401 without fallback to sibling providers.
    AuthenticationError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match self {
            AppError::RoutingError(msg) => (StatusCode::BAD_REQUEST, "error", msg),
            AppError::ParseError(msg) => (StatusCode::BAD_REQUEST, "invalid_request_error", msg),
            AppError::ProviderError(msg) => (StatusCode::BAD_GATEWAY, "error", msg),
            AppError::BudgetExceeded(msg) => (StatusCode::PAYMENT_REQUIRED, "budget_exceeded", msg),
            AppError::DlpBlocked(msg) => (StatusCode::BAD_REQUEST, "dlp_block", msg),
            AppError::AuthenticationError(msg) => {
                (StatusCode::UNAUTHORIZED, "authentication_error", msg)
            }
        };

        let body = Json(serde_json::json!({
            "error": {
                "type": error_type,
                "message": message
            }
        }));

        (status, body).into_response()
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::RoutingError(msg) => write!(f, "Routing error: {}", msg),
            AppError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            AppError::ProviderError(msg) => write!(f, "Provider error: {}", msg),
            AppError::BudgetExceeded(msg) => write!(f, "Budget exceeded: {}", msg),
            AppError::DlpBlocked(msg) => write!(f, "DLP blocked: {}", msg),
            AppError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extracts status code and parsed JSON body from an AppError response.
    async fn error_response_parts(error: AppError) -> (StatusCode, serde_json::Value) {
        let response = error.into_response();
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("invariant: in-memory body collection cannot fail");
        let json: serde_json::Value = serde_json::from_slice(&body_bytes)
            .expect("invariant: AppError always produces valid JSON");
        (status, json)
    }

    #[tokio::test]
    async fn parse_error_returns_400_with_invalid_request_type() {
        let err = AppError::ParseError("invalid JSON at line 1".to_string());
        let (status, json) = error_response_parts(err).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["type"], "invalid_request_error");
        assert_eq!(json["error"]["message"], "invalid JSON at line 1");
    }

    #[tokio::test]
    async fn routing_error_returns_400_with_error_type() {
        let err = AppError::RoutingError("no matching model: gpt-unknown".to_string());
        let (status, json) = error_response_parts(err).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["type"], "error");
        assert_eq!(json["error"]["message"], "no matching model: gpt-unknown");
    }

    #[tokio::test]
    async fn provider_error_returns_502() {
        let err = AppError::ProviderError("upstream timeout".to_string());
        let (status, json) = error_response_parts(err).await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(json["error"]["type"], "error");
        assert_eq!(json["error"]["message"], "upstream timeout");
    }

    #[tokio::test]
    async fn budget_exceeded_returns_402() {
        let err = AppError::BudgetExceeded("monthly limit reached".to_string());
        let (status, json) = error_response_parts(err).await;

        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(json["error"]["type"], "budget_exceeded");
        assert_eq!(json["error"]["message"], "monthly limit reached");
    }

    #[tokio::test]
    async fn dlp_blocked_returns_400_with_dlp_block_type() {
        let err = AppError::DlpBlocked("secret detected in prompt".to_string());
        let (status, json) = error_response_parts(err).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["type"], "dlp_block");
        assert_eq!(json["error"]["message"], "secret detected in prompt");
    }

    #[tokio::test]
    async fn authentication_error_returns_401_with_authentication_error_type() {
        let err = AppError::AuthenticationError(
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

    #[test]
    fn display_impl_includes_variant_prefix() {
        let err = AppError::ParseError("bad input".to_string());
        assert_eq!(err.to_string(), "Parse error: bad input");

        let err = AppError::RoutingError("no route".to_string());
        assert_eq!(err.to_string(), "Routing error: no route");
    }
}
