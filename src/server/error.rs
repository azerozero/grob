use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Application error types — all variants carry a user-facing message string.
#[derive(Debug)]
pub enum AppError {
    RoutingError(String),
    ParseError(String),
    ProviderError(String),
    BudgetExceeded(String),
    DlpBlocked(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match self {
            AppError::RoutingError(msg) => (StatusCode::BAD_REQUEST, "error", msg),
            AppError::ParseError(msg) => (StatusCode::BAD_REQUEST, "invalid_request_error", msg),
            AppError::ProviderError(msg) => (StatusCode::BAD_GATEWAY, "error", msg),
            AppError::BudgetExceeded(msg) => (StatusCode::PAYMENT_REQUIRED, "budget_exceeded", msg),
            AppError::DlpBlocked(msg) => (StatusCode::BAD_REQUEST, "dlp_block", msg),
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
        }
    }
}

impl std::error::Error for AppError {}
