//! Provider-level error types.
//!
//! This is a thin `thiserror` enum with no behavior of its own; its retry and
//! HTTP-status semantics are exercised through the conversion and classification
//! tests in [`crate::server::error`] and [`crate::server::budget`].

use thiserror::Error;

/// Provider-specific errors
#[derive(Error, Debug)]
pub enum ProviderError {
    /// HTTP request to the upstream provider failed.
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// JSON serialization or deserialization failed.
    #[error("JSON serialization failed: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Requested model is not configured in any provider.
    #[error("Model '{0}' is not configured. Add a [[models]] entry or set pass_through = true on a provider.")]
    ModelNotSupported(String),

    /// Upstream provider returned a non-success HTTP status.
    #[error("Provider API error: {status} - {message}")]
    ApiError {
        /// HTTP status code returned by the provider.
        status: u16,
        /// Error message from the provider response.
        message: String,
    },

    /// Provider returned a syntactically successful response that Grob cannot
    /// translate safely.
    #[error("Provider protocol error: {0}")]
    ProtocolError(String),

    /// Provider configuration is invalid or incomplete.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// The caller supplied a request this provider cannot translate safely.
    #[error("Invalid provider request: {0}")]
    InvalidRequest(String),

    /// Authentication with the upstream provider failed.
    #[error("Authentication error: {0}")]
    AuthError(String),

    /// No provider is configured or available for the request.
    #[error("No provider available for this request")]
    NoProviderAvailable,

    /// All configured providers failed for the request.
    #[error("All providers failed: {0}")]
    AllProvidersFailed(String),
}

/// Returns true when an upstream error message is a context-window overflow.
///
/// Some OpenAI-compatible gateways surface Responses API terminal failures as
/// `response.failed` inside an otherwise successful HTTP/SSE exchange. Treating
/// that as a protocol failure turns a user-fixable oversized prompt into a
/// misleading 502, so centralize the phrase matching here for provider and
/// server-side error mapping.
pub(crate) fn is_context_window_exceeded_message(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("context_length_exceeded")
        || normalized.contains("exceeds the context window")
        || normalized.contains("exceeded the context window")
        || normalized.contains("exceeds context window")
        || normalized.contains("context window of this model")
        || normalized.contains("maximum context length")
}
