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

    /// Requested model is not supported by the provider.
    #[error("Model not supported by provider: {0}")]
    ModelNotSupported(String),

    /// Upstream provider returned a non-success HTTP status.
    #[error("Provider API error: {status} - {message}")]
    ApiError {
        /// HTTP status code returned by the provider.
        status: u16,
        /// Error message from the provider response.
        message: String,
    },

    /// Provider configuration is invalid or incomplete.
    #[error("Configuration error: {0}")]
    ConfigError(String),

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
