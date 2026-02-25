use thiserror::Error;

/// Provider-specific errors
#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON serialization failed: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Model not supported by provider: {0}")]
    ModelNotSupported(String),

    #[error("Provider API error: {status} - {message}")]
    ApiError { status: u16, message: String },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Authentication error: {0}")]
    AuthError(String),

    #[error("No provider available for this request")]
    NoProviderAvailable,

    #[error("All providers failed: {0}")]
    AllProvidersFailed(String),
}
