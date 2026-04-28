//! Rate-limit detection and decision helpers.
//!
//! Centralises the 429-handling logic that was previously duplicated across
//! three call sites in [`super::retry`]. Provider error variants (429, 529,
//! Anthropic-specific 401-with-`rate_limit_error` payload) now flow through a
//! single [`RateLimitHandler`] implementation, so adding a new upstream
//! variant means touching one match arm instead of three.
//!
//! # Examples
//!
//! ```ignore
//! use crate::providers::error::ProviderError;
//! use crate::server::dispatch::rate_limit::RateLimitHandler;
//!
//! let err = ProviderError::ApiError { status: 429, message: "slow".into() };
//! assert!(err.is_rate_limit());
//! ```
//!
//! See `src/server/budget.rs::is_rate_limit_payload` for the 401-with-rate-limit
//! payload heuristic this trait reuses.

use crate::providers::error::ProviderError;

/// Upstream-agnostic rate-limit decision surface for a single provider attempt.
///
/// Implemented for [`ProviderError`] in this module. Replaces three inline
/// `matches!(e, ProviderError::ApiError { status: 429, .. })` checks in the
/// retry path with a single `err.is_rate_limit()` call so future provider
/// variants (e.g. 529, Anthropic 401-`rate_limit_error`) can be wired in
/// one place.
pub(crate) trait RateLimitHandler {
    /// Returns `true` when this error should be treated as a rate-limit signal.
    ///
    /// Recognised variants:
    ///
    /// - HTTP 429 (canonical "Too Many Requests")
    /// - HTTP 529 (Anthropic-specific "Overloaded")
    /// - HTTP 401 carrying an Anthropic `rate_limit_error` payload
    fn is_rate_limit(&self) -> bool;

    /// Returns the upstream-suggested cool-down in milliseconds, when
    /// available.
    ///
    /// The current `ProviderError` shape does not retain the upstream
    /// `Retry-After` header, so the default is `None`. The retry loop falls
    /// back to its own exponential-backoff schedule. The hook exists so that
    /// when [`ProviderError::ApiError`] grows headers (post unified-error
    /// refactor) the retry loop can consume them through the same trait.
    #[allow(dead_code)]
    fn retry_after_ms(&self) -> Option<u64> {
        None
    }
}

impl RateLimitHandler for ProviderError {
    fn is_rate_limit(&self) -> bool {
        match self {
            ProviderError::ApiError { status, message } => match status {
                429 | 529 => true,
                401 => super::super::budget::is_rate_limit_payload(message),
                _ => false,
            },
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_429_is_rate_limit() {
        let err = ProviderError::ApiError {
            status: 429,
            message: "Too Many Requests".into(),
        };
        assert!(err.is_rate_limit());
    }

    #[test]
    fn anthropic_529_overloaded_is_rate_limit() {
        let err = ProviderError::ApiError {
            status: 529,
            message: "overloaded_error".into(),
        };
        assert!(err.is_rate_limit());
    }

    #[test]
    fn anthropic_401_with_rate_limit_payload_is_rate_limit() {
        let err = ProviderError::ApiError {
            status: 401,
            message: r#"{"type":"error","error":{"type":"rate_limit_error","message":"slow"}}"#
                .into(),
        };
        assert!(err.is_rate_limit());
    }

    #[test]
    fn openai_429_is_rate_limit() {
        let err = ProviderError::ApiError {
            status: 429,
            message: r#"{"error":{"code":"rate_limit_exceeded"}}"#.into(),
        };
        assert!(err.is_rate_limit());
    }

    #[test]
    fn deepseek_429_is_rate_limit() {
        let err = ProviderError::ApiError {
            status: 429,
            message: "Rate limit reached for deepseek-chat".into(),
        };
        assert!(err.is_rate_limit());
    }

    #[test]
    fn openrouter_5xx_is_not_rate_limit() {
        let err = ProviderError::ApiError {
            status: 503,
            message: "service unavailable".into(),
        };
        assert!(!err.is_rate_limit());
    }

    #[test]
    fn auth_401_is_not_rate_limit() {
        let err = ProviderError::ApiError {
            status: 401,
            message: r#"{"type":"error","error":{"type":"authentication_error"}}"#.into(),
        };
        assert!(!err.is_rate_limit());
    }

    #[test]
    fn http_error_is_not_rate_limit() {
        let err = ProviderError::AuthError("token expired".into());
        assert!(!err.is_rate_limit());
    }

    #[test]
    fn retry_after_ms_default_is_none() {
        let err = ProviderError::ApiError {
            status: 429,
            message: "rate limited".into(),
        };
        assert_eq!(err.retry_after_ms(), None);
    }
}
