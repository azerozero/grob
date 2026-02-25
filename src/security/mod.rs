//! Security module for Grob
//! Implements HDS/PCI DSS/SecNumCloud compliance features

pub mod audit_log;
pub mod cache;
pub mod circuit_breaker;
pub mod encryption;
pub mod headers;
pub mod integration;
pub mod rate_limit;
pub mod schema_validate;

// Re-export commonly used types
pub use audit_log::{AuditEntry, AuditEntryBuilder, AuditEvent, AuditLog, Classification};
pub use cache::{
    jwt_validation_cache, rate_limit_cache, JwtCacheEntry, JwtValidationCache, ProviderMetadata,
    ProviderMetadataCache,
};
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, CircuitBreakerRegistry, CircuitState,
};
pub use encryption::{EncryptedEnvelope, EncryptionService, KmsProvider, LocalKms, Perimeter};
pub use headers::{
    apply_security_headers, build_cors_headers, security_headers_middleware, CorsConfig,
    SecurityHeadersConfig,
};
pub use rate_limit::{RateLimitConfig, RateLimitKey, RateLimiter};
pub use schema_validate::{
    strict_validation_middleware, validate_url, StrictValidator, ValidationError, MAX_BODY_SIZE,
};
