//! Security module for Grob
//! Implements HDS/PCI DSS/SecNumCloud compliance features

pub mod audit_log;
pub mod cache;
pub mod circuit_breaker;
pub mod headers;
pub mod rate_limit;

// Re-exports used by server/mod.rs and other modules
pub use audit_log::AuditLog;
pub use circuit_breaker::{CircuitBreakerRegistry, CircuitState};
pub use headers::{apply_security_headers, SecurityHeadersConfig};
pub use rate_limit::{RateLimitConfig, RateLimitKey, RateLimiter};
