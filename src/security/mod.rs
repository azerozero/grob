//! Security module for Grob
//! Implements HDS/PCI DSS/SecNumCloud/EU AI Act compliance features

pub mod audit_log;
pub mod audit_signer;
pub mod cache;
pub mod circuit_breaker;
pub mod fips;
pub mod headers;
pub mod merkle;
pub mod provider_scorer;
pub mod rate_limit;
pub mod risk;
pub mod tee;
pub mod tool_spike;

// Re-exports used by server/mod.rs and other modules
pub use audit_log::AuditLog;
pub use circuit_breaker::{CircuitBreakerRegistry, CircuitState};
pub use fips::FipsStatus;
pub use headers::{apply_security_headers, SecurityHeadersConfig};
pub use rate_limit::{RateLimitConfig, RateLimitKey, RateLimiter};
pub use tee::TeeStatus;
pub use tool_spike::{SpikeAction, ToolSpikeConfig, ToolSpikeDetector};
