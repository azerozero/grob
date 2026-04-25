//! Static TOML configuration structs for grob.
//!
//! Each submodule owns a domain-specific section of the `grob.toml` schema:
//!
//! | Module | Scope |
//! |--------|-------|
//! | [`budget`] | Monthly spend caps |
//! | [`cache`] | LLM response cache |
//! | [`security`] | Rate limits, audit log, compliance, TEE, FIPS |
//! | [`server`] | HTTP server, timeouts, TLS, ACME |
//! | [`telemetry`] | Message tracing, OpenTelemetry export |
//! | [`user`] | Preserved user section, preset selection |
//! | [`routing`] | Router rules, model mappings, fan-out, tiers, project overlays |
//! | [`providers`] | Provider definitions, auth, key pools |
//! | [`reliability`] | Circuit breaker and health check TOML views (`parse_duration`) |
//! | [`harness`] | Record-and-replay harness (opt-in) |
//!
//! All public types are re-exported at the crate root of [`crate::cli`] for
//! backwards compatibility with existing call sites.

pub mod budget;
pub mod cache;
#[cfg(feature = "harness")]
pub mod harness;
pub mod providers;
pub mod reliability;
pub mod routing;
pub mod secrets;
pub mod security;
pub mod server;
pub mod telemetry;
pub mod user;

pub use budget::BudgetConfig;
pub use cache::CacheConfig;
#[cfg(feature = "harness")]
pub use harness::HarnessConfig;
pub use providers::{AuthType, PoolConfig, PoolStrategy, ProviderConfig};
pub use reliability::{parse_duration, CircuitBreakerProviderConfig, HealthCheckProviderConfig};
pub use routing::{
    FanOutConfig, FanOutMode, ModelConfig, ModelMapping, ModelStrategy, ProjectConfig,
    ProjectRouterOverlay, PromptRule, RouterConfig, TierConfig, TierMatchCondition,
};
pub use secrets::{SecretsBackend, SecretsConfig, SecretsFileConfig};
pub use security::{ComplianceConfig, EnforcementMode, FipsConfig, SecurityConfig, TeeConfig};
pub use server::{AcmeConfig, ServerConfig, TimeoutConfig, TlsConfig};
pub use telemetry::{OtelConfig, TracingConfig};
pub use user::{PresetConfig, UserConfig};

// Shared across security.rs and telemetry.rs (any serde `default = "..."`
// path must resolve from the submodule's `super::`).
pub(crate) fn default_true() -> bool {
    true
}
