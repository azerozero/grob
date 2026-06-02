//! Routing primitives for the Grob dispatch pipeline.
//!
//! This module unifies two concerns that previously lived in separate top-level
//! modules:
//!
//! - [`classify`] — request classification engine (regex prompt rules, tier
//!   matching, auto-map, complexity classifier). Previously at
//!   `crate::router`; merged here as part of the vertical-slice foundation
//!   (audit item #12).
//! - Nature-inspired primitives from [ADR-0018][adr]:
//!   - [`circuit_breaker`] — RE-1a passive circuit breaker (Caddy-style
//!     `max_fails` + `fail_duration`). Per-endpoint (provider + model pair),
//!     lock-free hot path, tokio-driven failure decay. Off by default.
//!   - [`health_check`] — RE-1b active health checks (Caddy-style
//!     `health_uri` / `health_interval` / `health_timeout` / `health_status`).
//!     Per-provider background probe. Off by default.
//!
//! Future phases (tracked in ADR-0018):
//!
//! - RE-1c cooldown + half-open probes.
//! - RE-2 provider scoring v1 (implemented in `security::provider_scorer`);
//!   endpoint-level EMA is deferred until ADR-0022 migration.
//! - RE-3 hedged requests.
//! - RE-4 Thompson sampling bandit (rejected/deferred).
//!
//! [adr]: ../../../docs/decisions/0018-nature-inspired-routing.md

/// Request classification engine (prompt rules, tier matching, auto-map).
pub mod classify;

/// Passive per-endpoint circuit breaker (RE-1a, Caddy-style).
pub mod circuit_breaker;

/// Read-only endpoint-shaped adapter derived from legacy config (ADR-0022 phase 0).
pub mod endpoints;

/// Active per-provider health checker (RE-1b, Caddy-style).
pub mod health_check;

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, EndpointId};
pub use endpoints::{
    DerivedEndpoint, DerivedPolicy, EndpointInventory, EndpointModel, EndpointSource, PolicySource,
};
pub use health_check::{HealthCheckConfig, HealthChecker, HealthStatus, StatusMatcher};
