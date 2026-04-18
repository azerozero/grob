//! Routing primitives for the Grob dispatch pipeline (RE phase, ADR-0018).
//!
//! This module hosts the nature-inspired routing primitives defined by
//! [ADR-0018](../../../docs/decisions/0018-nature-inspired-routing.md). The
//! primitives are **opt-in** and **independent** — each adds one concern at a
//! time on top of the existing provider loop:
//!
//! - [`circuit_breaker`] — RE-1a passive circuit breaker (Caddy-style
//!   `max_fails` + `fail_duration`). Per-endpoint (provider + model pair),
//!   lock-free hot path, tokio-driven failure decay. Off by default.
//!
//! Future phases (tracked in ADR-0018):
//!
//! - RE-1b active health checks.
//! - RE-1c cooldown + half-open probes.
//! - RE-2 EMA stats per endpoint.
//! - RE-3 hedged requests.
//! - RE-4 Thompson sampling bandit.

/// Passive per-endpoint circuit breaker (RE-1a, Caddy-style).
pub mod circuit_breaker;

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, EndpointId};
