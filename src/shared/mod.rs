//! Cross-cutting modules shared across vertical slices.
//!
//! Hosts small, low-coupling modules that are used by multiple features but
//! do not themselves define a feature slice. Moved here as part of the
//! vertical-slice foundation (audit item #35) so that `src/` root only
//! contains genuinely top-level concerns (entry point, lib contract, core
//! traits).
//!
//! Contents:
//!
//! - [`acme`] — Automatic TLS certificate provisioning via ACME (feature-gated).
//! - [`instance`] — Multi-instance coordination (PID + port probing).
//! - [`message_tracing`] — Request/response trace pipeline (JSONL with rotation).
//! - [`net`] — Network binding helpers (SO_REUSEPORT for zero-downtime upgrades).
//! - [`otel`] — OpenTelemetry subscriber bootstrap.
//! - [`pid`] — PID file management for daemon mode.

/// Automatic TLS certificate provisioning via ACME.
#[cfg(feature = "acme")]
pub mod acme;

/// Server instance lifecycle helpers (PID + port probing).
pub mod instance;

/// Request/response message tracing utilities.
pub mod message_tracing;

/// Network utilities and port management.
pub mod net;

/// OpenTelemetry distributed tracing export.
pub mod otel;

/// PID file management for daemon mode.
pub mod pid;
