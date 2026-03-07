//! Grob: multi-provider LLM routing proxy with automatic fallback and format translation.

/// Automatic TLS certificate provisioning via ACME.
#[cfg(feature = "acme")]
pub mod acme;
/// Authentication: JWT validation, OAuth flows, and token storage.
pub mod auth;
/// LLM response caching for deterministic requests.
pub mod cache;
/// Configuration structs and CLI argument parsing.
pub mod cli;
/// CLI command implementations (start, stop, exec, doctor, etc.).
pub mod commands;
/// Optional features: DLP, MCP, TAP, token pricing.
pub mod features;
/// Server instance lifecycle management.
pub mod instance;
/// Request/response message tracing utilities.
pub mod message_tracing;
/// Shared data models (requests, responses, routing).
pub mod models;
/// Network utilities and port management.
pub mod net;
/// PID file management for daemon mode.
pub mod pid;
/// Preset management: builtin/installed presets and apply/export.
pub mod preset;
/// LLM provider implementations and registry.
pub mod providers;
/// Request routing engine with regex-based rules.
pub mod router;
/// Security: rate limiting, circuit breakers, audit, headers.
pub mod security;
/// Axum HTTP server, middleware, and application state.
pub mod server;
/// Unified redb storage backend.
pub mod storage;
/// Core trait contracts for the dispatch pipeline.
pub mod traits;
