//! Grob: multi-provider LLM routing proxy with automatic fallback and format translation.

// NOTE: deny (not forbid) so that the few justified unsafe blocks can #[allow].
#![deny(unsafe_code)]

use std::path::PathBuf;

/// Returns the Grob home directory (`~/.grob`).
///
/// When the `dirs` feature is disabled, falls back to reading `GROB_HOME`
/// from the environment. With `dirs` enabled it uses `dirs::home_dir()` but
/// still honours `GROB_HOME` if set (useful for containers).
pub fn grob_home() -> Option<PathBuf> {
    if let Ok(val) = std::env::var("GROB_HOME") {
        return Some(PathBuf::from(val));
    }

    #[cfg(feature = "dirs")]
    {
        dirs::home_dir().map(|h| h.join(".grob"))
    }

    #[cfg(not(feature = "dirs"))]
    {
        None
    }
}

/// Returns the user home directory.
///
/// Honours `GROB_HOME`'s parent when set; otherwise delegates to
/// `dirs::home_dir()` (requires the `dirs` feature).
pub fn home_dir() -> Option<PathBuf> {
    if let Ok(val) = std::env::var("GROB_HOME") {
        // GROB_HOME typically points to ~/.grob — parent is home
        return PathBuf::from(val).parent().map(|p| p.to_path_buf());
    }

    #[cfg(feature = "dirs")]
    {
        dirs::home_dir()
    }

    #[cfg(not(feature = "dirs"))]
    {
        None
    }
}

/// Expand a leading `~` to the user home directory.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

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
/// OpenTelemetry distributed tracing export.
pub mod otel;
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
