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

/// Returns the user home directory, honouring `GROB_HOME`'s parent as an override.
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

/// Expands a leading `~` to the user home directory.
///
/// # Examples
///
/// ```
/// use grob::expand_tilde;
///
/// // Absolute paths pass through unchanged.
/// assert_eq!(grob::expand_tilde("/etc/grob.toml").to_str().unwrap(), "/etc/grob.toml");
///
/// // Non-tilde relative paths pass through unchanged.
/// assert_eq!(grob::expand_tilde("relative/path").to_str().unwrap(), "relative/path");
/// ```
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

/// Authentication: JWT validation, OAuth flows, and token storage.
pub mod auth;
/// LLM response caching for deterministic requests.
pub mod cache;
/// Configuration structs and CLI argument parsing.
pub mod cli;
/// CLI command implementations (start, stop, exec, doctor, etc.).
pub mod commands;
/// Generic control engine for unified CLI / MCP / UI dispatch.
pub mod control;
/// Optional features: DLP, MCP, TAP, token pricing.
pub mod features;
/// Shared data models (requests, responses, routing).
pub mod models;
/// Preset management: builtin/installed presets and apply/export.
pub mod preset;
/// Static model pricing lookup (leaf module, no cross-module dependencies).
///
/// INTENTIONALLY a top-level module (not under `shared/`): both
/// `providers::streaming` and `features::token_pricing` import from here, and
/// keeping it as a leaf at the crate root breaks an otherwise circular
/// dependency between those two modules.
pub mod pricing;
/// LLM provider implementations and registry.
pub mod providers;
/// Request routing (classification engine + nature-inspired primitives).
///
/// Hosts the request classification engine under [`routing::classify`] plus
/// the nature-inspired primitives defined by ADR-0018 (circuit breaker,
/// health check, future EMA stats / hedging / bandit).
pub mod routing;
/// Security: rate limiting, circuit breakers, audit, headers.
pub mod security;
/// Axum HTTP server, middleware, and application state.
pub mod server;
/// Cross-cutting modules shared across vertical slices.
///
/// Hosts small, low-coupling modules used by multiple features but that do
/// not themselves define a feature slice: ACME TLS, instance coordination,
/// message tracing, network binding, OTel, PID file.
pub mod shared;
/// Persistent storage (atomic files + append-only journals).
pub mod storage;
/// Core trait contracts for the dispatch pipeline.
pub mod traits;
