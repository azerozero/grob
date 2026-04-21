//! Passive circuit breaker and active health check TOML views, plus
//! [`parse_duration`] for the `"<n><unit>"` strings they accept.
//!
//! These are the TOML-facing mirrors of the runtime types in
//! [`crate::routing`]. Each TOML struct exposes a `to_runtime()` helper that
//! translates duration strings into [`std::time::Duration`] and constructs the
//! runtime configuration.

use serde::{Deserialize, Serialize};

/// Parses a duration string used across provider TOML knobs.
///
/// Accepts `"<int|float><unit>"` where unit is one of `ms`, `s`, `m`, `h`.
/// Bare integers are treated as seconds for convenience.
///
/// # Errors
///
/// Returns a descriptive error string when the input is unparseable.
///
/// # Examples
///
/// ```
/// use grob::cli::parse_duration;
/// use std::time::Duration;
///
/// assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
/// assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
/// assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
/// ```
pub fn parse_duration(input: &str) -> Result<std::time::Duration, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty duration".to_string());
    }

    // Suffix-aware parse.
    let parse_number = |s: &str| -> Result<f64, String> {
        s.parse::<f64>()
            .map_err(|_| format!("invalid duration number '{s}'"))
    };

    if let Some(rest) = trimmed.strip_suffix("ms") {
        let n = parse_number(rest)?;
        return Ok(std::time::Duration::from_millis(n as u64));
    }
    if let Some(rest) = trimmed.strip_suffix('s') {
        let n = parse_number(rest)?;
        return Ok(std::time::Duration::from_secs_f64(n));
    }
    if let Some(rest) = trimmed.strip_suffix('m') {
        let n = parse_number(rest)?;
        return Ok(std::time::Duration::from_secs_f64(n * 60.0));
    }
    if let Some(rest) = trimmed.strip_suffix('h') {
        let n = parse_number(rest)?;
        return Ok(std::time::Duration::from_secs_f64(n * 3600.0));
    }
    // Bare integer -> seconds (lenient).
    if let Ok(n) = trimmed.parse::<u64>() {
        return Ok(std::time::Duration::from_secs(n));
    }
    Err(format!(
        "unknown duration '{input}' (expected suffix ms|s|m|h)"
    ))
}

/// Passive circuit breaker knobs exposed through `[providers.circuit_breaker]`.
///
/// Mirror of [`crate::routing::CircuitBreakerConfig`] with TOML-friendly
/// duration strings (`"30s"`, `"500ms"`). Durations accept any suffix
/// understood by [`parse_duration`].
///
/// # Examples
///
/// ```toml
/// [[providers]]
/// name = "anthropic"
/// provider_type = "anthropic"
///
/// [providers.circuit_breaker]
/// max_fails = 3
/// fail_duration = "30s"
/// cooldown = "60s"
/// ```
///
/// [`parse_duration`]: crate::cli::parse_duration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CircuitBreakerProviderConfig {
    /// Consecutive failures that trip the breaker. Defaults to 1 (Caddy parity).
    #[serde(default = "default_cb_max_fails")]
    pub max_fails: u32,
    /// Sliding window during which failures count. `"0s"` (or omitted) disables the breaker.
    #[serde(default)]
    pub fail_duration: Option<String>,
    /// Post-trip cooldown. Omit to recover as soon as `fail_duration` expires.
    #[serde(default)]
    pub cooldown: Option<String>,
}

fn default_cb_max_fails() -> u32 {
    1
}

impl CircuitBreakerProviderConfig {
    /// Converts the TOML view into a runtime [`crate::routing::CircuitBreakerConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error when any duration string fails to parse.
    pub fn to_runtime(&self) -> Result<crate::routing::CircuitBreakerConfig, String> {
        let fail_duration = match self.fail_duration.as_deref() {
            None => std::time::Duration::ZERO,
            Some(s) => parse_duration(s)?,
        };
        let cooldown = match self.cooldown.as_deref() {
            None => None,
            Some(s) => Some(parse_duration(s)?),
        };
        Ok(crate::routing::CircuitBreakerConfig {
            max_fails: self.max_fails,
            fail_duration,
            cooldown,
        })
    }
}

/// Active health check knobs exposed through `[providers.health_check]`.
///
/// Mirror of [`crate::routing::HealthCheckConfig`] with TOML-friendly
/// duration strings (`"30s"`, `"500ms"`). Durations accept any suffix
/// understood by [`parse_duration`]. `health_status` accepts `"2xx"`,
/// `"200-204"`, `"*"`, exact codes, and comma-separated mixes.
///
/// # Examples
///
/// ```toml
/// [[providers]]
/// name = "anthropic"
/// provider_type = "anthropic"
///
/// [providers.health_check]
/// health_uri = "https://api.anthropic.com/v1/models"
/// health_interval = "30s"
/// health_timeout = "5s"
/// health_status = "2xx"
/// ```
///
/// [`parse_duration`]: crate::cli::parse_duration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HealthCheckProviderConfig {
    /// Probe URI. Omit to disable the checker (Caddy parity — `health_uri` is mandatory to activate).
    #[serde(default)]
    pub health_uri: Option<String>,
    /// Interval between probes. Defaults to `"30s"`.
    #[serde(default)]
    pub health_interval: Option<String>,
    /// Per-probe request timeout. Defaults to `"5s"`.
    #[serde(default)]
    pub health_timeout: Option<String>,
    /// Expected status predicate. Defaults to `"2xx"`.
    #[serde(default)]
    pub health_status: Option<String>,
}

impl HealthCheckProviderConfig {
    /// Converts the TOML view into a runtime [`crate::routing::HealthCheckConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error when any duration string or status predicate is unparseable.
    pub fn to_runtime(&self) -> Result<crate::routing::HealthCheckConfig, String> {
        let interval = match self.health_interval.as_deref() {
            None => std::time::Duration::from_secs(30),
            Some(s) => parse_duration(s)?,
        };
        let timeout = match self.health_timeout.as_deref() {
            None => std::time::Duration::from_secs(5),
            Some(s) => parse_duration(s)?,
        };
        let status = match self.health_status.as_deref() {
            None => crate::routing::StatusMatcher::default(),
            Some(s) => crate::routing::StatusMatcher::parse(s)?,
        };
        Ok(crate::routing::HealthCheckConfig {
            uri: self.health_uri.clone().filter(|s| !s.is_empty()),
            interval,
            timeout,
            status,
        })
    }
}
