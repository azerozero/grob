//! Active health checks — RE-1b (Caddy-inspired, ADR-0018).
//!
//! Per-provider background probe that polls an external URI on a fixed
//! interval and flips the endpoint status based on the response. Mirrors
//! Caddy's `reverse_proxy` active health check knobs:
//!
//! - `health_uri` — mandatory to activate.
//! - `health_interval` — default `"30s"`.
//! - `health_timeout` — default `"5s"`.
//! - `health_status` — default `"2xx"`. Supports `"200"`, `"200-204"`,
//!   `"2xx"`, and comma-separated mixes like `"2xx,301"`.
//!
//! # Relation to RE-1a
//!
//! RE-1a (the passive circuit breaker) and RE-1b (this module) observe
//! different signals and are **independent**: the passive breaker reacts
//! to real traffic failures, the active checker reacts to out-of-band
//! probes. ADR-0018 prescribes an AND gate at the registry layer — an
//! endpoint is healthy only when *both* signals agree.
//!
//! # Task lifecycle
//!
//! Each enabled checker owns a `tokio::spawn`ed probe loop and the
//! `JoinHandle` is kept in the struct. `Drop` calls `abort()` on the
//! handle, so replacing the `ProviderRegistry` (via `/api/config/reload`)
//! cleans up previous tasks deterministically — no background leak.
//!
//! # Opt-in, zero cost when off
//!
//! When `health_uri` is absent, the checker is never instantiated: the
//! registry returns [`HealthStatus::NotConfigured`] and the AND gate
//! short-circuits to `true`. No HTTP client, no spawned task.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Maximum length of a `health_status` specification. Guard against
/// accidental config bloat (Caddy's knob is typically 3-10 chars).
const MAX_STATUS_SPEC_LEN: usize = 128;

/// Configuration for a per-provider active health checker.
///
/// Mirrors Caddy's four knobs 1:1. All durations are pre-parsed here —
/// the TOML view lives on [`crate::cli::HealthCheckProviderConfig`].
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// URI to probe. `None` disables the checker entirely.
    pub uri: Option<String>,
    /// How often to send a probe. Defaults to 30 seconds.
    pub interval: Duration,
    /// How long to wait for each probe to respond. Defaults to 5 seconds.
    pub timeout: Duration,
    /// Expected status code expression. See [`StatusMatcher`] for the grammar.
    pub status: StatusMatcher,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            uri: None,
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            status: StatusMatcher::default(),
        }
    }
}

impl HealthCheckConfig {
    /// Returns `true` when the checker has enough information to run.
    pub fn is_enabled(&self) -> bool {
        self.uri.as_deref().is_some_and(|s| !s.is_empty())
    }
}

/// Compiled predicate over HTTP status codes.
///
/// Accepted grammar (case-insensitive, whitespace trimmed per token):
///
/// - `"2xx"`, `"3xx"`, `"4xx"`, `"5xx"` — any code in the century.
/// - `"200"` — exact match.
/// - `"200-204"` — inclusive range.
/// - `"2xx,301,410"` — comma-separated list of any of the above.
///
/// The empty string and `"*"` match every code (Caddy `health_status = "*"`).
#[derive(Debug, Clone)]
pub struct StatusMatcher {
    rules: Vec<StatusRule>,
}

#[derive(Debug, Clone)]
enum StatusRule {
    Exact(u16),
    Range(u16, u16),
    Century(u8),
    Any,
}

impl Default for StatusMatcher {
    fn default() -> Self {
        Self {
            rules: vec![StatusRule::Century(2)],
        }
    }
}

impl StatusMatcher {
    /// Parses a `health_status` spec into a matcher.
    ///
    /// # Errors
    ///
    /// Returns a descriptive message when the spec is empty, too long, or
    /// contains an unparseable token.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Ok(Self::default());
        }
        if spec.len() > MAX_STATUS_SPEC_LEN {
            return Err(format!(
                "health_status spec too long ({} > {MAX_STATUS_SPEC_LEN})",
                spec.len()
            ));
        }
        if spec == "*" {
            return Ok(Self {
                rules: vec![StatusRule::Any],
            });
        }
        let mut rules = Vec::new();
        for token in spec.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            rules.push(Self::parse_token(token)?);
        }
        if rules.is_empty() {
            return Err(format!("health_status spec '{spec}' parsed to no rules"));
        }
        Ok(Self { rules })
    }

    fn parse_token(token: &str) -> Result<StatusRule, String> {
        let lower = token.to_ascii_lowercase();
        if lower.len() == 3 && lower.ends_with("xx") {
            let digit = lower.chars().next().and_then(|c| c.to_digit(10));
            if let Some(d) = digit {
                if (1..=5).contains(&d) {
                    return Ok(StatusRule::Century(d as u8));
                }
            }
            return Err(format!("unsupported century shorthand '{token}'"));
        }
        if let Some((lo, hi)) = token.split_once('-') {
            let lo = lo
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid range low '{lo}'"))?;
            let hi = hi
                .trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid range high '{hi}'"))?;
            if lo > hi {
                return Err(format!("range '{token}' has low > high"));
            }
            return Ok(StatusRule::Range(lo, hi));
        }
        token
            .parse::<u16>()
            .map(StatusRule::Exact)
            .map_err(|_| format!("unparseable status token '{token}'"))
    }

    /// Returns `true` when `code` matches any of the compiled rules.
    pub fn matches(&self, code: u16) -> bool {
        self.rules.iter().any(|rule| match *rule {
            StatusRule::Exact(c) => c == code,
            StatusRule::Range(lo, hi) => code >= lo && code <= hi,
            StatusRule::Century(d) => {
                let start = u16::from(d) * 100;
                let end = start + 99;
                code >= start && code <= end
            }
            StatusRule::Any => true,
        })
    }
}

/// Tri-state result reported by the registry to the AND gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// No checker configured — pass through.
    NotConfigured,
    /// Latest probe succeeded.
    Up,
    /// Latest probe failed.
    Down,
}

impl HealthStatus {
    /// Returns `true` for every state except [`HealthStatus::Down`].
    pub fn is_healthy(self) -> bool {
        !matches!(self, HealthStatus::Down)
    }
}

/// Active health checker for one provider.
///
/// Owns a tokio probe task whose `JoinHandle` is aborted on drop. The
/// observed status is shared via an `AtomicBool` for a lock-free hot
/// path. The label mirrors [`crate::routing::CircuitBreaker::label`] —
/// `"provider_name"` (not per-endpoint, since Caddy's `health_uri` is
/// naturally provider-scoped).
pub struct HealthChecker {
    label: String,
    config: HealthCheckConfig,
    up: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl HealthChecker {
    /// Spawns a checker for `label` with the given configuration.
    ///
    /// When the configuration is disabled (no `uri`), no task is spawned
    /// and the checker reports [`HealthStatus::NotConfigured`] forever.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use grob::routing::{HealthChecker, HealthCheckConfig};
    ///
    /// let cfg = HealthCheckConfig::default();
    /// let hc = HealthChecker::new("anthropic".into(), cfg);
    /// assert!(hc.status().is_healthy());
    /// ```
    pub fn new(label: String, config: HealthCheckConfig) -> Arc<Self> {
        if !config.is_enabled() {
            return Arc::new(Self {
                label,
                config,
                up: Arc::new(AtomicBool::new(true)),
                handle: None,
            });
        }

        let up = Arc::new(AtomicBool::new(true));
        let uri = config.uri.clone().expect("enabled checker has uri");
        let interval = config.interval;
        let timeout = config.timeout;
        let status = config.status.clone();
        let label_for_task = label.clone();
        let up_for_task = Arc::clone(&up);

        let handle = tokio::spawn(async move {
            probe_loop(label_for_task, uri, interval, timeout, status, up_for_task).await;
        });

        Arc::new(Self {
            label,
            config,
            up,
            handle: Some(handle),
        })
    }

    /// Returns the endpoint label used in log lines.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the configuration snapshot.
    pub fn config(&self) -> &HealthCheckConfig {
        &self.config
    }

    /// Returns the current probe verdict.
    pub fn status(&self) -> HealthStatus {
        if !self.config.is_enabled() {
            return HealthStatus::NotConfigured;
        }
        if self.up.load(Ordering::Relaxed) {
            HealthStatus::Up
        } else {
            HealthStatus::Down
        }
    }

    /// Returns `true` when the endpoint is not marked down by the checker.
    ///
    /// Equivalent to `self.status().is_healthy()` — exposed for symmetry
    /// with [`crate::routing::CircuitBreaker::is_healthy`].
    pub fn is_healthy(&self) -> bool {
        self.status().is_healthy()
    }
}

impl Drop for HealthChecker {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

async fn probe_loop(
    label: String,
    uri: String,
    interval: Duration,
    timeout: Duration,
    status: StatusMatcher,
    up: Arc<AtomicBool>,
) {
    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(
                endpoint = %label,
                error = %e,
                "failed to build health-check HTTP client; checker disabled"
            );
            return;
        }
    };

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;
        let was_up = up.load(Ordering::Relaxed);
        let probe_result = client.get(&uri).send().await;
        let now_up = match probe_result {
            Ok(resp) => {
                let code = resp.status().as_u16();
                let ok = status.matches(code);
                if !ok {
                    debug!(
                        endpoint = %label,
                        status = code,
                        "health-check probe returned unexpected status"
                    );
                }
                ok
            }
            Err(err) => {
                debug!(
                    endpoint = %label,
                    error = %err,
                    "health-check probe failed"
                );
                false
            }
        };

        up.store(now_up, Ordering::Relaxed);

        match (was_up, now_up) {
            (true, false) => info!(
                endpoint = %label,
                "🩺 health-check DOWN for endpoint {}", label
            ),
            (false, true) => info!(
                endpoint = %label,
                "🩺 health-check UP for endpoint {}", label
            ),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    #[test]
    fn hc_status_default_is_2xx() {
        let m = StatusMatcher::default();
        assert!(m.matches(200));
        assert!(m.matches(299));
        assert!(!m.matches(300));
        assert!(!m.matches(199));
    }

    #[test]
    fn hc_status_parses_century() {
        let m = StatusMatcher::parse("3xx").unwrap();
        assert!(m.matches(300));
        assert!(m.matches(399));
        assert!(!m.matches(299));
    }

    #[test]
    fn hc_status_parses_exact() {
        let m = StatusMatcher::parse("418").unwrap();
        assert!(m.matches(418));
        assert!(!m.matches(417));
        assert!(!m.matches(419));
    }

    #[test]
    fn hc_status_parses_range() {
        let m = StatusMatcher::parse("200-204").unwrap();
        assert!(m.matches(200));
        assert!(m.matches(204));
        assert!(!m.matches(205));
    }

    #[test]
    fn hc_status_parses_list() {
        let m = StatusMatcher::parse("2xx, 301, 410").unwrap();
        assert!(m.matches(200));
        assert!(m.matches(301));
        assert!(m.matches(410));
        assert!(!m.matches(302));
        assert!(!m.matches(411));
    }

    #[test]
    fn hc_status_wildcard_matches_any() {
        let m = StatusMatcher::parse("*").unwrap();
        assert!(m.matches(100));
        assert!(m.matches(599));
    }

    #[test]
    fn hc_status_rejects_bad_spec() {
        assert!(StatusMatcher::parse("banana").is_err());
        assert!(StatusMatcher::parse("6xx").is_err());
        assert!(StatusMatcher::parse("500-200").is_err());
        assert!(StatusMatcher::parse(&"2".repeat(200)).is_err());
    }

    #[tokio::test]
    async fn hc_disabled_when_uri_absent() {
        let hc = HealthChecker::new("test".into(), HealthCheckConfig::default());
        assert_eq!(hc.status(), HealthStatus::NotConfigured);
        assert!(hc.is_healthy());
    }

    #[tokio::test]
    async fn hc_polls_and_marks_up() {
        let addr = spawn_probe_server(|_| 200).await;
        let cfg = HealthCheckConfig {
            uri: Some(format!("http://{addr}/health")),
            interval: Duration::from_millis(20),
            timeout: Duration::from_millis(500),
            status: StatusMatcher::default(),
        };
        let hc = HealthChecker::new("up".into(), cfg);

        wait_for(|| hc.status() == HealthStatus::Up, Duration::from_secs(2)).await;
        assert!(hc.is_healthy());
    }

    #[tokio::test]
    async fn hc_marks_down_on_bad_status() {
        let addr = spawn_probe_server(|_| 503).await;
        let cfg = HealthCheckConfig {
            uri: Some(format!("http://{addr}/health")),
            interval: Duration::from_millis(20),
            timeout: Duration::from_millis(500),
            status: StatusMatcher::default(),
        };
        let hc = HealthChecker::new("down".into(), cfg);

        wait_for(|| hc.status() == HealthStatus::Down, Duration::from_secs(2)).await;
        assert!(!hc.is_healthy());
    }

    #[tokio::test]
    async fn hc_recovers_when_server_comes_back() {
        let switch = Arc::new(AtomicU16::new(503));
        let switch_for_server = Arc::clone(&switch);
        let addr = spawn_probe_server(move |_| switch_for_server.load(Ordering::Relaxed)).await;

        let cfg = HealthCheckConfig {
            uri: Some(format!("http://{addr}/health")),
            interval: Duration::from_millis(20),
            timeout: Duration::from_millis(500),
            status: StatusMatcher::default(),
        };
        let hc = HealthChecker::new("flaky".into(), cfg);

        wait_for(|| hc.status() == HealthStatus::Down, Duration::from_secs(2)).await;
        switch.store(200, Ordering::Relaxed);
        wait_for(|| hc.status() == HealthStatus::Up, Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn hc_drop_aborts_task() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_server = Arc::clone(&counter);
        let addr = spawn_probe_server(move |_| {
            counter_for_server.fetch_add(1, Ordering::Relaxed);
            200
        })
        .await;

        let cfg = HealthCheckConfig {
            uri: Some(format!("http://{addr}/health")),
            interval: Duration::from_millis(20),
            timeout: Duration::from_millis(500),
            status: StatusMatcher::default(),
        };
        let hc = HealthChecker::new("drop".into(), cfg);
        wait_for(
            || counter.load(Ordering::Relaxed) >= 2,
            Duration::from_secs(2),
        )
        .await;

        drop(hc);
        let after_drop = counter.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let later = counter.load(Ordering::Relaxed);
        assert!(
            later <= after_drop + 1,
            "probe kept running after drop: {after_drop} -> {later}"
        );
    }

    #[test]
    fn hc_status_healthy_helper() {
        assert!(HealthStatus::NotConfigured.is_healthy());
        assert!(HealthStatus::Up.is_healthy());
        assert!(!HealthStatus::Down.is_healthy());
    }

    async fn spawn_probe_server<F>(respond: F) -> SocketAddr
    where
        F: Fn(&str) -> u16 + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let respond = Arc::clone(&respond);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let req = String::from_utf8_lossy(&buf);
                    let code = respond(&req);
                    let reason = match code {
                        200 => "OK",
                        204 => "No Content",
                        301 => "Moved Permanently",
                        404 => "Not Found",
                        500 => "Internal Server Error",
                        503 => "Service Unavailable",
                        _ => "Status",
                    };
                    let body = format!(
                        "HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(body.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    async fn wait_for<F: Fn() -> bool>(cond: F, budget: Duration) {
        let start = std::time::Instant::now();
        while start.elapsed() < budget {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not satisfied within {budget:?}");
    }
}
