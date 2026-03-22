//! Statistics computation, result types, memory measurement, and concurrent runner.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::build_bench_client;

// ── Statistics ──────────────────────────────────────────────────────────

pub(super) struct Stats {
    pub(super) p50: Duration,
    pub(super) p95: Duration,
    pub(super) p99: Duration,
}

pub(super) fn compute_stats(mut latencies: Vec<Duration>) -> Stats {
    latencies.sort();
    let n = latencies.len();
    Stats {
        p50: latencies[n / 2],
        p95: latencies[n * 95 / 100],
        p99: latencies[n * 99 / 100],
    }
}

pub(super) fn format_us(d: Duration) -> String {
    let us = d.as_secs_f64() * 1_000_000.0;
    if us >= 1000.0 {
        format!("{:.1}ms", us / 1000.0)
    } else {
        format!("{:.0}us", us)
    }
}

pub(super) fn format_rps(rps: f64) -> String {
    if rps >= 1000.0 {
        format!("{:.1}k", rps / 1000.0)
    } else {
        format!("{:.0}", rps)
    }
}

// ── Result types for JSON output ────────────────────────────────────────

#[derive(serde::Serialize)]
pub(super) struct BenchResult {
    pub(super) system: SystemInfo,
    pub(super) requests_per_scenario: usize,
    pub(super) concurrency: usize,
    pub(super) payload_sizes: Vec<String>,
    pub(super) scenarios: Vec<ScenarioResult>,
    pub(super) verdict: String,
}

#[derive(serde::Serialize)]
pub(super) struct SystemInfo {
    pub(super) os: String,
    pub(super) arch: String,
    pub(super) cpu_count: usize,
    pub(super) grob_version: String,
}

#[derive(serde::Serialize)]
pub(super) struct ScenarioResult {
    pub(super) name: String,
    pub(super) payload_size: String,
    pub(super) p50_us: f64,
    pub(super) p95_us: f64,
    pub(super) p99_us: f64,
    pub(super) overhead_us: Option<f64>,
    /// Only populated in concurrent mode.
    pub(super) rps: Option<f64>,
}

// ── Memory measurement ──────────────────────────────────────────────────

/// Reads current process RSS on macOS/Linux. Returns "N/A" on failure.
pub(super) fn current_rss_mb() -> String {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let pid = std::process::id();
        if let Ok(output) = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
        {
            if let Ok(rss_kb) = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u64>()
            {
                return format!("{}MB", rss_kb / 1024);
            }
        }
        "N/A".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(val) = line.strip_prefix("VmRSS:") {
                    let kb: u64 = val
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    return format!("{}MB", kb / 1024);
                }
            }
        }
        "N/A".to_string()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "N/A".to_string()
    }
}

// ── Concurrent benchmark runner ─────────────────────────────────────────

/// Runs concurrent requests for a fixed duration, collecting latencies.
pub(super) async fn run_concurrent(
    target_url: &str,
    body: &serde_json::Value,
    auth_token: &Option<String>,
    enable_auth: bool,
    concurrency: usize,
    duration_secs: u64,
) -> (Vec<Duration>, usize) {
    let completed = Arc::new(AtomicUsize::new(0));
    let all_latencies = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let body = Arc::new(body.clone());
    let target_url = target_url.to_string();
    let auth_token = auth_token.clone();
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let completed = completed.clone();
        let all_latencies = all_latencies.clone();
        let body = body.clone();
        let target_url = target_url.clone();
        let auth_token = auth_token.clone();

        handles.push(tokio::spawn(async move {
            let client = build_bench_client();

            let mut local_latencies = Vec::new();
            while Instant::now() < deadline {
                let mut req = client
                    .post(format!("{}/v1/messages", target_url))
                    .json(body.as_ref());
                if enable_auth {
                    if let Some(ref token) = auth_token {
                        req = req.header("authorization", format!("Bearer {token}"));
                    }
                }
                let start = Instant::now();
                if let Ok(resp) = req.send().await {
                    let _ = resp.bytes().await;
                    local_latencies.push(start.elapsed());
                    completed.fetch_add(1, Ordering::Relaxed);
                }
            }

            let mut guard = all_latencies.lock().await;
            guard.extend(local_latencies);
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let latencies = match Arc::try_unwrap(all_latencies) {
        Ok(mutex) => mutex.into_inner(),
        Err(arc) => {
            let guard = arc.blocking_lock();
            guard.clone()
        }
    };
    let total = completed.load(Ordering::Relaxed);

    (latencies, total)
}
