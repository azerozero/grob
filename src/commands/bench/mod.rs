//! Self-contained performance evaluation of the grob proxy pipeline.
//!
//! Starts a mock backend, builds a minimal proxy with middleware layers,
//! runs scenarios with increasing feature combinations, and reports
//! latency percentiles plus overhead relative to the direct baseline.
//! Supports concurrent throughput testing and varied payload sizes.

mod mock;
mod payloads;
mod scenarios;
mod stats;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::auth::virtual_keys::{generate_key, VirtualKeyRecord};
use crate::cli::AppConfig;
use crate::storage::GrobStore;

use mock::{start_mock_backend, start_proxy, ProxyState};
use payloads::{clean_request_body, secrets_request_body};
use scenarios::{build_escalation_steps, build_scenarios, compile_dlp_patterns, DlpPatternSet};
use stats::{
    compute_stats, current_rss_mb, format_rps, format_us, run_concurrent, BenchResult,
    ScenarioResult, SystemInfo,
};

pub use payloads::{parse_payload_flag, PayloadSize};

// ── Constants ───────────────────────────────────────────────────────────

const WARMUP_REQUESTS: usize = 50;
const CONCURRENT_DURATION_SECS: u64 = 5;

/// Builds an HTTP client matching grob's real provider client optimizations.
fn build_bench_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tcp_nodelay(true)
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(Duration::from_secs(90))
        .http2_adaptive_window(true)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

// ── Entry point ─────────────────────────────────────────────────────────

/// Renders a Unicode bar chart of the given proportion (0.0..=1.0).
fn render_bar(proportion: f64, width: usize) -> String {
    let filled = (proportion * width as f64).round() as usize;
    let filled = filled.min(width);
    let empty = width - filled;
    format!("{}{}", "\u{2588}".repeat(filled), "\u{2591}".repeat(empty))
}

/// Runs the self-contained performance benchmark.
pub async fn cmd_bench(
    _config: &AppConfig,
    requests: usize,
    with_auth: bool,
    format: &str,
    concurrency: usize,
    payload: &str,
    escalate: bool,
) -> Result<()> {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let version = env!("CARGO_PKG_VERSION");

    // Resolve concurrency: 0 = auto = CPU count.
    let effective_concurrency = if concurrency == 0 {
        cpu_count
    } else {
        concurrency
    };
    let is_concurrent = effective_concurrency > 1;

    let payload_sizes = parse_payload_flag(payload);
    let is_multi_payload = payload_sizes.len() > 1;

    if format != "json" {
        println!();
        println!("Grob Performance Evaluation");
        println!(
            "  System: {} {}, {} cores, grob v{}",
            os, arch, cpu_count, version
        );
        if is_concurrent {
            println!(
                "  Mode: concurrent (c={}), {} sec/scenario",
                effective_concurrency, CONCURRENT_DURATION_SECS
            );
        } else {
            println!("  Requests: {} per scenario", requests);
        }
        if is_multi_payload {
            let labels: Vec<&str> = payload_sizes.iter().map(|s| s.label()).collect();
            println!("  Payloads: {}", labels.join(", "));
        }
        if with_auth {
            println!("  Auth: virtual key (SHA-256 hash + lookup)");
        }
        println!();
    }

    // Pre-compile patterns once (mirrors grob's startup behavior).
    let routing_patterns = Arc::new(vec![
        regex::Regex::new(r"(?i)\b(think|reason|analyze)\b").unwrap(),
        regex::Regex::new(r"(?i)\b(search|find|lookup)\b").unwrap(),
        regex::Regex::new(r"(?i)\b(summarize|translate|generate)\b").unwrap(),
    ]);
    let dlp_patterns = Arc::new(vec![
        regex::Regex::new(r"(?i)(sk-[a-zA-Z0-9]{32,})").unwrap(),
        regex::Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").unwrap(),
        regex::Regex::new(r"(?i)(ghp_[a-zA-Z0-9]{36})").unwrap(),
        regex::Regex::new(r"(?i)(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)").unwrap(),
        regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
        regex::Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b").unwrap(),
        // Additional patterns for credit cards and emails.
        regex::Regex::new(r"\b[46]\d{15}\b").unwrap(),
        regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
        regex::Regex::new(r"(?i)ignore\s+all\s+previous\s+instructions").unwrap(),
    ]);

    // Create a virtual key for auth scenarios.
    let (auth_token, auth_key_hash) = if with_auth {
        let store = GrobStore::open(&GrobStore::default_path())?;
        let (full_key, key_hash) = generate_key();
        let now = chrono::Utc::now();
        let record = VirtualKeyRecord {
            id: uuid::Uuid::new_v4(),
            name: "bench-ephemeral".to_string(),
            prefix: full_key[..12].to_string(),
            key_hash: key_hash.clone(),
            tenant_id: "bench".to_string(),
            budget_usd: None,
            rate_limit_rps: None,
            allowed_models: None,
            created_at: now,
            expires_at: Some(now + chrono::Duration::hours(1)),
            revoked: false,
            last_used_at: None,
        };
        store.store_virtual_key(&record)?;
        use sha2::{Digest, Sha256};
        let computed_hash = hex::encode(Sha256::digest(full_key.as_bytes()));
        (Some(full_key), Some(computed_hash))
    } else {
        (None, None)
    };

    // Start mock backend (shared across all scenarios).
    let (backend_url, _mock_handle) = start_mock_backend().await;

    // Verify mock is reachable.
    let probe_client = reqwest::Client::new();
    let probe_body = clean_request_body(PayloadSize::Small);
    let probe_resp = probe_client
        .post(format!("{}/v1/messages", backend_url))
        .json(&probe_body)
        .send()
        .await?;
    anyhow::ensure!(probe_resp.status() == 200, "Mock backend returned non-200");

    // ── Escalation mode ─────────────────────────────────────────────────
    if escalate {
        return run_escalation(
            &backend_url,
            &routing_patterns,
            &dlp_patterns,
            &auth_token,
            &auth_key_hash,
            requests,
            concurrency,
            format,
        )
        .await;
    }

    let scenarios = build_scenarios(with_auth);
    let mut results: Vec<ScenarioResult> = Vec::new();
    // Track baseline P50 per payload size for overhead calculation.
    let mut baseline_p50: std::collections::HashMap<&str, Duration> =
        std::collections::HashMap::new();
    let mut header_printed = false;

    // For multi-payload matrix mode, collect per-size results then print at end.
    // For single payload or concurrent, print as we go.
    type SizeResult = (PayloadSize, stats::Stats, Option<f64>, Option<f64>);
    let mut matrix_rows: Vec<(String, Vec<SizeResult>)> = Vec::new();

    for scenario in &scenarios {
        let is_direct = scenario.name == "direct (baseline)";
        let mut size_results = Vec::new();

        for &psize in &payload_sizes {
            let body = if scenario.inject_secrets {
                secrets_request_body(psize)
            } else {
                clean_request_body(psize)
            };

            let target_url = if is_direct {
                backend_url.clone()
            } else {
                let effective_dlp_patterns = match scenario.dlp_pattern_set {
                    Some(set) => compile_dlp_patterns(set),
                    None => dlp_patterns.clone(),
                };
                let state = ProxyState {
                    backend_url: backend_url.clone(),
                    client: build_bench_client(),
                    enable_routing: scenario.enable_routing,
                    enable_dlp: scenario.enable_dlp,
                    enable_auth: scenario.enable_auth,
                    enable_rate_limit: scenario.enable_rate_limit,
                    enable_cache: scenario.enable_cache,
                    auth_key_hash: auth_key_hash.clone(),
                    routing_patterns: routing_patterns.clone(),
                    dlp_patterns: effective_dlp_patterns,
                };
                let (proxy_url, _proxy_handle) = start_proxy(state).await;

                // Wait for proxy to be ready.
                let client = reqwest::Client::new();
                for _ in 0..50 {
                    if client
                        .get(format!("{proxy_url}/health"))
                        .send()
                        .await
                        .is_ok()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                proxy_url
            };

            let (stats, rps) = if is_concurrent {
                // Warmup with a burst.
                let warmup_client = reqwest::Client::builder()
                    .pool_max_idle_per_host(10)
                    .build()
                    .unwrap();
                for _ in 0..WARMUP_REQUESTS {
                    let mut req = warmup_client
                        .post(format!("{target_url}/v1/messages"))
                        .json(&body);
                    if scenario.enable_auth {
                        if let Some(ref token) = auth_token {
                            req = req.header("authorization", format!("Bearer {token}"));
                        }
                    }
                    if let Ok(resp) = req.send().await {
                        let _ = resp.bytes().await;
                    }
                }

                let (latencies, total) = run_concurrent(
                    &target_url,
                    &body,
                    &auth_token,
                    scenario.enable_auth,
                    effective_concurrency,
                    CONCURRENT_DURATION_SECS,
                )
                .await;

                if latencies.is_empty() {
                    anyhow::bail!(
                        "No requests completed for scenario '{}' with payload {}",
                        scenario.name,
                        psize.label()
                    );
                }

                let rps_val = total as f64 / CONCURRENT_DURATION_SECS as f64;
                (compute_stats(latencies), Some(rps_val))
            } else {
                // Sequential mode.
                let client = build_bench_client();

                // Warmup.
                for _ in 0..WARMUP_REQUESTS {
                    let mut req = client.post(format!("{target_url}/v1/messages")).json(&body);
                    if scenario.enable_auth {
                        if let Some(ref token) = auth_token {
                            req = req.header("authorization", format!("Bearer {token}"));
                        }
                    }
                    let resp = req.send().await?;
                    let _ = resp.bytes().await;
                }

                // Measured run.
                let mut latencies = Vec::with_capacity(requests);
                for _ in 0..requests {
                    let mut req = client.post(format!("{target_url}/v1/messages")).json(&body);
                    if scenario.enable_auth {
                        if let Some(ref token) = auth_token {
                            req = req.header("authorization", format!("Bearer {token}"));
                        }
                    }
                    let start = Instant::now();
                    let resp = req.send().await?;
                    let _ = resp.bytes().await;
                    latencies.push(start.elapsed());
                }

                (compute_stats(latencies), None)
            };

            if is_direct {
                baseline_p50.insert(psize.label(), stats.p50);
            }

            let overhead_us = if is_direct {
                None
            } else {
                baseline_p50
                    .get(psize.label())
                    .map(|b| (stats.p50.as_secs_f64() - b.as_secs_f64()) * 1_000_000.0)
            };

            results.push(ScenarioResult {
                name: scenario.name.to_string(),
                payload_size: psize.label().to_string(),
                p50_us: stats.p50.as_secs_f64() * 1_000_000.0,
                p95_us: stats.p95.as_secs_f64() * 1_000_000.0,
                p99_us: stats.p99.as_secs_f64() * 1_000_000.0,
                overhead_us,
                rps,
            });

            size_results.push((psize, stats, overhead_us, rps));
        }

        // Print output for non-matrix modes inline.
        if format != "json" && !is_multi_payload {
            let (psize, ref stats, overhead_us, rps) = size_results[0];
            let _ = psize; // Single payload, no label needed.

            if !header_printed {
                if is_concurrent {
                    println!(
                        "  {:<22} {:>9} {:>9} {:>9} {:>10} {:>10}",
                        "Scenario",
                        "P50",
                        "P95",
                        "RPS",
                        format!("c={}", effective_concurrency),
                        "Overhead"
                    );
                } else {
                    println!(
                        "  {:<22} {:>9} {:>9} {:>9} {:>10}",
                        "Scenario", "P50", "P95", "P99", "Overhead"
                    );
                }
                println!(
                    "  {}",
                    "\u{2500}".repeat(if is_concurrent { 73 } else { 63 })
                );
                header_printed = true;
            }

            let overhead_str = match overhead_us {
                Some(us) => format!("+{}", format_us(Duration::from_secs_f64(us / 1_000_000.0))),
                None => "\u{2014}".to_string(),
            };

            if is_concurrent {
                let rps_str = rps
                    .map(format_rps)
                    .unwrap_or_else(|| "\u{2014}".to_string());
                println!(
                    "  {:<22} {:>9} {:>9} {:>9} {:>10} {:>10}",
                    scenario.name,
                    format_us(stats.p50),
                    format_us(stats.p95),
                    format_us(stats.p99),
                    rps_str,
                    overhead_str,
                );
            } else {
                println!(
                    "  {:<22} {:>9} {:>9} {:>9} {:>10}",
                    scenario.name,
                    format_us(stats.p50),
                    format_us(stats.p95),
                    format_us(stats.p99),
                    overhead_str,
                );
            }
        }

        if is_multi_payload && format != "json" {
            matrix_rows.push((scenario.name.to_string(), size_results));
        }
    }

    // Print multi-payload matrix table.
    if format != "json" && is_multi_payload {
        let size_labels: Vec<&str> = payload_sizes.iter().map(|s| s.label()).collect();
        let col_width = 12;

        print!("  {:<22}", "Scenario");
        for label in &size_labels {
            print!(" {:>width$}", label, width = col_width);
        }
        println!();
        let total_width = 22 + size_labels.len() * (col_width + 1);
        println!("  {}", "\u{2500}".repeat(total_width));

        for (name, size_results) in &matrix_rows {
            print!("  {:<22}", name);
            for (_psize, stats, _overhead, _rps) in size_results {
                print!(" {:>width$}", format_us(stats.p50), width = col_width);
            }
            println!();
        }
    }

    let rss = current_rss_mb();

    // Determine verdict based on the "proxy+all" overhead (use first payload size).
    let all_overhead = results
        .iter()
        .find(|r| r.name == "proxy+all")
        .and_then(|r| r.overhead_us)
        .unwrap_or(0.0);
    let verdict = if all_overhead < 500.0 {
        "Production ready"
    } else if all_overhead < 2000.0 {
        "Acceptable"
    } else {
        "Needs investigation"
    };

    if format == "json" {
        let size_labels: Vec<String> = payload_sizes
            .iter()
            .map(|s| s.label().to_string())
            .collect();
        let output = BenchResult {
            system: SystemInfo {
                os: os.to_string(),
                arch: arch.to_string(),
                cpu_count,
                grob_version: version.to_string(),
            },
            requests_per_scenario: requests,
            concurrency: effective_concurrency,
            payload_sizes: size_labels,
            scenarios: results,
            verdict: verdict.to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!();
        if let Some(overhead) = results
            .iter()
            .find(|r| r.name == "proxy+all")
            .and_then(|r| r.overhead_us)
        {
            println!(
                "  Pure overhead (all features): ~{}",
                format_us(Duration::from_secs_f64(overhead / 1_000_000.0))
            );
        }
        println!("  Memory: {} RSS", rss);
        println!("  Verdict: {verdict}");
        println!();
    }

    Ok(())
}

// ── Escalation mode ─────────────────────────────────────────────────────

/// Holds results for one escalation step.
struct EscalationRow {
    step: usize,
    name: &'static str,
    p50: Duration,
    rps: Option<f64>,
    /// Overhead relative to step 0 (TCP baseline).
    overhead: Option<Duration>,
}

/// Runs the escalation staircase benchmark.
#[allow(clippy::too_many_arguments)]
async fn run_escalation(
    backend_url: &str,
    routing_patterns: &Arc<Vec<regex::Regex>>,
    _all_dlp_patterns: &Arc<Vec<regex::Regex>>,
    auth_token: &Option<String>,
    auth_key_hash: &Option<String>,
    requests: usize,
    concurrency: usize,
    format: &str,
) -> Result<()> {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let effective_concurrency = if concurrency == 0 {
        cpu_count
    } else {
        concurrency
    };
    let is_concurrent = effective_concurrency > 1;

    // Escalation always uses medium payload (realistic Claude Code traffic).
    let psize = PayloadSize::Medium;
    let steps = build_escalation_steps();

    if format != "json" {
        println!();
        println!("  Feature Escalation ({})", psize.label());
        if is_concurrent {
            println!(
                "  Mode: concurrent (c={}), {} sec/step",
                effective_concurrency, CONCURRENT_DURATION_SECS
            );
        } else {
            println!("  Requests: {} per step", requests);
        }
        println!();
    }

    let mut rows: Vec<EscalationRow> = Vec::new();
    let mut baseline_p50: Option<Duration> = None;

    for (idx, step) in steps.iter().enumerate() {
        let is_direct = idx == 0;

        let body = if step.inject_secrets {
            secrets_request_body(psize)
        } else {
            clean_request_body(psize)
        };

        let target_url = if is_direct {
            backend_url.to_string()
        } else {
            let dlp_pats = match step.dlp_pattern_set {
                Some(set) => compile_dlp_patterns(set),
                None => Arc::new(Vec::new()),
            };
            let state = ProxyState {
                backend_url: backend_url.to_string(),
                client: build_bench_client(),
                enable_routing: step.enable_routing,
                enable_dlp: step.enable_dlp,
                enable_auth: step.enable_auth,
                enable_rate_limit: step.enable_rate_limit,
                enable_cache: step.enable_cache,
                auth_key_hash: auth_key_hash.clone(),
                routing_patterns: routing_patterns.clone(),
                dlp_patterns: dlp_pats,
            };
            let (proxy_url, _handle) = start_proxy(state).await;

            // Wait for proxy readiness.
            let client = reqwest::Client::new();
            for _ in 0..50 {
                if client
                    .get(format!("{proxy_url}/health"))
                    .send()
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            proxy_url
        };

        let (stats, rps) = if is_concurrent {
            let warmup_client = reqwest::Client::builder()
                .pool_max_idle_per_host(10)
                .build()
                .unwrap();
            for _ in 0..WARMUP_REQUESTS {
                let mut req = warmup_client
                    .post(format!("{target_url}/v1/messages"))
                    .json(&body);
                if step.enable_auth {
                    if let Some(ref token) = auth_token {
                        req = req.header("authorization", format!("Bearer {token}"));
                    }
                }
                if let Ok(resp) = req.send().await {
                    let _ = resp.bytes().await;
                }
            }

            let (latencies, total) = run_concurrent(
                &target_url,
                &body,
                auth_token,
                step.enable_auth,
                effective_concurrency,
                CONCURRENT_DURATION_SECS,
            )
            .await;

            if latencies.is_empty() {
                anyhow::bail!("No requests completed for escalation step '{}'", step.name);
            }

            let rps_val = total as f64 / CONCURRENT_DURATION_SECS as f64;
            (compute_stats(latencies), Some(rps_val))
        } else {
            let client = build_bench_client();

            for _ in 0..WARMUP_REQUESTS {
                let mut req = client.post(format!("{target_url}/v1/messages")).json(&body);
                if step.enable_auth {
                    if let Some(ref token) = auth_token {
                        req = req.header("authorization", format!("Bearer {token}"));
                    }
                }
                let resp = req.send().await?;
                let _ = resp.bytes().await;
            }

            let mut latencies = Vec::with_capacity(requests);
            for _ in 0..requests {
                let mut req = client.post(format!("{target_url}/v1/messages")).json(&body);
                if step.enable_auth {
                    if let Some(ref token) = auth_token {
                        req = req.header("authorization", format!("Bearer {token}"));
                    }
                }
                let start = Instant::now();
                let resp = req.send().await?;
                let _ = resp.bytes().await;
                latencies.push(start.elapsed());
            }

            (compute_stats(latencies), None)
        };

        if is_direct {
            baseline_p50 = Some(stats.p50);
        }

        let overhead = baseline_p50.and_then(|b| {
            if is_direct {
                None
            } else {
                Some(stats.p50.saturating_sub(b))
            }
        });

        rows.push(EscalationRow {
            step: idx,
            name: step.name,
            p50: stats.p50,
            rps,
            overhead,
        });
    }

    // Run the "ALL" step with every feature enabled.
    {
        let all_dlp = compile_dlp_patterns(DlpPatternSet::Full);
        let state = ProxyState {
            backend_url: backend_url.to_string(),
            client: build_bench_client(),
            enable_routing: true,
            enable_dlp: true,
            enable_auth: auth_token.is_some(),
            enable_rate_limit: true,
            enable_cache: true,
            auth_key_hash: auth_key_hash.clone(),
            routing_patterns: routing_patterns.clone(),
            dlp_patterns: all_dlp,
        };
        let (proxy_url, _handle) = start_proxy(state).await;

        let client = reqwest::Client::new();
        for _ in 0..50 {
            if client
                .get(format!("{proxy_url}/health"))
                .send()
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let body = secrets_request_body(psize);

        let (stats, rps) = if is_concurrent {
            let warmup_client = reqwest::Client::builder()
                .pool_max_idle_per_host(10)
                .build()
                .unwrap();
            for _ in 0..WARMUP_REQUESTS {
                let mut req = warmup_client
                    .post(format!("{proxy_url}/v1/messages"))
                    .json(&body);
                if let Some(ref token) = auth_token {
                    req = req.header("authorization", format!("Bearer {token}"));
                }
                if let Ok(resp) = req.send().await {
                    let _ = resp.bytes().await;
                }
            }

            let (latencies, total) = run_concurrent(
                &proxy_url,
                &body,
                auth_token,
                auth_token.is_some(),
                effective_concurrency,
                CONCURRENT_DURATION_SECS,
            )
            .await;

            if latencies.is_empty() {
                anyhow::bail!("No requests completed for ALL escalation step");
            }

            let rps_val = total as f64 / CONCURRENT_DURATION_SECS as f64;
            (compute_stats(latencies), Some(rps_val))
        } else {
            let client = build_bench_client();

            for _ in 0..WARMUP_REQUESTS {
                let mut req = client.post(format!("{proxy_url}/v1/messages")).json(&body);
                if let Some(ref token) = auth_token {
                    req = req.header("authorization", format!("Bearer {token}"));
                }
                let resp = req.send().await?;
                let _ = resp.bytes().await;
            }

            let mut latencies = Vec::with_capacity(requests);
            for _ in 0..requests {
                let mut req = client.post(format!("{proxy_url}/v1/messages")).json(&body);
                if let Some(ref token) = auth_token {
                    req = req.header("authorization", format!("Bearer {token}"));
                }
                let start = Instant::now();
                let resp = req.send().await?;
                let _ = resp.bytes().await;
                latencies.push(start.elapsed());
            }

            (compute_stats(latencies), None)
        };

        let overhead = baseline_p50.map(|b| stats.p50.saturating_sub(b));

        rows.push(EscalationRow {
            step: rows.len(),
            name: "ALL (everything)",
            p50: stats.p50,
            rps,
            overhead,
        });
    }

    // ── Render output ───────────────────────────────────────────────
    if format == "json" {
        let json_rows: Vec<ScenarioResult> = rows
            .iter()
            .map(|r| ScenarioResult {
                name: format!("{} {}", r.step, r.name),
                payload_size: psize.label().to_string(),
                p50_us: r.p50.as_secs_f64() * 1_000_000.0,
                p95_us: 0.0,
                p99_us: 0.0,
                overhead_us: r.overhead.map(|d| d.as_secs_f64() * 1_000_000.0),
                rps: r.rps,
            })
            .collect();
        let output = BenchResult {
            system: SystemInfo {
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                cpu_count,
                grob_version: env!("CARGO_PKG_VERSION").to_string(),
            },
            requests_per_scenario: requests,
            concurrency: effective_concurrency,
            payload_sizes: vec![psize.label().to_string()],
            scenarios: json_rows,
            verdict: "escalation".to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    // Find max overhead for bar scaling.
    let max_overhead = rows
        .iter()
        .filter_map(|r| r.overhead)
        .max()
        .unwrap_or(Duration::ZERO);
    let max_overhead_us = max_overhead.as_secs_f64() * 1_000_000.0;

    const BAR_WIDTH: usize = 8;

    // Print escalation table header.
    println!(
        "  {:<28} {:>9} {:>9} {:>10}  {:>10}",
        "Feature Escalation", "P50", "RPS", "", "Overhead"
    );
    println!("  {}", "\u{2500}".repeat(70));

    for row in &rows {
        let p50_str = format_us(row.p50);
        let rps_str = row
            .rps
            .map(format_rps)
            .unwrap_or_else(|| "\u{2014}".to_string());

        let (bar_str, overhead_str) = match row.overhead {
            Some(oh) => {
                let oh_us = oh.as_secs_f64() * 1_000_000.0;
                let proportion = if max_overhead_us > 0.0 {
                    oh_us / max_overhead_us
                } else {
                    0.0
                };
                let bar = render_bar(proportion, BAR_WIDTH);
                let label = format!(
                    "+{}",
                    format_us(Duration::from_secs_f64(oh_us / 1_000_000.0))
                );
                (bar, label)
            }
            None => (" ".repeat(BAR_WIDTH), "\u{2014}".to_string()),
        };

        let label = if row.name == "ALL (everything)" {
            "ALL (everything)".to_string()
        } else {
            format!("{} {}", row.step, row.name)
        };

        println!(
            "  {:<28} {:>9} {:>9}    {}  {:>10}",
            label, p50_str, rps_str, bar_str, overhead_str,
        );
    }

    // ── Overhead breakdown ──────────────────────────────────────────
    println!();
    println!("  Overhead breakdown:");

    // Compute per-feature cost as delta between consecutive steps.
    let mut feature_costs: Vec<(&str, Duration)> = Vec::new();
    for i in 1..rows.len() {
        // Skip the ALL row — it validates the sum, not an incremental cost.
        if rows[i].name == "ALL (everything)" {
            continue;
        }
        let prev_p50 = rows[i - 1].p50;
        let curr_p50 = rows[i].p50;
        let delta = curr_p50.saturating_sub(prev_p50);
        feature_costs.push((rows[i].name, delta));
    }

    let max_feature_cost = feature_costs
        .iter()
        .map(|(_, d)| *d)
        .max()
        .unwrap_or(Duration::ZERO);
    let total_overhead = rows
        .iter()
        .rev()
        .find(|r| r.name != "ALL (everything)")
        .and_then(|r| r.overhead)
        .unwrap_or(Duration::ZERO);
    let total_overhead_us = total_overhead.as_secs_f64() * 1_000_000.0;
    let max_feature_us = max_feature_cost.as_secs_f64() * 1_000_000.0;

    const BREAKDOWN_BAR_WIDTH: usize = 40;

    for (name, cost) in &feature_costs {
        let cost_us = cost.as_secs_f64() * 1_000_000.0;
        let pct = if total_overhead_us > 0.0 {
            (cost_us / total_overhead_us * 100.0).round() as u32
        } else {
            0
        };
        let proportion = if max_feature_us > 0.0 {
            cost_us / max_feature_us
        } else {
            0.0
        };
        let bar = render_bar(proportion, BREAKDOWN_BAR_WIDTH);
        let clean_name = name.strip_prefix("+ ").unwrap_or(name);
        println!(
            "    {:<18} {}  {:>3}%  {}",
            clean_name,
            bar,
            pct,
            format_us(Duration::from_secs_f64(cost_us / 1_000_000.0)),
        );
    }

    println!();
    let rss = current_rss_mb();
    println!("  Memory: {} RSS", rss);
    println!();

    Ok(())
}
