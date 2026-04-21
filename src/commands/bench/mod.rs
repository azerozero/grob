//! Self-contained performance evaluation of the grob proxy pipeline.
//!
//! Starts a mock backend, builds a minimal proxy with middleware layers,
//! runs scenarios with increasing feature combinations, and reports
//! latency percentiles plus overhead relative to the direct baseline.
//! Supports concurrent throughput testing and varied payload sizes.

mod mock;
mod output;
mod payloads;
mod scenarios;
mod stats;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::auth::virtual_keys::{generate_key, VirtualKeyRecord};
use crate::models::config::AppConfig;
use crate::storage::GrobStore;

use mock::{start_mock_backend, start_proxy, ProxyState};
use output::{
    print_escalation_table, print_matrix_table, print_overhead_breakdown, print_scenario_header,
    print_scenario_row, EscalationRow,
};
use payloads::{clean_request_body, secrets_request_body};
#[cfg(feature = "policies")]
use scenarios::build_bench_policies;
use scenarios::{build_escalation_steps, build_scenarios, compile_dlp_patterns, DlpPatternSet};
use stats::{
    compute_stats, current_rss_mb, format_us, run_concurrent, BenchResult, ScenarioResult,
    SystemInfo,
};

pub use payloads::{parse_payload_flag, PayloadSize};

// ── Constants ───────────────────────────────────────────────────────────

const WARMUP_REQUESTS: usize = 50;
const CONCURRENT_DURATION_SECS: u64 = 5;

// ── Shared context ──────────────────────────────────────────────────────

/// Groups the shared state threaded through every benchmark function.
struct BenchContext {
    backend_url: String,
    routing_patterns: Arc<Vec<regex::Regex>>,
    auth_token: Option<String>,
    auth_key_hash: Option<String>,
    requests: usize,
    effective_concurrency: usize,
    format: String,
}

impl BenchContext {
    /// Whether the benchmark runs in concurrent (throughput) mode.
    fn is_concurrent(&self) -> bool {
        self.effective_concurrency > 1
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

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

/// Polls a proxy health endpoint until it responds (max 500 ms).
async fn wait_for_proxy_ready(proxy_url: &str) {
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
}

// ── Entry point ─────────────────────────────────────────────────────────

/// Runs the self-contained benchmark against an in-process mock backend and prints latency percentiles.
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

    let ctx = BenchContext {
        backend_url: backend_url.clone(),
        routing_patterns,
        auth_token,
        auth_key_hash,
        requests,
        effective_concurrency,
        format: format.to_string(),
    };

    // ── Escalation mode ─────────────────────────────────────────────────
    if escalate {
        return run_escalation(&ctx).await;
    }

    let scenarios = build_scenarios(with_auth);
    let mut results: Vec<ScenarioResult> = Vec::new();
    // Track baseline P50 per payload size for overhead calculation.
    let mut baseline_p50: std::collections::HashMap<&str, Duration> =
        std::collections::HashMap::new();
    let mut header_printed = false;

    // For multi-payload matrix mode, collect per-size results then print at end.
    type MatrixRow = (String, Vec<stats::Stats>);
    let mut matrix_rows: Vec<MatrixRow> = Vec::new();

    for scenario in &scenarios {
        let is_direct = scenario.name == "direct (baseline)";
        let mut size_stats = Vec::new();

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
                #[cfg(feature = "policies")]
                let policy_matcher = if scenario.policy_rule_count > 0 {
                    let configs = build_bench_policies(scenario.policy_rule_count);
                    crate::features::policies::matcher::PolicyMatcher::new(configs)
                        .ok()
                        .map(std::sync::Arc::new)
                } else {
                    None
                };

                let state = ProxyState {
                    backend_url: backend_url.clone(),
                    client: build_bench_client(),
                    enable_routing: scenario.enable_routing,
                    enable_dlp: scenario.enable_dlp,
                    enable_auth: scenario.enable_auth,
                    enable_rate_limit: scenario.enable_rate_limit,
                    enable_cache: scenario.enable_cache,
                    auth_key_hash: ctx.auth_key_hash.clone(),
                    routing_patterns: ctx.routing_patterns.clone(),
                    dlp_patterns: effective_dlp_patterns,
                    #[cfg(feature = "policies")]
                    policy_matcher,
                };
                let (proxy_url, _proxy_handle) = start_proxy(state).await;
                wait_for_proxy_ready(&proxy_url).await;
                proxy_url
            };

            let (s, rps) = measure(&ctx, &target_url, &body, scenario.enable_auth).await?;

            if is_direct {
                baseline_p50.insert(psize.label(), s.p50);
            }

            let overhead_us = if is_direct {
                None
            } else {
                baseline_p50
                    .get(psize.label())
                    .map(|b| (s.p50.as_secs_f64() - b.as_secs_f64()) * 1_000_000.0)
            };

            results.push(ScenarioResult {
                name: scenario.name.to_string(),
                payload_size: psize.label().to_string(),
                p50_us: s.p50.as_secs_f64() * 1_000_000.0,
                p95_us: s.p95.as_secs_f64() * 1_000_000.0,
                p99_us: s.p99.as_secs_f64() * 1_000_000.0,
                overhead_us,
                rps,
            });

            if format != "json" && !is_multi_payload {
                if !header_printed {
                    print_scenario_header(is_concurrent, effective_concurrency);
                    header_printed = true;
                }
                print_scenario_row(scenario.name, &s, overhead_us, rps, is_concurrent);
            }

            size_stats.push(s);
        }

        if is_multi_payload && format != "json" {
            matrix_rows.push((scenario.name.to_string(), size_stats));
        }
    }

    if format != "json" && is_multi_payload {
        let size_labels: Vec<&str> = payload_sizes.iter().map(|s| s.label()).collect();
        print_matrix_table(&size_labels, &matrix_rows);
    }

    let rss = current_rss_mb();

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

// ── Shared measurement helper ────────────────────────────────────────────────

/// Runs warmup + timed requests for one scenario/payload combination.
///
/// Returns `(stats, Option<rps>)`.
async fn measure(
    ctx: &BenchContext,
    target_url: &str,
    body: &serde_json::Value,
    enable_auth: bool,
) -> Result<(stats::Stats, Option<f64>)> {
    let auth_token = &ctx.auth_token;
    let is_concurrent = ctx.is_concurrent();
    let effective_concurrency = ctx.effective_concurrency;
    let requests = ctx.requests;

    if is_concurrent {
        let warmup_client = reqwest::Client::builder()
            .pool_max_idle_per_host(10)
            .build()
            .unwrap();
        for _ in 0..WARMUP_REQUESTS {
            let mut req = warmup_client
                .post(format!("{target_url}/v1/messages"))
                .json(body);
            if enable_auth {
                if let Some(ref token) = auth_token {
                    req = req.header("authorization", format!("Bearer {token}"));
                }
            }
            if let Ok(resp) = req.send().await {
                let _ = resp.bytes().await;
            }
        }

        let (latencies, total) = run_concurrent(
            target_url,
            body,
            auth_token,
            enable_auth,
            effective_concurrency,
            CONCURRENT_DURATION_SECS,
        )
        .await;

        anyhow::ensure!(!latencies.is_empty(), "No requests completed");
        let rps_val = total as f64 / CONCURRENT_DURATION_SECS as f64;
        Ok((compute_stats(latencies), Some(rps_val)))
    } else {
        let client = build_bench_client();

        for _ in 0..WARMUP_REQUESTS {
            let mut req = client.post(format!("{target_url}/v1/messages")).json(body);
            if enable_auth {
                if let Some(ref token) = auth_token {
                    req = req.header("authorization", format!("Bearer {token}"));
                }
            }
            let resp = req.send().await?;
            let _ = resp.bytes().await;
        }

        let mut latencies = Vec::with_capacity(requests);
        for _ in 0..requests {
            let mut req = client.post(format!("{target_url}/v1/messages")).json(body);
            if enable_auth {
                if let Some(ref token) = auth_token {
                    req = req.header("authorization", format!("Bearer {token}"));
                }
            }
            let start = Instant::now();
            let resp = req.send().await?;
            let _ = resp.bytes().await;
            latencies.push(start.elapsed());
        }

        Ok((compute_stats(latencies), None))
    }
}

// ── Escalation mode ─────────────────────────────────────────────────────

/// Runs the escalation staircase benchmark, adding one pipeline feature per step to measure its cost.
async fn run_escalation(ctx: &BenchContext) -> Result<()> {
    // Escalation always uses medium payload (realistic Claude Code traffic).
    let psize = PayloadSize::Medium;
    let steps = build_escalation_steps();

    if ctx.format != "json" {
        println!();
        println!("  Feature Escalation ({})", psize.label());
        if ctx.is_concurrent() {
            println!(
                "  Mode: concurrent (c={}), {} sec/step",
                ctx.effective_concurrency, CONCURRENT_DURATION_SECS
            );
        } else {
            println!("  Requests: {} per step", ctx.requests);
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
            ctx.backend_url.clone()
        } else {
            let dlp_pats = match step.dlp_pattern_set {
                Some(set) => compile_dlp_patterns(set),
                None => Arc::new(Vec::new()),
            };
            let state = ProxyState {
                backend_url: ctx.backend_url.clone(),
                client: build_bench_client(),
                enable_routing: step.enable_routing,
                enable_dlp: step.enable_dlp,
                enable_auth: step.enable_auth,
                enable_rate_limit: step.enable_rate_limit,
                enable_cache: step.enable_cache,
                auth_key_hash: ctx.auth_key_hash.clone(),
                routing_patterns: ctx.routing_patterns.clone(),
                dlp_patterns: dlp_pats,
                #[cfg(feature = "policies")]
                policy_matcher: None,
            };
            let (proxy_url, _handle) = start_proxy(state).await;
            wait_for_proxy_ready(&proxy_url).await;
            proxy_url
        };

        let (s, rps) = measure(ctx, &target_url, &body, step.enable_auth).await?;

        if is_direct {
            baseline_p50 = Some(s.p50);
        }

        let overhead = baseline_p50.and_then(|b| {
            if is_direct {
                None
            } else {
                Some(s.p50.saturating_sub(b))
            }
        });

        let label = format!("{} {}", idx, step.name);
        rows.push(EscalationRow {
            label,
            p50: s.p50,
            rps,
            overhead,
        });
    }

    // Run the "ALL" step with every feature enabled.
    {
        let all_dlp = compile_dlp_patterns(DlpPatternSet::Full);
        let state = ProxyState {
            backend_url: ctx.backend_url.clone(),
            client: build_bench_client(),
            enable_routing: true,
            enable_dlp: true,
            enable_auth: ctx.auth_token.is_some(),
            enable_rate_limit: true,
            enable_cache: true,
            auth_key_hash: ctx.auth_key_hash.clone(),
            routing_patterns: ctx.routing_patterns.clone(),
            dlp_patterns: all_dlp,
            #[cfg(feature = "policies")]
            policy_matcher: None,
        };
        let (proxy_url, _handle) = start_proxy(state).await;
        wait_for_proxy_ready(&proxy_url).await;

        let body = secrets_request_body(psize);
        let (s, rps) = measure(ctx, &proxy_url, &body, ctx.auth_token.is_some()).await?;

        let overhead = baseline_p50.map(|b| s.p50.saturating_sub(b));

        rows.push(EscalationRow {
            label: "ALL (everything)".to_string(),
            p50: s.p50,
            rps,
            overhead,
        });
    }

    // ── Render output ────────────────────────────────────────────────
    if ctx.format == "json" {
        let json_rows: Vec<ScenarioResult> = rows
            .iter()
            .map(|r| ScenarioResult {
                name: r.label.clone(),
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
                cpu_count: std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1),
                grob_version: env!("CARGO_PKG_VERSION").to_string(),
            },
            requests_per_scenario: ctx.requests,
            concurrency: ctx.effective_concurrency,
            payload_sizes: vec![psize.label().to_string()],
            scenarios: json_rows,
            verdict: "escalation".to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    print_escalation_table(&rows);

    // Compute per-feature costs as delta between consecutive steps.
    let mut feature_costs: Vec<(&str, Duration)> = Vec::new();
    for i in 1..rows.len() {
        if rows[i].label == "ALL (everything)" {
            continue;
        }
        let delta = rows[i].p50.saturating_sub(rows[i - 1].p50);
        feature_costs.push((&rows[i].label, delta));
    }

    let total_overhead = rows
        .iter()
        .rev()
        .find(|r| r.label != "ALL (everything)")
        .and_then(|r| r.overhead)
        .unwrap_or(Duration::ZERO);

    print_overhead_breakdown(&feature_costs, total_overhead);

    println!();
    println!("  Memory: {} RSS", current_rss_mb());
    println!();

    Ok(())
}
