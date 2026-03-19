//! Self-contained performance evaluation of the grob proxy pipeline.
//!
//! Starts a mock backend, builds a minimal proxy with middleware layers,
//! runs scenarios with increasing feature combinations, and reports
//! latency percentiles plus overhead relative to the direct baseline.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::net::TcpListener;

use crate::auth::virtual_keys::{generate_key, VirtualKeyRecord};
use crate::cli::AppConfig;
use crate::storage::GrobStore;

// ── Constants ───────────────────────────────────────────────────────────

const WARMUP_REQUESTS: usize = 50;

// ── Mock backend ────────────────────────────────────────────────────────

/// Starts a mock Anthropic Messages API backend on an ephemeral port.
async fn start_mock_backend() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    let handle = tokio::spawn(async move {
        let app = Router::new()
            .route("/v1/messages", post(mock_handler))
            .route("/v1/chat/completions", post(mock_handler));
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

async fn mock_handler(Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let model = body
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("mock-model");
    Json(serde_json::json!({
        "id": "msg_bench_001",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": "Benchmark response."}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 10, "output_tokens": 3}
    }))
}

// ── Proxy state ─────────────────────────────────────────────────────────

#[derive(Clone)]
struct ProxyState {
    backend_url: String,
    client: reqwest::Client,
    enable_routing: bool,
    enable_dlp: bool,
    enable_auth: bool,
    /// SHA-256 hash of the valid virtual key (for auth scenarios).
    auth_key_hash: Option<String>,
    routing_patterns: Arc<Vec<regex::Regex>>,
    dlp_patterns: Arc<Vec<regex::Regex>>,
}

// ── Middleware layers ───────────────────────────────────────────────────

async fn request_id_mw(mut req: Request<Body>, next: Next) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    req.extensions_mut().insert(id.clone());
    let mut resp = next.run(req).await;
    if let Ok(val) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", val);
    }
    resp
}

async fn security_headers_mw(req: Request<Body>, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    resp
}

/// Simulated auth middleware: SHA-256 hash of the bearer token + lookup.
async fn auth_mw(State(state): State<Arc<ProxyState>>, req: Request<Body>, next: Next) -> Response {
    if !state.enable_auth {
        return next.run(req).await;
    }

    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match (token, &state.auth_key_hash) {
        (Some(t), Some(expected_hash)) => {
            use sha2::{Digest, Sha256};
            let hash = hex::encode(Sha256::digest(t.as_bytes()));
            if hash == *expected_hash {
                next.run(req).await
            } else {
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from(r#"{"error":"invalid key"}"#))
                    .unwrap()
            }
        }
        _ => Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from(r#"{"error":"missing key"}"#))
            .unwrap(),
    }
}

/// Simulated routing middleware: matches pre-compiled regex patterns.
async fn routing_mw(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if state.enable_routing {
        let probe = "Hello, please help me with this benchmark test.";
        for pat in state.routing_patterns.iter() {
            let _ = pat.is_match(probe);
        }
    }
    next.run(req).await
}

/// Simulated DLP scan middleware: runs pre-compiled regex patterns.
async fn dlp_mw(
    State(state): State<Arc<ProxyState>>,
    body_bytes: axum::body::Bytes,
    next: Next,
) -> Response {
    if state.enable_dlp {
        let text = String::from_utf8_lossy(&body_bytes);
        for pat in state.dlp_patterns.iter() {
            let _ = pat.is_match(&text);
        }
    }

    let req = Request::builder()
        .method(axum::http::Method::POST)
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(body_bytes))
        .unwrap();

    next.run(req).await
}

/// Forwards the request to the mock backend.
async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, StatusCode> {
    let resp = state
        .client
        .post(format!("{}/v1/messages", state.backend_url))
        .json(&body)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let status = resp.status();
    let resp_bytes = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

    Ok(Response::builder()
        .status(status.as_u16())
        .header("content-type", "application/json")
        .body(Body::from(resp_bytes))
        .unwrap())
}

// ── Proxy builder ───────────────────────────────────────────────────────

async fn start_proxy(state: ProxyState) -> (String, tokio::task::JoinHandle<()>) {
    let shared = Arc::new(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    let app = Router::new()
        .route("/v1/messages", post(proxy_handler))
        .route("/health", get(|| async { "ok" }));

    // Layer order mirrors grob's middleware stack (outermost first).
    let app = if shared.enable_dlp {
        app.layer(middleware::from_fn_with_state(shared.clone(), dlp_mw))
    } else {
        app
    };

    let app = app
        .layer(middleware::from_fn_with_state(shared.clone(), auth_mw))
        .layer(middleware::from_fn_with_state(shared.clone(), routing_mw))
        .layer(middleware::from_fn(security_headers_mw))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            10 * 1024 * 1024,
        ))
        .layer(middleware::from_fn(request_id_mw))
        .with_state(shared);

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

// ── Scenario definitions ────────────────────────────────────────────────

struct Scenario {
    name: &'static str,
    enable_routing: bool,
    enable_dlp: bool,
    enable_auth: bool,
    inject_secrets: bool,
}

fn build_scenarios(with_auth: bool) -> Vec<Scenario> {
    let mut scenarios = vec![
        Scenario {
            name: "direct (baseline)",
            enable_routing: false,
            enable_dlp: false,
            enable_auth: false,
            inject_secrets: false,
        },
        Scenario {
            name: "proxy",
            enable_routing: false,
            enable_dlp: false,
            enable_auth: false,
            inject_secrets: false,
        },
    ];

    if with_auth {
        scenarios.push(Scenario {
            name: "proxy+auth",
            enable_routing: false,
            enable_dlp: false,
            enable_auth: true,
            inject_secrets: false,
        });
    }

    scenarios.push(Scenario {
        name: "proxy+dlp (clean)",
        enable_routing: true,
        enable_dlp: true,
        enable_auth: false,
        inject_secrets: false,
    });

    scenarios.push(Scenario {
        name: "proxy+dlp (trigger)",
        enable_routing: true,
        enable_dlp: true,
        enable_auth: false,
        inject_secrets: true,
    });

    scenarios.push(Scenario {
        name: "proxy+all",
        enable_routing: true,
        enable_dlp: true,
        enable_auth: with_auth,
        inject_secrets: false,
    });

    scenarios
}

// ── Request payloads ────────────────────────────────────────────────────

fn clean_request_body() -> serde_json::Value {
    serde_json::json!({
        "model": "mock-model",
        "messages": [{"role": "user", "content": "Hello, please help me with this benchmark test."}],
        "max_tokens": 1024
    })
}

fn secrets_request_body() -> serde_json::Value {
    serde_json::json!({
        "model": "mock-model",
        "messages": [{
            "role": "user",
            "content": "Here is my config: AKIAIOSFODNN7EXAMPLE and sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"
        }],
        "max_tokens": 1024
    })
}

// ── Statistics ──────────────────────────────────────────────────────────

struct Stats {
    p50: Duration,
    p95: Duration,
    p99: Duration,
}

fn compute_stats(mut latencies: Vec<Duration>) -> Stats {
    latencies.sort();
    let n = latencies.len();
    Stats {
        p50: latencies[n / 2],
        p95: latencies[n * 95 / 100],
        p99: latencies[n * 99 / 100],
    }
}

fn format_us(d: Duration) -> String {
    let us = d.as_secs_f64() * 1_000_000.0;
    if us >= 1000.0 {
        format!("{:.1}ms", us / 1000.0)
    } else {
        format!("{:.0}us", us)
    }
}

// ── Result types for JSON output ────────────────────────────────────────

#[derive(serde::Serialize)]
struct BenchResult {
    system: SystemInfo,
    requests_per_scenario: usize,
    scenarios: Vec<ScenarioResult>,
    verdict: String,
}

#[derive(serde::Serialize)]
struct SystemInfo {
    os: String,
    arch: String,
    cpu_count: usize,
    grob_version: String,
}

#[derive(serde::Serialize)]
struct ScenarioResult {
    name: String,
    p50_us: f64,
    p95_us: f64,
    p99_us: f64,
    overhead_us: Option<f64>,
}

// ── Memory measurement ──────────────────────────────────────────────────

/// Reads current process RSS on macOS/Linux. Returns "N/A" on failure.
fn current_rss_mb() -> String {
    #[cfg(target_os = "macos")]
    {
        // Read from mach task_info via rusage.
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
                        .trim()
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

// ── Entry point ─────────────────────────────────────────────────────────

/// Runs the self-contained performance benchmark.
pub async fn cmd_bench(
    _config: &AppConfig,
    requests: usize,
    with_auth: bool,
    format: &str,
) -> Result<()> {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let version = env!("CARGO_PKG_VERSION");

    if format != "json" {
        println!();
        println!("Grob Performance Evaluation");
        println!(
            "  System: {} {}, {} cores, grob v{}",
            os, arch, cpu_count, version
        );
        println!("  Requests: {} per scenario", requests);
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
        // Auth middleware in bench uses SHA-256 hash comparison directly,
        // so pass the hash for lookup.
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
    let probe_resp = probe_client
        .post(format!("{}/v1/messages", backend_url))
        .json(&clean_request_body())
        .send()
        .await?;
    anyhow::ensure!(probe_resp.status() == 200, "Mock backend returned non-200");

    let scenarios = build_scenarios(with_auth);
    let mut results: Vec<ScenarioResult> = Vec::new();
    let mut baseline_p50: Option<Duration> = None;

    for scenario in &scenarios {
        let body = if scenario.inject_secrets {
            secrets_request_body()
        } else {
            clean_request_body()
        };

        let is_direct = scenario.name == "direct (baseline)";

        let target_url = if is_direct {
            backend_url.clone()
        } else {
            let state = ProxyState {
                backend_url: backend_url.clone(),
                client: reqwest::Client::builder()
                    .pool_max_idle_per_host(10)
                    .pool_idle_timeout(Duration::from_secs(30))
                    .build()
                    .unwrap(),
                enable_routing: scenario.enable_routing,
                enable_dlp: scenario.enable_dlp,
                enable_auth: scenario.enable_auth,
                auth_key_hash: auth_key_hash.clone(),
                routing_patterns: routing_patterns.clone(),
                dlp_patterns: dlp_patterns.clone(),
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

        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .unwrap();

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

        let stats = compute_stats(latencies);

        if is_direct {
            baseline_p50 = Some(stats.p50);
        }

        let overhead_us = if is_direct {
            None
        } else {
            baseline_p50.map(|b| (stats.p50.as_secs_f64() - b.as_secs_f64()) * 1_000_000.0)
        };

        results.push(ScenarioResult {
            name: scenario.name.to_string(),
            p50_us: stats.p50.as_secs_f64() * 1_000_000.0,
            p95_us: stats.p95.as_secs_f64() * 1_000_000.0,
            p99_us: stats.p99.as_secs_f64() * 1_000_000.0,
            overhead_us,
        });

        if format != "json" {
            let overhead_str = match overhead_us {
                Some(us) => format!("+{}", format_us(Duration::from_secs_f64(us / 1_000_000.0))),
                None => "\u{2014}".to_string(), // em-dash
            };
            if results.len() == 1 {
                // Print table header before first row.
                println!(
                    "  {:<22} {:>9} {:>9} {:>9} {:>10}",
                    "Scenario", "P50", "P95", "P99", "Overhead"
                );
                println!("  {}", "\u{2500}".repeat(63));
            }
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

    let rss = current_rss_mb();

    // Determine verdict based on the "proxy+all" overhead.
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
        let output = BenchResult {
            system: SystemInfo {
                os: os.to_string(),
                arch: arch.to_string(),
                cpu_count,
                grob_version: version.to_string(),
            },
            requests_per_scenario: requests,
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
