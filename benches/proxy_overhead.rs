//! End-to-end HTTP proxy overhead benchmarks.
//!
//! Measures real RTT through a grob-like proxy pipeline with a zero-latency
//! mock backend. Since the mock responds instantly, measured latency equals
//! proxy overhead.
//!
//! Run: cargo bench --bench proxy_overhead --features harness
//!
//! Seven scenarios exercise progressively heavier middleware stacks:
//! baseline, routing, cache miss, rate limiting, DLP clean, DLP secrets, all.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::net::TcpListener;

// ── Constants ───────────────────────────────────────────────────────────

const WARMUP_REQUESTS: usize = 100;
const MEASURED_REQUESTS: usize = 1000;

// ── Mock backend ────────────────────────────────────────────────────────

/// Starts a mock backend on an ephemeral port that returns a canned Anthropic
/// response with zero latency.
async fn start_mock_backend() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

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

// ── Proxy middleware components ─────────────────────────────────────────

/// Shared proxy state passed to middleware layers.
#[derive(Clone)]
struct ProxyState {
    backend_url: String,
    client: reqwest::Client,
    /// Scenario flags.
    enable_routing: bool,
    enable_cache_lookup: bool,
    enable_rate_limit: bool,
    enable_dlp: bool,
    /// Pre-compiled routing patterns (mirrors grob's CompiledPromptRule).
    routing_patterns: Arc<Vec<regex::Regex>>,
    /// Pre-compiled DLP secret/PII patterns (mirrors grob's DFA scanner).
    dlp_patterns: Arc<Vec<regex::Regex>>,
}

/// Request ID middleware (always on — mirrors grob's request_id_middleware).
async fn request_id_mw(mut req: Request<Body>, next: Next) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    req.extensions_mut().insert(id.clone());
    let mut resp = next.run(req).await;
    if let Ok(val) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", val);
    }
    resp
}

/// Security headers middleware (always on — mirrors grob's security_headers).
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

/// Simulated routing middleware: matches pre-compiled regex patterns against
/// user prompt text. Mirrors grob's router which pre-compiles patterns at
/// startup and only runs `is_match` per request.
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

/// Simulated cache lookup middleware: computes a SHA-256 hash of the body
/// and does a HashMap lookup (miss path — mirrors grob's cache miss).
async fn cache_mw(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if state.enable_cache_lookup {
        use sha2::{Digest, Sha256};
        let cache: std::collections::HashMap<String, ()> = std::collections::HashMap::new();
        let mut hasher = Sha256::new();
        hasher.update(b"model:mock-model:messages:Hello");
        let key = hex::encode(hasher.finalize());
        let _ = cache.get(&key);
    }
    next.run(req).await
}

/// Simulated rate-limit check middleware: increments an atomic counter and
/// compares against a threshold (mirrors governor-style check).
async fn rate_limit_mw(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if state.enable_rate_limit {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        // High limit — never triggers, but does the atomic work.
        if count > 1_000_000_000 {
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Body::empty())
                .unwrap();
        }
    }
    next.run(req).await
}

/// Simulated DLP scan middleware: runs pre-compiled regex patterns against
/// body text to detect secrets/PII. Mirrors grob's DLP engine which
/// pre-compiles all patterns at startup.
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

    // Reconstruct the request with the consumed body.
    let req = Request::builder()
        .method(axum::http::Method::POST)
        .uri("/v1/messages")
        .header("content-type", "application/json")
        .body(Body::from(body_bytes))
        .unwrap();

    next.run(req).await
}

/// Core proxy handler: forwards the request to the mock backend.
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

// ── Proxy server builder ────────────────────────────────────────────────

/// Builds and starts a proxy server with the specified scenario config.
async fn start_proxy(state: ProxyState) -> (String, tokio::task::JoinHandle<()>) {
    let shared = Arc::new(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);

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
        .layer(middleware::from_fn_with_state(
            shared.clone(),
            rate_limit_mw,
        ))
        .layer(middleware::from_fn_with_state(shared.clone(), cache_mw))
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
    description: &'static str,
    enable_routing: bool,
    enable_cache_lookup: bool,
    enable_rate_limit: bool,
    enable_dlp: bool,
    /// If true, embeds fake secrets in the request body.
    inject_secrets: bool,
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "baseline",
            description: "No DLP, no cache, no rate limit, no routing — pure proxy overhead",
            enable_routing: false,
            enable_cache_lookup: false,
            enable_rate_limit: false,
            enable_dlp: false,
            inject_secrets: false,
        },
        Scenario {
            name: "with_routing",
            description: "Regex prompt rules active",
            enable_routing: true,
            enable_cache_lookup: false,
            enable_rate_limit: false,
            enable_dlp: false,
            inject_secrets: false,
        },
        Scenario {
            name: "with_cache_miss",
            description: "Cache enabled, unique requests (miss path)",
            enable_routing: false,
            enable_cache_lookup: true,
            enable_rate_limit: false,
            enable_dlp: false,
            inject_secrets: false,
        },
        Scenario {
            name: "with_rate_limiting",
            description: "Rate limiter enabled (high limit, never triggers)",
            enable_routing: false,
            enable_cache_lookup: false,
            enable_rate_limit: true,
            enable_dlp: false,
            inject_secrets: false,
        },
        Scenario {
            name: "with_dlp_clean",
            description: "DLP enabled, clean text payload (fast path)",
            enable_routing: false,
            enable_cache_lookup: false,
            enable_rate_limit: false,
            enable_dlp: true,
            inject_secrets: false,
        },
        Scenario {
            name: "with_dlp_secrets",
            description: "DLP enabled, payload with embedded secrets",
            enable_routing: false,
            enable_cache_lookup: false,
            enable_rate_limit: false,
            enable_dlp: true,
            inject_secrets: true,
        },
        Scenario {
            name: "with_all",
            description: "Everything enabled — full middleware stack",
            enable_routing: true,
            enable_cache_lookup: true,
            enable_rate_limit: true,
            enable_dlp: true,
            inject_secrets: false,
        },
    ]
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

// ── Percentile computation ──────────────────────────────────────────────

struct Stats {
    min: Duration,
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
    mean: Duration,
}

fn compute_stats(mut latencies: Vec<Duration>) -> Stats {
    latencies.sort();
    let n = latencies.len();
    let sum: Duration = latencies.iter().sum();
    Stats {
        min: latencies[0],
        p50: latencies[n / 2],
        p95: latencies[n * 95 / 100],
        p99: latencies[n * 99 / 100],
        max: latencies[n - 1],
        mean: sum / n as u32,
    }
}

fn format_us(d: Duration) -> String {
    format!("{:.0}us", d.as_secs_f64() * 1_000_000.0)
}

fn print_stats(name: &str, description: &str, stats: &Stats) {
    println!("  {:<25} {}", name, description);
    println!(
        "    min={:<10} P50={:<10} P95={:<10} P99={:<10} max={:<10} mean={}",
        format_us(stats.min),
        format_us(stats.p50),
        format_us(stats.p95),
        format_us(stats.p99),
        format_us(stats.max),
        format_us(stats.mean),
    );
    println!();
}

// ── Main benchmark runner ───────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!();
    println!("=== Grob Proxy Overhead Benchmark ===");
    println!("  Warmup: {} requests", WARMUP_REQUESTS);
    println!("  Measured: {} requests per scenario", MEASURED_REQUESTS);
    println!();

    // Start mock backend (shared across all scenarios).
    let (backend_url, _mock_handle) = start_mock_backend().await;

    // Verify mock is reachable.
    let probe_client = reqwest::Client::new();
    let probe_resp = probe_client
        .post(format!("{}/v1/messages", backend_url))
        .json(&clean_request_body())
        .send()
        .await
        .expect("Mock backend unreachable");
    assert_eq!(probe_resp.status(), 200, "Mock backend returned non-200");

    println!("--- Results (lower = better) ---");
    println!();

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

    for scenario in scenarios() {
        let state = ProxyState {
            backend_url: backend_url.clone(),
            client: reqwest::Client::builder()
                .pool_max_idle_per_host(10)
                .pool_idle_timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            enable_routing: scenario.enable_routing,
            enable_cache_lookup: scenario.enable_cache_lookup,
            enable_rate_limit: scenario.enable_rate_limit,
            enable_dlp: scenario.enable_dlp,
            routing_patterns: routing_patterns.clone(),
            dlp_patterns: dlp_patterns.clone(),
        };

        let (proxy_url, _proxy_handle) = start_proxy(state).await;

        // Use a dedicated client for this scenario.
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let body = if scenario.inject_secrets {
            secrets_request_body()
        } else {
            clean_request_body()
        };

        // Wait for proxy to be ready.
        for _ in 0..50 {
            if client
                .get(format!("{}/health", proxy_url))
                .send()
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Warmup.
        for _ in 0..WARMUP_REQUESTS {
            let resp = client
                .post(format!("{}/v1/messages", proxy_url))
                .json(&body)
                .send()
                .await
                .expect("Warmup request failed");
            let _ = resp.bytes().await;
        }

        // Measured run.
        let mut latencies = Vec::with_capacity(MEASURED_REQUESTS);
        for _ in 0..MEASURED_REQUESTS {
            let start = Instant::now();
            let resp = client
                .post(format!("{}/v1/messages", proxy_url))
                .json(&body)
                .send()
                .await
                .expect("Benchmark request failed");
            let _ = resp.bytes().await;
            latencies.push(start.elapsed());
        }

        let stats = compute_stats(latencies);
        print_stats(scenario.name, scenario.description, &stats);
    }

    println!("=== Done ===");
}
