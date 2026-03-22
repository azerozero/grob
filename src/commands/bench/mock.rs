//! Mock backend, proxy state, middleware layers, and proxy builder.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::net::TcpListener;

// ── Mock backend ────────────────────────────────────────────────────────

/// Starts a mock Anthropic Messages API backend on an ephemeral port.
pub(super) async fn start_mock_backend() -> (String, tokio::task::JoinHandle<()>) {
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
pub(super) struct ProxyState {
    pub(super) backend_url: String,
    pub(super) client: reqwest::Client,
    pub(super) enable_routing: bool,
    pub(super) enable_dlp: bool,
    pub(super) enable_auth: bool,
    pub(super) enable_rate_limit: bool,
    pub(super) enable_cache: bool,
    /// SHA-256 hash of the valid virtual key (for auth scenarios).
    pub(super) auth_key_hash: Option<String>,
    pub(super) routing_patterns: Arc<Vec<regex::Regex>>,
    pub(super) dlp_patterns: Arc<Vec<regex::Regex>>,
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

/// Simulated rate-limit check: atomic counter + window comparison.
async fn rate_limit_mw(
    State(state): State<Arc<ProxyState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if state.enable_rate_limit {
        // Simulate token-bucket overhead: atomic load + comparison.
        let counter = AtomicUsize::new(0);
        let _count = counter.fetch_add(1, Ordering::Relaxed);
        // Always allow in bench — measures pure overhead of the check.
    }
    next.run(req).await
}

/// Simulated cache lookup: SHA-256 hash of first 256 bytes as cache key.
async fn cache_mw(
    State(state): State<Arc<ProxyState>>,
    body_bytes: axum::body::Bytes,
    next: Next,
) -> Response {
    if state.enable_cache {
        use sha2::{Digest, Sha256};
        let key_slice = &body_bytes[..body_bytes.len().min(256)];
        let _cache_key = hex::encode(Sha256::digest(key_slice));
        // Simulate cache miss — always forward.
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

pub(super) async fn start_proxy(state: ProxyState) -> (String, tokio::task::JoinHandle<()>) {
    let shared = Arc::new(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    let app = Router::new()
        .route("/v1/messages", post(proxy_handler))
        .route("/health", get(|| async { "ok" }));

    // Layer order mirrors grob's middleware stack (outermost first).
    // DLP is the innermost content-inspecting layer.
    let app = if shared.enable_dlp {
        app.layer(middleware::from_fn_with_state(shared.clone(), dlp_mw))
    } else {
        app
    };

    // Cache layer sits before DLP.
    let app = if shared.enable_cache {
        app.layer(middleware::from_fn_with_state(shared.clone(), cache_mw))
    } else {
        app
    };

    let app = app
        .layer(middleware::from_fn_with_state(
            shared.clone(),
            rate_limit_mw,
        ))
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
