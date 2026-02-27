//! HTTP stack overhead benchmark — measures the real cost of:
//!   - TCP connect + keep-alive reuse
//!   - TLS handshake (rustls)
//!   - axum routing + middleware (request ID, body limit, security headers)
//!   - hyper HTTP/1.1 framing
//!   - serde_json body parse + serialize
//!
//! Run: cargo bench --bench http_overhead --features tls
//!
//! This spins up real axum servers on localhost and hits them with reqwest.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::OnceLock;
use std::time::Duration;

struct ServerState {
    rt: tokio::runtime::Runtime,
    http_url: String,
    tls_url: String,
    _tmp: tempfile::TempDir,
}

static SERVER: OnceLock<ServerState> = OnceLock::new();

fn get_server() -> &'static ServerState {
    SERVER.get_or_init(|| {
        // Install rustls crypto provider (ring)
        let _ = rustls::crypto::ring::default_provider().install_default();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let (http_url, tls_url, tmp) = rt.block_on(async {
            // ── HTTP server ──────────────────────────────────────
            let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let http_port = http_listener.local_addr().unwrap().port();

            use axum::{
                body::Body,
                extract::Request,
                http::{HeaderValue, StatusCode},
                middleware::{self, Next},
                response::{IntoResponse, Response},
                routing::{get, post},
                Json, Router,
            };

            async fn request_id_mw(mut req: Request<Body>, next: Next) -> Response {
                let id = req
                    .headers()
                    .get("x-request-id")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
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

            async fn echo_handler(Json(body): Json<serde_json::Value>) -> impl IntoResponse {
                let model = body
                    .get("model")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                Json(serde_json::json!({
                    "id": "msg_bench",
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [{"type": "text", "text": "ok"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 10, "output_tokens": 1}
                }))
            }

            async fn health() -> impl IntoResponse {
                (StatusCode::OK, "ok")
            }

            let http_app = Router::new()
                .route("/v1/messages", post(echo_handler))
                .route("/health", get(health))
                .layer(middleware::from_fn(security_headers_mw))
                .layer(tower_http::limit::RequestBodyLimitLayer::new(
                    10 * 1024 * 1024,
                ))
                .layer(middleware::from_fn(request_id_mw));

            tokio::spawn(async move {
                axum::serve(http_listener, http_app).await.unwrap();
            });

            // ── TLS server ───────────────────────────────────────
            use std::io::Write;

            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let cert_pem = cert.cert.pem();
            let key_pem = cert.key_pair.serialize_pem();

            let tmp = tempfile::TempDir::new().unwrap();
            let cert_path = tmp.path().join("cert.pem");
            let key_path = tmp.path().join("key.pem");
            std::fs::File::create(&cert_path)
                .unwrap()
                .write_all(cert_pem.as_bytes())
                .unwrap();
            std::fs::File::create(&key_path)
                .unwrap()
                .write_all(key_pem.as_bytes())
                .unwrap();

            use axum_server::tls_rustls::RustlsConfig;
            let rustls_config = RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .unwrap();

            let tls_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let tls_port = tls_listener.local_addr().unwrap().port();
            drop(tls_listener);

            let tls_app = Router::new().route("/health", get(health));

            tokio::spawn(async move {
                axum_server::bind_rustls(
                    format!("127.0.0.1:{}", tls_port).parse().unwrap(),
                    rustls_config,
                )
                .serve(tls_app.into_make_service())
                .await
                .unwrap();
            });

            // Wait for both servers
            let http_url = format!("http://127.0.0.1:{}", http_port);
            let tls_url = format!("https://127.0.0.1:{}", tls_port);

            let probe = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();
            for _ in 0..100 {
                let http_ok = probe
                    .get(format!("{}/health", http_url))
                    .send()
                    .await
                    .is_ok();
                let tls_ok = probe
                    .get(format!("{}/health", tls_url))
                    .send()
                    .await
                    .is_ok();
                if http_ok && tls_ok {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            (http_url, tls_url, tmp)
        });

        ServerState {
            rt,
            http_url,
            tls_url,
            _tmp: tmp,
        }
    })
}

fn make_request_json() -> serde_json::Value {
    serde_json::json!({
        "model": "claude-sonnet-4-6",
        "messages": [{"role": "user", "content": "Hello"}],
        "max_tokens": 1024
    })
}

fn make_large_request_json() -> serde_json::Value {
    let messages: Vec<serde_json::Value> = (0..20)
        .map(|i| {
            serde_json::json!({
                "role": if i % 2 == 0 { "user" } else { "assistant" },
                "content": format!("Message {} with typical content for a real conversation.", i)
            })
        })
        .collect();
    serde_json::json!({
        "model": "claude-sonnet-4-6",
        "messages": messages,
        "max_tokens": 4096,
        "system": "You are a helpful assistant."
    })
}

fn bench_http(c: &mut Criterion) {
    let srv = get_server();

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    // Warm up
    srv.rt.block_on(async {
        let _ = client.get(format!("{}/health", srv.http_url)).send().await;
    });

    let mut group = c.benchmark_group("http");

    // 1. GET /health keep-alive (pure HTTP overhead: hyper + axum + middleware)
    group.bench_function("health_keepalive", |b| {
        b.to_async(&srv.rt).iter(|| async {
            let resp = client
                .get(format!("{}/health", srv.http_url))
                .send()
                .await
                .unwrap();
            black_box(resp.status())
        })
    });

    // 2. POST small JSON keep-alive (HTTP + serde parse + serde response)
    let small_body = make_request_json();
    group.bench_function("post_small_keepalive", |b| {
        b.to_async(&srv.rt).iter(|| {
            let body = small_body.clone();
            let c = &client;
            async move {
                let resp = c
                    .post(format!("{}/v1/messages", srv.http_url))
                    .json(&body)
                    .send()
                    .await
                    .unwrap();
                let bytes = resp.bytes().await.unwrap();
                black_box(bytes.len())
            }
        })
    });

    // 3. POST large JSON keep-alive (20 messages)
    let large_body = make_large_request_json();
    group.bench_function("post_large_keepalive", |b| {
        b.to_async(&srv.rt).iter(|| {
            let body = large_body.clone();
            let c = &client;
            async move {
                let resp = c
                    .post(format!("{}/v1/messages", srv.http_url))
                    .json(&body)
                    .send()
                    .await
                    .unwrap();
                let bytes = resp.bytes().await.unwrap();
                black_box(bytes.len())
            }
        })
    });

    group.finish();
}

fn bench_tls(c: &mut Criterion) {
    let srv = get_server();

    let tls_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .pool_max_idle_per_host(10)
        .build()
        .unwrap();

    // Warm up
    srv.rt.block_on(async {
        let _ = tls_client
            .get(format!("{}/health", srv.tls_url))
            .send()
            .await;
    });

    let mut group = c.benchmark_group("tls");

    // TLS keep-alive (amortized handshake)
    group.bench_function("health_tls_keepalive", |b| {
        b.to_async(&srv.rt).iter(|| async {
            let resp = tls_client
                .get(format!("{}/health", srv.tls_url))
                .send()
                .await
                .unwrap();
            black_box(resp.status())
        })
    });

    // TLS fresh handshake — create a new client with pool size 1, do 1 request
    // (measures full TLS handshake cost; rate-limited to avoid port exhaustion)
    group.sample_size(20);
    group.bench_function("health_tls_fresh_handshake", |b| {
        b.to_async(&srv.rt).iter(|| async {
            let fresh = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .pool_max_idle_per_host(0)
                .no_proxy()
                .build()
                .unwrap();
            let resp = fresh
                .get(format!("{}/health", srv.tls_url))
                .send()
                .await
                .unwrap();
            // Read body to completion so connection fully closes
            let _ = resp.bytes().await;
            // Brief pause to let TIME_WAIT sockets recycle
            tokio::time::sleep(Duration::from_millis(5)).await;
            black_box(())
        })
    });

    group.finish();
}

criterion_group!(benches, bench_http, bench_tls);
criterion_main!(benches);
