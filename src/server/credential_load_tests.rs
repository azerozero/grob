//! Opt-in HTTP load probe against the real router and an in-process mock issuer.

use super::*;
use axum::{extract::State, http::HeaderMap, routing::post, Json};
use secrecy::SecretString;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::Instant;

#[derive(Default)]
struct Backend {
    old: AtomicUsize,
    new: AtomicUsize,
}

async fn upstream(
    State(state): State<Arc<Backend>>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap()
    {
        "Bearer synthetic-first" => {
            state.old.fetch_add(1, Ordering::Relaxed);
        }
        "Bearer synthetic-second" => {
            state.new.fetch_add(1, Ordering::Relaxed);
        }
        _ => panic!("unexpected authorization in synthetic load request"),
    }
    Json(
        json!({"id":"load","object":"chat.completion","model":"alpha","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}),
    )
}

async fn serve(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            socket,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (url, task)
}

fn configure(state: &Arc<AppState>, backend: &str, live: bool) {
    let mut config = state.snapshot().config.clone();
    config.cache.enabled = false;
    let provider = &mut config.providers[0];
    provider.base_url = Some(format!("{backend}/v1"));
    provider.api_key = Some(SecretString::from(if live {
        "secret:upstream"
    } else {
        "synthetic-first"
    }));
    provider.pool = None;
    provider.headers = None;
    let secrets = crate::storage::secrets::build_backend(&config.secrets, state.grob_store.clone());
    let registry = crate::providers::ProviderRegistry::from_configs_with_models(
        &config.providers,
        secrets,
        Some(state.token_store.clone()),
        &config.models,
        &config.server.timeouts,
    )
    .unwrap();
    *state.inner.write().unwrap() = Arc::new(ReloadableState::new(
        config.clone(),
        Router::new(config),
        Arc::new(registry),
    ));
}

async fn sample(
    client: &reqwest::Client,
    url: &str,
    key: &str,
    rate: usize,
    count: usize,
) -> serde_json::Value {
    let start = Instant::now();
    let permits = Arc::new(tokio::sync::Semaphore::new(64));
    let mut pending = tokio::task::JoinSet::new();
    for index in 0..count {
        let scheduled = start + Duration::from_secs_f64(index as f64 / rate as f64);
        tokio::time::sleep_until(scheduled).await;
        let permits = permits.clone();
        let request = client.post(format!("{url}/v1/messages")).bearer_auth(key).json(&json!({
            "model":"alpha", "max_tokens":20, "messages":[{"role":"user","content":format!("load {index}")}]
        }));
        pending.spawn(async move {
            let _permit = permits.acquire().await.unwrap();
            let response = request.send().await.unwrap();
            let status = response.status();
            let body: serde_json::Value = response.json().await.unwrap();
            assert!(status.is_success(), "{status}: {body}");
            assert_eq!(body["content"][0]["text"], "ok");
            // Includes scheduler and queue delay: slow responses cannot hide arrivals.
            scheduled.elapsed().as_secs_f64() * 1000.0
        });
    }
    let mut latencies = Vec::with_capacity(count);
    while let Some(result) = pending.join_next().await {
        latencies.push(result.unwrap());
    }
    let elapsed = start.elapsed().as_secs_f64();
    latencies.sort_by(f64::total_cmp);
    json!({"offered_rps":rate,"requests":count,"errors":0,"elapsed_s":elapsed,
        "completed_rps":count as f64/elapsed,"p50_ms":latencies[count/2],"p95_ms":latencies[count*95/100],"p99_ms":latencies[count*99/100]})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit load measurement; run alone with --release --ignored --nocapture"]
async fn credential_load() {
    let (_home, state, app) = super::credential_boundary_tests::fixture();
    let agent = super::credential_boundary_tests::agent(&app).await;
    let backend = Arc::new(Backend::default());
    let (upstream_url, upstream_task) = serve(
        axum::Router::new()
            .route("/v1/chat/completions", post(upstream))
            .with_state(backend.clone()),
    )
    .await;
    let (url, proxy_task) = serve(app).await;
    state
        .grob_store
        .set_secret("upstream", "synthetic-first")
        .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let mut results = Vec::new();
    for rate in [100, 500, 1000] {
        for live in [false, true, true, false] {
            configure(&state, &upstream_url, live);
            sample(&client, &url, &agent, 100, 100).await;
            let mut result = sample(&client, &url, &agent, rate, rate * 2).await;
            result["credential"] = json!(if live { "live-encrypted" } else { "literal" });
            results.push(result);
        }
    }
    configure(&state, &upstream_url, true);
    let store = state.grob_store.clone();
    let rotate = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        store.set_secret("upstream", "synthetic-second").unwrap();
    });
    let rotation = sample(&client, &url, &agent, 1000, 3000).await;
    rotate.await.unwrap();
    let old_before = backend.old.load(Ordering::Relaxed);
    sample(&client, &url, &agent, 100, 100).await;
    assert_eq!(
        backend.old.load(Ordering::Relaxed),
        old_before,
        "old credential reused after all in-flight requests drained"
    );
    assert!(backend.new.load(Ordering::Relaxed) > 0);
    let report = json!({"profile":if cfg!(debug_assertions) {"debug"} else {"release"},"os":std::env::consts::OS,"arch":std::env::consts::ARCH,
        "workers":4,"max_in_flight":64,"cache":false,"latency":"scheduled arrival to full body, including queue delay", "samples":results,"live_rotation":rotation,
        "old_credential_requests":old_before,"new_credential_requests":backend.new.load(Ordering::Relaxed)});
    println!(
        "CREDENTIAL_LOAD {}",
        serde_json::to_string(&report).unwrap()
    );
    if let Some(path) = std::env::var_os("GROB_LOAD_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    proxy_task.abort();
    upstream_task.abort();
}
