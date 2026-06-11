//! HTTP endpoints: health, liveness, readiness, metrics, scores.

use super::AppState;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

/// Adaptive provider scores endpoint.
pub(super) async fn scores_endpoint(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(ref scorer) = state.security.provider_scorer {
        let scores = scorer.all_scores().await;
        Json(serde_json::json!({
            "adaptive_scoring": true,
            "scores": scores
        }))
    } else {
        Json(serde_json::json!({
            "adaptive_scoring": false,
            "scores": {}
        }))
    }
}

/// Health check endpoint
pub(super) async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    let spend_total = {
        let tracker = state.observability.spend_tracker.lock().await;
        tracker.total()
    };
    let inner = state.snapshot();
    let budget_limit = inner.config.budget.monthly_limit_usd.value();
    Json(serde_json::json!({
        "status": "ok",
        "service": "grob",
        "pid": std::process::id(),
        "started_at": state.started_at.to_rfc3339(),
        "active_requests": active,
        "spend": {
            "total_usd": spend_total,
            "budget_usd": budget_limit,
        }
    }))
}

/// Liveness probe: process is alive, returns 200 always.
pub(super) async fn liveness_check() -> impl IntoResponse {
    Json(serde_json::json!({"status": "alive"}))
}

/// Readiness probe: check that providers are configured and circuit breakers aren't all open.
pub(super) async fn readiness_check(State(state): State<Arc<AppState>>) -> Response {
    let inner = state.snapshot();
    let provider_count = inner.provider_registry.list_providers().len();

    if provider_count == 0 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not_ready",
                "reason": "no providers configured"
            })),
        )
            .into_response();
    }

    // Check if all circuit breakers are open (all providers degraded)
    if let Some(ref cb) = state.security.circuit_breakers {
        let states = cb.all_states().await;
        if !states.is_empty() {
            let all_open = states
                .values()
                .all(|s| *s == crate::security::CircuitState::Open);
            if all_open {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "status": "not_ready",
                        "reason": "all circuit breakers open"
                    })),
                )
                    .into_response();
            }
        }
    }

    Json(serde_json::json!({
        "status": "ready",
        "providers": provider_count
    }))
    .into_response()
}

/// Prometheus metrics endpoint.
///
/// Public by default. When `[metrics] bearer_token`/`bearer_token_file` is set,
/// requires `Authorization: Bearer <token>` (compared in constant time) and
/// returns `401` otherwise — health/live/ready stay public. TLS is left to the
/// existing TLS/ACME layer. See [`crate::cli::MetricsConfig`] for the matching
/// Prometheus scrape config.
pub(super) async fn metrics_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    // Auth gate first, before doing any work, so unauthorized scrapers cannot
    // trigger the spend-tracker lock or gauge publication below.
    if let Some(expected) = state.observability.metrics_bearer_token.as_ref() {
        use secrecy::ExposeSecret;
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        // Length-hiding compare: hashes both sides to fixed-size digests so the
        // token's length cannot leak via an early-return timing side channel.
        let authorized = matches!(
            provided,
            Some(token) if super::middleware::constant_time_eq_hashed(token, expected.expose_secret())
        );
        if !authorized {
            return metrics_unauthorized();
        }
    }

    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    metrics::gauge!("grob_active_requests").set(active as f64);

    // Publish spend/budget gauges (point-in-time snapshots -> gauges are correct)
    let inner = state.snapshot();
    let tracker = state.observability.spend_tracker.lock().await;
    metrics::gauge!("grob_spend_usd").set(tracker.total());
    let budget_limit = inner.config.budget.monthly_limit_usd.value();
    if budget_limit > 0.0 {
        metrics::gauge!("grob_budget_limit_usd").set(budget_limit);
        metrics::gauge!("grob_budget_remaining_usd").set((budget_limit - tracker.total()).max(0.0));
    }
    drop(tracker);

    // Publish adaptive scoring gauges
    if let Some(ref scorer) = state.security.provider_scorer {
        let details = scorer.all_score_details().await;
        for (provider, (success_rate, latency_ewma, score)) in &details {
            metrics::gauge!(
                "grob_provider_score",
                "provider" => provider.clone()
            )
            .set(*score);
            metrics::gauge!(
                "grob_provider_latency_ewma_ms",
                "provider" => provider.clone()
            )
            .set(*latency_ewma);
            metrics::gauge!(
                "grob_provider_success_rate",
                "provider" => provider.clone()
            )
            .set(*success_rate);
        }
    }

    let body = state.observability.metrics_handle.render();
    // Header and body are controlled string constants; builder cannot fail.
    Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

/// Builds the generic `401` returned when the `/metrics` bearer token is missing
/// or wrong. The body reveals nothing about why; `WWW-Authenticate` signals the
/// scheme so scrapers know to present a bearer token.
fn metrics_unauthorized() -> Response {
    // Static inputs; builder cannot fail.
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("WWW-Authenticate", "Bearer")
        .body(Body::from("Unauthorized\n"))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ProviderRegistry;
    use crate::server::test_app_state;

    fn config(metrics_section: &str) -> crate::cli::AppConfig {
        let toml = format!(
            r#"
[server]
host = "127.0.0.1"
port = 18099

[router]
default = "alpha"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"
{metrics_section}
"#
        );
        crate::cli::AppConfig::from_content(&toml, "metrics_auth_test").expect("config parses")
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("valid header"),
        );
        h
    }

    // Default (no [metrics] token): /metrics is public — unchanged behaviour.
    #[tokio::test]
    async fn metrics_public_without_token() {
        let state = test_app_state(config(""), ProviderRegistry::new());
        let resp = metrics_endpoint(State(state), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Token configured: missing / wrong → 401, correct → 200.
    #[tokio::test]
    async fn metrics_requires_token_when_configured() {
        let state = test_app_state(
            config("\n[metrics]\nbearer_token = \"s3cr3t-token\"\n"),
            ProviderRegistry::new(),
        );

        let no_auth = metrics_endpoint(State(state.clone()), HeaderMap::new()).await;
        assert_eq!(
            no_auth.status(),
            StatusCode::UNAUTHORIZED,
            "missing Authorization must be rejected"
        );

        let wrong = metrics_endpoint(State(state.clone()), bearer("wrong-token")).await;
        assert_eq!(
            wrong.status(),
            StatusCode::UNAUTHORIZED,
            "wrong token must be rejected"
        );

        // A differently-sized token must also be rejected — the length-hiding
        // comparator returns 401 without an early length-based short-circuit.
        let wrong_len = metrics_endpoint(State(state.clone()), bearer("x")).await;
        assert_eq!(
            wrong_len.status(),
            StatusCode::UNAUTHORIZED,
            "token of a different length must be rejected"
        );

        let good = metrics_endpoint(State(state), bearer("s3cr3t-token")).await;
        assert_eq!(
            good.status(),
            StatusCode::OK,
            "correct token must be accepted"
        );
    }

    // /health stays public regardless of the /metrics token.
    #[tokio::test]
    async fn health_stays_public_with_metrics_token() {
        let public = test_app_state(config(""), ProviderRegistry::new());
        let resp = health_check(State(public)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let gated = test_app_state(
            config("\n[metrics]\nbearer_token = \"s3cr3t-token\"\n"),
            ProviderRegistry::new(),
        );
        let resp = health_check(State(gated)).await.into_response();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "/health must stay public even when /metrics is gated"
        );
    }
}
