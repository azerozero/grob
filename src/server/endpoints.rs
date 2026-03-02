//! HTTP endpoints: health, liveness, readiness, metrics, scores.

use super::AppState;
use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
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

/// Prometheus metrics endpoint
pub(super) async fn metrics_endpoint(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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
