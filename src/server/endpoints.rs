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
            // The FLEET-wide cap as configured.
            "budget_usd": budget_limit,
            // What THIS replica will actually allow. Differs from `budget_usd`
            // when the budget is split across replicas, and that difference is
            // what reconciles the configured cap with observed spend.
            "budget_usd_this_replica": crate::security::replica_budget_share(
                budget_limit,
                inner.config.budget.replicas,
                inner.config.budget.margin_percent,
            ),
            "replicas": inner.config.budget.replicas.max(1),
        },
        // Content hashes of the *active* snapshot on this replica. Two replicas
        // reporting different revisions are enforcing different policies, which
        // is otherwise invisible: both answer "ok". See
        // `docs/how-to/multi-replica-consistency.md`.
        "revision": {
            "config": inner.config_revision.full(),
            "policy": inner.policy_revision.full(),
        },
        // What the limiter actually enforces on THIS replica. A limit that is
        // only per-process is a different guarantee from a fleet-wide one, and
        // the difference is invisible from a response: both just answer 200.
        // Stating the scope is what lets an operator compute the real
        // fleet-wide ceiling instead of assuming the configured number.
        "rate_limit": rate_limit_status(&inner, state.security.rate_limiter.is_some()),
    }))
}

/// Reports the limiter's configuration and, crucially, its enforcement scope.
///
/// The scope is the honest part. Buckets are per process, so with N replicas
/// the fleet-wide ceiling is `N * rps`, not `rps`. LiteLLM's equivalent silently
/// degrades a configured global limit into a per-pod one on a Redis error;
/// grob has no shared store to lose, but the same reasoning applies — the
/// deployment must be told which guarantee it actually has.
fn rate_limit_status(
    inner: &crate::server::ReloadableState,
    limiter_active: bool,
) -> serde_json::Value {
    let security = &inner.config.security;
    if !limiter_active || security.rate_limit_rps == 0 {
        return serde_json::json!({ "enabled": false });
    }
    let replicas = security.rate_limit_replicas.max(1);
    let share = crate::security::replica_share(
        security.rate_limit_rps,
        replicas,
        security.rate_limit_margin_percent,
    );
    serde_json::json!({
        "enabled": true,
        // The scope is a promise about the blast radius of `rps`, not a
        // description of the storage backend. `fleet` means the configured
        // number is a real ceiling because each replica enforces its share;
        // `per_replica` means the fleet can reach `replicas * rps`.
        "scope": if replicas > 1 { "fleet" } else { "per_replica" },
        "rps": security.rate_limit_rps,
        "burst": security.rate_limit_burst,
        // What THIS process actually enforces, which is what an operator needs
        // to reconcile the configured number with observed throughput.
        "effective_rps_this_replica": share,
        "replicas": replicas,
        "margin_percent": security.rate_limit_margin_percent,
        "keyed_by": if security.rate_limit_by_client { "oidc_client" } else { "tenant" },
        "client_overrides": security.rate_limit_clients.len(),
    })
}

/// Liveness probe: process is alive, returns 200 always.
pub(super) async fn liveness_check() -> impl IntoResponse {
    Json(serde_json::json!({"status": "alive"}))
}

/// Readiness probe: providers configured, circuit breakers not all open, and
/// the active config revision matching what the deployment expects.
pub(super) async fn readiness_check(State(state): State<Arc<AppState>>) -> Response {
    let inner = state.snapshot();
    let provider_count = inner.provider_registry.list_providers().len();

    // Revision pinning (multi-replica). A replica that missed a reload is still
    // perfectly healthy in every other respect — it answers, it routes, it has
    // providers — which is exactly why this has to be checked explicitly: the
    // failure mode is silent enforcement of a superseded policy, not an outage.
    // Reporting not-ready lets the orchestrator drain it instead.
    if let Some(ref expected) = inner.config.server.expected_config_revision {
        let active = inner.config_revision.full();
        // Accept the short form too: an operator pinning a revision by hand
        // will copy the 12-char prefix shown in logs.
        let matches = active == expected || inner.config_revision.short() == expected.as_str();
        if !matches {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "not_ready",
                    "reason": "config revision mismatch",
                    "expected_config_revision": expected,
                    "active_config_revision": active,
                })),
            )
                .into_response();
        }
    }

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
    if let Some(ref availability) = state.security.provider_availability {
        let states = availability.all_states().await;
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
        "providers": provider_count,
        "config_revision": inner.config_revision.full(),
        "policy_revision": inner.policy_revision.full(),
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

    /// Builds a config with `expected_config_revision` set inside `[server]`.
    ///
    /// The `config()` helper appends its argument at the end of the document,
    /// which would place a bare key in whatever table happens to be last. This
    /// one puts it in the table it belongs to.
    fn config_with_expected_revision(expected: &str) -> crate::cli::AppConfig {
        let toml = format!(
            r#"
[server]
host = "127.0.0.1"
port = 18099
expected_config_revision = "{expected}"

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
"#
        );
        crate::cli::AppConfig::from_content(&toml, "revision_test").expect("config parses")
    }

    /// Registry holding one mock provider.
    ///
    /// Readiness short-circuits to 503 on an empty registry, so the revision
    /// checks below need a provider present to reach the code under test.
    fn registry_with_provider() -> ProviderRegistry {
        let mut registry = ProviderRegistry::new();
        registry.insert_provider_for_test(
            "mock",
            std::sync::Arc::new(crate::providers::mocks::MockLlmProvider::text(
                "alpha", "ok",
            )),
        );
        registry
    }

    /// Reads a JSON body out of a response for assertion.
    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("body should be JSON")
    }

    /// With no expected revision configured, readiness is unchanged.
    ///
    /// The single-daemon case must not acquire a new way to be unready.
    #[tokio::test]
    async fn readiness_ignores_revision_when_unpinned() {
        let state = test_app_state(config(""), registry_with_provider());
        let resp = readiness_check(State(state)).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an unpinned replica must stay ready"
        );
        let body = json_body(resp).await;
        assert!(
            body["config_revision"]
                .as_str()
                .is_some_and(|r| r.starts_with("sha256:")),
            "readiness should still report the active revision; body: {body}"
        );
    }

    /// A replica pinned to its own revision stays ready.
    #[tokio::test]
    async fn readiness_passes_when_revision_matches() {
        // Compute the revision this config actually has, then pin to it.
        let probe = test_app_state(config(""), registry_with_provider());
        let active = probe.snapshot().config_revision.full().to_string();

        let state = test_app_state(
            config_with_expected_revision(&active),
            registry_with_provider(),
        );
        let resp = readiness_check(State(state)).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a replica running the expected revision must be ready"
        );
    }

    /// A replica serving a superseded config must report itself unready.
    ///
    /// This is the whole point: such a replica is healthy by every other
    /// measure, so without this check it keeps serving a stale policy while the
    /// load balancer sees nothing wrong.
    #[tokio::test]
    async fn readiness_fails_on_revision_mismatch() {
        let state = test_app_state(
            config_with_expected_revision(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            registry_with_provider(),
        );
        let resp = readiness_check(State(state)).await;
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a stale replica must be pulled from the load balancer, not left serving"
        );
        let body = json_body(resp).await;
        assert_eq!(body["reason"], "config revision mismatch");
        assert!(
            body["active_config_revision"] != body["expected_config_revision"],
            "the failure must show both revisions so the drift is diagnosable; body: {body}"
        );
    }

    /// The short form is accepted, because that is what operators copy.
    #[tokio::test]
    async fn readiness_accepts_the_short_revision_form() {
        let probe = test_app_state(config(""), registry_with_provider());
        let short = probe.snapshot().config_revision.short().to_string();

        let state = test_app_state(
            config_with_expected_revision(&short),
            registry_with_provider(),
        );
        let resp = readiness_check(State(state)).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the 12-char form shown in logs must be usable as a pin"
        );
    }

    /// Health must state the limiter's enforcement scope.
    ///
    /// A per-replica limit and a fleet-wide one are indistinguishable from a
    /// response, so the scope has to be stated for the number to mean anything.
    #[tokio::test]
    async fn health_reports_rate_limit_scope() {
        // The section must be a real `[security]` table: `config()` appends its
        // argument at the end of the document, so bare keys would land in
        // whatever table happens to be last.
        let state = test_app_state(
            config("\n[security]\nrate_limit_rps = 10\nrate_limit_burst = 20\n"),
            registry_with_provider(),
        );
        let resp = health_check(State(state)).await.into_response();
        let body = json_body(resp).await;

        assert_eq!(body["rate_limit"]["enabled"], true);
        assert_eq!(
            body["rate_limit"]["scope"], "per_replica",
            "the scope must be explicit: with N replicas the real ceiling is N * rps"
        );
        assert_eq!(body["rate_limit"]["rps"], 10);
        assert_eq!(body["rate_limit"]["keyed_by"], "tenant");
    }

    /// Declaring a fleet must flip the scope and report the real share.
    #[tokio::test]
    async fn health_reports_fleet_scope_and_effective_share() {
        let state = test_app_state(
            config(
                "\n[security]\nrate_limit_rps = 1000\nrate_limit_burst = 2000\n\
                 rate_limit_replicas = 4\nrate_limit_margin_percent = 5\n",
            ),
            registry_with_provider(),
        );
        let resp = health_check(State(state)).await.into_response();
        let body = json_body(resp).await;

        assert_eq!(
            body["rate_limit"]["scope"], "fleet",
            "declaring replicas makes the configured number a real ceiling"
        );
        assert_eq!(body["rate_limit"]["rps"], 1000, "the fleet-wide limit");
        // 1000 - 5% = 950, split four ways.
        assert_eq!(
            body["rate_limit"]["effective_rps_this_replica"], 237,
            "the operator must see what THIS process enforces"
        );
        assert_eq!(body["rate_limit"]["replicas"], 4);
    }

    /// A disabled limiter must say so rather than report a phantom quota.
    #[tokio::test]
    async fn health_reports_rate_limit_disabled() {
        let state = test_app_state(config(""), registry_with_provider());
        let resp = health_check(State(state)).await.into_response();
        let body = json_body(resp).await;
        assert_eq!(
            body["rate_limit"]["enabled"], false,
            "no configured quota must not look like an enforced one"
        );
    }

    /// Health must expose both revisions so replicas can be compared.
    #[tokio::test]
    async fn health_reports_both_revisions() {
        let state = test_app_state(config(""), ProviderRegistry::new());
        let resp = health_check(State(state)).await.into_response();
        let body = json_body(resp).await;
        assert!(
            body["revision"]["config"]
                .as_str()
                .is_some_and(|r| r.starts_with("sha256:")),
            "health must carry the config revision; body: {body}"
        );
        assert!(
            body["revision"]["policy"]
                .as_str()
                .is_some_and(|r| r.starts_with("sha256:")),
            "health must carry the policy revision; body: {body}"
        );
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
