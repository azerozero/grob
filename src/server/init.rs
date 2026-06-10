use crate::auth::TokenStore;
use crate::config::AppConfig;
use crate::features::dlp::session::DlpSessionManager;
use crate::features::token_pricing::spend::SpendTracker;
use crate::features::token_pricing::SharedPricingTable;
use crate::providers::ProviderRegistry;
use crate::security::{
    AuditLog, CircuitBreakerRegistry, RateLimitConfig, RateLimiter, ToolSpikeConfig,
    ToolSpikeDetector,
};
use crate::shared::message_tracing::MessageTracer;
use crate::storage::GrobStore;
use std::sync::Arc;
use tracing::{error, info, warn};

pub(crate) type SecurityServices = (
    Option<Arc<RateLimiter>>,
    Option<Arc<CircuitBreakerRegistry>>,
    Option<Arc<AuditLog>>,
    Option<Arc<crate::cache::ResponseCache>>,
);

/// Initializes storage, token store, and provider registry.
pub(crate) async fn init_core_services(
    config: &AppConfig,
) -> anyhow::Result<(Arc<GrobStore>, TokenStore, Arc<ProviderRegistry>)> {
    let grob_store = Arc::new(
        GrobStore::open(&GrobStore::default_path())
            .map_err(|e| anyhow::anyhow!("Failed to initialize storage: {}", e))?,
    );
    info!("💾 Storage initialized at {}", grob_store.path().display());

    #[cfg(feature = "oauth")]
    let token_store = {
        let ts = TokenStore::with_store(grob_store.clone())
            .map_err(|e| anyhow::anyhow!("Failed to initialize token store: {}", e))?;
        let existing_tokens = ts.list_providers();
        if !existing_tokens.is_empty() {
            info!(
                "🔐 Loaded {} OAuth tokens from storage",
                existing_tokens.len()
            );
            // NOTE: Daemon handle is leaked intentionally — it lives for the
            // process lifetime. Graceful shutdown is driven by the tokio runtime
            // cancelling outstanding tasks.
            let _daemon = crate::auth::refresh_daemon::spawn(ts.clone());
        }
        ts
    };
    #[cfg(not(feature = "oauth"))]
    let token_store = TokenStore::new_empty();

    let secret_backend =
        crate::storage::secrets::build_backend(&config.secrets, grob_store.clone());
    info!("🔑 Secret backend: {}", secret_backend.label());

    let provider_registry = Arc::new(
        ProviderRegistry::from_configs_with_models(
            &config.providers,
            secret_backend.as_ref(),
            Some(token_store.clone()),
            &config.models,
            &config.server.timeouts,
        )
        .map_err(|e| anyhow::anyhow!("Failed to initialize provider registry: {}", e))?,
    );

    // Connection pre-warming is an outgoing network request per provider, so it
    // is opt-in: a default `grob start` stays fully offline.
    if config.server.warmup_connections {
        provider_registry.warmup_connections();
    }

    info!(
        "📦 Loaded {} providers with {} models",
        provider_registry.list_providers().len(),
        provider_registry.list_models().len()
    );

    // Startup validation sends a real (token-spending) probe to every provider
    // mapping, so it is opt-in. Off by default keeps startup free of surprise
    // outgoing requests and provider spend.
    if config.server.validate_on_start {
        let config_ref = config.clone();
        let registry_ref = provider_registry.clone();
        tokio::spawn(async move {
            info!("🔍 Validating providers and models...");
            let results = crate::preset::validate_config(&config_ref, &registry_ref).await;
            crate::preset::log_validation_results(&results);

            let total = results.len();
            let healthy = results.iter().filter(|r| r.any_ok()).count();
            if healthy == total {
                info!(
                    "✅ Validation complete: {}/{} models healthy",
                    healthy, total
                );
            } else {
                error!(
                    "⚠️ Validation: {}/{} models healthy — some models will fail at runtime",
                    healthy, total
                );
            }
        });
    }

    Ok((grob_store, token_store, provider_registry))
}

/// Initializes tracing, spend tracker, pricing table, and Prometheus.
pub(crate) async fn init_observability(
    config: &AppConfig,
    grob_store: &Arc<GrobStore>,
) -> anyhow::Result<(
    Arc<MessageTracer>,
    SpendTracker,
    SharedPricingTable,
    metrics_exporter_prometheus::PrometheusHandle,
)> {
    let message_tracer = Arc::new(MessageTracer::new(config.server.tracing.clone()));

    let spend_tracker = SpendTracker::with_store(grob_store.clone());
    if spend_tracker.total() > 0.0 {
        info!(
            "💰 Loaded spend tracker: ${:.2} spent this month",
            spend_tracker.total()
        );
    }

    // Synchronous + non-blocking: seeds the hardcoded table immediately and
    // only fetches OpenRouter prices in the background when explicitly enabled.
    let pricing_table = crate::features::token_pricing::init_pricing_table(&config.pricing);

    // Prometheus is the always-active metrics surface (`/metrics`). Installing
    // the global recorder is the single source of instrumentation.
    //
    // NOTE (deferred to SLICE 5b — OTLP metrics export): exporting these same
    // metrics over OTLP must layer a `metrics_util::layers::FanoutBuilder`
    // recorder OVER this one — `[PrometheusRecorder, OtelBridgeRecorder]` from the
    // ONE existing `metrics` instrumentation — and NOT stand up a second
    // OpenTelemetry `MeterProvider` (a parallel provider would re-instrument all
    // ~65 call sites and drift; the review's central risk). The bridge recorder is
    // tractable on the pinned versions (verified): `metrics::Recorder` →
    // per-family OTel instruments (`u64_counter().add`, `f64_gauge().record`,
    // `f64_histogram().record`) created from an `SdkMeterProvider::builder()
    // .with_periodic_exporter(MetricExporter::builder().with_tonic()…)`, with the
    // `Key`'s labels mapped to `KeyValue` attributes and gauge increment/decrement
    // tracked in an `AtomicU64`. It needs the `metrics` feature on
    // `opentelemetry-otlp`/`opentelemetry_sdk` plus a `metrics-util` dep, all gated
    // behind `otel`. Scoped out of this slice to keep the change reviewable and the
    // `--features otel` build green; the single-source groundwork is preserved.
    //
    // NOTE (deferred, security): `/metrics` is currently unauthenticated and
    // public (it carries spend/budget and tenant labels). Authenticating or
    // binding it to an admin interface is a separate security follow-up — not
    // changed in this slice so the scrape surface is not regressed.
    let prometheus_builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let metrics_handle = prometheus_builder
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("Failed to install Prometheus recorder: {}", e))?;

    // Register `# HELP` / `# TYPE` metadata for every exported metric family.
    // Must run after the recorder is installed so the descriptions land on it.
    describe_metrics();

    Ok((message_tracer, spend_tracker, pricing_table, metrics_handle))
}

/// Kind of an exported metric family, used to register its `# TYPE`.
#[derive(Clone, Copy)]
enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

/// Single source of truth for every exported Prometheus metric family:
/// `(name, kind, # HELP description)`.
///
/// `describe_metrics` registers `# HELP` / `# TYPE` for each entry; the
/// `every_metric_family_is_described` test emits + renders each one and fails if
/// any lacks metadata — so a newly-added metric family must be listed here.
const METRIC_FAMILIES: &[(&str, MetricKind, &str)] = &[
    (
        "grob_requests_total",
        MetricKind::Counter,
        "Total LLM requests processed, by model, provider, route_type and status.",
    ),
    (
        "grob_tokens_input_total",
        MetricKind::Counter,
        "Total billable input tokens, by model and provider.",
    ),
    (
        "grob_tokens_output_total",
        MetricKind::Counter,
        "Total output tokens generated, by model and provider.",
    ),
    (
        "grob_input_tokens_total",
        MetricKind::Counter,
        "Total input tokens observed (raw count).",
    ),
    (
        "grob_output_tokens_total",
        MetricKind::Counter,
        "Total output tokens observed (raw count).",
    ),
    (
        "grob_provider_errors_total",
        MetricKind::Counter,
        "Total provider errors, by provider.",
    ),
    (
        "grob_ratelimit_hits_total",
        MetricKind::Counter,
        "Total upstream 429 rate-limit responses, by provider.",
    ),
    (
        "grob_ratelimit_rejected_total",
        MetricKind::Counter,
        "Total requests rejected by the in-process rate limiter.",
    ),
    (
        "grob_cache_hits_total",
        MetricKind::Counter,
        "Total response-cache hits.",
    ),
    (
        "grob_cache_misses_total",
        MetricKind::Counter,
        "Total response-cache misses.",
    ),
    (
        "grob_cache_skipped_too_large_total",
        MetricKind::Counter,
        "Responses not cached because they exceeded the size limit.",
    ),
    (
        "grob_simhash_cache_hits_total",
        MetricKind::Counter,
        "SimHash near-duplicate cache hits.",
    ),
    (
        "grob_simhash_cache_misses_total",
        MetricKind::Counter,
        "SimHash near-duplicate cache misses.",
    ),
    (
        "grob_dlp_stream_blocked_total",
        MetricKind::Counter,
        "Streaming responses blocked by DLP.",
    ),
    (
        "grob_dlp_circuit_breaker_total",
        MetricKind::Counter,
        "DLP circuit-breaker trips.",
    ),
    (
        "grob_dlp_cross_chunk_total",
        MetricKind::Counter,
        "Cross-chunk DLP detections in streaming responses.",
    ),
    (
        "grob_dlp_name_ac_rebuilds_total",
        MetricKind::Counter,
        "Aho-Corasick name-matcher rebuilds in the DLP engine.",
    ),
    (
        "grob_dlp_signature_verified_total",
        MetricKind::Counter,
        "DLP canary-token signature verifications.",
    ),
    (
        "grob_dlp_hot_reload_total",
        MetricKind::Counter,
        "DLP signed-config hot reloads applied.",
    ),
    (
        "grob_dlp_detections_total",
        MetricKind::Counter,
        "DLP prompt-injection detections, by pattern.",
    ),
    (
        "grob_hit_approval_requested_total",
        MetricKind::Counter,
        "Human-in-the-loop tool approvals requested.",
    ),
    (
        "grob_hit_denied_total",
        MetricKind::Counter,
        "Tool calls denied by HIT policy (stream and non-stream).",
    ),
    (
        "grob_tool_spike_blocked_total",
        MetricKind::Counter,
        "Requests blocked by the tool-call spike detector (T-AD1).",
    ),
    (
        "grob_tool_spike_warn_total",
        MetricKind::Counter,
        "Tool-call spike warnings emitted.",
    ),
    (
        "grob_risk_escalation_total",
        MetricKind::Counter,
        "Security risk escalations triggered.",
    ),
    (
        "grob_escalation_webhook_failures_total",
        MetricKind::Counter,
        "Failed escalation webhook deliveries.",
    ),
    (
        "grob_circuit_breaker_rejected_total",
        MetricKind::Counter,
        "Requests rejected by an open provider circuit breaker.",
    ),
    (
        "grob_routing_endpoint_cb_rejected_total",
        MetricKind::Counter,
        "Requests rejected by an open routing-layer endpoint circuit breaker (RE-1a).",
    ),
    (
        "grob_active_requests",
        MetricKind::Gauge,
        "Currently in-flight requests (used for HPA / graceful drain).",
    ),
    (
        "grob_spend_usd",
        MetricKind::Gauge,
        "Recorded monthly spend in USD, by provider/model.",
    ),
    (
        "grob_estimated_cost_usd",
        MetricKind::Gauge,
        "Estimated cost in USD of the last accounted request.",
    ),
    (
        "grob_request_cost_usd",
        MetricKind::Gauge,
        "Cost in USD attributed to the last request.",
    ),
    (
        "grob_budget_limit_usd",
        MetricKind::Gauge,
        "Configured monthly budget limit in USD.",
    ),
    (
        "grob_budget_remaining_usd",
        MetricKind::Gauge,
        "Remaining monthly budget in USD.",
    ),
    (
        "grob_dlp_rules_loaded",
        MetricKind::Gauge,
        "Number of DLP rules currently loaded.",
    ),
    (
        "grob_dlp_config_hash_info",
        MetricKind::Gauge,
        "Info gauge carrying the active DLP config hash as a label.",
    ),
    (
        "grob_circuit_breaker_state",
        MetricKind::Gauge,
        "Provider circuit-breaker state (0=closed, 1=open, 2=half-open), by provider.",
    ),
    (
        "grob_provider_latency_ewma_ms",
        MetricKind::Gauge,
        "EWMA of provider latency in milliseconds, by provider.",
    ),
    (
        "grob_provider_score",
        MetricKind::Gauge,
        "Adaptive routing score, by provider.",
    ),
    (
        "grob_provider_success_rate",
        MetricKind::Gauge,
        "Provider success rate (0..1), by provider.",
    ),
    (
        "grob_ratelimit_tokens_remaining",
        MetricKind::Gauge,
        "Upstream remaining token quota (from provider rate-limit headers).",
    ),
    (
        "grob_ratelimit_requests_remaining",
        MetricKind::Gauge,
        "Upstream remaining request quota (from provider rate-limit headers).",
    ),
    (
        "grob_ratelimit_input_tokens_remaining",
        MetricKind::Gauge,
        "Upstream remaining input-token quota.",
    ),
    (
        "grob_ratelimit_output_tokens_remaining",
        MetricKind::Gauge,
        "Upstream remaining output-token quota.",
    ),
    (
        "grob_request_duration_seconds",
        MetricKind::Histogram,
        "End-to-end request duration in seconds, by model and provider.",
    ),
];

/// Registers `# HELP` / `# TYPE` descriptions for every exported metric family.
///
/// Metadata only — never emits or alters a metric value, so it is safe to call
/// unconditionally and changes no runtime behaviour. The `metrics` crate routes
/// these to whichever recorder is installed (Prometheus today; the `otel` fan-out
/// recorder inherits them with no extra instrumentation).
pub(crate) fn describe_metrics() {
    for &(name, kind, description) in METRIC_FAMILIES {
        match kind {
            MetricKind::Counter => metrics::describe_counter!(name, description),
            MetricKind::Gauge => metrics::describe_gauge!(name, description),
            MetricKind::Histogram => metrics::describe_histogram!(name, description),
        }
    }
}

/// Initializes the DLP session manager and optional hot-reload loop.
pub(crate) fn init_dlp(config: &AppConfig) -> Option<Arc<DlpSessionManager>> {
    #[cfg(feature = "dlp")]
    {
        let sessions = DlpSessionManager::from_config(config.dlp.clone());
        if let Some(ref dlp_mgr) = sessions {
            let dlp_cfg = dlp_mgr.config();
            if dlp_cfg.signed_config.enabled {
                let public_key = if dlp_cfg.signed_config.verify_signature {
                    match crate::features::dlp::signed_config::load_public_key(
                        &dlp_cfg.signed_config.public_key_path,
                    ) {
                        Ok(pk) => Some(pk),
                        Err(e) => {
                            warn!("Failed to load DLP signing public key: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };
                crate::features::dlp::signed_config::spawn_hot_reload(
                    dlp_cfg.signed_config.clone(),
                    dlp_mgr.hot_config().clone(),
                    dlp_cfg.url_exfil.domain_match_mode.clone(),
                    public_key,
                );
            }
        }
        sessions
    }
    #[cfg(not(feature = "dlp"))]
    {
        let _ = config;
        None
    }
}

/// Initializes the policy engine from configured `[[policies]]` rules.
///
/// Returns `None` when no policies are configured or the `policies` feature is disabled.
#[cfg(feature = "policies")]
pub(crate) fn init_policies(
    config: &AppConfig,
) -> Option<Arc<crate::features::policies::matcher::PolicyMatcher>> {
    if config.policies.is_empty() {
        return None;
    }
    match crate::features::policies::matcher::PolicyMatcher::new(config.policies.clone()) {
        Ok(matcher) => {
            info!(
                "Policy engine loaded with {} policies",
                config.policies.len()
            );
            Some(Arc::new(matcher))
        }
        Err(e) => {
            error!("Failed to initialize policy engine: {}", e);
            None
        }
    }
}

/// Initializes JWT validation and spawns the JWKS refresh loop.
///
/// The initial JWKS fetch runs inside the spawned background task (first
/// iteration, before any sleep) rather than being awaited here, so a slow or
/// unreachable JWKS endpoint can never stall the listener bind. The function
/// returns as soon as the validator is built.
///
/// As a consequence, JWT requests that rely on JWKS keys are rejected with an
/// auth error (mapped to HTTP 401) until the first refresh completes — see
/// [`crate::auth::JwtValidator::validate`], which returns `InvalidToken` when no
/// loaded key can verify the token rather than panicking.
pub(crate) async fn init_auth(
    config: &AppConfig,
) -> anyhow::Result<Option<Arc<crate::auth::JwtValidator>>> {
    if config.auth.mode != "jwt" {
        return Ok(None);
    }

    let validator = Arc::new(
        crate::auth::JwtValidator::from_config(&config.auth.jwt)
            .map_err(|e| anyhow::anyhow!("Failed to initialize JWT validator: {}", e))?,
    );

    if validator.jwks_url().is_some() {
        let jwt_validator = validator.clone();
        let base_interval = config.auth.jwt.jwks_refresh_interval;
        tokio::spawn(async move {
            // Immediate first refresh, backgrounded so it can never block the
            // bind. JWT requests are rejected until this succeeds.
            if let Err(e) = jwt_validator.refresh_jwks().await {
                warn!("Initial JWKS fetch failed (will retry): {}", e);
            }
            let mut current_interval = base_interval;
            let max_interval = base_interval * 8;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(current_interval)).await;
                match jwt_validator.refresh_jwks().await {
                    Ok(_) => {
                        current_interval = base_interval;
                    }
                    Err(e) => {
                        warn!(
                            "JWKS refresh failed (next retry in {}s): {}",
                            current_interval.min(max_interval) * 2,
                            e
                        );
                        current_interval = (current_interval * 2).min(max_interval);
                    }
                }
            }
        });
    }

    info!("🔐 JWT auth enabled");
    Ok(Some(validator))
}

/// Initializes rate limiter, circuit breakers, audit log, and cache.
pub(crate) fn init_security(config: &AppConfig) -> anyhow::Result<SecurityServices> {
    let security_enabled = config.security.enabled;
    // 0 = unlimited; render it as such instead of "0MB".
    let body_limit_desc = if config.security.max_body_size.value() == 0 {
        "unlimited".to_string()
    } else {
        format!(
            "{}MB",
            config.security.max_body_size.value() / (1024 * 1024)
        )
    };
    // A rate_limit_rps of 0 disables throttling — don't install the limiter
    // (rps=0 would otherwise starve the token bucket and reject every request).
    let rate_limiter = if security_enabled && config.security.rate_limit_rps > 0 {
        let rl_config = RateLimitConfig {
            requests_per_second: config.security.rate_limit_rps,
            burst: config.security.rate_limit_burst,
        };
        info!(
            "🛡️  Security: rate limit {}rps burst={}, body limit {}, headers={}, circuit_breaker={}",
            config.security.rate_limit_rps,
            config.security.rate_limit_burst,
            body_limit_desc,
            config.security.security_headers,
            config.security.circuit_breaker,
        );
        Some(Arc::new(RateLimiter::new(rl_config)))
    } else if security_enabled {
        info!(
            "🛡️  Security: rate limit disabled, body limit {}, headers={}, circuit_breaker={}",
            body_limit_desc, config.security.security_headers, config.security.circuit_breaker,
        );
        None
    } else {
        info!("🛡️  Security middleware disabled");
        None
    };

    let circuit_breakers = if security_enabled && config.security.circuit_breaker {
        Some(Arc::new(CircuitBreakerRegistry::new()))
    } else {
        None
    };

    #[cfg(not(feature = "compliance"))]
    let audit_log: Option<Arc<AuditLog>> = None;
    #[cfg(feature = "compliance")]
    let audit_log = if !config.security.audit_dir.is_empty() {
        let audit_dir = if config.security.audit_dir.starts_with('~') {
            let home = crate::home_dir().unwrap_or_default();
            home.join(&config.security.audit_dir[2..])
        } else {
            std::path::PathBuf::from(&config.security.audit_dir)
        };
        let signing_algorithm = if config.security.audit_signing_algorithm.is_empty() {
            crate::security::audit_log::SigningAlgorithm::default()
        } else {
            crate::security::audit_log::SigningAlgorithm::from_str_config(
                &config.security.audit_signing_algorithm,
            )
        };
        let hmac_key_path = if config.security.audit_hmac_key_path.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(
                &config.security.audit_hmac_key_path,
            ))
        };
        match AuditLog::new(crate::security::audit_log::AuditConfig {
            log_dir: audit_dir.clone(),
            sign_key_path: Some(audit_dir.join("audit_key.pem")),
            signing_algorithm,
            hmac_key_path,
            batch_size: config.security.audit_batch_size,
            flush_interval_ms: config.security.audit_flush_interval_ms,
            include_merkle_proof: config.security.audit_include_merkle_proof,
        }) {
            Ok(log) => {
                info!("📝 Audit logging enabled: {}", audit_dir.display());
                Some(Arc::new(log))
            }
            Err(e) => {
                error!("⚠️  Failed to initialize audit log: {}", e);
                None
            }
        }
    } else {
        None
    };

    let response_cache = if config.cache.enabled {
        let cache = crate::cache::ResponseCache::new(
            config.cache.max_capacity,
            config.cache.ttl_secs,
            config.cache.max_entry_bytes,
            config.cache.simhash_threshold,
        );
        info!(
            "💾 Response cache enabled: max_capacity={}, ttl={}s, max_entry={}B, simhash_threshold={}",
            config.cache.max_capacity,
            config.cache.ttl_secs,
            config.cache.max_entry_bytes,
            config.cache.simhash_threshold,
        );
        Some(Arc::new(cache))
    } else {
        None
    };

    Ok((rate_limiter, circuit_breakers, audit_log, response_cache))
}

/// Initializes the MCP tool matrix system if enabled.
///
/// Follows the same pattern as [`init_dlp`]: loads the matrix, builds the
/// state, and optionally spawns the background bench engine.
#[cfg(feature = "mcp")]
pub(crate) fn init_mcp(
    config: &AppConfig,
    registry: &Arc<ProviderRegistry>,
) -> Option<Arc<crate::features::mcp::McpState>> {
    if !config.mcp.enabled {
        return None;
    }

    let matrix = crate::features::mcp::matrix::ToolMatrix::load(&config.mcp.matrix_path);
    info!(tool_count = matrix.tool_count(), "MCP tool matrix loaded");

    let state = Arc::new(crate::features::mcp::McpState::new(
        config.mcp.clone(),
        matrix,
    ));

    if config.mcp.bench.enabled {
        crate::features::mcp::bench::spawn_bench_engine(
            config.mcp.bench.clone(),
            &state.matrix,
            state.scorer(),
            state.matrix_handle(),
            registry.clone(),
        );
    }

    Some(state)
}

/// Initializes the tool-call spike anomaly detector (T-AD1).
///
/// Returns `None` when both warn and block thresholds are zero (the
/// feature is fully disabled), otherwise an `Arc` ready to store on
/// [`crate::server::SecurityState`].
pub(crate) fn init_tool_spike_detector(config: &AppConfig) -> Option<Arc<ToolSpikeDetector>> {
    let cfg = ToolSpikeConfig {
        warn_per_min: config.security.tool_spike_warn_per_min,
        block_per_min: config.security.tool_spike_block_per_min,
    };
    if !cfg.is_active() {
        return None;
    }
    info!(
        "🔍 Tool-spike detector enabled (warn={}, block={} per session per min)",
        cfg.warn_per_min, cfg.block_per_min
    );
    Some(Arc::new(ToolSpikeDetector::new(cfg)))
}

/// Initializes the adaptive provider scorer if enabled.
pub(crate) fn init_provider_scorer(
    config: &AppConfig,
    circuit_breakers: &Option<Arc<CircuitBreakerRegistry>>,
) -> Option<Arc<crate::security::provider_scorer::ProviderScorer>> {
    if !config.security.adaptive_scoring {
        return None;
    }
    let scorer_config = crate::security::provider_scorer::ScorerConfig {
        latency_alpha: config.security.scoring_latency_alpha,
        window_size: config.security.scoring_window_size,
        decay_rate: config.security.scoring_decay_rate,
    };
    let scorer = Arc::new(crate::security::provider_scorer::ProviderScorer::new(
        scorer_config,
        circuit_breakers.clone(),
    ));
    info!(
        "📊 Adaptive provider scoring enabled (window={}, alpha={}, decay={})",
        config.security.scoring_window_size,
        config.security.scoring_latency_alpha,
        config.security.scoring_decay_rate
    );
    Some(scorer)
}

/// Emits the TEE attestation report into the audit log if both are available.
pub(crate) fn emit_tee_attestation(
    tee_status: &crate::security::tee::TeeStatus,
    audit_log: &Option<Arc<AuditLog>>,
) {
    let (Some(ref report), Some(ref audit)) = (&tee_status.attestation_report, audit_log) else {
        return;
    };
    use crate::security::audit_log::{AuditEntry, AuditEvent, Classification};
    let entry = AuditEntry {
        timestamp: chrono::Utc::now(),
        event_id: uuid::Uuid::new_v4().to_string(),
        tenant_id: "system".to_string(),
        user_id: None,
        action: AuditEvent::TeeAttestation,
        classification: Classification::C1,
        backend_routed: tee_status.platform.clone(),
        request_hash: Some(report.clone()),
        dlp_rules_triggered: vec![],
        ip_source: "localhost".to_string(),
        duration_ms: 0,
        previous_hash: String::new(),
        signature: vec![],
        signature_algorithm: String::new(),
        model_name: None,
        input_tokens: None,
        output_tokens: None,
        risk_level: None,
        batch_id: None,
        batch_index: None,
        merkle_root: None,
        merkle_proof: None,
    };
    if let Err(e) = audit.write(entry) {
        warn!("⚠️  Failed to write TEE attestation to audit log: {e}");
    } else {
        info!("📜 TEE attestation written to audit log");
    }
}

/// Spawns background tasks: webhook relay and model mapping validation.
#[cfg_attr(
    not(all(feature = "policies", feature = "watch")),
    allow(unused_variables)
)]
pub(crate) fn spawn_background_tasks(state: &Arc<super::AppState>) {
    // Webhook relay: HitApprovalRequest events with auth_method="webhook"
    #[cfg(all(feature = "policies", feature = "watch"))]
    {
        let mut relay_rx = state.event_bus.subscribe();
        tokio::spawn(async move {
            use crate::features::watch::events::WatchEvent;
            let client = reqwest::Client::new();
            loop {
                match relay_rx.recv().await {
                    Ok(WatchEvent::HitApprovalRequest {
                        auth_method,
                        webhook_url: Some(url),
                        request_id,
                        tool_name,
                        tool_input_preview,
                        ..
                    }) if auth_method == "webhook" => {
                        let payload = serde_json::json!({
                            "request_id": request_id,
                            "tool_name": tool_name,
                            "tool_input_preview": tool_input_preview,
                            "callback": "POST /api/hit/approve",
                        });
                        if let Err(e) = client.post(&url).json(&payload).send().await {
                            tracing::warn!(
                                url = %url,
                                error = %e,
                                "HIT webhook relay: failed to notify webhook"
                            );
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    _ => {}
                }
            }
        });
    }

    // Tool-spike detector: prune session rings idle longer than the
    // rolling window so memory stays bounded under churning session ids.
    if let Some(detector) = state.security.tool_spike_detector.clone() {
        tokio::spawn(async move {
            // 60s cadence matches the rolling window: an entry is dropped
            // at most one window after its last activity.
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                ticker.tick().await;
                detector.cleanup_idle();
            }
        });
    }
}

/// Spawns initial and periodic preset sync without blocking the bind.
///
/// The initial sync runs in a detached task rather than being awaited so an
/// unreachable or slow `sync_url` can never stall the listener from binding —
/// the same failure class as the pricing fetch. Preset sync is also opt-in
/// (it only runs when `sync_url` is configured), keeping default startup offline.
pub(crate) fn maybe_preset_sync(config: &AppConfig) {
    if !config.presets.auto_sync {
        return;
    }
    let Some(sync_url) = config.presets.sync_url.clone() else {
        return;
    };
    let interval = config.presets.sync_interval.clone();
    tokio::spawn(async move {
        info!("🔄 Initial preset sync from {}...", sync_url);
        match crate::preset::sync_presets(&sync_url).await {
            Ok(_) => info!("✅ Initial preset sync complete"),
            Err(e) => error!("⚠️ Initial preset sync failed: {}", e),
        }
        if let Some(interval) = interval {
            crate::preset::spawn_background_sync(sync_url, interval);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    // Completeness: EVERY family in `METRIC_FAMILIES` must render a `# HELP` and
    // `# TYPE` line — so a metric emitted without a describe entry fails the
    // build. Runs under default features (no `otel`), doubling as the
    // anti-regression for the always-active Prometheus surface. This is the only
    // lib test that installs the process-global recorder (nothing else does), so
    // it cannot double-install.
    #[test]
    fn every_metric_family_is_described_without_otel() {
        let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .expect("install prometheus recorder");
        describe_metrics();

        // A metric must be touched to appear in the rendered output, so emit one
        // sample per family using its declared kind.
        for &(name, kind, _) in METRIC_FAMILIES {
            match kind {
                MetricKind::Counter => metrics::counter!(name).increment(1),
                MetricKind::Gauge => metrics::gauge!(name).set(1.0),
                MetricKind::Histogram => metrics::histogram!(name).record(0.01),
            }
        }

        let rendered = handle.render();
        for &(name, _, _) in METRIC_FAMILIES {
            assert!(
                rendered.contains(&format!("# HELP {name}")),
                "metric family `{name}` is missing its `# HELP` line"
            );
            assert!(
                rendered.contains(&format!("# TYPE {name}")),
                "metric family `{name}` is missing its `# TYPE` line"
            );
        }
        assert!(
            rendered.contains("# TYPE grob_requests_total counter"),
            "counters must render as `counter`"
        );
        assert!(
            rendered.contains("# TYPE grob_active_requests gauge"),
            "gauges must render as `gauge`"
        );
    }

    /// Recursively collects every `.rs` file under `dir`.
    fn collect_rs_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    out.extend(collect_rs_files(&path));
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
        out
    }

    // Non-circular completeness: scan the *actual source* for every metric family
    // emitted at a call-site (`metrics::{counter,gauge,histogram}!("…")`) and
    // assert each one has a `METRIC_FAMILIES` describe entry. Unlike the test
    // above (which only re-emits the catalogue), this FAILS when a new metric is
    // added anywhere in `src/` without a `# HELP`/`# TYPE`. `cargo test` runs with
    // the crate root as CWD, so `src/` is reachable. Names built from a runtime
    // variable (e.g. the `RATE_LIMIT_HEADERS` table) can't be detected statically
    // and are simply not asserted here.
    #[test]
    fn no_emitted_metric_family_lacks_a_catalog_entry() {
        use std::collections::BTreeSet;

        let cataloged: BTreeSet<&str> = METRIC_FAMILIES.iter().map(|&(n, _, _)| n).collect();

        // `\s*` spans newlines, so multi-line macro calls are matched too.
        let re =
            regex::Regex::new(r#"metrics::(?:counter|gauge|histogram)!\s*\(\s*"([a-z0-9_]+)""#)
                .expect("valid regex");

        let mut emitted: BTreeSet<String> = BTreeSet::new();
        for path in collect_rs_files(std::path::Path::new("src")) {
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            for cap in re.captures_iter(&content) {
                let name = &cap[1];
                if name.starts_with("grob_") {
                    emitted.insert(name.to_string());
                }
            }
        }

        // Guard against a silently-passing test (wrong CWD / broken walk).
        assert!(
            emitted.len() >= 20,
            "source scan found only {} metric call-sites — walk/CWD problem?",
            emitted.len()
        );

        let missing: Vec<&String> = emitted
            .iter()
            .filter(|n| !cataloged.contains(n.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "metric families emitted in src/ but missing a `describe_metrics` entry \
             (they would ship without # HELP / # TYPE): {missing:?}"
        );
    }
}
