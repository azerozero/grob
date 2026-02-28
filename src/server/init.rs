use crate::auth::TokenStore;
use crate::cli::AppConfig;
use crate::features::dlp::session::DlpSessionManager;
use crate::features::token_pricing::spend::SpendTracker;
use crate::features::token_pricing::SharedPricingTable;
use crate::message_tracing::MessageTracer;
use crate::providers::ProviderRegistry;
use crate::security::{AuditLog, CircuitBreakerRegistry, RateLimitConfig, RateLimiter};
use crate::storage::GrobStore;
use std::sync::Arc;
use tracing::{error, info, warn};

pub(crate) type SecurityServices = (
    Option<Arc<RateLimiter>>,
    Option<Arc<CircuitBreakerRegistry>>,
    Option<Arc<AuditLog>>,
    Option<Arc<crate::cache::ResponseCache>>,
);

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
        }
        ts
    };
    #[cfg(not(feature = "oauth"))]
    let token_store = TokenStore::new_empty();

    let provider_registry = Arc::new(
        ProviderRegistry::from_configs_with_models(
            &config.providers,
            Some(token_store.clone()),
            &config.models,
            &config.server.timeouts,
        )
        .map_err(|e| anyhow::anyhow!("Failed to initialize provider registry: {}", e))?,
    );

    provider_registry.warmup_connections();

    info!(
        "📦 Loaded {} providers with {} models",
        provider_registry.list_providers().len(),
        provider_registry.list_models().len()
    );

    {
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

    let pricing_table = crate::features::token_pricing::init_pricing_table().await;

    let prometheus_builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let metrics_handle = prometheus_builder
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("Failed to install Prometheus recorder: {}", e))?;

    Ok((message_tracer, spend_tracker, pricing_table, metrics_handle))
}

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
        if let Err(e) = jwt_validator.refresh_jwks().await {
            warn!("Initial JWKS fetch failed (will retry): {}", e);
        }
        let base_interval = config.auth.jwt.jwks_refresh_interval;
        tokio::spawn(async move {
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

pub(crate) fn init_security(config: &AppConfig) -> anyhow::Result<SecurityServices> {
    let security_enabled = config.security.enabled;
    let rate_limiter = if security_enabled {
        let rl_config = RateLimitConfig {
            requests_per_second: config.security.rate_limit_rps,
            burst: config.security.rate_limit_burst,
        };
        info!(
            "🛡️  Security: rate limit {}rps burst={}, body limit {}MB, headers={}, circuit_breaker={}",
            config.security.rate_limit_rps,
            config.security.rate_limit_burst,
            config.security.max_body_size / (1024 * 1024),
            config.security.security_headers,
            config.security.circuit_breaker,
        );
        Some(Arc::new(RateLimiter::new(rl_config)))
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
            let home = dirs::home_dir().unwrap_or_default();
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
        );
        info!(
            "💾 Response cache enabled: max_capacity={}, ttl={}s, max_entry={}B",
            config.cache.max_capacity, config.cache.ttl_secs, config.cache.max_entry_bytes
        );
        Some(Arc::new(cache))
    } else {
        None
    };

    Ok((rate_limiter, circuit_breakers, audit_log, response_cache))
}

pub(crate) async fn maybe_preset_sync(config: &AppConfig) {
    if !config.presets.auto_sync {
        return;
    }
    if let Some(ref sync_url) = config.presets.sync_url {
        info!("🔄 Initial preset sync from {}...", sync_url);
        match crate::preset::sync_presets(sync_url).await {
            Ok(_) => info!("✅ Initial preset sync complete"),
            Err(e) => error!("⚠️ Initial preset sync failed: {}", e),
        }
        if let Some(ref interval) = config.presets.sync_interval {
            crate::preset::spawn_background_sync(sync_url.clone(), interval.clone());
        }
    }
}
