//! `grob/provider/*` namespace: provider listing and scoring.

use super::auth::{require_role, CallerIdentity};
use super::types::{ProviderInfo, ProviderScore, Role};
use crate::server::AppState;
use jsonrpsee::types::ErrorObjectOwned;
use std::collections::HashMap;
use std::sync::Arc;

/// Lists all configured providers and their registered models.
pub async fn list(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<Vec<ProviderInfo>, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let inner = state.snapshot();

    // Build provider → models from config mappings
    let mut provider_models: HashMap<String, Vec<String>> = HashMap::new();
    for mc in &inner.config.models {
        for mp in &mc.mappings {
            provider_models
                .entry(mp.provider.clone())
                .or_default()
                .push(mc.name.clone());
        }
    }

    let providers: Vec<ProviderInfo> = inner
        .provider_registry
        .list_providers()
        .into_iter()
        .map(|name| {
            let models = provider_models.remove(&name).unwrap_or_default();
            ProviderInfo { name, models }
        })
        .collect();

    Ok(providers)
}

/// Returns adaptive provider scores (latency, success rate, composite).
pub async fn score(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    if let Some(ref scorer) = state.security.provider_scorer {
        let details = scorer.all_score_details().await;
        let scores: Vec<ProviderScore> = details
            .into_iter()
            .map(
                |(provider, (success_rate, latency_ewma, score))| ProviderScore {
                    provider,
                    score,
                    latency_ewma_ms: latency_ewma,
                    success_rate,
                },
            )
            .collect();
        Ok(serde_json::json!({
            "adaptive_scoring": true,
            "scores": scores,
        }))
    } else {
        Ok(serde_json::json!({
            "adaptive_scoring": false,
            "scores": [],
        }))
    }
}
