//! `grob/model/*` namespace: model listing and routing rules.

use super::auth::{require_role, CallerIdentity};
use super::types::{Role, RoutingRule};
use crate::server::AppState;
use jsonrpsee::types::ErrorObjectOwned;
use std::sync::Arc;

/// Lists all configured models with their provider mappings.
pub async fn list(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let inner = state.snapshot();
    let models: Vec<serde_json::Value> = inner
        .config
        .models
        .iter()
        .map(|m| {
            let providers: Vec<&str> = m.mappings.iter().map(|mp| mp.provider.as_str()).collect();
            serde_json::json!({
                "name": m.name,
                "providers": providers,
                "strategy": format!("{:?}", m.strategy),
            })
        })
        .collect();

    Ok(serde_json::json!({ "models": models }))
}

/// Returns current routing configuration and prompt rules.
pub async fn routing(
    state: &Arc<AppState>,
    caller: &CallerIdentity,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    require_role(caller, Role::Observer)?;

    let inner = state.snapshot();
    let config = &inner.config.router;

    let prompt_rules: Vec<RoutingRule> = config
        .prompt_rules
        .iter()
        .map(|r| RoutingRule {
            pattern: r.pattern.clone(),
            model: r.model.clone(),
        })
        .collect();

    Ok(serde_json::json!({
        "default": config.default,
        "background": config.background,
        "think": config.think,
        "websearch": config.websearch,
        "prompt_rules": prompt_rules,
    }))
}
