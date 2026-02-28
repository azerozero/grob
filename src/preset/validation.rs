//! Config validation: smoke-test providers + models + fallback chains.

use anyhow::Result;
use std::sync::Arc;

use crate::auth::TokenStore;
use crate::cli::AppConfig;
use crate::models::{AnthropicRequest, Message, MessageContent};
use crate::providers::ProviderRegistry;

/// Result of validating a single provider/model mapping
#[derive(Debug)]
pub struct MappingResult {
    pub priority: u32,
    pub provider: String,
    pub actual_model: String,
    pub ok: bool,
    pub detail: String,
}

/// Result of validating a router model (with all its fallback mappings)
#[derive(Debug)]
pub struct ModelValidation {
    pub model_name: String,
    pub role: String,
    pub mappings: Vec<MappingResult>,
}

impl ModelValidation {
    pub fn healthy_count(&self) -> usize {
        self.mappings.iter().filter(|m| m.ok).count()
    }
    pub fn all_ok(&self) -> bool {
        !self.mappings.is_empty() && self.mappings.iter().all(|m| m.ok)
    }
    pub fn any_ok(&self) -> bool {
        self.mappings.iter().any(|m| m.ok)
    }
}

/// Build a provider registry from config (for CLI validation path).
pub fn build_registry(config: &AppConfig) -> Result<(Arc<ProviderRegistry>, TokenStore)> {
    let token_store = TokenStore::at_default_path()
        .map_err(|e| anyhow::anyhow!("Failed to init token store: {}", e))?;

    let registry = Arc::new(
        ProviderRegistry::from_configs_with_models(
            &config.providers,
            Some(token_store.clone()),
            &config.models,
            &config.server.timeouts,
        )
        .map_err(|e| anyhow::anyhow!("Failed to init providers: {}", e))?,
    );

    Ok((registry, token_store))
}

/// Test a single provider mapping by sending a minimal request.
async fn validate_provider_mapping(
    mapping: &crate::cli::ModelMapping,
    registry: &ProviderRegistry,
) -> MappingResult {
    let Some(provider) = registry.get_provider(&mapping.provider) else {
        return MappingResult {
            priority: mapping.priority,
            provider: mapping.provider.clone(),
            actual_model: mapping.actual_model.clone(),
            ok: false,
            detail: "Provider not in registry".to_string(),
        };
    };

    let start = std::time::Instant::now();
    let test_req = make_test_request(&mapping.actual_model);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        provider.send_message(test_req),
    )
    .await;

    let latency = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(_)) => MappingResult {
            priority: mapping.priority,
            provider: mapping.provider.clone(),
            actual_model: mapping.actual_model.clone(),
            ok: true,
            detail: format!("OK ({}ms)", latency),
        },
        Ok(Err(e)) => {
            let err_str = e.to_string();
            let short = if err_str.len() > 80 {
                format!("{}...", &err_str[..77])
            } else {
                err_str
            };
            MappingResult {
                priority: mapping.priority,
                provider: mapping.provider.clone(),
                actual_model: mapping.actual_model.clone(),
                ok: false,
                detail: short,
            }
        }
        Err(_) => MappingResult {
            priority: mapping.priority,
            provider: mapping.provider.clone(),
            actual_model: mapping.actual_model.clone(),
            ok: false,
            detail: "Timeout (30s)".to_string(),
        },
    }
}

/// Validate all router models by sending a minimal request to each provider mapping.
pub async fn validate_config(
    config: &AppConfig,
    registry: &ProviderRegistry,
) -> Vec<ModelValidation> {
    // Collect router models to test
    let mut models_to_test: Vec<(&str, &str)> = vec![(&config.router.default, "default")];
    if let Some(ref m) = config.router.think {
        models_to_test.push((m, "think"));
    }
    if let Some(ref m) = config.router.background {
        models_to_test.push((m, "background"));
    }
    if let Some(ref m) = config.router.websearch {
        models_to_test.push((m, "websearch"));
    }

    // Deduplicate (a model can be used for multiple roles)
    let mut seen = std::collections::HashSet::new();
    models_to_test.retain(|(name, _)| seen.insert(*name));

    let mut results = Vec::new();

    for (model_name, role) in &models_to_test {
        let model_config = match config.models.iter().find(|m| m.name == *model_name) {
            Some(mc) => mc,
            None => {
                results.push(ModelValidation {
                    model_name: model_name.to_string(),
                    role: role.to_string(),
                    mappings: vec![MappingResult {
                        priority: 0,
                        provider: "?".to_string(),
                        actual_model: "?".to_string(),
                        ok: false,
                        detail: "Model not found in [[models]]".to_string(),
                    }],
                });
                continue;
            }
        };

        let mut sorted = model_config.mappings.clone();
        sorted.sort_by_key(|m| m.priority);

        let mut mapping_results = Vec::new();
        for mapping in &sorted {
            mapping_results.push(validate_provider_mapping(mapping, registry).await);
        }

        results.push(ModelValidation {
            model_name: model_name.to_string(),
            role: role.to_string(),
            mappings: mapping_results,
        });
    }

    results
}

/// Create a minimal test request (max_tokens=1, single short message).
fn make_test_request(model: &str) -> AnthropicRequest {
    AnthropicRequest {
        model: model.to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text("Say OK".to_string()),
        }],
        max_tokens: 1,
        thinking: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop_sequences: None,
        stream: None,
        metadata: None,
        system: None,
        tools: None,
        tool_choice: None,
    }
}

/// Print validation results to stdout.
pub fn print_validation_results(results: &[ModelValidation]) {
    let all_ok = results.iter().all(|r| r.any_ok());

    for r in results {
        let healthy = r.healthy_count();
        let total = r.mappings.len();
        let icon = if r.all_ok() {
            "✅"
        } else if r.any_ok() {
            "⚠️"
        } else {
            "❌"
        };

        println!(
            "  {} {} [{}] — {}/{} mappings healthy",
            icon, r.model_name, r.role, healthy, total
        );

        for m in &r.mappings {
            let status = if m.ok { "✅" } else { "❌" };
            println!(
                "    [{}] {}/{}: {} {}",
                m.priority, m.provider, m.actual_model, status, m.detail
            );
        }
    }

    println!();
    if all_ok {
        println!("  All models have at least one healthy provider.");
    } else {
        let broken: Vec<&str> = results
            .iter()
            .filter(|r| !r.any_ok())
            .map(|r| r.model_name.as_str())
            .collect();
        if !broken.is_empty() {
            println!(
                "  ❌ Models with NO healthy providers: {}",
                broken.join(", ")
            );
            println!("     These will fail at runtime. Check credentials and model names.");
        }
    }
}

/// Log validation results (for server startup / reload).
pub fn log_validation_results(results: &[ModelValidation]) {
    for r in results {
        let healthy = r.healthy_count();
        let total = r.mappings.len();

        if r.all_ok() {
            tracing::info!("✅ {} [{}]: {}/{} OK", r.model_name, r.role, healthy, total);
        } else if r.any_ok() {
            tracing::warn!(
                "⚠️ {} [{}]: {}/{} OK (some fallbacks broken)",
                r.model_name,
                r.role,
                healthy,
                total
            );
            for m in &r.mappings {
                if !m.ok {
                    tracing::warn!(
                        "  ❌ [{}] {}/{}: {}",
                        m.priority,
                        m.provider,
                        m.actual_model,
                        m.detail
                    );
                }
            }
        } else {
            tracing::error!(
                "❌ {} [{}]: 0/{} — ALL providers failed!",
                r.model_name,
                r.role,
                total
            );
            for m in &r.mappings {
                tracing::error!(
                    "  ❌ [{}] {}/{}: {}",
                    m.priority,
                    m.provider,
                    m.actual_model,
                    m.detail
                );
            }
        }
    }
}
