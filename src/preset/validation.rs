//! Config validation: smoke-test providers + models + fallback chains.

use anyhow::Result;
use std::sync::Arc;

use crate::auth::TokenStore;
use crate::models::config::AppConfig;
use crate::models::{CanonicalRequest, Message, MessageContent};
use crate::providers::ProviderRegistry;

/// Result of validating a single provider/model mapping
#[derive(Debug)]
pub struct MappingResult {
    /// Priority rank for fallback ordering.
    pub priority: u32,
    /// Provider name used for this mapping.
    pub provider: String,
    /// Actual model identifier sent to the provider.
    pub actual_model: String,
    /// Whether the validation request succeeded.
    pub ok: bool,
    /// Human-readable result detail or error message.
    pub detail: String,
}

/// Result of validating a router model (with all its fallback mappings)
#[derive(Debug)]
pub struct ModelValidation {
    /// Router model name being validated.
    pub model_name: String,
    /// Router role (e.g. "default", "think", "background").
    pub role: String,
    /// Validation results for each provider mapping.
    pub mappings: Vec<MappingResult>,
}

impl ModelValidation {
    /// Returns the number of healthy (passing) mappings.
    pub fn healthy_count(&self) -> usize {
        self.mappings.iter().filter(|m| m.ok).count()
    }
    /// Returns true if every mapping passed validation.
    pub fn all_ok(&self) -> bool {
        !self.mappings.is_empty() && self.mappings.iter().all(|m| m.ok)
    }
    /// Returns true if at least one mapping passed validation.
    pub fn any_ok(&self) -> bool {
        self.mappings.iter().any(|m| m.ok)
    }
}

/// Builds a provider registry from config (for CLI validation path).
///
/// # Errors
///
/// Returns an error if the token store cannot be initialized or the
/// provider registry cannot be built from the config.
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
    let Some(provider) = registry.provider(&mapping.provider) else {
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

/// Validates router models (default/think/background/websearch) by sending a minimal request to each provider mapping in parallel.
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
fn make_test_request(model: &str) -> CanonicalRequest {
    CanonicalRequest {
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
        extensions: Default::default(),
    }
}

/// Prints a per-model health summary (checkmark, warning, or cross) and lists the failing provider mappings underneath.
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

/// Extracts the first HTTP status code (400–599) found in `detail`.
///
/// Returns `Some(code)` when a 3-digit code in the 400–599 range is present,
/// `None` for network errors, timeouts, or any other non-HTTP failure text.
fn extract_http_code(detail: &str) -> Option<u16> {
    // Walk through the string looking for a standalone 3-digit sequence.
    let bytes = detail.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i + 2 < len {
        let a = bytes[i];
        let b = bytes[i + 1];
        let c = bytes[i + 2];
        if a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit() {
            // Ensure the digit run is exactly 3 (not part of a longer number).
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
            let after_ok = i + 3 >= len || !bytes[i + 3].is_ascii_digit();
            if before_ok && after_ok {
                let code = (a - b'0') as u16 * 100 + (b - b'0') as u16 * 10 + (c - b'0') as u16;
                if (400..=599).contains(&code) {
                    return Some(code);
                }
            }
            // Skip past these three digits to avoid overlapping matches.
            i += 3;
        } else {
            i += 1;
        }
    }
    None
}

/// Returns true when all broken mappings are "expected" 429 fallbacks
/// (priority > 1, rate-limited but not the primary provider).
fn all_failures_expected(mappings: &[MappingResult]) -> bool {
    mappings
        .iter()
        .filter(|m| !m.ok)
        .all(|m| m.priority > 1 && extract_http_code(&m.detail) == Some(429))
}

/// Log validation results (for server startup / reload).
pub fn log_validation_results(results: &[ModelValidation]) {
    for r in results {
        let healthy = r.healthy_count();
        let total = r.mappings.len();

        if r.all_ok() {
            tracing::info!("✅ {} [{}]: {}/{} OK", r.model_name, r.role, healthy, total);
        } else if r.any_ok() {
            // Log each broken fallback with a level that reflects its HTTP status.
            for m in &r.mappings {
                if !m.ok {
                    log_broken_mapping(m);
                }
            }

            // Rollup: downgrade to info when every failure is an expected fallback 429.
            if all_failures_expected(&r.mappings) {
                tracing::info!(
                    "ℹ️  {} [{}]: {}/{} OK (expected fallbacks rate-limited)",
                    r.model_name,
                    r.role,
                    healthy,
                    total,
                );
            } else {
                tracing::warn!(
                    "⚠️ {} [{}]: {}/{} OK (some fallbacks broken)",
                    r.model_name,
                    r.role,
                    healthy,
                    total,
                );
            }
        } else {
            tracing::error!(
                "❌ {} [{}]: 0/{} — ALL providers failed!",
                r.model_name,
                r.role,
                total
            );
            for m in &r.mappings {
                log_broken_mapping(m);
            }
        }
    }
}

/// Emits a single broken-mapping log line at the appropriate level.
fn log_broken_mapping(m: &MappingResult) {
    match extract_http_code(&m.detail) {
        Some(429) if m.priority > 1 => {
            // Rate-limited fallback — expected operational behaviour.
            tracing::info!(
                "  💤 [{}] {}/{}: rate-limited (expected fallback)",
                m.priority,
                m.provider,
                m.actual_model,
            );
        }
        Some(429) => {
            // Primary provider is rate-limited — unexpected.
            tracing::warn!(
                "  ⚠️ [{}] {}/{}: primary rate-limited — {}",
                m.priority,
                m.provider,
                m.actual_model,
                m.detail,
            );
        }
        Some(401) => {
            tracing::error!(
                "  🔒 [{}] {}/{}: auth revoked — run grob connect --force-reauth",
                m.priority,
                m.provider,
                m.actual_model,
            );
        }
        Some(code) if (500..=599).contains(&code) => {
            tracing::warn!(
                "  ⚠️ [{}] {}/{}: transient server error: {}",
                m.priority,
                m.provider,
                m.actual_model,
                m.detail,
            );
        }
        _ => {
            // 400, 404, network errors, timeouts, etc.
            tracing::warn!(
                "  ❌ [{}] {}/{}: {}",
                m.priority,
                m.provider,
                m.actual_model,
                m.detail,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_http_code ──────────────────────────────────────────────────────

    #[test]
    fn extract_http_code_recognises_429_in_anthropic_error() {
        assert_eq!(extract_http_code("429 - anthropic API error"), Some(429));
    }

    #[test]
    fn extract_http_code_returns_none_for_connection_refused() {
        assert_eq!(extract_http_code("connection refused"), None);
    }

    #[test]
    fn extract_http_code_recognises_401_with_prefix() {
        assert_eq!(extract_http_code("Provider API error: 401"), Some(401));
    }

    #[test]
    fn extract_http_code_returns_none_for_timeout() {
        assert_eq!(extract_http_code("timeout after 5s"), None);
    }

    #[test]
    fn extract_http_code_recognises_500() {
        assert_eq!(
            extract_http_code("HTTP 500 Internal Server Error"),
            Some(500)
        );
    }

    #[test]
    fn extract_http_code_ignores_non_http_three_digit_numbers() {
        // 200 is not in 400-599 range
        assert_eq!(extract_http_code("response 200 OK"), None);
    }

    #[test]
    fn extract_http_code_ignores_longer_digit_sequences() {
        // 12345 contains no standalone 4xx/5xx code
        assert_eq!(extract_http_code("error code 12345"), None);
    }

    // ── log_validation_results: level routing via log capture ─────────────────
    //
    // We test the *classification logic* by asserting on `all_failures_expected`
    // and `extract_http_code` rather than capturing tracing output (which would
    // require a subscriber harness).  The mapping-level helpers are tested
    // indirectly through `all_failures_expected`.

    fn make_mapping(priority: u32, ok: bool, detail: &str) -> MappingResult {
        MappingResult {
            priority,
            provider: "test-provider".to_string(),
            actual_model: "test-model".to_string(),
            ok,
            detail: detail.to_string(),
        }
    }

    /// priority=1 + 429 → NOT an expected failure (primary is rate-limited).
    #[test]
    fn primary_429_is_not_expected() {
        let mappings = vec![make_mapping(1, false, "429 - rate limited")];
        assert!(!all_failures_expected(&mappings));
    }

    /// priority=2 + 429 → expected fallback failure.
    #[test]
    fn fallback_429_is_expected() {
        let mappings = vec![make_mapping(2, false, "429 - rate limited")];
        assert!(all_failures_expected(&mappings));
    }

    /// priority=1 + 401 → NOT expected (auth error is always a real problem).
    #[test]
    fn primary_401_is_not_expected() {
        let mappings = vec![make_mapping(1, false, "Provider API error: 401")];
        assert!(!all_failures_expected(&mappings));
    }

    /// priority=2 + 500 → NOT expected (5xx server errors are not expected fallbacks).
    #[test]
    fn fallback_500_is_not_expected() {
        let mappings = vec![make_mapping(2, false, "HTTP 500 Internal Server Error")];
        assert!(!all_failures_expected(&mappings));
    }

    /// Mix: one ok mapping + one fallback 429 → all_failures_expected is true.
    #[test]
    fn mixed_ok_and_fallback_429_all_expected() {
        let mappings = vec![
            make_mapping(1, true, "OK (123ms)"),
            make_mapping(2, false, "429 - anthropic API error"),
        ];
        assert!(all_failures_expected(&mappings));
    }

    /// Mix: one ok + one fallback with 500 → not all expected.
    #[test]
    fn mixed_ok_and_fallback_500_not_all_expected() {
        let mappings = vec![
            make_mapping(1, true, "OK (123ms)"),
            make_mapping(2, false, "HTTP 500"),
        ];
        assert!(!all_failures_expected(&mappings));
    }
}
