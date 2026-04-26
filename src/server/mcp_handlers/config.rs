//! Config-section read/write helpers shared by `grob_configure`, `grob_autotune`, and the wizard tools.
//!
//! These helpers operate on an [`AppConfig`](crate::models::config::AppConfig)
//! by value: the caller clones the active config, mutates it via
//! [`apply_config_update`], then persists and hot-reloads through
//! [`super::super::config_guard::persist_and_reload`]. The deny-list lives in
//! [`super::super::config_guard::is_key_denied`].

use crate::features::mcp::server::types::ConfigSection;

/// Returns a safe JSON view of the requested config section (no secrets).
pub(super) fn read_config_section(
    config: &crate::models::config::AppConfig,
    section: &ConfigSection,
) -> serde_json::Value {
    match section {
        ConfigSection::Router => serde_json::json!({
            "default": config.router.default,
            "background": config.router.background,
            "think": config.router.think,
            "websearch": config.router.websearch,
            "auto_map_regex": config.router.auto_map_regex,
            "background_regex": config.router.background_regex,
            "prompt_rules": config.router.prompt_rules,
            "gdpr": config.router.gdpr,
            "region": config.router.region,
        }),
        ConfigSection::Budget => serde_json::json!({
            "monthly_limit_usd": config.budget.monthly_limit_usd,
            "warn_at_percent": config.budget.warn_at_percent,
        }),
        ConfigSection::Dlp => serde_json::json!({
            "enabled": config.dlp.enabled,
            "scan_input": config.dlp.scan_input,
            "scan_output": config.dlp.scan_output,
            "entropy_enabled": config.dlp.entropy.enabled,
            "entropy_action": format!("{:?}", config.dlp.entropy.action),
            "pii_credit_cards": config.dlp.pii.credit_cards,
            "pii_iban": config.dlp.pii.iban,
            "pii_action": format!("{:?}", config.dlp.pii.action),
            "url_exfil_enabled": config.dlp.url_exfil.enabled,
            "prompt_injection_enabled": config.dlp.prompt_injection.enabled,
        }),
        ConfigSection::Cache => serde_json::json!({
            "enabled": config.cache.enabled,
            "max_capacity": config.cache.max_capacity,
            "ttl_secs": config.cache.ttl_secs,
            "max_entry_bytes": config.cache.max_entry_bytes,
        }),
        ConfigSection::Classifier => {
            let cfg = config.classifier.clone().unwrap_or_default();
            serde_json::json!({
                "weights": {
                    "max_tokens": cfg.weights.max_tokens,
                    "tools": cfg.weights.tools,
                    "context_size": cfg.weights.context_size,
                    "keywords": cfg.weights.keywords,
                    "system_prompt": cfg.weights.system_prompt,
                },
                "thresholds": {
                    "medium_threshold": cfg.thresholds.medium_threshold,
                    "complex_threshold": cfg.thresholds.complex_threshold,
                },
            })
        }
    }
}

/// Applies an update to a config section, returning the modified config.
///
/// The caller is responsible for triggering the hot-reload after a successful update.
///
/// # Errors
///
/// Returns an error string when the key is unknown for the section, when the
/// value type does not match the field, or when the section is read-only
/// (currently `Dlp`).
pub(super) fn apply_config_update(
    config: &mut crate::models::config::AppConfig,
    section: &ConfigSection,
    key: &str,
    value: &serde_json::Value,
) -> Result<(), String> {
    match section {
        ConfigSection::Router => match key {
            "default" => {
                config.router.default = value
                    .as_str()
                    .ok_or("expected string for router.default")?
                    .to_string();
            }
            "background" => {
                config.router.background = value.as_str().map(String::from);
            }
            "think" => {
                config.router.think = value.as_str().map(String::from);
            }
            "websearch" => {
                config.router.websearch = value.as_str().map(String::from);
            }
            "auto_map_regex" => {
                config.router.auto_map_regex = value.as_str().map(String::from);
            }
            "background_regex" => {
                config.router.background_regex = value.as_str().map(String::from);
            }
            "gdpr" => {
                config.router.gdpr = value.as_bool().ok_or("expected bool for router.gdpr")?;
            }
            "region" => {
                config.router.region = value.as_str().map(String::from);
            }
            _ => return Err(format!("unknown router key: {key}")),
        },
        ConfigSection::Budget => match key {
            "monthly_limit_usd" => {
                let v = value
                    .as_f64()
                    .ok_or("expected number for budget.monthly_limit_usd")?;
                config.budget.monthly_limit_usd =
                    crate::cli::BudgetUsd::new(v).map_err(|e| format!("invalid budget: {e}"))?;
            }
            "warn_at_percent" => {
                let v = value
                    .as_u64()
                    .ok_or("expected integer for budget.warn_at_percent")?;
                if v > 100 {
                    return Err("warn_at_percent must be 0-100".to_string());
                }
                config.budget.warn_at_percent = v as u32;
            }
            _ => return Err(format!("unknown budget key: {key}")),
        },
        ConfigSection::Dlp => {
            return Err("DLP section is read-only via self-tuning".to_string());
        }
        ConfigSection::Cache => match key {
            "enabled" => {
                config.cache.enabled = value.as_bool().ok_or("expected bool for cache.enabled")?;
            }
            "max_capacity" => {
                config.cache.max_capacity = value
                    .as_u64()
                    .ok_or("expected integer for cache.max_capacity")?;
            }
            "ttl_secs" => {
                config.cache.ttl_secs = value
                    .as_u64()
                    .ok_or("expected integer for cache.ttl_secs")?;
            }
            "max_entry_bytes" => {
                let v = value
                    .as_u64()
                    .ok_or("expected integer for cache.max_entry_bytes")?;
                config.cache.max_entry_bytes = v as usize;
            }
            _ => return Err(format!("unknown cache key: {key}")),
        },
        ConfigSection::Classifier => {
            let cfg = config.classifier.get_or_insert_with(Default::default);
            let v = value
                .as_f64()
                .ok_or_else(|| format!("expected number for classifier.{key}"))?
                as f32;
            match key {
                "weights.max_tokens" => cfg.weights.max_tokens = v,
                "weights.tools" => cfg.weights.tools = v,
                "weights.context_size" => cfg.weights.context_size = v,
                "weights.keywords" => cfg.weights.keywords = v,
                "weights.system_prompt" => cfg.weights.system_prompt = v,
                "thresholds.medium_threshold" => cfg.thresholds.medium_threshold = v,
                "thresholds.complex_threshold" => cfg.thresholds.complex_threshold = v,
                _ => return Err(format!("unknown classifier key: {key}")),
            }
        }
    }
    Ok(())
}

/// Parses the `section` parameter (or returns `None` when absent).
///
/// # Errors
///
/// Returns an error string when the JSON value is not a recognized
/// [`ConfigSection`] variant.
pub(super) fn parse_section(
    value: Option<&serde_json::Value>,
) -> Result<Option<ConfigSection>, String> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => serde_json::from_value::<ConfigSection>(v.clone())
            .map(Some)
            .map_err(|e| e.to_string()),
    }
}
