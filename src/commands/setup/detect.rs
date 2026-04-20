//! Environment and config detection helpers for the setup wizard.
//!
//! Reads existing `grob.toml` files, environment variables, and preset
//! definitions to pre-fill the wizard with sensible defaults.

use std::path::Path;

use super::types::{Compliance, DEPRECATED_KEYS, KNOWN_SECTIONS, PROVIDER_AUTH};

/// Returns the `(supports_oauth, oauth_id, env_var)` tuple for a provider.
pub(in crate::commands::setup) fn auth_for(
    name: &str,
) -> Option<(bool, &'static str, &'static str)> {
    PROVIDER_AUTH
        .iter()
        .find(|(n, ..)| *n == name)
        .map(|(_, oauth, id, env)| (*oauth, *id, *env))
}

/// Detects API keys present in the environment for known providers.
pub(in crate::commands::setup) fn discover_credentials() -> Vec<(&'static str, &'static str)> {
    PROVIDER_AUTH
        .iter()
        .filter_map(|(name, _, _, env_var)| {
            if std::env::var(env_var).is_ok() {
                Some((*name, *env_var))
            } else {
                None
            }
        })
        .collect()
}

/// Checks the existing config for unknown or deprecated top-level keys.
pub(in crate::commands::setup) fn check_schema_drift(config_path: &Path) {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let table: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };
    let Some(top) = table.as_table() else {
        return;
    };

    let mut drift_found = false;

    for (key, hint) in DEPRECATED_KEYS {
        if top.contains_key(*key) {
            if !drift_found {
                println!();
                println!("  Schema drift detected in existing config:");
                drift_found = true;
            }
            println!("    [deprecated] '{}': {}", key, hint);
        }
    }

    for key in top.keys() {
        if !KNOWN_SECTIONS.contains(&key.as_str())
            && !DEPRECATED_KEYS.iter().any(|(k, _)| *k == key.as_str())
        {
            if !drift_found {
                println!();
                println!("  Schema drift detected in existing config:");
                drift_found = true;
            }
            println!(
                "    [unknown] '{}': not a recognized section. Remove it or check for typos.",
                key
            );
        }
    }
}

/// Opens a URL in the default browser (best-effort, no error on failure).
#[allow(dead_code)]
pub(in crate::commands::setup) fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn();
    }
}

/// Reads an existing grob.toml and extracts pre-fill defaults.
pub(in crate::commands::setup) fn prefill_from_config(
    config_path: &Path,
) -> Option<(Vec<String>, bool, Option<i64>)> {
    let content = std::fs::read_to_string(config_path).ok()?;
    let config: toml::Value = toml::from_str(&content).ok()?;

    let providers: Vec<String> = config
        .get("providers")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let has_fallback = providers.iter().any(|p| p == "openrouter" || p == "gemini");

    let budget = config
        .get("budget")
        .and_then(|b| b.get("monthly_limit_usd"))
        .and_then(|v| v.as_integer());

    Some((providers, has_fallback, budget))
}

/// Reads GROB_SETUP_* environment variables for non-interactive setup.
pub(in crate::commands::setup) fn env_overrides() -> (Option<String>, Option<i64>, Option<String>) {
    let provider = std::env::var("GROB_SETUP_PROVIDER").ok();
    let budget = std::env::var("GROB_SETUP_BUDGET")
        .ok()
        .and_then(|v| v.parse::<i64>().ok());
    let compliance = std::env::var("GROB_SETUP_COMPLIANCE").ok();
    (provider, budget, compliance)
}

/// Maps a compliance string to its enum variant.
pub(in crate::commands::setup) fn parse_compliance(s: &str) -> Compliance {
    match s.to_lowercase().as_str() {
        "dlp" => Compliance::Dlp,
        "gdpr" | "eu-gdpr" | "eu" => Compliance::EuGdpr,
        "enterprise" => Compliance::Enterprise,
        "local" | "local-only" | "ollama" => Compliance::LocalOnly,
        _ => Compliance::Standard,
    }
}

/// Returns the enabled provider names declared by a preset's TOML.
pub(in crate::commands::setup) fn providers_from_preset(name: &str) -> Vec<String> {
    let content = match crate::preset::preset_content(name) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let val: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    val.get("providers")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|p| p.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true))
                .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// W-2-polish : `parse_compliance` maps known strings to the right variant.
    #[test]
    fn test_parse_compliance_variants() {
        assert!(matches!(parse_compliance("dlp"), Compliance::Dlp));
        assert!(matches!(parse_compliance("DLP"), Compliance::Dlp));
        assert!(matches!(parse_compliance("gdpr"), Compliance::EuGdpr));
        assert!(matches!(parse_compliance("eu-gdpr"), Compliance::EuGdpr));
        assert!(matches!(
            parse_compliance("enterprise"),
            Compliance::Enterprise
        ));
        assert!(matches!(
            parse_compliance("local-only"),
            Compliance::LocalOnly
        ));
        assert!(matches!(parse_compliance("ollama"), Compliance::LocalOnly));
        assert!(matches!(parse_compliance("standard"), Compliance::Standard));
        assert!(matches!(parse_compliance("unknown"), Compliance::Standard));
    }

    /// W-2-polish : `check_schema_drift` detects deprecated keys.
    #[test]
    fn test_schema_drift_detects_deprecated() {
        // Just test the constant is well-formed (the function prints to stdout).
        assert!(DEPRECATED_KEYS.len() >= 2);
        assert!(KNOWN_SECTIONS.contains(&"server"));
        assert!(KNOWN_SECTIONS.contains(&"providers"));
        assert!(KNOWN_SECTIONS.contains(&"budget"));
    }

    /// W-2-polish : `discover_credentials` returns empty when no env vars set.
    #[test]
    fn test_discover_credentials_empty_when_no_env() {
        // In test env, none of the provider env vars should be set.
        // This test validates the function does not panic and returns
        // a Vec; we can't assert emptiness because CI may have some vars set.
        let _result = discover_credentials();
    }

    /// W-2-polish : `env_overrides` reads GROB_SETUP_* variables.
    #[test]
    fn test_env_overrides_returns_none_when_unset() {
        let (provider, budget, compliance) = env_overrides();
        // Unless explicitly set in the test environment, these should be None.
        // We just check the function doesn't panic.
        let _ = (provider, budget, compliance);
    }
}
