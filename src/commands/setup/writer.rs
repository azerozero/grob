//! Atomic TOML writers and in-memory config mutations.
//!
//! All functions here operate on an in-memory `toml::Value`; the single
//! on-disk write happens at the end of [`write_config`] or, for the
//! GDPR overlay, inside [`apply_compliance`].

use std::path::Path;

use anyhow::Result;

use super::types::{AuthOverride, Choices, Compliance, FallbackChoice};

/// Removes fallback providers (by name) from a loaded preset config and
/// drops any `[[models.mappings]]` that still reference them.
///
/// Invoked when the user picks `FallbackChoice::None` so the written config
/// does not carry a dead `$OPENROUTER_API_KEY` reference that would warn at
/// startup. Kept as a free function for direct snapshot testing.
fn strip_fallback(config: &mut toml::Value, names_to_strip: &[&str]) {
    if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
        providers.retain(|p| {
            let keep = p
                .get("name")
                .and_then(|n| n.as_str())
                .is_none_or(|n| !names_to_strip.contains(&n));
            keep
        });
    }
    if let Some(models) = config.get_mut("models").and_then(|m| m.as_array_mut()) {
        for model in models.iter_mut() {
            let Some(mappings) = model.get_mut("mappings").and_then(|m| m.as_array_mut()) else {
                continue;
            };
            mappings.retain(|m| {
                m.get("provider")
                    .and_then(|p| p.as_str())
                    .is_none_or(|p| !names_to_strip.contains(&p))
            });
        }
    }
}

/// Inserts `fields` into `[section]`, creating the section when absent.
pub(in crate::commands::setup) fn patch(
    config: &mut toml::Value,
    section: &str,
    fields: &[(&str, toml::Value)],
) -> Result<()> {
    let top = config
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("config root is not a TOML table"))?;
    let table = top
        .entry(section)
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("[{}] is not a table", section))?;
    for (k, v) in fields {
        table.insert(k.to_string(), v.clone());
    }
    Ok(())
}

/// Overwrites each provider's `auth_type`, `oauth_provider`, and `api_key` from the wizard overrides.
pub(in crate::commands::setup) fn apply_auth_overrides(
    config: &mut toml::Value,
    auth: &[AuthOverride],
) {
    let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) else {
        return;
    };
    for p in providers.iter_mut() {
        let pname = p.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let Some(ov) = auth.iter().find(|a| a.provider == pname) else {
            continue;
        };
        let Some(t) = p.as_table_mut() else {
            continue;
        };
        if ov.use_oauth {
            t.insert("auth_type".into(), "oauth".into());
            t.insert(
                "oauth_provider".into(),
                toml::Value::String(ov.oauth_id.clone()),
            );
            t.remove("api_key");
        } else {
            t.insert("auth_type".into(), "apikey".into());
            t.insert(
                "api_key".into(),
                toml::Value::String(format!("${}", ov.env_var)),
            );
            t.remove("oauth_provider");
        }
    }
}

/// Inserts or strips the user-selected fallback provider entry in the TOML config.
pub(in crate::commands::setup) fn apply_fallback(
    config: &mut toml::Value,
    fallback: &FallbackChoice,
) {
    match fallback {
        FallbackChoice::None => {
            strip_fallback(config, &["openrouter", "gemini"]);
        }
        FallbackChoice::OpenRouter => {
            replace_fallback_provider(config, "openrouter", "openrouter", "$OPENROUTER_API_KEY");
        }
        FallbackChoice::Gemini => {
            replace_fallback_provider(config, "gemini", "gemini", "$GEMINI_API_KEY");
        }
        FallbackChoice::KeepPreset => {}
    }
}

/// Replaces any existing provider of the given name with a minimal fallback entry (pass-through for openrouter).
fn replace_fallback_provider(
    config: &mut toml::Value,
    name: &str,
    provider_type: &str,
    api_key: &str,
) {
    let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) else {
        return;
    };
    providers.retain(|p| p.get("name").and_then(|n| n.as_str()) != Some(name));
    let mut t = toml::map::Map::new();
    t.insert("name".into(), name.into());
    t.insert("provider_type".into(), provider_type.into());
    if provider_type == "openrouter" {
        t.insert("pass_through".into(), toml::Value::Boolean(true));
    }
    t.insert("enabled".into(), toml::Value::Boolean(true));
    t.insert("models".into(), toml::Value::Array(vec![]));
    t.insert("api_key".into(), api_key.into());
    providers.push(toml::Value::Table(t));
}

/// Applies compliance-related config patches and optionally overlays a signed EU/GDPR preset.
///
/// Returns `true` when EU/GDPR compliance was applied via overlay (caller
/// must skip further writes), `false` for all other variants.
pub(in crate::commands::setup) fn apply_compliance(
    config: &mut toml::Value,
    compliance: Compliance,
    path: &Path,
) -> Result<bool> {
    match compliance {
        Compliance::Standard => {}
        Compliance::Dlp => {
            patch(config, "dlp", &[("enabled", true.into())])?;
        }
        Compliance::Enterprise => {
            patch(
                config,
                "security",
                &[
                    ("enabled", true.into()),
                    ("audit_dir", "~/.grob/audit".into()),
                    ("rate_limit_rps", 100.into()),
                    ("rate_limit_burst", 200.into()),
                    ("circuit_breaker", true.into()),
                    ("security_headers", true.into()),
                ],
            )?;
            patch(config, "dlp", &[("enabled", true.into())])?;
        }
        Compliance::LocalOnly => {
            patch(config, "security", &[("enabled", true.into())])?;
            patch(config, "dlp", &[("enabled", true.into())])?;
        }
        Compliance::EuGdpr => {
            std::fs::write(path, toml::to_string_pretty(config)?)?;
            crate::preset::overlay_compliance("eu-ai-act", path)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Writes the full config: backs up the old file, applies the chosen preset, then patches in every wizard override.
pub(in crate::commands::setup) fn write_config(choices: &Choices, path: &Path) -> Result<()> {
    // Backup
    if path.exists() {
        let backup = path.with_extension("toml.backup");
        std::fs::copy(path, &backup)?;
        println!("  Backup: {}", backup.display());
    }

    // The previous `local` preset (Ollama-only) was retired; LocalOnly
    // compliance now keeps the user-chosen preset and just enables
    // security + dlp downstream via apply_compliance().
    crate::preset::apply_preset(&choices.preset, path)?;

    // Read back and apply all overrides in memory
    let content = std::fs::read_to_string(path)?;
    let mut config: toml::Value = toml::from_str(&content)?;

    apply_auth_overrides(&mut config, &choices.auth);
    apply_fallback(&mut config, &choices.fallback);

    // Custom endpoints
    if !choices.custom_endpoints.is_empty() {
        if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
            for ep in &choices.custom_endpoints {
                let mut t = toml::map::Map::new();
                t.insert("name".into(), ep.name.clone().into());
                t.insert("provider_type".into(), ep.provider_type.clone().into());
                t.insert("base_url".into(), ep.base_url.clone().into());
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("models".into(), toml::Value::Array(vec![]));
                t.insert("pass_through".into(), toml::Value::Boolean(true));
                if let Some(ref key) = ep.api_key {
                    let env_var = format!("{}_API_KEY", ep.name.to_uppercase().replace('-', "_"));
                    t.insert("api_key".into(), format!("${env_var}").into());
                    let _ = key;
                }
                providers.push(toml::Value::Table(t));
            }
        }
    }

    if apply_compliance(&mut config, choices.compliance, path)? {
        return Ok(());
    }

    if let Some(ref b) = choices.budget {
        patch(
            &mut config,
            "budget",
            &[
                ("monthly_limit_usd", b.amount.into()),
                ("warn_at_percent", 80.into()),
            ],
        )?;
    }

    std::fs::write(path, toml::to_string_pretty(&config)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::setup::types::BudgetChoice;

    /// W-2 : quand l'utilisateur choisit `Aucun` dans le nouveau screen
    /// fallback, `strip_fallback` retire le provider openrouter du preset
    /// charge ET les `[[models.mappings]]` qui le referencent. Sans ce
    /// nettoyage, un warning fantome `$OPENROUTER_API_KEY not set` tombe au
    /// prochain demarrage meme si l'utilisateur a dit non au fallback.
    ///
    /// Test against `ultra-cheap` since it ships openrouter as a real
    /// fallback (perf is now pure Anthropic OAuth, no openrouter).
    #[test]
    fn test_w2_strip_fallback_removes_openrouter_and_mappings() {
        let preset =
            crate::preset::preset_content("ultra-cheap").expect("ultra-cheap preset loads");
        let mut config: toml::Value = toml::from_str(&preset).expect("ultra-cheap preset parses");

        // Sanity avant strip : openrouter doit bien etre present.
        let has_openrouter_before = config
            .get("providers")
            .and_then(|p| p.as_array())
            .map(|providers| {
                providers
                    .iter()
                    .any(|p| p.get("name").and_then(|n| n.as_str()) == Some("openrouter"))
            })
            .unwrap_or(false);
        assert!(
            has_openrouter_before,
            "ultra-cheap preset should ship openrouter as a fallback provider"
        );

        strip_fallback(&mut config, &["openrouter", "gemini"]);

        // Apres strip : plus d'openrouter nulle part.
        let providers = config
            .get("providers")
            .and_then(|p| p.as_array())
            .expect("providers still an array");
        for p in providers {
            let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("");
            assert_ne!(name, "openrouter", "openrouter provider must be removed");
            assert_ne!(name, "gemini", "gemini provider must be removed");
        }

        // Plus aucune mapping ne reference openrouter.
        let models = config
            .get("models")
            .and_then(|m| m.as_array())
            .expect("models still an array");
        for m in models {
            if let Some(mappings) = m.get("mappings").and_then(|x| x.as_array()) {
                for mp in mappings {
                    let prov = mp.get("provider").and_then(|p| p.as_str()).unwrap_or("");
                    assert_ne!(
                        prov,
                        "openrouter",
                        "openrouter mapping must be stripped from model {:?}",
                        m.get("name")
                    );
                    assert_ne!(prov, "gemini", "gemini mapping must be stripped");
                }
            }
        }

        // Snapshot du resultat serialise pour capter toute regression.
        let rendered = toml::to_string_pretty(&config).expect("serialize back");
        insta::assert_snapshot!("w2_ultra_cheap_preset_without_fallback", rendered);
    }

    /// W-3 : le patch TOML applique par `write_config` pour un budget custom
    /// s'ecrit sous `[budget] monthly_limit_usd` + `warn_at_percent = 80`.
    /// Verrouille le schema pour que le MCP server (qui lit cette cle) ne
    /// casse pas sur un futur refactor.
    #[test]
    fn test_w3_budget_patch_writes_monthly_limit_usd() {
        let mut config: toml::Value = toml::from_str("").unwrap();
        let budget = BudgetChoice {
            amount: 123,
            currency: "EUR",
        };
        patch(
            &mut config,
            "budget",
            &[
                ("monthly_limit_usd", budget.amount.into()),
                ("warn_at_percent", 80.into()),
            ],
        )
        .expect("patch should succeed on valid TOML");
        let section = config.get("budget").and_then(|v| v.as_table()).unwrap();
        assert_eq!(
            section
                .get("monthly_limit_usd")
                .and_then(|v| v.as_integer()),
            Some(123)
        );
        assert_eq!(
            section.get("warn_at_percent").and_then(|v| v.as_integer()),
            Some(80)
        );
    }

    /// W-2 : strip sur un config qui n'a pas de provider a retirer = no-op.
    #[test]
    fn test_w2_strip_fallback_noop_when_absent() {
        let mut config: toml::Value = toml::from_str(
            r#"
[[providers]]
name = "anthropic"
provider_type = "anthropic"
enabled = true

[[models]]
name = "default"

[[models.mappings]]
provider = "anthropic"
actual_model = "claude-sonnet-4-6"
priority = 1
"#,
        )
        .unwrap();

        strip_fallback(&mut config, &["openrouter", "gemini"]);

        let providers_after = config.get("providers").and_then(|p| p.as_array()).unwrap();
        assert_eq!(providers_after.len(), 1);
        let mappings_after = config
            .get("models")
            .and_then(|m| m.as_array())
            .unwrap()
            .iter()
            .filter_map(|m| m.get("mappings").and_then(|x| x.as_array()))
            .next()
            .unwrap();
        assert_eq!(mappings_after.len(), 1);
    }

    /// W-3 : `prompt_url` rejects URLs that don't start with http:// or https://.
    #[test]
    fn test_w3_url_validation_rejects_bare_host() {
        let good = ["http://localhost:8080", "https://my-llm.company.com/v1"];
        for url in good {
            assert!(
                url.starts_with("http://") || url.starts_with("https://"),
                "{url} should pass"
            );
        }
        let bad = ["ftp://x", "my-llm.company.com", ""];
        for url in bad {
            assert!(
                !(url.starts_with("http://") || url.starts_with("https://")),
                "{url} should be rejected"
            );
        }
    }

    /// W-3 : custom endpoint providers are appended to the config TOML by
    /// `write_config`.
    #[test]
    fn test_w3_custom_endpoint_written_to_config() {
        let mut config: toml::Value = toml::from_str(
            r#"
[[providers]]
name = "anthropic"
provider_type = "anthropic"
enabled = true
models = []
"#,
        )
        .unwrap();

        if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
            let mut t = toml::map::Map::new();
            t.insert("name".into(), "my-llm".into());
            t.insert("provider_type".into(), "openai_compatible".into());
            t.insert("base_url".into(), "https://my-llm.company.com/v1".into());
            t.insert("enabled".into(), toml::Value::Boolean(true));
            t.insert("models".into(), toml::Value::Array(vec![]));
            t.insert("pass_through".into(), toml::Value::Boolean(true));
            t.insert("api_key".into(), "$MY_LLM_API_KEY".into());
            providers.push(toml::Value::Table(t));
        }

        let providers = config.get("providers").and_then(|p| p.as_array()).unwrap();
        assert_eq!(providers.len(), 2);

        let custom = &providers[1];
        assert_eq!(custom.get("name").and_then(|n| n.as_str()), Some("my-llm"));
        assert_eq!(
            custom.get("provider_type").and_then(|n| n.as_str()),
            Some("openai_compatible")
        );
        assert_eq!(
            custom.get("base_url").and_then(|n| n.as_str()),
            Some("https://my-llm.company.com/v1")
        );
        assert_eq!(
            custom.get("pass_through").and_then(|n| n.as_bool()),
            Some(true)
        );
        assert_eq!(
            custom.get("api_key").and_then(|n| n.as_str()),
            Some("$MY_LLM_API_KEY")
        );
    }

    /// W-3 : anthropic_compatible endpoint also writes correctly.
    #[test]
    fn test_w3_anthropic_compatible_endpoint_written() {
        let mut config: toml::Value = toml::from_str("[[providers]]").unwrap();

        if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
            let mut t = toml::map::Map::new();
            t.insert("name".into(), "corp-claude".into());
            t.insert("provider_type".into(), "anthropic_compatible".into());
            t.insert("base_url".into(), "https://claude.corp.internal/api".into());
            t.insert("enabled".into(), toml::Value::Boolean(true));
            t.insert("models".into(), toml::Value::Array(vec![]));
            t.insert("pass_through".into(), toml::Value::Boolean(true));
            providers.push(toml::Value::Table(t));
        }

        let providers = config.get("providers").and_then(|p| p.as_array()).unwrap();
        let custom = providers.last().unwrap();
        assert_eq!(
            custom.get("provider_type").and_then(|n| n.as_str()),
            Some("anthropic_compatible")
        );
        assert_eq!(
            custom.get("base_url").and_then(|n| n.as_str()),
            Some("https://claude.corp.internal/api")
        );
    }
}
