use anyhow::{Context, Result};
use std::collections::HashSet;

use super::{AppConfig, ModelStrategy};

impl AppConfig {
    /// Validate configuration for common errors
    pub fn validate(&self) -> Result<()> {
        let provider_names: HashSet<&str> =
            self.providers.iter().map(|p| p.name.as_str()).collect();

        // Check model mappings reference existing providers
        for model in &self.models {
            for mapping in &model.mappings {
                if !provider_names.contains(mapping.provider.as_str()) {
                    anyhow::bail!(
                        "Model '{}' references unknown provider '{}'. Available: {:?}",
                        model.name,
                        mapping.provider,
                        provider_names.iter().collect::<Vec<_>>()
                    );
                }
            }
        }

        // Check enabled providers have auth configured
        for provider in &self.providers {
            if !provider.is_enabled() {
                continue;
            }
            use crate::providers::AuthType;
            match provider.auth_type {
                AuthType::ApiKey => {
                    let key_missing = provider.api_key.is_none();
                    if key_missing {
                        // Special case: gemini/vertex-ai may use ADC
                        if provider.provider_type != "vertex-ai" {
                            anyhow::bail!(
                                "Provider '{}' has auth_type=apikey but no api_key configured",
                                provider.name
                            );
                        }
                    }
                }
                AuthType::OAuth => {
                    if provider.oauth_provider.is_none() {
                        anyhow::bail!(
                            "Provider '{}' has auth_type=oauth but no oauth_provider configured",
                            provider.name
                        );
                    }
                }
            }
        }

        // Validate regex patterns compile
        if let Some(ref pattern) = self.router.auto_map_regex {
            if !pattern.is_empty() {
                regex::Regex::new(pattern)
                    .with_context(|| format!("Invalid auto_map_regex: '{}'", pattern))?;
            }
        }
        if let Some(ref pattern) = self.router.background_regex {
            if !pattern.is_empty() {
                regex::Regex::new(pattern)
                    .with_context(|| format!("Invalid background_regex: '{}'", pattern))?;
            }
        }
        for (i, rule) in self.router.prompt_rules.iter().enumerate() {
            regex::Regex::new(&rule.pattern).with_context(|| {
                format!("Invalid prompt_rule[{}] pattern: '{}'", i, rule.pattern)
            })?;
        }

        // Warn if router models don't exist in [[models]]
        let model_names: HashSet<&str> = self.models.iter().map(|m| m.name.as_str()).collect();

        let check_router_model = |name: &str, field: &str| {
            if !model_names.contains(name) && !model_names.is_empty() {
                eprintln!(
                    "⚠️  Warning: router.{} = '{}' not found in [[models]]",
                    field, name
                );
            }
        };

        check_router_model(&self.router.default, "default");
        if let Some(ref m) = self.router.background {
            check_router_model(m, "background");
        }
        if let Some(ref m) = self.router.think {
            check_router_model(m, "think");
        }
        if let Some(ref m) = self.router.websearch {
            check_router_model(m, "websearch");
        }

        // Validate ACME config (require domains + contacts when enabled)
        if self.server.tls.acme.enabled {
            if self.server.tls.acme.domains.is_empty() {
                anyhow::bail!(
                    "ACME is enabled but no domains configured. Set [server.tls.acme] domains = [\"example.com\"]"
                );
            }
            if self.server.tls.acme.contacts.is_empty() {
                anyhow::bail!(
                    "ACME is enabled but no contacts configured. Set [server.tls.acme] contacts = [\"admin@example.com\"]"
                );
            }
        }

        // Validate auth mode
        match self.auth.mode.as_str() {
            "none" | "api_key" | "jwt" => {}
            other => anyhow::bail!(
                "Invalid auth.mode '{}'. Must be one of: none, api_key, jwt",
                other
            ),
        }

        // Validate fan_out config consistency
        for model in &self.models {
            if model.strategy == ModelStrategy::FanOut && model.fan_out.is_none() {
                anyhow::bail!(
                    "Model '{}' has strategy=fan_out but no [fan_out] config block",
                    model.name
                );
            }
            // Warn if judge_model not in [[models]]
            if let Some(ref fo) = model.fan_out {
                if let Some(ref judge) = fo.judge_model {
                    if !model_names.contains(judge.as_str()) && !model_names.is_empty() {
                        eprintln!(
                            "⚠️  Warning: model '{}' fan_out.judge_model '{}' not found in [[models]]",
                            model.name, judge
                        );
                    }
                }
            }
        }

        Ok(())
    }
}
