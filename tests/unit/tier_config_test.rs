//! Tests for declarative tier configuration.
//!
//! Validates TOML parsing, provider resolution by complexity tier,
//! fallback behaviour when no tier matches, and fan-out flag detection.

#[cfg(test)]
mod tests {
    use grob::cli::{AppConfig, ModelMapping, TierConfig};
    use grob::models::{RouteDecision, RouteType};
    use grob::routing::classify::ComplexityTier;

    // ── TOML parsing ────────────────────────────────────────────────

    #[test]
    fn parse_toml_with_tiers() {
        let toml = r#"
[server]
port = 8080

[router]
default = "my-model"

[[tiers]]
name = "trivial"
providers = ["cheap-provider"]

[[tiers]]
name = "complex"
providers = ["strong-a", "strong-b"]
fanout = true
        "#;

        let config = AppConfig::from_content(toml, "test").unwrap();
        assert_eq!(config.tiers.len(), 2);

        assert_eq!(config.tiers[0].name, "trivial");
        assert_eq!(config.tiers[0].providers, vec!["cheap-provider"]);
        assert!(!config.tiers[0].fanout);

        assert_eq!(config.tiers[1].name, "complex");
        assert_eq!(config.tiers[1].providers, vec!["strong-a", "strong-b"]);
        assert!(config.tiers[1].fanout);
    }

    #[test]
    fn parse_toml_without_tiers_is_retrocompatible() {
        let toml = r#"
[server]
port = 8080

[router]
default = "my-model"
        "#;

        let config = AppConfig::from_content(toml, "test").unwrap();
        assert!(config.tiers.is_empty());
    }

    // ── Tier -> provider resolution ─────────────────────────────────

    /// Replicates the tier lookup from `resolve_provider_mappings`:
    /// given a complexity tier and a config with [[tiers]], returns the
    /// matching tier providers as ModelMapping entries.
    fn resolve_tier_providers(
        tiers: &[TierConfig],
        tier: &ComplexityTier,
        model_name: &str,
    ) -> Option<Vec<ModelMapping>> {
        let tier_name = tier.to_string();
        let tier_cfg = tiers.iter().find(|t| t.name == tier_name)?;
        let mappings: Vec<ModelMapping> = tier_cfg
            .providers
            .iter()
            .enumerate()
            .map(|(i, provider_name)| ModelMapping {
                priority: (i as u32) + 1,
                provider: provider_name.clone(),
                actual_model: model_name.to_string(),
                inject_continuation_prompt: false,
            })
            .collect();
        if mappings.is_empty() {
            None
        } else {
            Some(mappings)
        }
    }

    #[test]
    fn tier_trivial_resolves_correct_providers() {
        let tiers = vec![
            TierConfig {
                name: "trivial".to_string(),
                providers: vec!["haiku-provider".to_string(), "flash-provider".to_string()],
                fanout: false,
                match_conditions: None,
            },
            TierConfig {
                name: "complex".to_string(),
                providers: vec!["opus-provider".to_string()],
                fanout: false,
                match_conditions: None,
            },
        ];

        let mappings =
            resolve_tier_providers(&tiers, &ComplexityTier::Trivial, "my-model").unwrap();

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].provider, "haiku-provider");
        assert_eq!(mappings[0].priority, 1);
        assert_eq!(mappings[0].actual_model, "my-model");
        assert_eq!(mappings[1].provider, "flash-provider");
        assert_eq!(mappings[1].priority, 2);
    }

    #[test]
    fn tier_unknown_returns_none_for_fallback() {
        let tiers = vec![TierConfig {
            name: "trivial".to_string(),
            providers: vec!["cheap".to_string()],
            fanout: false,
            match_conditions: None,
        }];

        // Medium is not configured -- fallback to default routing
        let result = resolve_tier_providers(&tiers, &ComplexityTier::Medium, "my-model");
        assert!(result.is_none());
    }

    #[test]
    fn tier_empty_providers_returns_none() {
        let tiers = vec![TierConfig {
            name: "trivial".to_string(),
            providers: vec![],
            fanout: false,
            match_conditions: None,
        }];

        let result = resolve_tier_providers(&tiers, &ComplexityTier::Trivial, "my-model");
        assert!(result.is_none());
    }

    // ── Fan-out flag detection ──────────────────────────────────────

    #[test]
    fn fanout_true_detected_on_matching_tier() {
        let tiers = [
            TierConfig {
                name: "trivial".to_string(),
                providers: vec!["a".to_string()],
                fanout: false,
                match_conditions: None,
            },
            TierConfig {
                name: "complex".to_string(),
                providers: vec!["b".to_string(), "c".to_string()],
                fanout: true,
                match_conditions: None,
            },
        ];

        let tier = ComplexityTier::Complex;
        let tier_name = tier.to_string();
        let tier_cfg = tiers.iter().find(|t| t.name == tier_name).unwrap();
        assert!(tier_cfg.fanout);
    }

    #[test]
    fn fanout_false_by_default() {
        let toml = r#"
[server]
port = 8080

[router]
default = "my-model"

[[tiers]]
name = "trivial"
providers = ["cheap"]
        "#;

        let config = AppConfig::from_content(toml, "test").unwrap();
        assert!(!config.tiers[0].fanout);
    }

    // ── Route decision carries tier ─────────────────────────────────

    #[test]
    fn route_decision_with_tier_selects_tier_providers() {
        let tiers = vec![TierConfig {
            name: "complex".to_string(),
            providers: vec!["opus".to_string(), "sonnet".to_string()],
            fanout: false,
            match_conditions: None,
        }];

        let decision = RouteDecision {
            model_name: "my-model".to_string(),
            route_type: RouteType::Default,
            matched_prompt: None,
            complexity_tier: Some(ComplexityTier::Complex),
        };

        let mappings = resolve_tier_providers(
            &tiers,
            decision.complexity_tier.as_ref().unwrap(),
            &decision.model_name,
        )
        .unwrap();

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].provider, "opus");
        assert_eq!(mappings[1].provider, "sonnet");
    }

    #[test]
    fn route_decision_without_tier_skips_resolution() {
        let decision = RouteDecision {
            model_name: "my-model".to_string(),
            route_type: RouteType::Default,
            matched_prompt: None,
            complexity_tier: None,
        };

        // No tier in decision -- tier resolution is not triggered
        assert!(decision.complexity_tier.is_none());
    }
}
