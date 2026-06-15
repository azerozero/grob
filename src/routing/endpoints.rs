//! Read-only endpoint inventory derived from the legacy routing schema.
//!
//! This is ADR-0022 phase 0: expose a deterministic endpoint-shaped view of the
//! current `[[providers]]`, `[[models]]`, and `[[tiers]]` configuration without
//! adding a public `[[endpoints]]` TOML schema or changing dispatch behavior.
//!
//! The adapter is intentionally read-only. It is useful for migration previews,
//! golden tests, and future observability, while the runtime resolver continues
//! to use the legacy routing code until the migration path is proven.

use std::collections::BTreeMap;

use crate::config::AppConfig;

/// Read-only endpoint/policy view derived from legacy config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInventory {
    /// Physical provider/model or provider/pass-through endpoints.
    pub endpoints: Vec<DerivedEndpoint>,
    /// Logical routing policies derived from `[[models]]` and `[[tiers]]`.
    pub policies: Vec<DerivedPolicy>,
}

impl EndpointInventory {
    /// Builds a deterministic read-only endpoint inventory from the legacy
    /// `[[providers]]`, `[[models]]`, and `[[tiers]]` schema.
    #[must_use]
    pub fn from_legacy_config(config: &AppConfig) -> Self {
        let provider_lookup: BTreeMap<&str, &crate::cli::ProviderConfig> = config
            .providers
            .iter()
            .map(|provider| (provider.name.as_str(), provider))
            .collect();

        let mut builder = EndpointBuilder::new(&provider_lookup);

        for model in &config.models {
            for mapping in &model.mappings {
                builder.add_exact(
                    &mapping.provider,
                    &mapping.actual_model,
                    EndpointSource::ModelMapping {
                        model: model.name.clone(),
                        priority: mapping.priority,
                    },
                );
            }
        }

        for provider in &config.providers {
            for model in &provider.models {
                builder.add_exact(
                    &provider.name,
                    model,
                    EndpointSource::ProviderModel {
                        provider: provider.name.clone(),
                    },
                );
            }
            if provider.pass_through.unwrap_or(false) {
                builder.add_pass_through(
                    &provider.name,
                    EndpointSource::PassThroughProvider {
                        provider: provider.name.clone(),
                    },
                );
            }
        }

        let endpoints = builder.finish();
        let endpoint_by_pair: BTreeMap<(String, EndpointModel), String> = endpoints
            .iter()
            .map(|endpoint| {
                (
                    (endpoint.provider.clone(), endpoint.model.clone()),
                    endpoint.id.clone(),
                )
            })
            .collect();

        let mut policies = Vec::new();

        for model in &config.models {
            let mut mappings = model.mappings.clone();
            mappings.sort_by_key(|mapping| mapping.priority);
            let endpoint_ids = mappings
                .iter()
                .filter_map(|mapping| {
                    endpoint_by_pair
                        .get(&(
                            mapping.provider.clone(),
                            EndpointModel::Exact(mapping.actual_model.clone()),
                        ))
                        .cloned()
                })
                .collect();

            policies.push(DerivedPolicy {
                name: format!("model:{}", model.name),
                source: PolicySource::Model {
                    model: model.name.clone(),
                },
                match_model: Some(model.name.clone()),
                endpoint_ids,
                provider_order: mappings
                    .into_iter()
                    .map(|mapping| mapping.provider)
                    .collect(),
                fanout: model.strategy == crate::cli::ModelStrategy::FanOut,
            });
        }

        for tier in &config.tiers {
            let provider_order = tier.providers.clone();
            let endpoint_ids = provider_order
                .iter()
                .flat_map(|provider| {
                    endpoints
                        .iter()
                        .filter(move |endpoint| endpoint.provider == *provider)
                        .map(|endpoint| endpoint.id.clone())
                })
                .collect();

            policies.push(DerivedPolicy {
                name: format!("tier:{}", tier.name),
                source: PolicySource::Tier {
                    tier: tier.name.clone(),
                },
                match_model: None,
                endpoint_ids,
                provider_order,
                fanout: tier.fanout,
            });
        }

        Self {
            endpoints,
            policies,
        }
    }
}

/// A physical endpoint derived from legacy config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedEndpoint {
    /// Stable adapter-local endpoint id.
    pub id: String,
    /// Legacy provider name.
    pub provider: String,
    /// Provider backend type, copied from `[[providers]]` when available.
    pub provider_type: String,
    /// Exact model or pass-through wildcard.
    pub model: EndpointModel,
    /// Provider region, defaulting to `"global"` like dispatch does.
    pub region: String,
    /// Provider enabled flag after applying legacy default semantics.
    pub enabled: bool,
    /// Sources that caused this endpoint to be present in the derived view.
    pub sources: Vec<EndpointSource>,
}

/// Endpoint model identity in the read-only adapter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EndpointModel {
    /// Exact upstream model string.
    Exact(String),
    /// Provider accepts arbitrary model names.
    PassThrough,
}

impl EndpointModel {
    fn id_fragment(&self) -> &str {
        match self {
            Self::Exact(model) => model,
            Self::PassThrough => "pass-through",
        }
    }
}

/// Where a derived endpoint came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointSource {
    /// `[[models.mappings]]` entry.
    ModelMapping {
        /// Logical Grob model name.
        model: String,
        /// Legacy mapping priority.
        priority: u32,
    },
    /// Legacy `models = [...]` field on `[[providers]]`.
    ProviderModel {
        /// Provider name owning the model list.
        provider: String,
    },
    /// `pass_through = true` on `[[providers]]`.
    PassThroughProvider {
        /// Provider name owning pass-through behavior.
        provider: String,
    },
}

/// Logical policy derived from legacy routing config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedPolicy {
    /// Adapter-local policy name.
    pub name: String,
    /// Legacy source of the policy.
    pub source: PolicySource,
    /// Exact requested model match for model policies. Tier policies are
    /// request-dependent and therefore leave this unset.
    pub match_model: Option<String>,
    /// Candidate endpoint ids known statically. Tier policies also keep
    /// `provider_order` because their exact upstream model is resolved at
    /// request time in the legacy resolver.
    pub endpoint_ids: Vec<String>,
    /// Provider order preserved from legacy priority/tier configuration.
    pub provider_order: Vec<String>,
    /// Whether this policy fans out.
    pub fanout: bool,
}

/// Source of a derived policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySource {
    /// `[[models]]` entry.
    Model {
        /// Logical Grob model name.
        model: String,
    },
    /// `[[tiers]]` entry.
    Tier {
        /// Tier name.
        tier: String,
    },
}

struct EndpointBuilder<'a> {
    provider_lookup: &'a BTreeMap<&'a str, &'a crate::cli::ProviderConfig>,
    entries: BTreeMap<(String, EndpointModel), DerivedEndpoint>,
}

impl<'a> EndpointBuilder<'a> {
    fn new(provider_lookup: &'a BTreeMap<&'a str, &'a crate::cli::ProviderConfig>) -> Self {
        Self {
            provider_lookup,
            entries: BTreeMap::new(),
        }
    }

    fn add_exact(&mut self, provider: &str, model: &str, source: EndpointSource) {
        self.add(provider, EndpointModel::Exact(model.to_string()), source);
    }

    fn add_pass_through(&mut self, provider: &str, source: EndpointSource) {
        self.add(provider, EndpointModel::PassThrough, source);
    }

    fn add(&mut self, provider: &str, model: EndpointModel, source: EndpointSource) {
        let key = (provider.to_string(), model.clone());
        if let Some(existing) = self.entries.get_mut(&key) {
            existing.sources.push(source);
            return;
        }

        let provider_config = self.provider_lookup.get(provider).copied();
        self.entries.insert(
            key,
            DerivedEndpoint {
                id: endpoint_id(provider, &model),
                provider: provider.to_string(),
                provider_type: provider_config
                    .map(|p| p.provider_type.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                model,
                region: provider_config
                    .and_then(|p| p.region.clone())
                    .unwrap_or_else(|| "global".to_string()),
                enabled: provider_config.map(|p| p.is_enabled()).unwrap_or(true),
                sources: vec![source],
            },
        );
    }

    fn finish(self) -> Vec<DerivedEndpoint> {
        self.entries.into_values().collect()
    }
}

fn endpoint_id(provider: &str, model: &EndpointModel) -> String {
    format!("{}__{}", slug(provider), slug(model.id_fragment()))
}

fn slug(input: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for byte in input.bytes() {
        let ch = byte as char;
        let next = if ch.is_ascii_alphanumeric() {
            last_dash = false;
            ch.to_ascii_lowercase()
        } else if matches!(ch, '.' | '_' | '-') {
            last_dash = false;
            ch
        } else if !last_dash {
            last_dash = true;
            '-'
        } else {
            continue;
        };
        out.push(next);
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "endpoint".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{ModelConfig, ModelMapping, TierConfig};

    fn provider(name: &str, models: &[&str]) -> crate::cli::ProviderConfig {
        crate::cli::ProviderConfig {
            name: name.to_string(),
            provider_type: "openai".to_string(),
            auth_type: crate::cli::AuthType::ApiKey,
            api_key: None,
            oauth_provider: None,
            project_id: None,
            location: None,
            base_url: None,
            headers: None,
            models: models.iter().map(|m| (*m).to_string()).collect(),
            enabled: Some(true),
            budget_usd: None,
            region: None,
            pass_through: None,
            reasoning_effort: None,
            service_tier: None,
            codex: crate::cli::CodexOptions::default(),
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            pool: None,
            circuit_breaker: None,
            health_check: None,
            max_retries: None,
        }
    }

    fn mapping(priority: u32, provider: &str, actual_model: &str) -> ModelMapping {
        ModelMapping {
            priority,
            provider: provider.to_string(),
            actual_model: actual_model.to_string(),
            inject_continuation_prompt: false,
        }
    }

    fn config() -> AppConfig {
        AppConfig {
            router: crate::cli::RouterConfig {
                default: "smart".to_string(),
                background: None,
                think: None,
                websearch: None,
                auto_map_regex: None,
                background_regex: None,
                prompt_rules: vec![],
                gdpr: false,
                region: None,
            },
            providers: vec![
                provider("anthropic", &[]),
                provider("openrouter", &["mistral/a"]),
            ],
            models: vec![ModelConfig {
                name: "smart".to_string(),
                mappings: vec![
                    mapping(2, "openrouter", "anthropic/claude-sonnet"),
                    mapping(1, "anthropic", "claude-sonnet"),
                ],
                budget_usd: None,
                context_window_tokens: None,
                strategy: crate::cli::ModelStrategy::Fallback,
                fan_out: None,
                deprecated: None,
            }],
            tiers: vec![TierConfig {
                name: "trivial".to_string(),
                model: None,
                providers: vec!["openrouter".to_string(), "anthropic".to_string()],
                fanout: true,
                match_conditions: None,
            }],
            server: Default::default(),
            classifier: None,
            presets: Default::default(),
            budget: Default::default(),
            pricing: Default::default(),
            dlp: Default::default(),
            auth: Default::default(),
            tap: Default::default(),
            security: Default::default(),
            cache: Default::default(),
            secrets: Default::default(),
            compliance: Default::default(),
            version: None,
            user: Default::default(),
            otel: Default::default(),
            metrics: Default::default(),
            log_export: Default::default(),
            pledge: Default::default(),
            tool_validation: Default::default(),
            policies: vec![],
            tool_layer: Default::default(),
            tee: Default::default(),
            fips: Default::default(),
            #[cfg(feature = "harness")]
            harness: Default::default(),
            #[cfg(feature = "mcp")]
            mcp: Default::default(),
        }
    }

    #[test]
    fn derives_exact_endpoints_from_model_mappings_and_provider_models() {
        let inventory = EndpointInventory::from_legacy_config(&config());
        let ids: Vec<&str> = inventory
            .endpoints
            .iter()
            .map(|endpoint| endpoint.id.as_str())
            .collect();

        assert_eq!(
            ids,
            vec![
                "anthropic__claude-sonnet",
                "openrouter__anthropic-claude-sonnet",
                "openrouter__mistral-a",
            ]
        );

        let openrouter_sonnet = inventory
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == "openrouter__anthropic-claude-sonnet")
            .unwrap();
        assert_eq!(openrouter_sonnet.provider_type, "openai");
        assert_eq!(openrouter_sonnet.region, "global");
        assert!(matches!(
            openrouter_sonnet.sources.as_slice(),
            [EndpointSource::ModelMapping { model, priority }] if model == "smart" && *priority == 2
        ));
    }

    #[test]
    fn derives_model_policy_in_priority_order() {
        let inventory = EndpointInventory::from_legacy_config(&config());
        let policy = inventory
            .policies
            .iter()
            .find(|policy| policy.name == "model:smart")
            .unwrap();

        assert_eq!(policy.match_model.as_deref(), Some("smart"));
        assert_eq!(
            policy.endpoint_ids,
            vec![
                "anthropic__claude-sonnet".to_string(),
                "openrouter__anthropic-claude-sonnet".to_string()
            ]
        );
        assert_eq!(policy.provider_order, vec!["anthropic", "openrouter"]);
        assert!(!policy.fanout);
    }

    #[test]
    fn derives_tier_policy_without_claiming_exact_runtime_model_resolution() {
        let inventory = EndpointInventory::from_legacy_config(&config());
        let policy = inventory
            .policies
            .iter()
            .find(|policy| policy.name == "tier:trivial")
            .unwrap();

        assert_eq!(policy.match_model, None);
        assert_eq!(policy.provider_order, vec!["openrouter", "anthropic"]);
        assert!(policy.fanout);
        assert!(
            policy
                .endpoint_ids
                .contains(&"openrouter__anthropic-claude-sonnet".to_string()),
            "tier policies expose provider inventory but keep request-time model resolution separate"
        );
    }

    #[test]
    fn derives_pass_through_endpoint() {
        let mut config = config();
        config.providers[0].pass_through = Some(true);

        let inventory = EndpointInventory::from_legacy_config(&config);

        let endpoint = inventory
            .endpoints
            .iter()
            .find(|endpoint| endpoint.id == "anthropic__pass-through")
            .unwrap();
        assert_eq!(endpoint.model, EndpointModel::PassThrough);
        assert!(matches!(
            endpoint.sources.as_slice(),
            [EndpointSource::PassThroughProvider { provider }] if provider == "anthropic"
        ));
    }
}
