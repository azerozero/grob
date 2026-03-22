//! Policy matcher: evaluates request context against compiled policy rules.

use super::config::PolicyConfig;
use super::context::RequestContext;
use super::resolved::ResolvedPolicy;
use globset::{Glob, GlobMatcher};

/// Compiled policy with pre-built glob matchers for fast evaluation.
#[derive(Debug)]
struct CompiledPolicy {
    config: PolicyConfig,
    tenant: Option<GlobMatcher>,
    zone: Option<GlobMatcher>,
    project: Option<GlobMatcher>,
    user: Option<GlobMatcher>,
    agent: Option<GlobMatcher>,
    model: Option<GlobMatcher>,
    provider: Option<GlobMatcher>,
    /// Number of non-None match fields (for specificity ranking).
    specificity: usize,
}

/// Evaluates request contexts against a set of compiled policies.
pub struct PolicyMatcher {
    policies: Vec<CompiledPolicy>,
}

impl PolicyMatcher {
    /// Compiles policies from config. Fails fast on invalid glob patterns.
    pub fn new(configs: Vec<PolicyConfig>) -> Result<Self, globset::Error> {
        let mut policies = Vec::with_capacity(configs.len());
        for config in configs {
            let tenant = compile_glob(&config.match_rules.tenant)?;
            let zone = compile_glob(&config.match_rules.zone)?;
            let project = compile_glob(&config.match_rules.project)?;
            let user = compile_glob(&config.match_rules.user)?;
            let agent = compile_glob(&config.match_rules.agent)?;
            let model = compile_glob(&config.match_rules.model)?;
            let provider = compile_glob(&config.match_rules.provider)?;

            let specificity = [
                &config.match_rules.tenant,
                &config.match_rules.zone,
                &config.match_rules.project,
                &config.match_rules.user,
                &config.match_rules.agent,
                &config.match_rules.model,
                &config.match_rules.provider,
            ]
            .iter()
            .filter(|f| f.is_some())
            .count()
                + config.match_rules.compliance.as_ref().map_or(0, |_| 1)
                + config.match_rules.dlp_triggered.map_or(0, |_| 1)
                + config.match_rules.cost_above.map_or(0, |_| 1)
                + config.match_rules.route_type.as_ref().map_or(0, |_| 1);

            policies.push(CompiledPolicy {
                config,
                tenant,
                zone,
                project,
                user,
                agent,
                model,
                provider,
                specificity,
            });
        }
        Ok(Self { policies })
    }

    /// Evaluates the request context against all policies.
    ///
    /// Returns the merged result of all matching policies, ordered by
    /// specificity (most-specific wins). Most-restrictive values are
    /// chosen for conflicts. Returns `default_deny()` when no policy matches.
    pub fn evaluate(&self, ctx: &RequestContext) -> ResolvedPolicy {
        let mut matches: Vec<&CompiledPolicy> = self
            .policies
            .iter()
            .filter(|p| self.matches(p, ctx))
            .collect();

        if matches.is_empty() {
            return ResolvedPolicy::default_deny();
        }

        // Sort by specificity descending (most specific first).
        matches.sort_by(|a, b| b.specificity.cmp(&a.specificity));

        self.merge(&matches)
    }

    /// Checks whether a compiled policy matches the given context.
    fn matches(&self, policy: &CompiledPolicy, ctx: &RequestContext) -> bool {
        let rules = &policy.config.match_rules;

        if !glob_matches(&policy.tenant, ctx.tenant.as_deref()) {
            return false;
        }
        if !glob_matches(&policy.zone, ctx.zone.as_deref()) {
            return false;
        }
        if !glob_matches(&policy.project, ctx.project.as_deref()) {
            return false;
        }
        if !glob_matches(&policy.user, ctx.user.as_deref()) {
            return false;
        }
        if !glob_matches(&policy.agent, ctx.agent.as_deref()) {
            return false;
        }
        if !glob_matches_required(&policy.model, &ctx.model) {
            return false;
        }
        if !glob_matches_required(&policy.provider, &ctx.provider) {
            return false;
        }

        // Compliance: ANY tag in the rule must be present in the context.
        if let Some(ref required) = rules.compliance {
            if !required.iter().any(|tag| ctx.compliance.contains(tag)) {
                return false;
            }
        }

        // DLP triggered filter.
        if let Some(required) = rules.dlp_triggered {
            if ctx.dlp_triggered != required {
                return false;
            }
        }

        // Cost threshold.
        if let Some(threshold) = rules.cost_above {
            if ctx.estimated_cost <= threshold {
                return false;
            }
        }

        // Route type exact match.
        if let Some(ref required) = rules.route_type {
            if ctx.route_type != *required {
                return false;
            }
        }

        true
    }

    /// Merges matching policies into a single resolved policy.
    ///
    /// First match (most specific) wins for single-value fields.
    /// Most restrictive wins for rate limits and budgets.
    /// Union for recipient lists.
    fn merge(&self, matches: &[&CompiledPolicy]) -> ResolvedPolicy {
        let mut result = ResolvedPolicy {
            matched: true,
            ..Default::default()
        };

        for policy in matches {
            let cfg = &policy.config;

            // DLP: first match wins.
            if result.dlp.is_none() {
                result.dlp = cfg.dlp.clone();
            }

            // Rate limit: most restrictive (lowest rps).
            if let Some(ref rl) = cfg.rate_limit {
                match result.rate_limit {
                    None => result.rate_limit = Some(rl.clone()),
                    Some(ref mut existing) => {
                        if let (Some(new_rps), Some(ref mut old_rps)) = (rl.rps, &mut existing.rps)
                        {
                            if new_rps < *old_rps {
                                *old_rps = new_rps;
                            }
                        } else if existing.rps.is_none() {
                            existing.rps = rl.rps;
                        }
                    }
                }
            }

            // Routing: first match wins.
            if result.routing.is_none() {
                result.routing = cfg.routing.clone();
            }

            // Budget: most restrictive (lowest monthly_usd).
            if let Some(ref budget) = cfg.budget {
                match result.budget {
                    None => result.budget = Some(budget.clone()),
                    Some(ref mut existing) => {
                        if let (Some(new_val), Some(ref mut old_val)) =
                            (budget.monthly_usd, &mut existing.monthly_usd)
                        {
                            if new_val < *old_val {
                                *old_val = new_val;
                            }
                        } else if existing.monthly_usd.is_none() {
                            existing.monthly_usd = budget.monthly_usd;
                        }
                    }
                }
            }

            // Log export: union recipients.
            if let Some(ref le) = cfg.log_export {
                match result.log_export {
                    None => result.log_export = Some(le.clone()),
                    Some(ref mut existing) => {
                        if let Some(ref new_recipients) = le.recipients {
                            let recipients = existing.recipients.get_or_insert_with(Vec::new);
                            for r in new_recipients {
                                if !recipients.contains(r) {
                                    recipients.push(r.clone());
                                }
                            }
                        }
                        // Content: first match wins.
                        if existing.content.is_none() {
                            existing.content = le.content.clone();
                        }
                    }
                }
            }
        }

        result
    }
}

/// Compiles an optional glob pattern string into a matcher.
fn compile_glob(pattern: &Option<String>) -> Result<Option<GlobMatcher>, globset::Error> {
    match pattern {
        Some(p) => Ok(Some(Glob::new(p)?.compile_matcher())),
        None => Ok(None),
    }
}

/// Checks if a glob matcher matches an optional value. None pattern = match any.
fn glob_matches(matcher: &Option<GlobMatcher>, value: Option<&str>) -> bool {
    match (matcher, value) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(m), Some(v)) => m.is_match(v),
    }
}

/// Checks if a glob matcher matches a required (non-optional) value.
fn glob_matches_required(matcher: &Option<GlobMatcher>, value: &str) -> bool {
    match matcher {
        None => true,
        Some(m) => m.is_match(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::policies::config::*;

    fn empty_context() -> RequestContext {
        RequestContext::default()
    }

    fn policy(name: &str, rules: MatchRules) -> PolicyConfig {
        PolicyConfig {
            name: name.to_string(),
            match_rules: rules,
            dlp: None,
            rate_limit: None,
            routing: None,
            budget: None,
            log_export: None,
        }
    }

    // ── TDD Cycle 1: RED → GREEN ──

    #[test]
    fn test_empty_rules_matches_everything() {
        let matcher = PolicyMatcher::new(vec![policy("catch-all", MatchRules::default())]).unwrap();
        let result = matcher.evaluate(&empty_context());
        assert!(result.matched);
    }

    // ── TDD Cycle 2 ──

    #[test]
    fn test_tenant_glob_match() {
        let rules = MatchRules {
            tenant: Some("hospital-*".to_string()),
            ..Default::default()
        };
        let matcher = PolicyMatcher::new(vec![policy("hospitals", rules)]).unwrap();

        let mut ctx = empty_context();
        ctx.tenant = Some("hospital-paris".to_string());
        assert!(matcher.evaluate(&ctx).matched);

        ctx.tenant = Some("bank-london".to_string());
        assert!(!matcher.evaluate(&ctx).matched);
    }

    // ── TDD Cycle 3 ──

    #[test]
    fn test_compliance_any_match() {
        let rules = MatchRules {
            compliance: Some(vec!["gdpr".to_string()]),
            ..Default::default()
        };
        let matcher = PolicyMatcher::new(vec![policy("gdpr-policy", rules)]).unwrap();

        let mut ctx = empty_context();
        ctx.compliance = vec!["gdpr".to_string(), "hds".to_string()];
        assert!(matcher.evaluate(&ctx).matched);

        ctx.compliance = vec!["pci-dss".to_string()];
        assert!(!matcher.evaluate(&ctx).matched);
    }

    // ── TDD Cycle 4 ──

    #[test]
    fn test_no_match_returns_default_deny() {
        let rules = MatchRules {
            tenant: Some("specific-tenant".to_string()),
            ..Default::default()
        };
        let matcher = PolicyMatcher::new(vec![policy("specific", rules)]).unwrap();
        let result = matcher.evaluate(&empty_context());
        assert!(!result.matched);
    }

    // ── TDD Cycle 5 ──

    #[test]
    fn test_specificity_ordering() {
        let broad = PolicyConfig {
            name: "broad".to_string(),
            match_rules: MatchRules {
                tenant: Some("*".to_string()),
                ..Default::default()
            },
            rate_limit: Some(RateLimitOverride { rps: Some(100) }),
            ..policy("broad", MatchRules::default())
        };
        let specific = PolicyConfig {
            name: "specific".to_string(),
            match_rules: MatchRules {
                tenant: Some("hospital-*".to_string()),
                zone: Some("eu-*".to_string()),
                compliance: Some(vec!["gdpr".to_string()]),
                ..Default::default()
            },
            rate_limit: Some(RateLimitOverride { rps: Some(50) }),
            ..policy("specific", MatchRules::default())
        };
        let matcher = PolicyMatcher::new(vec![broad, specific]).unwrap();

        let ctx = RequestContext {
            tenant: Some("hospital-paris".to_string()),
            zone: Some("eu-west".to_string()),
            compliance: vec!["gdpr".to_string()],
            ..Default::default()
        };
        let result = matcher.evaluate(&ctx);
        assert!(result.matched);
        // Most specific policy (3 fields) should win — rps=50.
        assert_eq!(result.rate_limit.unwrap().rps, Some(50));
    }

    // ── TDD Cycle 6 ──

    #[test]
    fn test_most_restrictive_merge() {
        let p1 = PolicyConfig {
            name: "p1".to_string(),
            match_rules: MatchRules::default(),
            rate_limit: Some(RateLimitOverride { rps: Some(100) }),
            budget: Some(BudgetOverride {
                monthly_usd: Some(500.0),
            }),
            ..policy("p1", MatchRules::default())
        };
        let p2 = PolicyConfig {
            name: "p2".to_string(),
            match_rules: MatchRules::default(),
            rate_limit: Some(RateLimitOverride { rps: Some(50) }),
            budget: Some(BudgetOverride {
                monthly_usd: Some(200.0),
            }),
            ..policy("p2", MatchRules::default())
        };
        let matcher = PolicyMatcher::new(vec![p1, p2]).unwrap();
        let result = matcher.evaluate(&empty_context());

        // Most restrictive: lower rps and lower budget.
        assert_eq!(result.rate_limit.unwrap().rps, Some(50));
        assert_eq!(result.budget.unwrap().monthly_usd, Some(200.0));
    }

    // ── TDD Cycle 7 ──

    #[test]
    fn test_cost_above_filter() {
        let rules = MatchRules {
            cost_above: Some(0.10),
            ..Default::default()
        };
        let matcher = PolicyMatcher::new(vec![policy("expensive", rules)]).unwrap();

        let mut ctx = empty_context();
        ctx.estimated_cost = 0.05;
        assert!(!matcher.evaluate(&ctx).matched);

        ctx.estimated_cost = 0.50;
        assert!(matcher.evaluate(&ctx).matched);
    }

    // ── TDD Cycle 8 ──

    #[test]
    fn test_policy_config_toml_roundtrip() {
        let toml_str = r#"
[[policies]]
name = "hospital-eu"

[policies.match]
tenant = "hospital-*"
zone = "eu-*"
compliance = ["gdpr", "hds"]

[policies.rate_limit]
rps = 50

[policies.budget]
monthly_usd = 500.0
"#;

        #[derive(serde::Deserialize)]
        struct Wrapper {
            policies: Vec<PolicyConfig>,
        }

        let wrapper: Wrapper = toml::from_str(toml_str).unwrap();
        assert_eq!(wrapper.policies.len(), 1);
        assert_eq!(wrapper.policies[0].name, "hospital-eu");
        assert_eq!(
            wrapper.policies[0].match_rules.tenant,
            Some("hospital-*".to_string())
        );
        assert_eq!(
            wrapper.policies[0].rate_limit.as_ref().unwrap().rps,
            Some(50)
        );
    }

    // ── TDD Cycle 9 ──

    #[test]
    fn test_backward_compat_no_policies_key() {
        let toml_str = r#"
[server]
port = 13456
"#;

        #[derive(serde::Deserialize)]
        struct Wrapper {
            #[serde(default)]
            policies: Vec<PolicyConfig>,
        }

        let wrapper: Wrapper = toml::from_str(toml_str).unwrap();
        assert!(wrapper.policies.is_empty());
    }

    // ── TDD Cycle 10 ──

    #[test]
    fn test_log_export_recipients_union() {
        let p1 = PolicyConfig {
            name: "p1".to_string(),
            match_rules: MatchRules::default(),
            log_export: Some(LogExportOverride {
                content: Some("encrypted".to_string()),
                recipients: Some(vec!["alice".to_string(), "bob".to_string()]),
            }),
            ..policy("p1", MatchRules::default())
        };
        let p2 = PolicyConfig {
            name: "p2".to_string(),
            match_rules: MatchRules::default(),
            log_export: Some(LogExportOverride {
                content: None,
                recipients: Some(vec!["bob".to_string(), "charlie".to_string()]),
            }),
            ..policy("p2", MatchRules::default())
        };
        let matcher = PolicyMatcher::new(vec![p1, p2]).unwrap();
        let result = matcher.evaluate(&empty_context());

        let le = result.log_export.unwrap();
        let recipients = le.recipients.unwrap();
        assert!(recipients.contains(&"alice".to_string()));
        assert!(recipients.contains(&"bob".to_string()));
        assert!(recipients.contains(&"charlie".to_string()));
        assert_eq!(recipients.len(), 3);
    }
}
