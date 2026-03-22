//! Access policy: resolves which auditors can decrypt a given log entry.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Access policy configuration from TOML.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessPolicyConfig {
    /// Human-readable policy name.
    pub name: String,
    /// Match rules (same fields as policy engine match).
    #[serde(default, rename = "match")]
    pub match_rules: AccessMatchRules,
    /// Named auditor recipients (references keys in `[log_export.auditors]`).
    pub recipients: Vec<String>,
}

/// Simplified match rules for access policies.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AccessMatchRules {
    /// Glob pattern for tenant.
    #[serde(default)]
    pub tenant: Option<String>,
    /// Compliance tags (ANY match).
    #[serde(default)]
    pub compliance: Option<Vec<String>>,
    /// Matches when DLP was triggered.
    #[serde(default)]
    pub dlp_triggered: Option<bool>,
}

/// Context for access policy resolution.
#[derive(Debug, Default)]
pub struct AccessContext {
    /// Tenant identifier.
    pub tenant: Option<String>,
    /// Active compliance tags.
    pub compliance: Vec<String>,
    /// Whether DLP was triggered.
    pub dlp_triggered: bool,
}

/// Resolves which auditor recipients should receive encrypted content.
///
/// Returns the union of recipients from all matching access policies.
/// Falls back to the default policy (empty match rules) when no specific match.
pub fn resolve_recipients(
    policies: &[AccessPolicyConfig],
    auditors: &HashMap<String, String>,
    ctx: &AccessContext,
) -> Vec<String> {
    let mut matched_names: Vec<String> = Vec::new();

    for policy in policies {
        if matches_access(&policy.match_rules, ctx) {
            for name in &policy.recipients {
                if !matched_names.contains(name) {
                    matched_names.push(name.clone());
                }
            }
        }
    }

    // If only default matched, keep it. If specific matched, include default too (already unioned).

    // Resolve names to public keys.
    matched_names
        .iter()
        .filter_map(|name| auditors.get(name).cloned())
        .collect()
}

/// Checks whether access match rules match the given context.
fn matches_access(rules: &AccessMatchRules, ctx: &AccessContext) -> bool {
    // Tenant glob match.
    if let Some(ref pattern) = rules.tenant {
        match ctx.tenant.as_deref() {
            None => return false,
            Some(tenant) => {
                if !glob_match(pattern, tenant) {
                    return false;
                }
            }
        }
    }

    // Compliance ANY match.
    if let Some(ref required) = rules.compliance {
        if !required.iter().any(|tag| ctx.compliance.contains(tag)) {
            return false;
        }
    }

    // DLP triggered.
    if let Some(required) = rules.dlp_triggered {
        if ctx.dlp_triggered != required {
            return false;
        }
    }

    true
}

/// Simple glob matching supporting `*` as wildcard prefix/suffix.
///
/// Supports patterns like `"hospital-*"`, `"*-paris"`, `"*"`, or exact match.
/// No dependency on the `globset` crate.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    pattern == value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_auditors() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("alice".to_string(), "age1alice_pubkey".to_string());
        m.insert("bob".to_string(), "age1bob_pubkey".to_string());
        m.insert("charlie".to_string(), "age1charlie_pubkey".to_string());
        m
    }

    #[test]
    fn test_resolve_recipients_single_match() {
        let policies = vec![AccessPolicyConfig {
            name: "healthcare".to_string(),
            match_rules: AccessMatchRules {
                tenant: Some("hospital-*".to_string()),
                ..Default::default()
            },
            recipients: vec!["alice".to_string(), "bob".to_string()],
        }];
        let ctx = AccessContext {
            tenant: Some("hospital-paris".to_string()),
            ..Default::default()
        };
        let keys = resolve_recipients(&policies, &test_auditors(), &ctx);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"age1alice_pubkey".to_string()));
        assert!(keys.contains(&"age1bob_pubkey".to_string()));
    }

    #[test]
    fn test_resolve_recipients_union() {
        let policies = vec![
            AccessPolicyConfig {
                name: "healthcare".to_string(),
                match_rules: AccessMatchRules {
                    tenant: Some("hospital-*".to_string()),
                    ..Default::default()
                },
                recipients: vec!["alice".to_string()],
            },
            AccessPolicyConfig {
                name: "compliance".to_string(),
                match_rules: AccessMatchRules {
                    compliance: Some(vec!["gdpr".to_string()]),
                    ..Default::default()
                },
                recipients: vec!["bob".to_string(), "charlie".to_string()],
            },
        ];
        let ctx = AccessContext {
            tenant: Some("hospital-paris".to_string()),
            compliance: vec!["gdpr".to_string()],
            ..Default::default()
        };
        let keys = resolve_recipients(&policies, &test_auditors(), &ctx);
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_resolve_recipients_no_match_uses_default() {
        let policies = vec![
            AccessPolicyConfig {
                name: "specific".to_string(),
                match_rules: AccessMatchRules {
                    tenant: Some("bank-*".to_string()),
                    ..Default::default()
                },
                recipients: vec!["charlie".to_string()],
            },
            AccessPolicyConfig {
                name: "default".to_string(),
                match_rules: AccessMatchRules::default(),
                recipients: vec!["alice".to_string()],
            },
        ];
        let ctx = AccessContext {
            tenant: Some("hospital-paris".to_string()),
            ..Default::default()
        };
        let keys = resolve_recipients(&policies, &test_auditors(), &ctx);
        // Only default matched.
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&"age1alice_pubkey".to_string()));
    }

    #[test]
    fn test_resolve_recipients_no_match_no_default() {
        let policies = vec![AccessPolicyConfig {
            name: "specific".to_string(),
            match_rules: AccessMatchRules {
                tenant: Some("bank-*".to_string()),
                ..Default::default()
            },
            recipients: vec!["charlie".to_string()],
        }];
        let ctx = AccessContext {
            tenant: Some("hospital-paris".to_string()),
            ..Default::default()
        };
        let keys = resolve_recipients(&policies, &test_auditors(), &ctx);
        assert!(keys.is_empty());
    }

    #[test]
    fn test_backward_compat_empty_policies() {
        let keys = resolve_recipients(&[], &HashMap::new(), &AccessContext::default());
        assert!(keys.is_empty());
    }
}
