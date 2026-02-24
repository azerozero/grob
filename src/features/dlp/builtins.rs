use super::config::{SecretAction, SecretRule};

/// Returns a curated set of built-in secret detection rules covering
/// common API keys, tokens, and private key headers found in the wild.
///
/// All builtins use `Redact` action (no canary format defined per family).
pub fn builtin_rules() -> Vec<SecretRule> {
    vec![
        // ── AI / LLM ──────────────────────────────────────────
        SecretRule {
            name: "openai_api_key".into(),
            prefix: "sk-proj-".into(),
            pattern: r"sk-proj-[A-Za-z0-9_-]{40,}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "anthropic_api_key".into(),
            prefix: "sk-ant-api03-".into(),
            pattern: r"sk-ant-api03-[A-Za-z0-9_-]{90,}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "huggingface_token".into(),
            prefix: "hf_".into(),
            pattern: r"hf_[A-Za-z0-9]{34}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "perplexity_api_key".into(),
            prefix: "pplx-".into(),
            pattern: r"pplx-[A-Za-z0-9]{48}".into(),
            action: SecretAction::Redact,
        },
        // ── Cloud ─────────────────────────────────────────────
        SecretRule {
            name: "gcp_api_key".into(),
            prefix: "AIza".into(),
            pattern: r"AIza[0-9A-Za-z_-]{35}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "vault_token".into(),
            prefix: "hvs.".into(),
            pattern: r"hvs\.[A-Za-z0-9_-]{24,}".into(),
            action: SecretAction::Redact,
        },
        // ── Payment / SaaS ────────────────────────────────────
        SecretRule {
            name: "stripe_secret_key".into(),
            prefix: "sk_".into(),
            pattern: r"sk_(live|test)_[A-Za-z0-9]{24,}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "stripe_restricted_key".into(),
            prefix: "rk_live_".into(),
            pattern: r"rk_live_[A-Za-z0-9]{24,}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "sendgrid_api_key".into(),
            prefix: "SG.".into(),
            pattern: r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}".into(),
            action: SecretAction::Redact,
        },
        // ── Platforms ─────────────────────────────────────────
        SecretRule {
            name: "github_pat_v2".into(),
            prefix: "github_pat_".into(),
            pattern: r"github_pat_[A-Za-z0-9_]{82}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "github_pat".into(),
            prefix: "ghp_".into(),
            pattern: r"ghp_[A-Za-z0-9]{36}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "github_oauth".into(),
            prefix: "gho_".into(),
            pattern: r"gho_[A-Za-z0-9]{36}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "github_app".into(),
            prefix: "ghs_".into(),
            pattern: r"ghs_[A-Za-z0-9]{36}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "gitlab_pat".into(),
            prefix: "glpat-".into(),
            pattern: r"glpat-[A-Za-z0-9_-]{20,}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "npm_token".into(),
            prefix: "npm_".into(),
            pattern: r"npm_[A-Za-z0-9]{36}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "slack_bot_token".into(),
            prefix: "xoxb-".into(),
            pattern: r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}".into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "slack_user_token".into(),
            prefix: "xoxp-".into(),
            pattern: r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}".into(),
            action: SecretAction::Redact,
        },
        // ── AWS ───────────────────────────────────────────────
        SecretRule {
            name: "aws_access_key".into(),
            prefix: "AKIA".into(),
            pattern: r"AKIA[0-9A-Z]{16}".into(),
            action: SecretAction::Redact,
        },
        // ── JWT ───────────────────────────────────────────────
        SecretRule {
            name: "jwt_token".into(),
            prefix: "eyJ".into(),
            pattern: r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}".into(),
            action: SecretAction::Redact,
        },
        // ── Private keys ──────────────────────────────────────
        SecretRule {
            name: "rsa_private_key".into(),
            prefix: "-----BEGIN RSA PRIVATE KEY-----".into(),
            pattern: r"-----BEGIN RSA PRIVATE KEY-----[\s\S]{10,}?-----END RSA PRIVATE KEY-----"
                .into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "openssh_private_key".into(),
            prefix: "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
            pattern:
                r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{10,}?-----END OPENSSH PRIVATE KEY-----"
                    .into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "ec_private_key".into(),
            prefix: "-----BEGIN EC PRIVATE KEY-----".into(),
            pattern: r"-----BEGIN EC PRIVATE KEY-----[\s\S]{10,}?-----END EC PRIVATE KEY-----"
                .into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "generic_private_key".into(),
            prefix: "-----BEGIN PRIVATE KEY-----".into(),
            pattern: r"-----BEGIN PRIVATE KEY-----[\s\S]{10,}?-----END PRIVATE KEY-----".into(),
            action: SecretAction::Redact,
        },
        // ── Database connection strings ───────────────────────
        SecretRule {
            name: "postgres_uri".into(),
            prefix: "postgres://".into(),
            pattern: r#"postgres://[^\s'"<>]{8,}"#.into(),
            action: SecretAction::Redact,
        },
        SecretRule {
            name: "mongodb_uri".into(),
            prefix: "mongodb://".into(),
            pattern: r#"mongodb(?:\+srv)?://[^\s'"<>]{8,}"#.into(),
            action: SecretAction::Redact,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_rules_count() {
        let rules = builtin_rules();
        assert!(
            rules.len() >= 20,
            "Expected at least 20 builtin rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_all_builtin_regexes_compile() {
        for rule in builtin_rules() {
            regex::Regex::new(&rule.pattern).unwrap_or_else(|e| {
                panic!(
                    "Builtin rule '{}' has invalid regex '{}': {}",
                    rule.name, rule.pattern, e
                )
            });
        }
    }

    #[test]
    fn test_all_builtins_have_valid_prefix() {
        for rule in builtin_rules() {
            assert!(
                !rule.prefix.is_empty(),
                "Builtin rule '{}' has empty prefix",
                rule.name
            );
        }
    }

    #[test]
    fn test_all_builtins_use_redact() {
        for rule in builtin_rules() {
            assert_eq!(
                rule.action,
                SecretAction::Redact,
                "Builtin rule '{}' should use Redact action",
                rule.name
            );
        }
    }

    #[test]
    fn test_builtin_patterns_match_examples() {
        let cases = vec![
            ("openai_api_key", "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
            ("anthropic_api_key", "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb"),
            ("huggingface_token", "hf_abcdefghijklmnopqrstuvwxyz12345678"),
            ("github_pat", "ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
            ("github_oauth", "gho_abcdefghijklmnopqrstuvwxyz1234567890"),
            ("gitlab_pat", "glpat-abcdefghijklmnopq_rst"),
            ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
            ("stripe_secret_key", concat!("sk_te", "st_abcdefghijklmnopqrstuvwx")),
            ("gcp_api_key", "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"),
            ("postgres_uri", "postgres://user:pass@localhost:5432/db"),
            ("mongodb_uri", "mongodb://user:pass@localhost:27017/db"),
        ];

        let rules = builtin_rules();
        for (rule_name, sample) in cases {
            let rule = rules
                .iter()
                .find(|r| r.name == rule_name)
                .unwrap_or_else(|| panic!("Rule '{}' not found in builtins", rule_name));
            let re = regex::Regex::new(&rule.pattern).unwrap();
            assert!(
                re.is_match(sample),
                "Rule '{}' pattern '{}' should match '{}'",
                rule_name,
                rule.pattern,
                sample
            );
        }
    }
}
