use super::*;
use config::*;
use proptest::prelude::*;
use std::borrow::Cow;

fn test_config() -> DlpConfig {
    DlpConfig {
        enabled: true,
        scan_input: true,
        scan_output: true,
        rules_file: String::new(),
        no_builtins: true, // disable builtins for focused unit tests
        secrets: vec![SecretRule {
            name: "github_token".into(),
            prefix: "ghp_".into(),
            pattern: "ghp_[A-Za-z0-9]{36}".into(),
            action: SecretAction::Canary,
        }],
        custom_prefixes: vec![],
        names: vec![NameRule {
            term: "Thales".into(),
            action: NameAction::Pseudonym,
        }],
        entropy: EntropyConfig::default(),
        pii: Default::default(),
        enable_sessions: false,
        url_exfil: Default::default(),
        prompt_injection: Default::default(),
        signed_config: Default::default(),
        key_rotation_hours: 24,
    }
}

#[test]
fn test_sanitize_text_names() {
    let config = test_config();
    let engine = DlpEngine::from_config(config).unwrap();
    let result = engine.sanitize_text("Working at Thales");
    assert!(!result.contains("Thales"));
    assert!(matches!(result, Cow::Owned(_)));
}

#[test]
fn test_sanitize_text_no_match_is_borrowed() {
    let config = test_config();
    let engine = DlpEngine::from_config(config).unwrap();
    let result = engine.sanitize_text("Hello world, nothing secret here");
    // No name, no secret prefix: should be Cow::Borrowed (zero alloc)
    assert!(matches!(result, Cow::Borrowed(_)));
}

#[test]
fn test_sanitize_text_secrets() {
    let config = test_config();
    let engine = DlpEngine::from_config(config).unwrap();
    let result = engine.sanitize_text("token: ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    assert!(!result.contains("ghp_abcdefghijklmnopqrstuvwxyz1234567890"));
    assert!(result.contains("ghp_~CANARY"));
}

#[test]
fn test_response_deanonymize() {
    let config = test_config();
    let engine = DlpEngine::from_config(config).unwrap();

    let anonymized = engine.sanitize_text("Working at Thales");
    assert!(!anonymized.contains("Thales"));

    let restored = engine.sanitize_response_text(&anonymized);
    assert!(restored.contains("Thales"));
}

#[test]
fn test_disabled_returns_none() {
    let config = DlpConfig {
        enabled: false,
        ..Default::default()
    };
    assert!(DlpEngine::from_config(config).is_none());
}

#[test]
fn test_builtins_loaded_by_default() {
    let config = DlpConfig {
        enabled: true,
        ..Default::default()
    };
    let engine = DlpEngine::from_config(config).unwrap();
    // Should have loaded builtin rules (at least 20)
    assert!(
        engine.scanner.rules.len() >= 20,
        "Expected >= 20 builtin rules, got {}",
        engine.scanner.rules.len()
    );
}

#[test]
fn test_builtins_opt_out() {
    let config = DlpConfig {
        enabled: true,
        no_builtins: true,
        ..Default::default()
    };
    let engine = DlpEngine::from_config(config).unwrap();
    assert_eq!(engine.scanner.rules.len(), 0);
}

#[test]
fn test_builtin_detects_openai_key() {
    let config = DlpConfig {
        enabled: true,
        ..Default::default()
    };
    let engine = DlpEngine::from_config(config).unwrap();
    let text = "my key is sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD";
    let result = engine.sanitize_text(text);
    // Redact action now uses canary tokens for traceability.
    assert!(
        result.contains("~CANARY"),
        "OpenAI key should be replaced with a canary token, got: {}",
        result
    );
}

#[test]
fn test_builtin_detects_pem_header() {
    let config = DlpConfig {
        enabled: true,
        ..Default::default()
    };
    let engine = DlpEngine::from_config(config).unwrap();
    let text =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAHudeSA/x3hB2f-----END RSA PRIVATE KEY-----";
    let result = engine.sanitize_text(text);
    // Redact action now uses canary tokens for traceability.
    assert!(
        result.contains("~CANARY"),
        "PEM key should be replaced with a canary token, got: {}",
        result
    );
}

// ── Property-based tests ─────────────────────────────────────

proptest! {
    /// Name anonymization roundtrip: anonymize then deanonymize restores original text.
    #[test]
    fn prop_name_anonymize_roundtrip(text in "[a-z ]{0,20}") {
        let rules = vec![NameRule {
            term: "alice".into(),
            action: NameAction::Pseudonym,
        }];
        let anon = names::NameAnonymizer::new(&rules);
        let input = format!("Hello alice, {text}");
        let (anonymized, _) = anon.anonymize_if_match(&input).unwrap();
        let restored = anon.deanonymize_if_match(&anonymized).unwrap();
        prop_assert_eq!(restored, input);
    }

    /// Text without configured names passes through unchanged (zero-copy).
    #[test]
    fn prop_no_false_positive_names(text in "[b-z0-9 ]{1,100}") {
        let rules = vec![NameRule {
            term: "alice".into(),
            action: NameAction::Pseudonym,
        }];
        let anon = names::NameAnonymizer::new(&rules);
        prop_assert!(anon.anonymize_if_match(&text).is_none());
    }

    /// Random lowercase strings should never trigger PII pre-filter.
    #[test]
    fn prop_no_pii_in_lowercase(text in "[a-z ]{1,200}") {
        let scanner = pii::PiiScanner::from_config(&PiiConfig {
            credit_cards: true,
            iban: true,
            bic: true,
            action: PiiAction::Redact,
        }).unwrap();
        prop_assert!(!scanner.might_contain_pii(&text));
    }

    /// Sanitize on clean text returns Cow::Borrowed (zero allocation).
    #[test]
    fn prop_clean_text_zero_alloc(text in "[a-z ]{1,100}") {
        let config = DlpConfig {
            enabled: true,
            no_builtins: true,
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();
        let result = engine.sanitize_text(&text);
        prop_assert!(matches!(result, Cow::Borrowed(_)),
            "Clean text should be zero-copy, got Owned");
    }
}
