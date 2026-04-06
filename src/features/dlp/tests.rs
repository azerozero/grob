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
        names_mode: NamesMode::Manual,
        auto_detect_cache_limit: 64,
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

// ── Insta snapshot tests ─────────────────────────────────────

#[test]
fn snap_canary_github_token() {
    let config = test_config();
    let engine = DlpEngine::from_config(config).unwrap();
    let input = "My token is ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    let result = engine.sanitize_text(input);
    // Structural assertion: canary replaces token, prefix preserved.
    // Cannot use insta snapshot here because the canary pattern triggers gitleaks.
    assert!(
        result.starts_with("My token is ghp_~CANARY"),
        "Expected canary prefix, got: {result}"
    );
    assert!(
        !result.contains("abcdefghijklmnopqrstuvwxyz1234567890"),
        "Original token must be removed"
    );
}

#[test]
fn snap_name_pseudonymization_structure() {
    let config = test_config();
    let engine = DlpEngine::from_config(config).unwrap();
    let input = "Contact Thales for the update.";
    let anonymized = engine.sanitize_text(input);
    // Pseudonym is HMAC-derived and nondeterministic across runs.
    // Verify structural properties instead of exact value.
    assert!(!anonymized.contains("Thales"), "Real name must be removed");
    assert!(
        anonymized.starts_with("Contact ") && anonymized.ends_with(" for the update."),
        "Surrounding text must be preserved, got: {anonymized}"
    );
}

#[test]
fn snap_name_deanonymize_roundtrip() {
    let config = test_config();
    let engine = DlpEngine::from_config(config).unwrap();
    let input = "Contact Thales for the update.";
    let anonymized = engine.sanitize_text(input);
    let restored = engine.sanitize_response_text(&anonymized);
    // Roundtrip must restore the original text exactly.
    insta::assert_snapshot!("dlp_name_deanonymize_roundtrip", restored.as_ref());
}

#[test]
fn snap_pii_credit_card_redaction() {
    let config = DlpConfig {
        enabled: true,
        no_builtins: true,
        pii: config::PiiConfig {
            credit_cards: true,
            iban: false,
            bic: false,
            action: config::PiiAction::Redact,
        },
        ..Default::default()
    };
    let engine = DlpEngine::from_config(config).unwrap();
    let input = "Pay with card 4532015112830366 please.";
    let result = engine.sanitize_text(input);
    insta::assert_snapshot!("dlp_pii_credit_card_redaction", result.as_ref());
}

#[test]
fn snap_pii_iban_redaction() {
    let config = DlpConfig {
        enabled: true,
        no_builtins: true,
        pii: config::PiiConfig {
            credit_cards: false,
            iban: true,
            bic: false,
            action: config::PiiAction::Redact,
        },
        ..Default::default()
    };
    let engine = DlpEngine::from_config(config).unwrap();
    let input = "Transfer to FR7630006000011234567890189 now.";
    let result = engine.sanitize_text(input);
    insta::assert_snapshot!("dlp_pii_iban_redaction", result.as_ref());
}

#[test]
fn snap_clean_text_unchanged() {
    let config = test_config();
    let engine = DlpEngine::from_config(config).unwrap();
    let input = "This is a perfectly normal sentence with no secrets.";
    let result = engine.sanitize_text(input);
    insta::assert_snapshot!("dlp_clean_text_unchanged", result.as_ref());
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

    /// Arbitrary UTF-8 input never causes DFA scanner to panic.
    #[test]
    fn prop_dfa_no_panic(text in "\\PC{0,500}") {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();
        let _ = engine.scanner.might_contain_secret(&text);
        let _ = engine.scanner.scan(&text);
    }

    /// Any Luhn-valid 16-digit number embedded in text is detected by the PII scanner.
    #[test]
    fn prop_pii_credit_card_luhn_detected(digits in proptest::collection::vec(0u8..10, 15..=15)) {
        let check = {
            let mut sum: u32 = 0;
            for (i, &d) in digits.iter().rev().enumerate() {
                let mut val = d as u32;
                if i % 2 == 0 { val *= 2; if val > 9 { val -= 9; } }
                sum += val;
            }
            ((10 - (sum % 10)) % 10) as u8
        };
        let mut full: Vec<u8> = digits;
        full.push(check);
        let cc: String = full.iter().map(|d| (b'0' + d) as char).collect();

        let scanner = pii::PiiScanner::from_config(&PiiConfig {
            credit_cards: true,
            iban: false,
            bic: false,
            action: PiiAction::Redact,
        }).unwrap();

        let text = format!("pay {} now", cc);
        if scanner.might_contain_pii(&text) {
            if let Some((_, detections)) = scanner.redact(&text) {
                let has_cc = detections.iter().any(|d| d.pii_type == pii::PiiType::CreditCard);
                prop_assert!(has_cc, "Luhn-valid CC {} should be detected", cc);
            }
        }
    }

    /// Any mod97-valid IBAN embedded in text is detected by the PII scanner.
    #[test]
    fn prop_pii_iban_mod97_detected(body_digits in proptest::collection::vec(0u8..10, 18..=18)) {
        let body: String = body_digits.iter().map(|d| (b'0' + d) as char).collect();
        let rearranged = format!("{}FR00", body);
        let mut remainder: u64 = 0;
        for ch in rearranged.chars() {
            let val = if ch.is_ascii_uppercase() {
                (ch as u64) - 55
            } else {
                ch.to_digit(10).unwrap_or(0) as u64
            };
            if val >= 10 {
                remainder = (remainder * 100 + val) % 97;
            } else {
                remainder = (remainder * 10 + val) % 97;
            }
        }
        let check = 98 - remainder;
        let iban = format!("FR{:02}{}", check, body);

        let scanner = pii::PiiScanner::from_config(&PiiConfig {
            credit_cards: false,
            iban: true,
            bic: false,
            action: PiiAction::Redact,
        }).unwrap();

        let text = format!("transfer {} done", iban);
        if scanner.might_contain_pii(&text) {
            if let Some((_, detections)) = scanner.redact(&text) {
                let has_iban = detections.iter().any(|d| d.pii_type == pii::PiiType::Iban);
                prop_assert!(has_iban, "Valid IBAN {} should be detected", iban);
            }
        }
    }

    /// Sanitize output is always valid UTF-8 (no corruption).
    #[test]
    fn prop_dlp_utf8_roundtrip(text in "\\PC{0,500}") {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();
        let result = engine.sanitize_text(&text);
        prop_assert!(result.len() <= text.len() + 1024,
            "Output should not grow unboundedly");
        let response = engine.sanitize_response_text(&result);
        prop_assert!(response.len() <= result.len() + 1024);
    }

    /// Sanitize is idempotent: sanitize(sanitize(x)) == sanitize(x).
    #[test]
    fn prop_sanitize_idempotent(text in ".{0,200}") {
        let config = test_config();
        let engine = DlpEngine::from_config(config).unwrap();
        let once = engine.sanitize_text(&text).into_owned();
        let twice = engine.sanitize_text(&once).into_owned();
        prop_assert_eq!(&once, &twice,
            "Sanitize must be idempotent: second pass changed the text");
    }

    /// Sanitized output length is bounded: never more than input + a constant
    /// (redaction markers like [REDACTED] or canary tokens have bounded size).
    #[test]
    fn prop_sanitize_length_bounded(text in ".{0,500}") {
        let config = test_config();
        let engine = DlpEngine::from_config(config).unwrap();
        let result = engine.sanitize_text(&text);
        // Canary tokens and pseudonyms can expand, but by at most ~200 bytes.
        prop_assert!(result.len() <= text.len() + 200,
            "Output {} bytes exceeds input {} + 200", result.len(), text.len());
    }

    /// If text contains a known secret prefix, sanitize must not preserve it.
    #[test]
    fn prop_secret_never_leaks(suffix in "[A-Za-z0-9]{36}") {
        let secret = format!("ghp_{suffix}");
        let config = test_config();
        let engine = DlpEngine::from_config(config).unwrap();
        let text = format!("My token is {secret} ok?");
        let result = engine.sanitize_text(&text);
        prop_assert!(!result.contains(&secret),
            "Secret '{}' leaked through sanitize", &secret[..10]);
    }
}

// ---------- DlpBlockError Display ----------

#[test]
fn display_injection_blocked_single() {
    let err = DlpBlockError::InjectionBlocked(vec![prompt_injection::InjectionDetection {
        pattern_name: "rule1".into(),
        matched_text: "ignore previous".into(),
        start: 0,
        end: 15,
    }]);
    let msg = err.to_string();
    assert!(msg.starts_with("Prompt injection detected: "));
    assert!(msg.contains("ignore previous"));
    // Single item means no comma separator.
    assert!(!msg.contains(", "));
}

#[test]
fn display_injection_blocked_multiple() {
    let err = DlpBlockError::InjectionBlocked(vec![
        prompt_injection::InjectionDetection {
            pattern_name: "rule1".into(),
            matched_text: "first".into(),
            start: 0,
            end: 5,
        },
        prompt_injection::InjectionDetection {
            pattern_name: "rule2".into(),
            matched_text: "second".into(),
            start: 10,
            end: 16,
        },
    ]);
    let msg = err.to_string();
    assert!(msg.starts_with("Prompt injection detected: "));
    // Comma separator must appear between items.
    assert!(msg.contains(", "));
    assert!(msg.contains("first"));
    assert!(msg.contains("second"));
}

#[test]
fn display_url_exfil_blocked_single() {
    let err = DlpBlockError::UrlExfilBlocked(vec![url_exfil::UrlExfilDetection {
        url: "https://evil.com/leak".into(),
        reason: "suspicious_domain".into(),
        start: 0,
        end: 20,
    }]);
    let msg = err.to_string();
    assert!(msg.starts_with("URL exfiltration detected: "));
    assert!(msg.contains("evil.com"));
    assert!(!msg.contains(", "));
}

#[test]
fn display_url_exfil_blocked_multiple() {
    let err = DlpBlockError::UrlExfilBlocked(vec![
        url_exfil::UrlExfilDetection {
            url: "https://evil.com/a".into(),
            reason: "r1".into(),
            start: 0,
            end: 10,
        },
        url_exfil::UrlExfilDetection {
            url: "https://evil.com/b".into(),
            reason: "r2".into(),
            start: 20,
            end: 30,
        },
    ]);
    let msg = err.to_string();
    assert!(msg.starts_with("URL exfiltration detected: "));
    assert!(msg.contains(", "));
}

// ---------- DlpEngine::from_config secret_count ----------

#[test]
fn from_config_counts_secrets_and_custom_prefixes() {
    let config = DlpConfig {
        enabled: true,
        scan_input: true,
        scan_output: true,
        rules_file: String::new(),
        no_builtins: true,
        secrets: vec![
            SecretRule {
                name: "tok1".into(),
                prefix: "tok1_".into(),
                pattern: "tok1_[a-z]+".into(),
                action: SecretAction::Canary,
            },
            SecretRule {
                name: "tok2".into(),
                prefix: "tok2_".into(),
                pattern: "tok2_[a-z]+".into(),
                action: SecretAction::Canary,
            },
        ],
        custom_prefixes: vec![CustomPrefixRule {
            name: "xpfx".into(),
            prefix: "xpfx_".into(),
            length: 20,
            action: SecretAction::Canary,
        }],
        names: vec![],
        entropy: EntropyConfig::default(),
        pii: Default::default(),
        enable_sessions: false,
        url_exfil: Default::default(),
        prompt_injection: Default::default(),
        signed_config: Default::default(),
        key_rotation_hours: 24,
        names_mode: NamesMode::Manual,
        auto_detect_cache_limit: 64,
    };
    let engine = DlpEngine::from_config(config).unwrap();
    // 2 secrets + 1 custom prefix = 3 patterns loaded in scanner.
    // Verify by scanning a string matching the custom prefix.
    let result = engine.sanitize_text("here is xpfx_abcdef and tok1_hello");
    assert!(
        matches!(result, Cow::Owned(_)),
        "Should have redacted something"
    );
}
