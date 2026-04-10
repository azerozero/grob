use super::*;
use config::*;
use proptest::prelude::*;
use std::borrow::Cow;
use std::sync::Arc;

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
    // Fake token assembled at runtime to avoid Semgrep literal detection.
    let fake_token = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890");
    let input = format!("token: {fake_token}");
    let result = engine.sanitize_text(&input);
    assert!(!result.contains(&fake_token));
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
    let fake_token = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890");
    let input = format!("My token is {fake_token}");
    let result = engine.sanitize_text(&input);
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

// ─── Tests tueurs de mutants cargo-mutants pour dlp/mod.rs ───
// Couvrent les mutants MISSED identifies dans le shard 2 de la matrice
// mutation-testing CI (voir docs interne T-CI-0b).

/// Tue : L229 `+` → `-` / `*` dans `DlpEngine::from_config` (compte de rules).
///
/// Le compteur `secret_count = secrets.len() + custom_prefixes.len()` a ete
/// extrait dans `count_secret_rules` pour etre observable depuis les tests.
#[test]
fn test_kill_mutant_229_count_secret_rules_addition() {
    // 2 + 3 = 5 (les mutants `-` donneraient -1, `*` donneraient 6).
    let config = DlpConfig {
        enabled: true,
        no_builtins: true,
        secrets: vec![
            SecretRule {
                name: "a".into(),
                prefix: "a_".into(),
                pattern: "a_[a-z]+".into(),
                action: SecretAction::Canary,
            },
            SecretRule {
                name: "b".into(),
                prefix: "b_".into(),
                pattern: "b_[a-z]+".into(),
                action: SecretAction::Canary,
            },
        ],
        custom_prefixes: vec![
            CustomPrefixRule {
                name: "c".into(),
                prefix: "c_".into(),
                length: 10,
                action: SecretAction::Canary,
            },
            CustomPrefixRule {
                name: "d".into(),
                prefix: "d_".into(),
                length: 10,
                action: SecretAction::Canary,
            },
            CustomPrefixRule {
                name: "e".into(),
                prefix: "e_".into(),
                length: 10,
                action: SecretAction::Canary,
            },
        ],
        ..Default::default()
    };
    assert_eq!(DlpEngine::count_secret_rules(&config), 5);

    // Bornes asymetriques : 2 et 0, 0 et 3 — tue `*` (donnerait 0).
    let only_secrets = DlpConfig {
        enabled: true,
        no_builtins: true,
        secrets: vec![
            SecretRule {
                name: "a".into(),
                prefix: "a_".into(),
                pattern: "a_[a-z]+".into(),
                action: SecretAction::Canary,
            },
            SecretRule {
                name: "b".into(),
                prefix: "b_".into(),
                pattern: "b_[a-z]+".into(),
                action: SecretAction::Canary,
            },
        ],
        ..Default::default()
    };
    assert_eq!(DlpEngine::count_secret_rules(&only_secrets), 2);

    let only_prefixes = DlpConfig {
        enabled: true,
        no_builtins: true,
        custom_prefixes: vec![CustomPrefixRule {
            name: "x".into(),
            prefix: "x_".into(),
            length: 10,
            action: SecretAction::Canary,
        }],
        ..Default::default()
    };
    assert_eq!(DlpEngine::count_secret_rules(&only_prefixes), 1);
}

/// Helper pour fabriquer un engine qui matche sur un secret et sur un nom.
fn engine_with_secret_and_name() -> Arc<DlpEngine> {
    let config = DlpConfig {
        enabled: true,
        scan_input: true,
        scan_output: true,
        no_builtins: true,
        secrets: vec![SecretRule {
            name: "github_token".into(),
            prefix: "ghp_".into(),
            pattern: "ghp_[A-Za-z0-9]{36}".into(),
            action: SecretAction::Canary,
        }],
        names: vec![NameRule {
            term: "Thales".into(),
            action: NameAction::Pseudonym,
        }],
        ..Default::default()
    };
    DlpEngine::from_config(config).unwrap()
}

/// Tue : L610 `delete !` + `&& → ||` sur `!scanner.is_empty() && might_contain_secret`.
///
/// On s'appuie sur le flag `secret_scan_attempted` du rapport pour distinguer
/// les mutations des branches conditionnelles (sinon `redact` agit comme un
/// second garde-fou et masque `&& → ||`).
#[test]
fn test_kill_mutant_610_scan_end_of_stream_secret_branch() {
    // Cas 1 : engine SANS secrets → branche non evaluee (scanner empty).
    let empty_secrets = DlpConfig {
        enabled: true,
        no_builtins: true,
        ..Default::default()
    };
    let engine_empty = DlpEngine::from_config(empty_secrets).unwrap();
    let fake_token = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890");
    let report = engine_empty.scan_end_of_stream_reported(&fake_token);
    assert_eq!(report.secrets, 0);
    assert!(
        !report.secret_scan_attempted,
        "scanner vide → branche pas evaluee"
    );

    // Cas 2 : engine AVEC secrets mais texte qui ne passe PAS le pre-filter
    // (aucun byte 'g' ni 'A'). Tue `&& → ||` : avec `||`, on entrerait dans
    // la branche alors qu'avec `&&` on saute.
    let engine_full = engine_with_secret_and_name();
    let clean_report = engine_full.scan_end_of_stream_reported("rien ici");
    assert_eq!(clean_report.secrets, 0);
    assert!(
        !clean_report.secret_scan_attempted,
        "pre-filter rejete → branche PAS entree (tue `&& → ||`)"
    );

    // Cas 3 : engine AVEC secrets ET texte piege → branche entree ET detection.
    // Tue `delete !` : avec `self.scanner.is_empty() && ...` le scanner
    // non-vide donne false et on ne rentre plus dans la branche.
    let dirty_token = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890");
    let dirty_report = engine_full.scan_end_of_stream_reported(&dirty_token);
    assert_eq!(
        dirty_report.secrets, 1,
        "secret present → 1 detection (tue `delete !`)"
    );
    assert!(
        dirty_report.secret_scan_attempted,
        "branche entree (tue `delete !`)"
    );
}

/// Tue : L626 `delete !` + `&& → ||` sur `!anonymizer.is_empty() && deanonymize_if_match`.
#[test]
fn test_kill_mutant_626_scan_end_of_stream_name_branch() {
    // Engine avec un nom a pseudonymiser.
    let engine = engine_with_secret_and_name();

    // Etape 1 : anonymise "Thales" pour produire un pseudonyme deterministique.
    let anon = engine.sanitize_text("Contact Thales svp");
    let pseudo = anon
        .as_ref()
        .strip_prefix("Contact ")
        .and_then(|s| s.strip_suffix(" svp"))
        .expect("format stable");
    assert_ne!(pseudo, "Thales", "anonymisation attendue");

    // Cas A : anonymizer non-vide + texte contenant le pseudonyme.
    // Tue `delete !` (sans !, scanner non-vide → false, branche PAS entree).
    let report = engine.scan_end_of_stream_reported(&anon);
    assert_eq!(report.pseudonyms, 1, "1 detection attendue");
    assert!(
        report.name_scan_attempted,
        "branche entree avec detection (tue `delete !`)"
    );

    // Cas B : anonymizer non-vide + texte SANS pseudonyme. Tue `&& → ||` :
    // avec `||`, anonymizer non-vide suffit a entrer la branche.
    let clean = engine.scan_end_of_stream_reported("hello world");
    assert_eq!(clean.pseudonyms, 0);
    assert!(
        !clean.name_scan_attempted,
        "pas de pseudo → branche pas entree (tue `&& → ||`)"
    );

    // Cas C : anonymizer vide → branche jamais entree.
    let empty_config = DlpConfig {
        enabled: true,
        no_builtins: true,
        ..Default::default()
    };
    let empty_engine = DlpEngine::from_config(empty_config).unwrap();
    let r = empty_engine.scan_end_of_stream_reported(&anon);
    assert_eq!(r.pseudonyms, 0);
    assert!(!r.name_scan_attempted);
}

/// Tue : L635 `delete !` sur `!matches!(result, url_exfil::UrlExfilResult::Clean)`.
#[test]
fn test_kill_mutant_635_scan_end_of_stream_url_exfil_branch() {
    // Engine avec URL exfil actif. Les valeurs par defaut activent
    // `flag_long_query_params` et `flag_data_uris` — un data URI declenche
    // sans dependance a la config de domaines.
    let config = DlpConfig {
        enabled: true,
        no_builtins: true,
        url_exfil: UrlExfilConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let engine = DlpEngine::from_config(config).unwrap();

    // Cas propre : aucune URL → report.url_exfils == 0.
    let clean = engine.scan_end_of_stream_reported("hello world sans url");
    assert_eq!(clean.url_exfils, 0, "pas d'URL → pas de detection");

    // Cas sale : data URI explicitement flagge par la config par defaut.
    // Le mutant `delete !` rend la branche `matches!(Clean)`, donc
    // avec une URL suspecte (resultat = Logged), la condition devient
    // fausse et url_exfils reste a 0. L'assertion == 1 kills la mutation.
    let dirty = engine.scan_end_of_stream_reported(
        "leak data:text/plain;base64,SGVsbG8gV29ybGQhIFRoaXMgaXMgc2VjcmV0IGRhdGE=",
    );
    assert_eq!(
        dirty.url_exfils, 1,
        "data URI doit etre detectee (tue `delete !`)"
    );
}

/// Tue : L765 `scan_input_enabled -> bool` (true/false stub).
#[cfg(feature = "dlp")]
#[test]
fn test_kill_mutant_765_scan_input_enabled_reflects_config() {
    use crate::traits::DlpPipeline;

    // scan_input = true → retourne true, mutant `-> false` tue.
    let config_true = DlpConfig {
        enabled: true,
        scan_input: true,
        no_builtins: true,
        ..Default::default()
    };
    let engine_true = DlpEngine::from_config(config_true).unwrap();
    assert!(DlpPipeline::scan_input_enabled(&*engine_true));

    // scan_input = false → retourne false, mutant `-> true` tue.
    let config_false = DlpConfig {
        enabled: true,
        scan_input: false,
        no_builtins: true,
        ..Default::default()
    };
    let engine_false = DlpEngine::from_config(config_false).unwrap();
    assert!(!DlpPipeline::scan_input_enabled(&*engine_false));
}

/// Tue : L769 `scan_output_enabled -> bool` (true/false stub).
#[cfg(feature = "dlp")]
#[test]
fn test_kill_mutant_769_scan_output_enabled_reflects_config() {
    use crate::traits::DlpPipeline;

    // scan_output = true → retourne true.
    let config_true = DlpConfig {
        enabled: true,
        scan_output: true,
        no_builtins: true,
        ..Default::default()
    };
    let engine_true = DlpEngine::from_config(config_true).unwrap();
    assert!(DlpPipeline::scan_output_enabled(&*engine_true));

    // scan_output = false → retourne false.
    let config_false = DlpConfig {
        enabled: true,
        scan_output: false,
        no_builtins: true,
        ..Default::default()
    };
    let engine_false = DlpEngine::from_config(config_false).unwrap();
    assert!(!DlpPipeline::scan_output_enabled(&*engine_false));
}
