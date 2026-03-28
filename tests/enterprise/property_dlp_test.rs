//! Property-based tests for the DLP pipeline.
//!
//! Invariant: the DLP engine must NEVER leak a known secret pattern in its
//! output. For any input containing a secret, the sanitized output must not
//! contain the original secret value.

use grob::features::dlp::config::DlpConfig;
use grob::features::dlp::DlpEngine;
use proptest::prelude::*;
use std::sync::Arc;

// ── Secret Generators ────────────────────────────────────────────

/// Generates a realistic OpenAI API key (sk-proj- prefix + 48 alnum chars).
fn openai_key_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{48,60}".prop_map(|suffix| format!("sk-proj-{}", suffix))
}

/// Generates a realistic Anthropic API key.
fn anthropic_key_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{90,110}".prop_map(|suffix| format!("sk-ant-api03-{}", suffix))
}

/// Generates a realistic GitHub personal access token.
fn github_pat_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{36}".prop_map(|suffix| format!("ghp_{}", suffix))
}

/// Generates a realistic HuggingFace token.
fn huggingface_token_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{34}".prop_map(|suffix| format!("hf_{}", suffix))
}

/// Generates a realistic Stripe secret key.
fn stripe_key_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{24,40}".prop_map(|suffix| format!("sk_live_{}", suffix))
}

/// Generates a realistic GCP API key.
fn gcp_key_strategy() -> impl Strategy<Value = String> {
    "[0-9A-Za-z_-]{35}".prop_map(|suffix| format!("AIza{}", suffix))
}

/// Generates a realistic Vault token.
fn vault_token_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{24,40}".prop_map(|suffix| format!("hvs.{}", suffix))
}

/// Generates a Perplexity API key.
fn perplexity_key_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{48}".prop_map(|suffix| format!("pplx-{}", suffix))
}

/// Generates surrounding prose that wraps a secret.
fn prose_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9 .,!?\\-]{10,100}").unwrap()
}

/// Generates a combined secret type from any of the supported families.
fn any_secret_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        openai_key_strategy(),
        anthropic_key_strategy(),
        github_pat_strategy(),
        huggingface_token_strategy(),
        stripe_key_strategy(),
        gcp_key_strategy(),
        vault_token_strategy(),
        perplexity_key_strategy(),
    ]
}

// ── DLP Engine Factory ───────────────────────────────────────────

fn build_dlp_engine() -> Arc<DlpEngine> {
    let config = DlpConfig {
        enabled: true,
        scan_input: true,
        scan_output: true,
        ..Default::default()
    };
    DlpEngine::from_config(config).expect("DLP engine should initialize with defaults")
}

// ── Property Tests ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Invariant: sanitize_text never returns the original secret verbatim.
    #[test]
    fn dlp_never_leaks_secret_in_output(
        secret in any_secret_strategy(),
        prefix in prose_strategy(),
        suffix in prose_strategy(),
    ) {
        let engine = build_dlp_engine();
        let input = format!("{} {} {}", prefix, secret, suffix);
        let output = engine.sanitize_text(&input);

        prop_assert!(
            !output.contains(&secret),
            "DLP leaked secret '{}' in output: {}",
            &secret[..secret.len().min(20)],
            output
        );
    }

    /// Invariant: sanitize_text is idempotent — running it twice yields the same result.
    #[test]
    fn dlp_sanitization_is_idempotent(
        secret in any_secret_strategy(),
        prose in prose_strategy(),
    ) {
        let engine = build_dlp_engine();
        let input = format!("{} {}", prose, secret);
        let first_pass = engine.sanitize_text(&input).to_string();
        let second_pass = engine.sanitize_text(&first_pass).to_string();

        prop_assert_eq!(
            &first_pass, &second_pass,
            "DLP sanitization is not idempotent"
        );
    }

    /// Invariant: clean input (no secrets) passes through unchanged.
    #[test]
    fn dlp_preserves_clean_text(
        text in "[A-Za-z ]{10,200}",
    ) {
        let engine = build_dlp_engine();
        let output = engine.sanitize_text(&text);

        prop_assert_eq!(
            text.as_str(), output.as_ref(),
            "DLP modified clean text"
        );
    }

    /// Invariant: multiple secrets in a single input are ALL sanitized.
    #[test]
    fn dlp_sanitizes_all_secrets_in_multi_secret_input(
        secret1 in openai_key_strategy(),
        secret2 in github_pat_strategy(),
        filler in "[A-Za-z ]{5,30}",
    ) {
        let engine = build_dlp_engine();
        let input = format!("{} {} {}", secret1, filler, secret2);
        let output = engine.sanitize_text(&input);

        prop_assert!(
            !output.contains(&secret1),
            "DLP leaked first secret"
        );
        prop_assert!(
            !output.contains(&secret2),
            "DLP leaked second secret"
        );
    }

    /// Invariant: deanonymize(anonymize(text)) restores the original text.
    #[test]
    fn dlp_deanonymize_is_inverse_of_anonymize(
        name_idx in 0_usize..5,
        prefix in "[A-Za-z ]{5,30}",
        suffix in "[A-Za-z ]{5,30}",
    ) {
        use grob::features::dlp::config::{NameRule, NameAction};
        use grob::features::dlp::names::NameAnonymizer;

        let names = ["Alice Dupont", "Bob Martin", "Carlos Rivera", "Diana Chen", "Erika Müller"];
        let name = names[name_idx % names.len()];

        let rules: Vec<NameRule> = names.iter().map(|n| NameRule {
            term: n.to_string(),
            action: NameAction::Pseudonym,
        }).collect();

        let anon = NameAnonymizer::new_with_session(&rules, b"test-stable-seed");
        let input = format!("{} {} {}", prefix, name, suffix);

        if let Some((anonymized, _)) = anon.anonymize_if_match(&input) {
            // Anonymized text must NOT contain the original name.
            prop_assert!(
                !anonymized.contains(name),
                "Anonymized text still contains original name '{}'",
                name
            );

            // Deanonymize must restore the original.
            if let Some(restored) = anon.deanonymize_if_match(&anonymized) {
                prop_assert_eq!(
                    &input, &restored,
                    "deanonymize(anonymize(x)) != x"
                );
            } else {
                // If deanonymize returns None, the pseudonym wasn't found — this is a bug.
                prop_assert!(false, "deanonymize_if_match returned None for anonymized text");
            }
        }
        // If anonymize returns None, the name wasn't matched — skip (no assertion needed).
    }

    /// Invariant: output length is bounded — DLP replacement never explodes output size.
    #[test]
    fn dlp_output_length_is_bounded(
        secret in any_secret_strategy(),
        prose in prose_strategy(),
    ) {
        let engine = build_dlp_engine();
        let input = format!("{} {}", prose, secret);
        let output = engine.sanitize_text(&input);

        // Canary tokens add overhead but should not exceed 3x the input.
        let max_allowed = input.len() * 3 + 256;
        prop_assert!(
            output.len() <= max_allowed,
            "DLP output {} bytes exceeds 3x input {} bytes",
            output.len(),
            input.len()
        );
    }
}
