//! Scenario definitions, DLP pattern sets, and escalation steps.

use std::sync::Arc;

// ── Scenario definitions ────────────────────────────────────────────────

pub(super) struct Scenario {
    pub(super) name: &'static str,
    pub(super) enable_routing: bool,
    pub(super) enable_dlp: bool,
    pub(super) enable_auth: bool,
    pub(super) enable_rate_limit: bool,
    pub(super) enable_cache: bool,
    pub(super) inject_secrets: bool,
    /// DLP patterns to use (None = use default full set).
    pub(super) dlp_pattern_set: Option<DlpPatternSet>,
}

/// Controls which subset of DLP patterns to compile for escalation steps.
#[derive(Clone, Copy)]
pub(super) enum DlpPatternSet {
    /// Only secret-detection patterns (AWS, GitHub PAT, PEM, OpenAI key).
    SecretsOnly,
    /// Secrets + PII patterns (credit card, email, SSN).
    SecretsPlusPii,
    /// All patterns including injection detection.
    Full,
}

pub(super) fn build_scenarios(with_auth: bool) -> Vec<Scenario> {
    let mut scenarios = vec![
        Scenario {
            name: "direct (baseline)",
            enable_routing: false,
            enable_dlp: false,
            enable_auth: false,
            enable_rate_limit: false,
            enable_cache: false,
            inject_secrets: false,
            dlp_pattern_set: None,
        },
        Scenario {
            name: "proxy",
            enable_routing: false,
            enable_dlp: false,
            enable_auth: false,
            enable_rate_limit: false,
            enable_cache: false,
            inject_secrets: false,
            dlp_pattern_set: None,
        },
    ];

    if with_auth {
        scenarios.push(Scenario {
            name: "proxy+auth",
            enable_routing: false,
            enable_dlp: false,
            enable_auth: true,
            enable_rate_limit: false,
            enable_cache: false,
            inject_secrets: false,
            dlp_pattern_set: None,
        });
    }

    scenarios.push(Scenario {
        name: "proxy+dlp (clean)",
        enable_routing: true,
        enable_dlp: true,
        enable_auth: false,
        enable_rate_limit: false,
        enable_cache: false,
        inject_secrets: false,
        dlp_pattern_set: None,
    });

    scenarios.push(Scenario {
        name: "proxy+dlp (trigger)",
        enable_routing: true,
        enable_dlp: true,
        enable_auth: false,
        enable_rate_limit: false,
        enable_cache: false,
        inject_secrets: true,
        dlp_pattern_set: None,
    });

    scenarios.push(Scenario {
        name: "proxy+all",
        enable_routing: true,
        enable_dlp: true,
        enable_auth: with_auth,
        enable_rate_limit: true,
        enable_cache: true,
        inject_secrets: false,
        dlp_pattern_set: None,
    });

    scenarios
}

/// Builds the escalation staircase: each step adds one feature on top.
pub(super) fn build_escalation_steps() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "TCP baseline",
            enable_routing: false,
            enable_dlp: false,
            enable_auth: false,
            enable_rate_limit: false,
            enable_cache: false,
            inject_secrets: false,
            dlp_pattern_set: None,
        },
        Scenario {
            name: "+ HTTP proxy",
            enable_routing: false,
            enable_dlp: false,
            enable_auth: false,
            enable_rate_limit: false,
            enable_cache: false,
            inject_secrets: false,
            dlp_pattern_set: None,
        },
        Scenario {
            name: "+ routing",
            enable_routing: true,
            enable_dlp: false,
            enable_auth: false,
            enable_rate_limit: false,
            enable_cache: false,
            inject_secrets: false,
            dlp_pattern_set: None,
        },
        Scenario {
            name: "+ rate limiting",
            enable_routing: true,
            enable_dlp: false,
            enable_auth: false,
            enable_rate_limit: true,
            enable_cache: false,
            inject_secrets: false,
            dlp_pattern_set: None,
        },
        Scenario {
            name: "+ cache lookup",
            enable_routing: true,
            enable_dlp: false,
            enable_auth: false,
            enable_rate_limit: true,
            enable_cache: true,
            inject_secrets: false,
            dlp_pattern_set: None,
        },
        Scenario {
            name: "+ DLP secrets",
            enable_routing: true,
            enable_dlp: true,
            enable_auth: false,
            enable_rate_limit: true,
            enable_cache: true,
            inject_secrets: true,
            dlp_pattern_set: Some(DlpPatternSet::SecretsOnly),
        },
        Scenario {
            name: "+ DLP PII",
            enable_routing: true,
            enable_dlp: true,
            enable_auth: false,
            enable_rate_limit: true,
            enable_cache: true,
            inject_secrets: true,
            dlp_pattern_set: Some(DlpPatternSet::SecretsPlusPii),
        },
        Scenario {
            name: "+ DLP injection",
            enable_routing: true,
            enable_dlp: true,
            enable_auth: false,
            enable_rate_limit: true,
            enable_cache: true,
            inject_secrets: true,
            dlp_pattern_set: Some(DlpPatternSet::Full),
        },
        Scenario {
            name: "+ auth",
            enable_routing: true,
            enable_dlp: true,
            enable_auth: true,
            enable_rate_limit: true,
            enable_cache: true,
            inject_secrets: true,
            dlp_pattern_set: Some(DlpPatternSet::Full),
        },
    ]
}

/// Compiles DLP patterns for the given subset.
pub(super) fn compile_dlp_patterns(set: DlpPatternSet) -> Arc<Vec<regex::Regex>> {
    // Secret-detection patterns (always included).
    let mut patterns = vec![
        regex::Regex::new(r"(?i)(sk-[a-zA-Z0-9]{32,})").unwrap(),
        regex::Regex::new(r"(?i)(AKIA[0-9A-Z]{16})").unwrap(),
        regex::Regex::new(r"(?i)(ghp_[a-zA-Z0-9]{36})").unwrap(),
        regex::Regex::new(r"(?i)(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)").unwrap(),
    ];

    if matches!(set, DlpPatternSet::SecretsPlusPii | DlpPatternSet::Full) {
        // PII patterns.
        patterns.push(regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());
        patterns.push(regex::Regex::new(r"\b[46]\d{15}\b").unwrap());
        patterns.push(
            regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
        );
        patterns.push(
            regex::Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b").unwrap(),
        );
    }

    if matches!(set, DlpPatternSet::Full) {
        // Injection detection.
        patterns.push(regex::Regex::new(r"(?i)ignore\s+all\s+previous\s+instructions").unwrap());
    }

    Arc::new(patterns)
}
