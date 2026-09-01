//! Cheap, dependency-free detectors over already-probed media.
//!
//! Every detector here reads bytes that are already in memory and returns a
//! signal, never a decision. Ordering matters: the cheapest checks run first,
//! and none of them decode pixels.
//!
//! These catch the careless case, not the determined adversary. A motivated
//! steganographer defeats all of this, and the module says so rather than
//! implying a guarantee it cannot keep.

pub mod heuristics;
pub mod normalize;
pub mod stego;
#[cfg(test)]
mod tests;
pub mod text;

use super::decode::MediaProbe;

/// Severity of a single observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Worth recording, not worth acting on.
    Info,
    /// Unusual enough that a human might want to know.
    Notice,
    /// Strongly suggests deliberate concealment or leakage.
    Suspicious,
}

/// One thing a detector noticed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable identifier, safe to alert on (e.g. `exif_gps`).
    pub rule: &'static str,
    /// How much it matters.
    pub severity: Severity,
    /// Human-readable detail.
    ///
    /// Never contains payload bytes: a finding that quotes the secret it
    /// found would leak it into every log that records the finding.
    pub detail: String,
}

impl Finding {
    /// Builds a finding.
    #[must_use]
    pub fn new(rule: &'static str, severity: Severity, detail: impl Into<String>) -> Self {
        Self {
            rule,
            severity,
            detail: detail.into(),
        }
    }
}

/// Everything the detectors noticed about one media item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Findings, in detector order.
    pub findings: Vec<Finding>,
}

impl ScanReport {
    /// Returns whether anything at all was noticed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Highest severity observed, if any.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Returns whether a given rule fired.
    #[must_use]
    pub fn has(&self, rule: &str) -> bool {
        self.findings.iter().any(|f| f.rule == rule)
    }

    /// Rule identifiers that fired, for structured logging.
    #[must_use]
    pub fn rules(&self) -> Vec<&'static str> {
        self.findings.iter().map(|f| f.rule).collect()
    }
}

/// Runs every cheap detector over a probed payload.
///
/// `bytes` must be the decoded payload that produced `probe`.
#[must_use]
pub fn scan(bytes: &[u8], probe: &MediaProbe) -> ScanReport {
    let mut findings = Vec::new();
    findings.extend(heuristics::detect(bytes, probe));
    findings.extend(stego::detect(bytes, probe));
    ScanReport { findings }
}

#[cfg(test)]
mod text_tests {
    use super::normalize::{fold_confusions, scan_variants};
    use super::text::scan_ocr_text;
    use crate::features::dlp::config::{DlpConfig, PiiConfig};
    use crate::features::dlp::DlpEngine;

    /// Production-shaped engine: builtins on, PII on.
    fn engine() -> std::sync::Arc<DlpEngine> {
        let config = DlpConfig {
            enabled: true,
            scan_input: true,
            scan_output: true,
            no_builtins: false,
            pii: PiiConfig {
                credit_cards: true,
                iban: true,
                bic: true,
                ..Default::default()
            },
            ..Default::default()
        };
        DlpEngine::from_config(config).expect("engine")
    }

    /// Verbatim macOS Vision output on the screenshot fixture, transcription
    /// errors included: AKIAI read as AKIAT, sk_live as sk_Live, x as U+00D7.
    const VISION_OCR: &str = concat!(
        "$cat ,env\n",
        "AWS_ACCESS_KEY_ID=AKIATOSFODNN7EXAMPLE\n",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
        "DATABASE_URL=postgres://admin:hunter2@10.0.0.4:5432/prod\n",
        "STRIPE_KEY=sk_Live_51H8\u{d7}YzABCDEFGHIJKLMNOPqr\n",
    );

    /// Verbatim ocrs output on the same fixture: underscores dropped.
    const OCRS_OCR: &str = concat!(
        "$ cat .env\n",
        "AWS ACCESS KEY ID=AKIAIOSFODNN7EXAMPLE\n",
        "AWS SECRET ACCESS KEY=WJalrXUtnFEMI/K7MDENG/bPXRfiCYEXAMPLEKEY\n",
        "GITHUB TOKEN=ghp_abcdefghijklmnopqrstuvWxyz1234567890\n",
        "DATABASE URL=postgres://admin:hunter2@10.0, 0.4:5432/prod\n",
        "STRIPE KEY=sk Live_51H8XYzABCDEFGHIJKLMNOPqr\n",
    );

    #[test]
    fn normalisation_recovers_the_secret_raw_ocr_loses() {
        // The measured baseline was 3 of 4 on raw Vision output, the miss
        // being Stripe because its errors landed in a literal prefix.
        let engine = engine();
        let found = scan_ocr_text(&engine, VISION_OCR);

        assert!(
            found.rules.iter().any(|r| r.contains("aws_access_key")),
            "AWS key should survive raw OCR: {:?}",
            found.rules
        );
        assert!(
            found.rules.iter().any(|r| r.contains("stripe")),
            "normalisation should recover the Stripe key raw OCR loses: {:?}",
            found.rules
        );
    }

    #[test]
    fn both_engines_reach_the_same_findings_after_normalisation() {
        // Vision and ocrs fail differently. Normalisation should close both
        // gaps, otherwise the engine choice would leak into the security
        // properties instead of staying a deployment preference.
        let engine = engine();
        let vision = scan_ocr_text(&engine, VISION_OCR);
        let ocrs = scan_ocr_text(&engine, OCRS_OCR);

        for expected in ["aws_access_key", "github", "postgres", "stripe"] {
            assert!(
                vision.rules.iter().any(|r| r.contains(expected)),
                "Vision path missed {expected}: {:?}",
                vision.rules
            );
            assert!(
                ocrs.rules.iter().any(|r| r.contains(expected)),
                "ocrs path missed {expected}: {:?}",
                ocrs.rules
            );
        }
    }

    #[test]
    fn findings_never_carry_the_text_that_produced_them() {
        // The OCR text contains the secrets; a report quoting them would copy
        // the leak into every log line recording it.
        let engine = engine();
        let findings = scan_ocr_text(&engine, VISION_OCR);
        for rule in &findings.rules {
            assert!(!rule.contains("AKIA"), "finding leaked a secret: {rule}");
            assert!(!rule.contains("hunter2"), "finding leaked a secret: {rule}");
        }
    }

    #[test]
    fn clean_text_produces_no_findings() {
        let engine = engine();
        assert!(scan_ocr_text(&engine, "just a screenshot of a cat").is_empty());
    }

    #[test]
    fn confusion_folding_covers_only_observed_substitutions() {
        assert_eq!(fold_confusions("51H8\u{d7}Yz"), "51H8xYz");
        assert_eq!(fold_confusions("a\u{2013}b"), "a-b");
        assert_eq!(fold_confusions("a\u{00a0}b"), "a b");
        // Characters engines do not confuse pass through untouched: every
        // extra mapping widens the false-positive surface.
        assert_eq!(fold_confusions("0O1lI"), "0O1lI");
        assert_eq!(fold_confusions("normal text"), "normal text");
    }

    #[test]
    fn the_original_text_is_always_scanned_first() {
        // A rule that already matches must not be perturbed by normalisation.
        let variants = scan_variants("sk_Live_51H8\u{d7}Yz");
        assert_eq!(variants[0], "sk_Live_51H8\u{d7}Yz");
        assert!(variants.len() > 1, "a confusable input should add variants");
    }

    #[test]
    fn variants_are_deduplicated() {
        // Lowercase input with no spaces or confusables costs exactly one
        // pass, so the common case of clean OCR adds no extra scans.
        assert_eq!(scan_variants("already_lowercase").len(), 1);
    }
}
