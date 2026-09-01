//! Reinjects OCR text into the existing DLP engine.
//!
//! The whole point of the image path is that it adds no rules. A screenshot
//! containing an AWS key is caught by the same code that catches one in a
//! chat message, so operators maintain one rule set and every future DLP
//! improvement reaches images for free.

use super::normalize::scan_variants;
use crate::features::dlp::{DlpEngine, DlpRuleType};
use std::collections::BTreeSet;

/// What the DLP engine found in an image's text.
///
/// Carries rule identifiers only. The OCR text itself never appears here,
/// because it contains the secrets that triggered the findings: a report that
/// quoted them would copy the leak into every log line that records it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextFindings {
    /// Identifiers of the rules that fired, deduplicated and ordered.
    pub rules: BTreeSet<String>,
}

impl TextFindings {
    /// Returns whether anything was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Number of distinct rules that fired.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

/// Scans OCR output with the configured DLP engine.
///
/// Each normalisation variant is scanned and the findings are unioned, since
/// a rule may only match one of them: the folded form recovers a mis-read
/// character, the underscored form recovers a dropped separator.
///
/// Deduplication by rule identifier means a secret found in three variants is
/// reported once, so the count reflects secrets rather than passes.
#[must_use]
pub fn scan_ocr_text(engine: &DlpEngine, text: &str) -> TextFindings {
    let mut rules = BTreeSet::new();
    for variant in scan_variants(text) {
        let (_sanitized, reports) = engine.sanitize_text_reported(&variant);
        for report in reports {
            rules.insert(rule_id(&report.rule_type, &report.detail));
        }
    }
    TextFindings { rules }
}

/// Builds a stable identifier for a report.
///
/// The engine's `detail` already carries the rule name for secrets
/// (`rule=aws_access_key`); for other categories it may include the matched
/// value, so those are reduced to their category. A stable identifier is what
/// makes deduplication across variants meaningful, and it keeps matched values
/// out of the record.
fn rule_id(rule_type: &DlpRuleType, detail: &str) -> String {
    if let Some(name) = detail.strip_prefix("rule=") {
        return format!("{rule_type:?}:{name}");
    }
    format!("{rule_type:?}")
}
