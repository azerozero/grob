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
pub mod stego;
#[cfg(test)]
mod tests;

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
