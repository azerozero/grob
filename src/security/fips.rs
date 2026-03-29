//! FIPS 140-3 compliance detection and enforcement.
//!
//! Checks whether the system's crypto libraries operate in FIPS mode
//! and validates that grob's own crypto choices are FIPS-compatible.
//! The enforcement mode (off/warn/enforce) is configured via `[fips]`
//! in `grob.toml`.

use anyhow::Result;
use tracing::{info, warn};

use crate::cli::EnforcementMode;

/// Result of the FIPS compliance probe.
#[derive(Debug, Clone)]
pub struct FipsStatus {
    /// Whether FIPS mode is active on the system.
    pub active: bool,
    /// Details about the FIPS state.
    pub details: String,
    /// Crypto algorithms that are NOT FIPS-approved.
    pub non_compliant: Vec<String>,
}

// ── FIPS detection ──────────────────────────────────────────────────────────

/// Probes the system for FIPS 140-3 mode.
///
/// Checks multiple indicators:
/// 1. `/proc/sys/crypto/fips_enabled` (kernel FIPS mode)
/// 2. OpenSSL FIPS provider status (via env)
/// 3. Algorithm audit against FIPS 140-3 approved list
pub fn detect_fips() -> FipsStatus {
    let kernel_fips = std::fs::read_to_string("/proc/sys/crypto/fips_enabled")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    // Check OpenSSL FIPS env (used by some Rust TLS backends when built with OpenSSL).
    let openssl_fips = std::env::var("OPENSSL_FIPS")
        .map(|v| v == "1")
        .unwrap_or(false);

    // Check if SymCrypt FIPS provider is loaded (Azure confidential computing).
    let symcrypt_fips = std::path::Path::new("/usr/lib/libsymcrypt.so").exists()
        || std::env::var("SYMCRYPT_FIPS").is_ok();

    let active = kernel_fips || openssl_fips || symcrypt_fips;

    let mut sources = Vec::new();
    if kernel_fips {
        sources.push("kernel");
    }
    if openssl_fips {
        sources.push("openssl");
    }
    if symcrypt_fips {
        sources.push("symcrypt");
    }

    let details = if active {
        format!("FIPS mode active via: {}", sources.join(", "))
    } else {
        "FIPS mode not detected".to_string()
    };

    // Audit grob's crypto choices against FIPS 140-3 approved algorithms.
    let non_compliant = audit_algorithms();

    FipsStatus {
        active,
        details,
        non_compliant,
    }
}

/// Audits grob's configured crypto algorithms against FIPS 140-3.
///
/// FIPS 140-3 approved (SP 800-140C):
/// - AES-128/192/256 (GCM, CCM, CBC)  → AES-256-GCM ✓
/// - SHA-2 family (SHA-256, SHA-384, SHA-512) → SHA-256 ✓
/// - HMAC with approved hash → HMAC-SHA256 ✓
/// - ECDSA P-256, P-384, P-521 → ECDSA P-256 ✓
/// - RSA ≥ 2048 bits
///
/// NOT approved:
/// - Ed25519 (not in FIPS 186-5 until recent updates, still transitional)
/// - ChaCha20-Poly1305 (not in FIPS)
fn audit_algorithms() -> Vec<String> {
    let mut issues = Vec::new();

    // Ed25519 is used for audit signing but is not yet universally FIPS-approved.
    // NIST SP 800-186 (2023) added EdDSA but CMVP validation lags.
    issues.push("ed25519 (audit signing option — use ecdsa-p256 or hmac-sha256 for FIPS)".into());

    // Note: AES-256-GCM, ECDSA P-256, HMAC-SHA256, SHA-256 are all approved.
    // reqwest with rustls uses TLS 1.3 cipher suites that may include
    // ChaCha20-Poly1305 alongside AES-GCM. In FIPS mode, only AES-GCM
    // cipher suites should be negotiated.
    issues.push(
        "rustls TLS 1.3 (may negotiate ChaCha20-Poly1305 — restrict to AES-GCM suites in FIPS)"
            .into(),
    );

    issues
}

// ── Startup enforcement ─────────────────────────────────────────────────────

/// Runs the FIPS startup check according to the configured enforcement mode.
pub fn enforce_fips(mode: EnforcementMode) -> Result<FipsStatus> {
    if mode == EnforcementMode::Off {
        return Ok(FipsStatus {
            active: false,
            details: "disabled".to_string(),
            non_compliant: Vec::new(),
        });
    }

    let status = detect_fips();
    info!(
        "🔐 FIPS detection: active={}, {}",
        status.active, status.details
    );

    if !status.active {
        let msg = format!(
            "FIPS mode not detected ({}). Cryptographic operations are NOT running in a FIPS-validated module.",
            status.details
        );
        match mode {
            EnforcementMode::Enforce => {
                anyhow::bail!("🛑 {msg} Refusing to start (fips.mode = \"enforce\").");
            }
            EnforcementMode::Warn => {
                warn!("⚠️  {msg} Continuing anyway (fips.mode = \"warn\").");
            }
            EnforcementMode::Off => unreachable!(),
        }
    }

    if !status.non_compliant.is_empty() {
        let list = status.non_compliant.join(", ");
        match mode {
            EnforcementMode::Enforce if status.active => {
                warn!(
                    "⚠️  FIPS active but non-compliant algorithms available: {list}. \
                     Ensure only FIPS-approved algorithms are used in config."
                );
            }
            EnforcementMode::Warn => {
                info!("ℹ️  Non-FIPS algorithms in use: {list}");
            }
            _ => {}
        }
    }

    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_fips_returns_status() {
        let status = detect_fips();
        // On most CI/dev machines, FIPS is not active.
        assert!(!status.details.is_empty());
    }

    #[test]
    fn enforcement_off_skips_detection() {
        let status = enforce_fips(EnforcementMode::Off).unwrap();
        assert!(!status.active);
        assert_eq!(status.details, "disabled");
        assert!(status.non_compliant.is_empty());
    }

    #[test]
    fn enforcement_warn_succeeds_without_fips() {
        // Should not error — just warn.
        let status = enforce_fips(EnforcementMode::Warn).unwrap();
        // On CI, FIPS is typically not active.
        assert!(!status.details.is_empty());
    }

    #[test]
    fn algorithm_audit_reports_known_issues() {
        let issues = audit_algorithms();
        assert!(
            issues.iter().any(|s| s.contains("ed25519")),
            "should flag ed25519"
        );
    }
}
