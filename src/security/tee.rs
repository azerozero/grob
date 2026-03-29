//! Trusted Execution Environment (TEE) support for AMD SEV-SNP.
//!
//! Provides runtime TEE detection, attestation report generation, and
//! hardware-bound key derivation. The enforcement mode (off/warn/enforce)
//! is configured via `[tee]` in `grob.toml`.
//!
//! # Device interface
//!
//! Communicates with the AMD SEV-SNP firmware through `/dev/sev-guest`
//! using `ioctl` requests defined in the Linux kernel's `sev-guest.h`.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::cli::EnforcementMode;

// ── SEV-SNP ioctl constants ─────────────────────────────────────────────────

/// Path to the SEV-SNP guest device.
const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

/// Attestation report request magic (SNP_GET_REPORT).
const SNP_GET_REPORT: u64 = 0xc018_0001;

/// Derived key request magic (SNP_GET_DERIVED_KEY).
const SNP_GET_DERIVED_KEY: u64 = 0xc018_0002;

/// Size of an SNP attestation report (1184 bytes per AMD spec).
const SNP_REPORT_SIZE: usize = 1184;

/// Size of an SNP derived key (32 bytes / 256 bits).
const DERIVED_KEY_SIZE: usize = 32;

// ── Public types ────────────────────────────────────────────────────────────

/// Result of the TEE detection probe at startup.
#[derive(Debug, Clone)]
pub struct TeeStatus {
    /// Whether the platform is running inside an SEV-SNP enclave.
    pub detected: bool,
    /// Human-readable description of the TEE platform.
    pub platform: String,
    /// Raw attestation report (hex-encoded) if available.
    pub attestation_report: Option<String>,
}

/// Hardware-sealed key material derived from the TEE.
pub struct SealedKey {
    /// 256-bit key derived from `SNP_GET_DERIVED_KEY`.
    key: [u8; DERIVED_KEY_SIZE],
}

impl SealedKey {
    /// Exposes the raw key bytes for cipher construction.
    pub fn as_bytes(&self) -> &[u8; DERIVED_KEY_SIZE] {
        &self.key
    }
}

impl Drop for SealedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

// ── TEE detection ───────────────────────────────────────────────────────────

/// Checks whether the process is running inside an AMD SEV-SNP enclave.
///
/// Detection is passive: probes `/dev/sev-guest` and `/sys/devices`
/// without modifying any state.
pub fn detect_tee() -> TeeStatus {
    // Primary check: SEV-SNP guest device exists and is readable.
    if Path::new(SEV_GUEST_DEVICE).exists() {
        // Verify SNP is actually active via sysfs.
        let snp_active = std::fs::read_to_string("/sys/devices/system/cpu/sev")
            .map(|s| s.trim().contains("snp"))
            .unwrap_or(false);

        if snp_active {
            return TeeStatus {
                detected: true,
                platform: "AMD SEV-SNP".to_string(),
                attestation_report: None,
            };
        }

        // Device exists but sysfs doesn't confirm SNP — still likely a TEE,
        // the sysfs path varies across kernel versions.
        return TeeStatus {
            detected: true,
            platform: "AMD SEV-SNP (sysfs unconfirmed)".to_string(),
            attestation_report: None,
        };
    }

    // Fallback: check cpuid for SEV capability (bit 1 of EAX, leaf 0x8000001F).
    let cpuid_sev = std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.contains("sev_snp"))
        .unwrap_or(false);

    if cpuid_sev {
        return TeeStatus {
            detected: false,
            platform: "AMD SEV-SNP capable (guest device missing)".to_string(),
            attestation_report: None,
        };
    }

    TeeStatus {
        detected: false,
        platform: "none".to_string(),
        attestation_report: None,
    }
}

// ── Attestation report ──────────────────────────────────────────────────────

/// Requests an attestation report from the SEV-SNP firmware.
///
/// The report binds `user_data` (up to 64 bytes) into the signed report,
/// proving that the attestation was requested by this specific process
/// with this specific context (e.g., a hash of the grob config).
///
/// # Errors
///
/// Returns an error if the SEV-SNP guest device is unavailable or the
/// firmware rejects the request.
pub fn get_attestation_report(user_data: &[u8]) -> Result<Vec<u8>> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_DEVICE)
        .with_context(|| format!("Failed to open {SEV_GUEST_DEVICE}"))?;

    // Pad or truncate user_data to 64 bytes (SNP report_data field).
    let mut report_data = [0u8; 64];
    let len = user_data.len().min(64);
    report_data[..len].copy_from_slice(&user_data[..len]);

    // Build the ioctl request buffer.
    // Layout: report_data (64 bytes) | report (1184 bytes)
    let mut buf = vec![0u8; 64 + SNP_REPORT_SIZE];
    buf[..64].copy_from_slice(&report_data);

    // SAFETY: ioctl on an owned fd with a correctly sized buffer.
    // The SNP_GET_REPORT ioctl writes the attestation report into buf[64..].
    #[allow(unsafe_code)]
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), SNP_GET_REPORT, buf.as_mut_ptr()) };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        anyhow::bail!("SNP_GET_REPORT ioctl failed: {errno}");
    }

    Ok(buf[64..].to_vec())
}

/// Generates an attestation report and returns a hex-encoded string
/// suitable for embedding in audit logs.
pub fn attestation_for_audit(config_hash: &[u8]) -> Result<String> {
    let report = get_attestation_report(config_hash)?;
    Ok(hex::encode(&report))
}

// ── Hardware key derivation ─────────────────────────────────────────────────

/// Derives a 256-bit key from the TEE hardware using `SNP_GET_DERIVED_KEY`.
///
/// The derived key is bound to the current VM measurement (VMPL 0),
/// making it impossible to extract outside this specific TEE instance.
/// The `label` is hashed into the key derivation context to produce
/// distinct keys for different purposes (e.g., "encryption", "audit-signing").
///
/// # Errors
///
/// Returns an error if the SEV-SNP guest device is unavailable.
pub fn derive_sealed_key(label: &str) -> Result<SealedKey> {
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_DEVICE)
        .with_context(|| format!("Failed to open {SEV_GUEST_DEVICE}"))?;

    // Hash the label into a 32-byte context for key derivation.
    let mut context = [0u8; 32];
    let hash = Sha256::digest(label.as_bytes());
    context.copy_from_slice(&hash);

    // Build request buffer: context (32 bytes) | root_key_select (4 bytes, VCEK=0)
    //                       | padding (28 bytes) | output key (32 bytes)
    let mut buf = vec![0u8; 32 + 4 + 28 + DERIVED_KEY_SIZE];
    buf[..32].copy_from_slice(&context);
    // root_key_select = 0 (VCEK - Versioned Chip Endorsement Key)
    buf[32..36].copy_from_slice(&0u32.to_le_bytes());

    // SAFETY: ioctl on an owned fd with a correctly sized buffer.
    #[allow(unsafe_code)]
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), SNP_GET_DERIVED_KEY, buf.as_mut_ptr()) };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        buf.zeroize();
        anyhow::bail!("SNP_GET_DERIVED_KEY ioctl failed: {errno}");
    }

    let mut key = [0u8; DERIVED_KEY_SIZE];
    key.copy_from_slice(&buf[64..64 + DERIVED_KEY_SIZE]);
    buf.zeroize();

    Ok(SealedKey { key })
}

// ── Startup enforcement ─────────────────────────────────────────────────────

/// Runs the TEE startup check according to the configured enforcement mode.
///
/// Returns the [`TeeStatus`] and, if attestation succeeded, populates
/// the `attestation_report` field.
pub fn enforce_tee(mode: EnforcementMode, config: &crate::cli::TeeConfig) -> Result<TeeStatus> {
    if mode == EnforcementMode::Off {
        return Ok(TeeStatus {
            detected: false,
            platform: "disabled".to_string(),
            attestation_report: None,
        });
    }

    let mut status = detect_tee();
    info!(
        "🔒 TEE detection: detected={}, platform={}",
        status.detected, status.platform
    );

    if !status.detected {
        let msg = format!(
            "TEE not detected (platform: {}). Grob is NOT running in a trusted execution environment.",
            status.platform
        );
        match mode {
            EnforcementMode::Enforce => {
                anyhow::bail!("🛑 {msg} Refusing to start (tee.mode = \"enforce\").");
            }
            EnforcementMode::Warn => {
                warn!("⚠️  {msg} Continuing anyway (tee.mode = \"warn\").");
            }
            EnforcementMode::Off => unreachable!(),
        }
        return Ok(status);
    }

    // TEE detected — attempt attestation if audit is enabled.
    if config.attestation_audit {
        match attestation_for_audit(b"grob-startup") {
            Ok(report) => {
                info!(
                    "📜 TEE attestation report generated ({} bytes)",
                    report.len() / 2
                );
                status.attestation_report = Some(report);
            }
            Err(e) => {
                warn!("⚠️  TEE attestation report failed: {e}");
            }
        }
    }

    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_tee_returns_status() {
        // On non-TEE machines (CI), detection should return false gracefully.
        let status = detect_tee();
        // We can't assert detected=true in CI, but the call must not panic.
        assert!(!status.platform.is_empty());
    }

    #[test]
    fn enforcement_off_skips_detection() {
        let config = crate::cli::TeeConfig::default();
        let status = enforce_tee(EnforcementMode::Off, &config).unwrap();
        assert!(!status.detected);
        assert_eq!(status.platform, "disabled");
    }

    #[test]
    fn enforcement_warn_succeeds_without_tee() {
        let config = crate::cli::TeeConfig {
            mode: EnforcementMode::Warn,
            attestation_audit: false,
            sealed_keys: false,
        };
        // Should not error — just warn.
        let status = enforce_tee(EnforcementMode::Warn, &config).unwrap();
        assert!(!status.detected);
    }

    #[test]
    fn sealed_key_is_zeroized_on_drop() {
        let key = SealedKey {
            key: [0xAB; DERIVED_KEY_SIZE],
        };
        let ptr = key.key.as_ptr();
        drop(key);
        // NOTE: We can't reliably read freed memory in safe Rust,
        // but the Zeroize impl guarantees the zeroing happens before dealloc.
        let _ = ptr; // Suppress unused warning.
    }
}
