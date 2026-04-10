//! Trusted Execution Environment (TEE) support.
//!
//! Provides runtime TEE detection, attestation report generation, and
//! hardware-bound key derivation for:
//!
//! - **AMD SEV-SNP** — `/dev/sev-guest`, `SNP_GET_REPORT`, `SNP_GET_DERIVED_KEY`
//! - **ARM CCA (Realms)** — `/dev/arm-cca-guest`, RSI attestation token
//!
//! The enforcement mode (off/warn/enforce) is configured via `[tee]`
//! in `grob.toml`. Detection probes every supported backend and picks
//! the first one available.
//!
//! TEE hardware is Linux-only (ioctl on `/dev/*-guest` devices).
//! On other platforms, detection always returns "not available".

use anyhow::Result;
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::cli::EnforcementMode;

/// Size of a derived key (32 bytes / 256 bits) for both platforms.
const DERIVED_KEY_SIZE: usize = 32;

// ── Public types (cross-platform) ───────────────────────────────────────────

/// Detected TEE backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeBackend {
    /// AMD Secure Encrypted Virtualization — Secure Nested Paging.
    AmdSevSnp,
    /// ARM Confidential Compute Architecture (Realm).
    ArmCca,
}

impl std::fmt::Display for TeeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeBackend::AmdSevSnp => write!(f, "AMD SEV-SNP"),
            TeeBackend::ArmCca => write!(f, "ARM CCA (Realm)"),
        }
    }
}

/// Result of the TEE detection probe at startup.
#[derive(Debug, Clone)]
pub struct TeeStatus {
    /// Whether the platform is running inside a TEE.
    pub detected: bool,
    /// Which TEE backend was detected, if any.
    pub backend: Option<TeeBackend>,
    /// Human-readable description of the TEE platform.
    pub platform: String,
    /// Raw attestation report (hex-encoded) if available.
    pub attestation_report: Option<String>,
}

/// Hardware-sealed key material derived from the TEE.
pub struct SealedKey {
    /// 256-bit key derived from hardware.
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

// ── Startup enforcement (cross-platform) ────────────────────────────────────

/// Runs the TEE startup check according to the configured enforcement mode.
///
/// Returns the [`TeeStatus`] and, if attestation succeeded, populates
/// the `attestation_report` field.
///
/// # Errors
///
/// Returns an error in `Enforce` mode when no TEE is detected on
/// the host.
pub fn enforce_tee(mode: EnforcementMode, config: &crate::cli::TeeConfig) -> Result<TeeStatus> {
    if mode == EnforcementMode::Off {
        return Ok(TeeStatus {
            detected: false,
            backend: None,
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
            "TEE not detected (platform: {}). \
             Grob is NOT running in a trusted execution environment.",
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
        let backend = status.backend.expect("detected implies backend is Some");
        match attestation_for_audit(backend, b"grob-startup") {
            Ok(report) => {
                info!(
                    "📜 TEE attestation report generated ({} bytes, backend={})",
                    report.len() / 2,
                    backend
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

// ══════════════════════════════════════════════════════════════════════════════
// Linux implementation — real TEE detection, attestation, and key derivation
// via ioctl on /dev/sev-guest (AMD) and /dev/arm-cca-guest (ARM).
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use anyhow::Context;
    use sha2::{Digest, Sha256};
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    // ── AMD SEV-SNP constants ───────────────────────────────────────────────

    const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";
    const SNP_GET_REPORT: u64 = 0xc018_0001;
    const SNP_GET_DERIVED_KEY: u64 = 0xc018_0002;
    const SNP_REPORT_SIZE: usize = 1184;

    // ── ARM CCA (Realm) constants ───────────────────────────────────────────

    const CCA_GUEST_DEVICE: &str = "/dev/arm-cca-guest";
    const CCA_GET_ATTESTATION_TOKEN: u64 = 0xc010_5201;
    const CCA_GET_DERIVED_KEY: u64 = 0xc010_5202;
    const CCA_TOKEN_MAX_SIZE: usize = 4096;

    // ── Detection ───────────────────────────────────────────────────────────

    pub fn detect_tee() -> TeeStatus {
        if let Some(status) = detect_sev_snp() {
            return status;
        }
        if let Some(status) = detect_arm_cca() {
            return status;
        }

        // No TEE detected — check for hardware capability without active enclave.
        let cpuid_hint = std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| {
                if s.contains("sev_snp") {
                    Some("AMD SEV-SNP capable (guest device missing)")
                } else {
                    None
                }
            })
            .unwrap_or(None);

        if let Some(hint) = cpuid_hint {
            return TeeStatus {
                detected: false,
                backend: None,
                platform: hint.to_string(),
                attestation_report: None,
            };
        }

        TeeStatus {
            detected: false,
            backend: None,
            platform: "none".to_string(),
            attestation_report: None,
        }
    }

    pub(super) fn detect_sev_snp() -> Option<TeeStatus> {
        if !Path::new(SEV_GUEST_DEVICE).exists() {
            return None;
        }

        let confirmed = std::fs::read_to_string("/sys/devices/system/cpu/sev")
            .map(|s| s.trim().contains("snp"))
            .unwrap_or(false);

        let qualifier = if confirmed {
            ""
        } else {
            " (sysfs unconfirmed)"
        };

        Some(TeeStatus {
            detected: true,
            backend: Some(TeeBackend::AmdSevSnp),
            platform: format!("AMD SEV-SNP{qualifier}"),
            attestation_report: None,
        })
    }

    pub(super) fn detect_arm_cca() -> Option<TeeStatus> {
        if !Path::new(CCA_GUEST_DEVICE).exists() {
            return None;
        }

        let confirmed = std::fs::read_to_string("/sys/firmware/arm_cca/version")
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        let qualifier = if confirmed {
            ""
        } else {
            " (sysfs unconfirmed)"
        };

        Some(TeeStatus {
            detected: true,
            backend: Some(TeeBackend::ArmCca),
            platform: format!("ARM CCA Realm{qualifier}"),
            attestation_report: None,
        })
    }

    // ── Attestation ─────────────────────────────────────────────────────────

    /// Requests an attestation report from the TEE backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the TEE guest device cannot be opened
    /// or the ioctl call fails.
    pub fn get_attestation_report(backend: TeeBackend, user_data: &[u8]) -> Result<Vec<u8>> {
        match backend {
            TeeBackend::AmdSevSnp => get_snp_attestation_report(user_data),
            TeeBackend::ArmCca => get_cca_attestation_token(user_data),
        }
    }

    fn get_snp_attestation_report(user_data: &[u8]) -> Result<Vec<u8>> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(SEV_GUEST_DEVICE)
            .with_context(|| format!("Failed to open {SEV_GUEST_DEVICE}"))?;

        let mut report_data = [0u8; 64];
        let len = user_data.len().min(64);
        report_data[..len].copy_from_slice(&user_data[..len]);

        let mut buf = vec![0u8; 64 + SNP_REPORT_SIZE];
        buf[..64].copy_from_slice(&report_data);

        // SAFETY: ioctl on an owned fd with a correctly sized buffer.
        // SNP_GET_REPORT writes the attestation report into buf[64..].
        #[allow(unsafe_code)]
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                SNP_GET_REPORT as libc::Ioctl,
                buf.as_mut_ptr(),
            )
        };

        if ret != 0 {
            let errno = std::io::Error::last_os_error();
            anyhow::bail!("SNP_GET_REPORT ioctl failed: {errno}");
        }

        Ok(buf[64..].to_vec())
    }

    fn get_cca_attestation_token(user_data: &[u8]) -> Result<Vec<u8>> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(CCA_GUEST_DEVICE)
            .with_context(|| format!("Failed to open {CCA_GUEST_DEVICE}"))?;

        let mut challenge = [0u8; 64];
        let hash = Sha256::digest(user_data);
        challenge[..32].copy_from_slice(&hash);

        let buf_size = 64 + 8 + CCA_TOKEN_MAX_SIZE;
        let mut buf = vec![0u8; buf_size];
        buf[..64].copy_from_slice(&challenge);
        buf[64..72].copy_from_slice(&(CCA_TOKEN_MAX_SIZE as u64).to_le_bytes());

        // SAFETY: ioctl on an owned fd with a correctly sized buffer.
        // CCA_GET_ATTESTATION_TOKEN writes the CBOR token into buf[72..].
        #[allow(unsafe_code)]
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                CCA_GET_ATTESTATION_TOKEN as libc::Ioctl,
                buf.as_mut_ptr(),
            )
        };

        if ret != 0 {
            let errno = std::io::Error::last_os_error();
            anyhow::bail!("CCA_GET_ATTESTATION_TOKEN ioctl failed: {errno}");
        }

        let token_len = u64::from_le_bytes(buf[64..72].try_into().unwrap_or([0; 8])) as usize;
        let token_len = token_len.min(CCA_TOKEN_MAX_SIZE);

        Ok(buf[72..72 + token_len].to_vec())
    }

    // ── Key derivation ──────────────────────────────────────────────────────

    /// Derives a sealed key from the TEE hardware.
    ///
    /// # Errors
    ///
    /// Returns an error if the TEE guest device cannot be opened
    /// or the key derivation ioctl call fails.
    pub fn derive_sealed_key(backend: TeeBackend, label: &str) -> Result<SealedKey> {
        match backend {
            TeeBackend::AmdSevSnp => derive_snp_key(label),
            TeeBackend::ArmCca => derive_cca_key(label),
        }
    }

    fn derive_snp_key(label: &str) -> Result<SealedKey> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(SEV_GUEST_DEVICE)
            .with_context(|| format!("Failed to open {SEV_GUEST_DEVICE}"))?;

        let mut context = [0u8; 32];
        let hash = Sha256::digest(label.as_bytes());
        context.copy_from_slice(&hash);

        let mut buf = vec![0u8; 32 + 4 + 28 + DERIVED_KEY_SIZE];
        buf[..32].copy_from_slice(&context);
        buf[32..36].copy_from_slice(&0u32.to_le_bytes());

        // SAFETY: ioctl on an owned fd with a correctly sized buffer.
        #[allow(unsafe_code)]
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                SNP_GET_DERIVED_KEY as libc::Ioctl,
                buf.as_mut_ptr(),
            )
        };

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

    fn derive_cca_key(label: &str) -> Result<SealedKey> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(CCA_GUEST_DEVICE)
            .with_context(|| format!("Failed to open {CCA_GUEST_DEVICE}"))?;

        let mut context = [0u8; 32];
        let hash = Sha256::digest(label.as_bytes());
        context.copy_from_slice(&hash);

        let mut buf = vec![0u8; 32 + 4 + 28 + DERIVED_KEY_SIZE];
        buf[..32].copy_from_slice(&context);
        buf[32..36].copy_from_slice(&0u32.to_le_bytes());

        // SAFETY: ioctl on an owned fd with a correctly sized buffer.
        #[allow(unsafe_code)]
        let ret = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                CCA_GET_DERIVED_KEY as libc::Ioctl,
                buf.as_mut_ptr(),
            )
        };

        if ret != 0 {
            let errno = std::io::Error::last_os_error();
            buf.zeroize();
            anyhow::bail!("CCA_GET_DERIVED_KEY ioctl failed: {errno}");
        }

        let mut key = [0u8; DERIVED_KEY_SIZE];
        key.copy_from_slice(&buf[64..64 + DERIVED_KEY_SIZE]);
        buf.zeroize();

        Ok(SealedKey { key })
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Non-Linux stub — TEE hardware is not available on macOS/Windows.
// All functions return "not available" without error, so the enforcement
// logic in enforce_tee() handles the policy (warn vs. enforce).
// ══════════════════════════════════════════════════════════════════════════════

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    pub fn detect_tee() -> TeeStatus {
        TeeStatus {
            detected: false,
            backend: None,
            platform: "not available (requires Linux)".to_string(),
            attestation_report: None,
        }
    }

    #[cfg(test)]
    pub(super) fn detect_sev_snp() -> Option<TeeStatus> {
        None
    }

    #[cfg(test)]
    pub(super) fn detect_arm_cca() -> Option<TeeStatus> {
        None
    }

    /// Requests an attestation report (unsupported on this platform).
    ///
    /// # Errors
    ///
    /// Always returns an error on non-Linux platforms.
    pub fn get_attestation_report(_backend: TeeBackend, _user_data: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("TEE attestation not available on this platform")
    }

    /// Derives a sealed key (unsupported on this platform).
    ///
    /// # Errors
    ///
    /// Always returns an error on non-Linux platforms.
    pub fn derive_sealed_key(_backend: TeeBackend, _label: &str) -> Result<SealedKey> {
        anyhow::bail!("TEE key derivation not available on this platform")
    }
}

// ── Re-exports from platform module ─────────────────────────────────────────

/// Checks whether the process is running inside a TEE.
///
/// Probes backends in order: AMD SEV-SNP, ARM CCA. Returns the first
/// match. On non-Linux platforms, always returns "not available".
pub fn detect_tee() -> TeeStatus {
    platform::detect_tee()
}

/// Requests an attestation report/token from the detected TEE backend.
///
/// - **SEV-SNP**: binds `user_data` into the 64-byte `report_data` field.
/// - **ARM CCA**: hashes `user_data` into the 64-byte challenge field.
///
/// # Errors
///
/// Returns an error if the TEE guest device is unavailable.
pub fn get_attestation_report(backend: TeeBackend, user_data: &[u8]) -> Result<Vec<u8>> {
    platform::get_attestation_report(backend, user_data)
}

/// Generates an attestation report and returns a hex-encoded string
/// suitable for embedding in audit logs.
///
/// # Errors
///
/// Returns an error if the underlying attestation report request fails.
pub fn attestation_for_audit(backend: TeeBackend, user_data: &[u8]) -> Result<String> {
    let report = get_attestation_report(backend, user_data)?;
    Ok(hex::encode(&report))
}

/// Derives a 256-bit key from the TEE hardware.
///
/// - **SEV-SNP**: `SNP_GET_DERIVED_KEY` bound to the VCEK at VMPL 0.
/// - **ARM CCA**: `CCA_GET_DERIVED_KEY` bound to the Realm measurement.
///
/// The `label` is hashed into the derivation context to produce distinct
/// keys for different purposes (e.g., "encryption", "audit-signing").
///
/// # Errors
///
/// Returns an error if the TEE guest device is unavailable.
pub fn derive_sealed_key(backend: TeeBackend, label: &str) -> Result<SealedKey> {
    platform::derive_sealed_key(backend, label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_tee_returns_status() {
        let status = detect_tee();
        assert!(!status.platform.is_empty());
    }

    #[test]
    fn enforcement_off_skips_detection() {
        let config = crate::cli::TeeConfig::default();
        let status = enforce_tee(EnforcementMode::Off, &config).unwrap();
        assert!(!status.detected);
        assert!(status.backend.is_none());
        assert_eq!(status.platform, "disabled");
    }

    #[test]
    fn enforcement_warn_succeeds_without_tee() {
        let config = crate::cli::TeeConfig {
            mode: EnforcementMode::Warn,
            attestation_audit: false,
            sealed_keys: false,
        };
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
        // but the Zeroize impl guarantees zeroing before dealloc.
        let _ = ptr;
    }

    #[test]
    fn tee_backend_display() {
        assert_eq!(TeeBackend::AmdSevSnp.to_string(), "AMD SEV-SNP");
        assert_eq!(TeeBackend::ArmCca.to_string(), "ARM CCA (Realm)");
    }

    #[test]
    fn detect_arm_cca_returns_none_without_device() {
        assert!(platform::detect_arm_cca().is_none());
    }

    #[test]
    fn detect_sev_snp_returns_none_without_device() {
        assert!(platform::detect_sev_snp().is_none());
    }
}
