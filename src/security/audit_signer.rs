//! Pluggable signing backends for the audit log.
//!
//! [`AuditSigner`] abstracts over ECDSA P-256, Ed25519, and HMAC-SHA256
//! so the audit log can be configured at runtime without touching the
//! write pipeline.

use anyhow::{Context, Result};
use sha2::Sha256;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Trait for audit log signature operations.
pub trait AuditSigner: Send + Sync {
    /// Signs `data` and returns the raw signature bytes.
    fn sign(&self, data: &[u8]) -> Vec<u8>;

    /// Returns the algorithm label stored in each entry (e.g. `"ecdsa-p256"`).
    fn algorithm(&self) -> &'static str;

    /// Verifies `signature` over `data`. Returns `true` if valid.
    fn verify(&self, data: &[u8], signature: &[u8]) -> bool;
}

// ── ECDSA P-256 ──

/// ECDSA P-256 (NIST) signer with 64-byte signatures.
pub struct EcdsaP256Signer {
    signing_key: p256::ecdsa::SigningKey,
    verifying_key: p256::ecdsa::VerifyingKey,
}

impl EcdsaP256Signer {
    /// Loads a key from `path` or generates a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the key file cannot be read, contains
    /// invalid P-256 key material, or a new key cannot be written.
    pub fn load_or_generate(path: Option<&Path>) -> Result<Self> {
        let signing_key = if let Some(p) = path {
            if p.exists() {
                let mut bytes = std::fs::read(p).context("Failed to read ECDSA key")?;
                let key = p256::ecdsa::SigningKey::from_slice(&bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid ECDSA key: {e}"));
                bytes.zeroize();
                key?
            } else {
                let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
                std::fs::write(p, key.to_bytes()).context("Failed to save ECDSA key")?;
                set_key_permissions(p)?;
                key
            }
        } else {
            tracing::warn!("Using ephemeral ECDSA key. Logs won't be verifiable across restarts.");
            p256::ecdsa::SigningKey::random(&mut rand::thread_rng())
        };
        let verifying_key = *signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
}

impl AuditSigner for EcdsaP256Signer {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = self.signing_key.sign(data);
        sig.to_bytes().to_vec()
    }

    fn algorithm(&self) -> &'static str {
        "ecdsa-p256"
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        let Ok(sig) = p256::ecdsa::Signature::from_slice(signature) else {
            return false;
        };
        self.verifying_key.verify(data, &sig).is_ok()
    }
}

// ── Ed25519 ──

/// Ed25519 signer with 64-byte signatures (Curve25519).
pub struct Ed25519Signer {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519Signer {
    /// Loads a key from `path` or generates a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the key file cannot be read, is not exactly
    /// 32 bytes, or a new key cannot be written.
    pub fn load_or_generate(path: Option<&Path>) -> Result<Self> {
        let signing_key = if let Some(p) = path {
            if p.exists() {
                let mut bytes = std::fs::read(p).context("Failed to read Ed25519 key")?;
                let mut key_bytes: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Ed25519 key must be 32 bytes"))?;
                bytes.zeroize();
                let key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                key_bytes.zeroize();
                key
            } else {
                let key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
                std::fs::write(p, key.to_bytes()).context("Failed to save Ed25519 key")?;
                set_key_permissions(p)?;
                key
            }
        } else {
            tracing::warn!(
                "Using ephemeral Ed25519 key. Logs won't be verifiable across restarts."
            );
            ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
        };
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
}

impl AuditSigner for Ed25519Signer {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(data);
        sig.to_bytes().to_vec()
    }

    fn algorithm(&self) -> &'static str {
        "ed25519"
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        use ed25519_dalek::Verifier;
        let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else {
            return false;
        };
        self.verifying_key.verify(data, &sig).is_ok()
    }
}

// ── HMAC-SHA256 ──

/// HMAC-SHA256 symmetric signer with 32-byte MACs.
///
/// Key material is zeroed from memory on drop via [`ZeroizeOnDrop`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HmacSha256Signer {
    key: [u8; 32],
}

impl HmacSha256Signer {
    /// Loads a key from `path` or generates a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the key file cannot be read, is not exactly
    /// 32 bytes, or a new key cannot be written.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        let key = if path.exists() {
            let mut bytes = std::fs::read(path).context("Failed to read HMAC key")?;
            if bytes.len() != 32 {
                bytes.zeroize();
                anyhow::bail!("HMAC key must be 32 bytes, got {}", bytes.len());
            }
            let mut key = [0u8; 32]; // CodeQL: hard-coded-cryptographic-value — zero-initialized buffer, immediately overwritten from file.
            key.copy_from_slice(&bytes);
            bytes.zeroize();
            key
        } else {
            let mut key = [0u8; 32]; // CodeQL: hard-coded-cryptographic-value — zero-initialized buffer, immediately overwritten with CSPRNG output.
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
            std::fs::write(path, key).context("Failed to save HMAC key")?;
            set_key_permissions(path)?;
            tracing::info!("Generated new HMAC-SHA256 key at {}", path.display());
            key
        };
        Ok(Self { key })
    }
}

impl AuditSigner for HmacSha256Signer {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("invariant: self.key is [u8; 32], always valid for HMAC-SHA256");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn algorithm(&self) -> &'static str {
        "hmac-sha256"
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("invariant: self.key is [u8; 32], always valid for HMAC-SHA256");
        mac.update(data);
        mac.verify_slice(signature).is_ok()
    }
}

// ── Helpers ──

/// Sets owner-only permissions on a key file (cross-platform).
fn set_key_permissions(path: &Path) -> Result<()> {
    crate::auth::token_store::set_owner_only_permissions(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_sign_verify() {
        let signer = EcdsaP256Signer::load_or_generate(None).unwrap();
        let data = b"test audit hash";
        let sig = signer.sign(data);
        assert_eq!(sig.len(), 64);
        assert!(signer.verify(data, &sig));
        assert!(!signer.verify(b"tampered", &sig));
    }

    #[test]
    fn ed25519_sign_verify() {
        let signer = Ed25519Signer::load_or_generate(None).unwrap();
        let data = b"test audit hash";
        let sig = signer.sign(data);
        assert_eq!(sig.len(), 64);
        assert!(signer.verify(data, &sig));
        assert!(!signer.verify(b"tampered", &sig));
    }

    #[test]
    fn hmac_sign_verify() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("hmac.key");
        let signer = HmacSha256Signer::load_or_generate(&key_path).unwrap();
        let data = b"test audit hash";
        let sig = signer.sign(data);
        assert_eq!(sig.len(), 32);
        assert!(signer.verify(data, &sig));
        assert!(!signer.verify(b"tampered", &sig));
    }

    #[test]
    fn ecdsa_persist_and_reload() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("ecdsa.key");

        let signer1 = EcdsaP256Signer::load_or_generate(Some(&key_path)).unwrap();
        let data = b"persistent test";
        let sig = signer1.sign(data);

        let signer2 = EcdsaP256Signer::load_or_generate(Some(&key_path)).unwrap();
        assert!(signer2.verify(data, &sig), "reloaded key should verify");
    }

    #[test]
    fn ed25519_persist_and_reload() {
        let dir = tempfile::TempDir::new().unwrap();
        let key_path = dir.path().join("ed25519.key");

        let signer1 = Ed25519Signer::load_or_generate(Some(&key_path)).unwrap();
        let data = b"persistent test";
        let sig = signer1.sign(data);

        let signer2 = Ed25519Signer::load_or_generate(Some(&key_path)).unwrap();
        assert!(signer2.verify(data, &sig), "reloaded key should verify");
    }
}
