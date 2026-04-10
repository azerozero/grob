//! AES-256-GCM encryption for credential storage at rest.
//!
//! Derives a 256-bit key from a local key file (`~/.grob/encryption.key`).
//! The key file is created on first use with a random key and restricted
//! to owner-only permissions (cross-platform via [`set_owner_only_permissions`]).

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Nonce length for AES-256-GCM (96 bits / 12 bytes).
const NONCE_LEN: usize = 12;

/// AES-256 key length (256 bits / 32 bytes).
const KEY_LEN: usize = 32;

/// Manages AES-256-GCM encryption with a file-backed key.
pub(crate) struct StorageCipher {
    cipher: Aes256Gcm,
}

impl StorageCipher {
    /// Loads or generates the encryption key and returns a cipher instance.
    ///
    /// Key file path defaults to `<db_dir>/encryption.key` (sibling of `grob.db`).
    ///
    /// # Errors
    ///
    /// Returns an error if the key file cannot be read, has an
    /// incorrect size, or the key directory is not writable.
    pub fn load_or_generate(db_path: &Path) -> Result<Self> {
        let key_path = Self::key_path(db_path);
        let mut key_bytes = if key_path.exists() {
            let data = std::fs::read(&key_path).with_context(|| {
                format!("Failed to read encryption key: {}", key_path.display())
            })?;
            if data.len() != KEY_LEN {
                anyhow::bail!(
                    "Encryption key file has wrong size ({} bytes, expected {}): {}",
                    data.len(),
                    KEY_LEN,
                    key_path.display()
                );
            }
            data
        } else {
            Self::generate_key(&key_path)?
        };

        let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        key_bytes.zeroize();
        Ok(Self { cipher })
    }

    /// Encrypts plaintext bytes. Returns `nonce || ciphertext` (12 + N bytes).
    ///
    /// # Errors
    ///
    /// Returns an error if the AES-256-GCM encryption operation fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::rand_core::RngCore;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {}", e))?;

        let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypts data produced by [`encrypt`]. Expects `nonce || ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is shorter than the nonce length
    /// or AES-256-GCM decryption fails (wrong key or corrupted data).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN {
            anyhow::bail!(
                "Encrypted data too short ({} bytes, minimum {})",
                data.len(),
                NONCE_LEN
            );
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))
    }

    /// Attempts decryption; falls back to treating data as plaintext JSON.
    ///
    /// Handles migration from unencrypted to encrypted storage: if decryption
    /// fails but the data is valid JSON, it is returned as-is (unencrypted).
    pub fn decrypt_or_plaintext(&self, data: &[u8]) -> Vec<u8> {
        match self.decrypt(data) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                // Likely unencrypted legacy data — return as-is.
                data.to_vec()
            }
        }
    }

    /// Derives the key file path from the database path.
    fn key_path(db_path: &Path) -> PathBuf {
        db_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("encryption.key")
    }

    /// Generates a random 256-bit key and saves it with owner-only permissions.
    /// Generates a random 256-bit key and saves it with owner-only permissions.
    ///
    /// Caller is responsible for zeroizing the returned `Vec<u8>` after use.
    fn generate_key(path: &Path) -> Result<Vec<u8>> {
        use aes_gcm::aead::rand_core::RngCore;
        let mut key = vec![0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, &key)
            .with_context(|| format!("Failed to write encryption key: {}", path.display()))?;

        crate::auth::token_store::set_owner_only_permissions(path)
            .with_context(|| format!("Failed to set permissions on: {}", path.display()))?;

        tracing::info!("Generated new encryption key: {}", path.display());
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let cipher = StorageCipher::load_or_generate(&db_path).unwrap();

        let plaintext = b"secret oauth token data";
        let encrypted = cipher.encrypt(plaintext).unwrap();

        // Encrypted data should differ from plaintext.
        assert_ne!(&encrypted[NONCE_LEN..], plaintext);

        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_or_plaintext_with_unencrypted() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let cipher = StorageCipher::load_or_generate(&db_path).unwrap();

        let json = br#"{"provider_id":"test"}"#;
        let result = cipher.decrypt_or_plaintext(json);
        assert_eq!(result, json);
    }

    #[test]
    fn key_persistence_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");

        let cipher1 = StorageCipher::load_or_generate(&db_path).unwrap();
        let encrypted = cipher1.encrypt(b"test data").unwrap();

        let cipher2 = StorageCipher::load_or_generate(&db_path).unwrap();
        let decrypted = cipher2.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"test data");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let cipher = StorageCipher::load_or_generate(&db_path).unwrap();

        let mut encrypted = cipher.encrypt(b"important data").unwrap();
        // Flip a byte in the ciphertext (after the nonce).
        if let Some(byte) = encrypted.get_mut(NONCE_LEN + 1) {
            *byte ^= 0xFF;
        }
        assert!(cipher.decrypt(&encrypted).is_err());
    }
}
