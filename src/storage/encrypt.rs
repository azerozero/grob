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

/// Magic prefix marking a grob-encrypted blob (`b"GRB1"`).
///
/// Legacy blobs (written before this envelope existed) carry no magic and are
/// the bare `nonce || ciphertext` produced by older builds. The magic makes
/// "is this ciphertext or plaintext?" decidable: any blob starting with this
/// prefix is unambiguously encrypted, so a GCM authentication failure on it is
/// tampering or corruption — never a reason to fall back to plaintext.
const MAGIC: &[u8; 4] = b"GRB1";

/// Envelope format version, appended after [`MAGIC`].
const VERSION: u8 = 1;

/// Length of the envelope header (`MAGIC || VERSION`).
const HEADER_LEN: usize = MAGIC.len() + 1;

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

    /// Encrypts plaintext bytes. Returns `MAGIC || VERSION || nonce || ciphertext`.
    ///
    /// The [`MAGIC`] prefix makes the output self-describing so a later read can
    /// tell encrypted blobs apart from legacy plaintext without guessing.
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

        let mut result = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
        result.extend_from_slice(MAGIC);
        result.push(VERSION);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Reports whether a blob carries the grob encryption envelope header.
    ///
    /// A blob that starts with [`MAGIC`] is unambiguously encrypted; the body
    /// must authenticate or be rejected. A blob without it is legacy data
    /// (either a pre-envelope ciphertext or genuine plaintext).
    fn has_envelope(data: &[u8]) -> bool {
        data.len() >= HEADER_LEN && &data[..MAGIC.len()] == MAGIC
    }

    /// Decrypts the AES-256-GCM body `nonce || ciphertext` (no envelope header).
    ///
    /// # Errors
    ///
    /// Returns an error if the body is shorter than the nonce length
    /// or AES-256-GCM decryption fails (wrong key or corrupted data).
    fn decrypt_body(&self, body: &[u8]) -> Result<Vec<u8>> {
        if body.len() < NONCE_LEN {
            anyhow::bail!(
                "Encrypted data too short ({} bytes, minimum {})",
                body.len(),
                NONCE_LEN
            );
        }

        let (nonce_bytes, ciphertext) = body.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))
    }

    /// Decrypts a blob produced by [`encrypt`].
    ///
    /// Accepts both the current envelope (`MAGIC || VERSION || nonce ||
    /// ciphertext`) and the legacy bare-body form (`nonce || ciphertext`) so
    /// upgrades do not lock anyone out.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is too short, the envelope version is
    /// unsupported, or AES-256-GCM decryption fails (wrong key, tampering, or
    /// corruption).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if Self::has_envelope(data) {
            let version = data[MAGIC.len()];
            if version != VERSION {
                anyhow::bail!("Unsupported encryption envelope version: {}", version);
            }
            self.decrypt_body(&data[HEADER_LEN..])
        } else {
            self.decrypt_body(data)
        }
    }

    /// Decrypts a credential blob, tolerating only genuine legacy plaintext.
    ///
    /// This is the credential-read path (OAuth tokens, secrets, virtual keys).
    /// It fails closed: an enveloped blob (carrying [`MAGIC`]) that fails
    /// authentication is treated as tampering or corruption and surfaces an
    /// error — it is never reinterpreted as plaintext. Only a blob with no
    /// envelope and no decryptable legacy body is accepted as legacy plaintext,
    /// and that fallback always logs a `warn!` so the silent fail-open is gone.
    ///
    /// # Errors
    ///
    /// Returns an error when an enveloped blob fails to decrypt, i.e. when data
    /// that should be authentic ciphertext does not authenticate.
    pub fn decrypt_or_plaintext(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Enveloped blobs are unambiguously ciphertext: authenticate or reject.
        // Falling back to plaintext here would be a fail-open on credentials.
        if Self::has_envelope(data) {
            return self.decrypt(data).context(
                "encrypted credential blob failed authentication (tampered or corrupted); \
                 refusing to fall back to plaintext",
            );
        }

        // No envelope: either a pre-envelope ciphertext or genuine legacy
        // plaintext. A successful legacy decrypt proves it was ciphertext.
        if let Ok(plaintext) = self.decrypt_body(data) {
            return Ok(plaintext);
        }

        // Genuine legacy plaintext (or undecryptable non-enveloped bytes). We
        // accept it for backward compatibility but never silently: emit a
        // warning so operators can migrate it by re-saving. No secret material
        // is logged — only the size.
        tracing::warn!(
            bytes = data.len(),
            "reading credential as unencrypted legacy plaintext (no encryption envelope); \
             re-save it to migrate to AES-256-GCM at rest"
        );
        Ok(data.to_vec())
    }

    /// Derives the key file path from the database path.
    fn key_path(db_path: &Path) -> PathBuf {
        db_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("encryption.key")
    }

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

    fn test_cipher() -> (tempfile::TempDir, StorageCipher) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("grob.db");
        let cipher = StorageCipher::load_or_generate(&db_path).unwrap();
        (dir, cipher)
    }

    /// Builds a legacy (pre-envelope) ciphertext: bare `nonce || ciphertext`.
    fn legacy_encrypt(cipher: &StorageCipher, plaintext: &[u8]) -> Vec<u8> {
        let enveloped = cipher.encrypt(plaintext).unwrap();
        assert!(StorageCipher::has_envelope(&enveloped));
        enveloped[HEADER_LEN..].to_vec()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (_dir, cipher) = test_cipher();

        let plaintext = b"secret oauth token data";
        let encrypted = cipher.encrypt(plaintext).unwrap();

        // Output carries the self-describing envelope header.
        assert!(StorageCipher::has_envelope(&encrypted));
        assert_eq!(&encrypted[..MAGIC.len()], MAGIC);
        assert_eq!(encrypted[MAGIC.len()], VERSION);
        // Ciphertext body must differ from plaintext.
        assert_ne!(&encrypted[HEADER_LEN + NONCE_LEN..], plaintext);

        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// (a) A valid enveloped ciphertext round-trips through the credential path.
    #[test]
    fn decrypt_or_plaintext_roundtrips_valid_ciphertext() {
        let (_dir, cipher) = test_cipher();

        let secret = br#"{"provider_id":"anthropic","token":"sk-xxx"}"#;
        let encrypted = cipher.encrypt(secret).unwrap();
        let out = cipher.decrypt_or_plaintext(&encrypted).unwrap();
        assert_eq!(out, secret);
    }

    /// (b) Genuine legacy plaintext (no envelope, not decryptable) still reads.
    #[test]
    fn decrypt_or_plaintext_reads_genuine_legacy_plaintext() {
        let (_dir, cipher) = test_cipher();

        let json = br#"{"provider_id":"test"}"#;
        // Sanity: this does not accidentally look like our envelope.
        assert!(!StorageCipher::has_envelope(json));
        let result = cipher.decrypt_or_plaintext(json).unwrap();
        assert_eq!(result, json);
    }

    /// Backward compatibility: a pre-envelope ciphertext still decrypts.
    #[test]
    fn decrypt_or_plaintext_reads_legacy_ciphertext() {
        let (_dir, cipher) = test_cipher();

        let secret = b"legacy encrypted secret";
        let legacy = legacy_encrypt(&cipher, secret);
        assert!(!StorageCipher::has_envelope(&legacy));
        let out = cipher.decrypt_or_plaintext(&legacy).unwrap();
        assert_eq!(out, secret);
    }

    /// (c) A tampered enveloped ciphertext fails closed — no raw-byte fallback.
    #[test]
    fn decrypt_or_plaintext_tampered_envelope_fails_closed() {
        let (_dir, cipher) = test_cipher();

        let mut encrypted = cipher.encrypt(b"important credential").unwrap();
        // Flip a byte inside the ciphertext body (after header + nonce).
        let idx = HEADER_LEN + NONCE_LEN + 1;
        encrypted[idx] ^= 0xFF;

        let result = cipher.decrypt_or_plaintext(&encrypted);
        assert!(
            result.is_err(),
            "tampered enveloped ciphertext must not fall back to plaintext"
        );
    }

    /// A truncated enveloped blob (looks encrypted, body invalid) fails closed.
    #[test]
    fn decrypt_or_plaintext_truncated_envelope_fails_closed() {
        let (_dir, cipher) = test_cipher();

        let mut encrypted = cipher.encrypt(b"important credential").unwrap();
        // Drop the authentication tag and part of the ciphertext.
        encrypted.truncate(HEADER_LEN + NONCE_LEN + 1);
        assert!(StorageCipher::has_envelope(&encrypted));

        let result = cipher.decrypt_or_plaintext(&encrypted);
        assert!(
            result.is_err(),
            "truncated enveloped ciphertext must fail closed"
        );
    }

    /// An unsupported envelope version is rejected rather than mis-parsed.
    #[test]
    fn decrypt_rejects_unknown_version() {
        let (_dir, cipher) = test_cipher();

        let mut encrypted = cipher.encrypt(b"data").unwrap();
        encrypted[MAGIC.len()] = VERSION.wrapping_add(1);
        assert!(cipher.decrypt(&encrypted).is_err());
        assert!(cipher.decrypt_or_plaintext(&encrypted).is_err());
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
        let (_dir, cipher) = test_cipher();

        let mut encrypted = cipher.encrypt(b"important data").unwrap();
        // Flip a byte in the ciphertext body (after header + nonce).
        let idx = HEADER_LEN + NONCE_LEN + 1;
        if let Some(byte) = encrypted.get_mut(idx) {
            *byte ^= 0xFF;
        }
        assert!(cipher.decrypt(&encrypted).is_err());
    }
}
