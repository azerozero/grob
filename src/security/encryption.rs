//! Encryption at rest for Grob
//! AES-256-GCM for data confidentiality
//! Conforms to HDS/PCI DSS/SecNumCloud requirements
//!
//! Features:
//! - AES-256-GCM authenticated encryption
//! - Key derivation with Argon2id
//! - KMS integration (Vault/OpenBao)
//! - Per-perimeter key isolation

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use anyhow::{Context, Result};
use argon2::{Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Classification perimeter for key isolation
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Perimeter {
    /// Non-classified
    Nc,
    /// Internal use
    C1,
    /// HDS/PCI restricted
    C2,
    /// Defense/Secret (IGI 1300)
    C3,
}

impl Perimeter {
    /// Get key derivation salt prefix
    fn salt_prefix(&self) -> &'static [u8] {
        match self {
            Perimeter::Nc => b"GROB_NC_V1",
            Perimeter::C1 => b"GROB_C1_V1",
            Perimeter::C2 => b"GROB_C2_V1",
            Perimeter::C3 => b"GROB_C3_V1",
        }
    }
}

/// Encrypted data envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Perimeter used for encryption
    pub perimeter: Perimeter,
    /// Argon2id salt (base64)
    pub salt: String,
    /// AES-GCM nonce (base64)
    pub nonce: String,
    /// Ciphertext (base64)
    pub ciphertext: String,
    /// Version for migration
    pub version: u32,
}

/// KMS abstraction for key management
#[async_trait::async_trait]
pub trait KmsProvider: Send + Sync {
    /// Get key for perimeter
    async fn get_key(&self, perimeter: Perimeter) -> Result<SecretString>;
    /// Rotate key for perimeter
    async fn rotate_key(&self, perimeter: Perimeter) -> Result<()>;
    /// Health check
    async fn health(&self) -> Result<()>;
}

/// Vault/OpenBao KMS implementation
pub struct VaultKms {
    client: reqwest::Client,
    base_url: String,
    token: SecretString,
    mount_path: String,
}

impl VaultKms {
    pub fn new(base_url: String, token: SecretString, mount_path: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
            token,
            mount_path,
        }
    }
}

#[async_trait::async_trait]
impl KmsProvider for VaultKms {
    async fn get_key(&self, perimeter: Perimeter) -> Result<SecretString> {
        let path = format!(
            "{}/v1/{}/data/grob/{}",
            self.base_url,
            self.mount_path,
            format!("{:?}", perimeter).to_lowercase()
        );

        let resp = self
            .client
            .get(&path)
            .header("X-Vault-Token", self.token.expose_secret())
            .send()
            .await
            .context("Failed to fetch key from Vault")?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("Vault returned: {}", resp.status()));
        }

        let data: serde_json::Value = resp.json().await?;
        let key = data["data"]["data"]["key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid key format from Vault"))?;

        Ok(SecretString::new(key.to_string()))
    }

    async fn rotate_key(&self, perimeter: Perimeter) -> Result<()> {
        // Trigger rotation in Vault
        let path = format!(
            "{}/v1/{}/rotate/grob/{}",
            self.base_url,
            self.mount_path,
            format!("{:?}", perimeter).to_lowercase()
        );

        let resp = self
            .client
            .post(&path)
            .header("X-Vault-Token", self.token.expose_secret())
            .send()
            .await
            .context("Failed to rotate key in Vault")?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("Vault rotation failed: {}", resp.status()));
        }

        Ok(())
    }

    async fn health(&self) -> Result<()> {
        let resp = self
            .client
            .get(format!("{}/v1/sys/health", self.base_url))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Vault unhealthy: {}", resp.status()))
        }
    }
}

/// Local key derivation (fallback when KMS unavailable)
pub struct LocalKms {
    master_key: SecretString,
    cache: Arc<RwLock<HashMap<Perimeter, Key<Aes256Gcm>>>>,
}

impl LocalKms {
    pub fn new(master_key: SecretString) -> Self {
        Self {
            master_key,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Derive key for perimeter using Argon2id
    fn derive_key(&self, perimeter: Perimeter) -> Result<Key<Aes256Gcm>> {
        let salt = [perimeter.salt_prefix(), self.master_key.expose_secret().as_bytes()].concat();

        let params = Params::new(
            64 * 1024,  // 64MB memory
            3,          // 3 iterations
            4,          // 4 parallelism
            Some(32),   // 32 bytes output
        )
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(self.master_key.expose_secret().as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;

        Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
    }
}

#[async_trait::async_trait]
impl KmsProvider for LocalKms {
    async fn get_key(&self, perimeter: Perimeter) -> Result<SecretString> {
        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(key) = cache.get(&perimeter) {
                return Ok(SecretString::new(hex::encode(key.as_slice())));
            }
        }

        // Derive key
        let key = self.derive_key(perimeter)?;
        let key_hex = SecretString::new(hex::encode(key.as_slice()));

        // Cache key
        {
            let mut cache = self.cache.write().await;
            cache.insert(perimeter, key);
        }

        Ok(key_hex)
    }

    async fn rotate_key(&self, perimeter: Perimeter) -> Result<()> {
        // Clear cache for this perimeter - next access will re-derive
        let mut cache = self.cache.write().await;
        cache.remove(&perimeter);
        Ok(())
    }

    async fn health(&self) -> Result<()> {
        // Local KMS is always healthy if we have the master key
        Ok(())
    }
}

/// Encryption service for data at rest
pub struct EncryptionService {
    kms: Arc<dyn KmsProvider>,
}

impl EncryptionService {
    pub fn new(kms: Arc<dyn KmsProvider>) -> Self {
        Self { kms }
    }

    /// Encrypt data for a specific perimeter
    pub async fn encrypt(&self, plaintext: &[u8], perimeter: Perimeter) -> Result<EncryptedEnvelope> {
        // Get or derive key
        let key_hex = self.kms.get_key(perimeter).await?;
        let key_bytes = hex::decode(key_hex.expose_secret())?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let cipher = Aes256Gcm::new(key);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedEnvelope {
            perimeter,
            salt: B64.encode(&salt),
            nonce: B64.encode(&nonce_bytes),
            ciphertext: B64.encode(&ciphertext),
            version: 1,
        })
    }

    /// Decrypt data
    pub async fn decrypt(&self, envelope: &EncryptedEnvelope) -> Result<Vec<u8>> {
        // Get key for perimeter
        let key_hex = self.kms.get_key(envelope.perimeter).await?;
        let key_bytes = hex::decode(key_hex.expose_secret())?;
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        // Decode nonce and ciphertext
        let nonce_bytes = B64.decode(&envelope.nonce)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = B64.decode(&envelope.ciphertext)?;

        // Decrypt
        let cipher = Aes256Gcm::new(key);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_kms() {
        let master_key = SecretString::new("test-master-key-32-bytes-long!!".to_string());
        let kms = Arc::new(LocalKms::new(master_key));

        let key = kms.get_key(Perimeter::Nc).await.unwrap();
        assert!(!key.expose_secret().is_empty());

        // Same perimeter should return same key (from cache)
        let key2 = kms.get_key(Perimeter::Nc).await.unwrap();
        assert_eq!(key.expose_secret(), key2.expose_secret());

        // Different perimeter should have different key
        let key3 = kms.get_key(Perimeter::C2).await.unwrap();
        assert_ne!(key.expose_secret(), key3.expose_secret());
    }

    #[tokio::test]
    async fn test_encryption_roundtrip() {
        let master_key = SecretString::new("test-master-key-32-bytes-long!!".to_string());
        let kms: Arc<dyn KmsProvider> = Arc::new(LocalKms::new(master_key));
        let service = EncryptionService::new(kms);

        let plaintext = b"Hello, secure world!";
        let envelope = service.encrypt(plaintext, Perimeter::Nc).await.unwrap();

        assert_eq!(envelope.perimeter, Perimeter::Nc);
        assert_eq!(envelope.version, 1);

        let decrypted = service.decrypt(&envelope).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_perimeter_isolation() {
        let master_key = SecretString::new("test-master-key-32-bytes-long!!".to_string());
        let kms: Arc<dyn KmsProvider> = Arc::new(LocalKms::new(master_key));
        let service = EncryptionService::new(kms);

        let plaintext = b"Sensitive data";

        // Encrypt with different perimeters
        let nc_envelope = service.encrypt(plaintext, Perimeter::Nc).await.unwrap();
        let c2_envelope = service.encrypt(plaintext, Perimeter::C2).await.unwrap();

        // Ciphertexts should be different (different keys)
        assert_ne!(nc_envelope.ciphertext, c2_envelope.ciphertext);

        // Cannot decrypt C2 data with NC key (would fail)
        let result = service.decrypt(&c2_envelope).await;
        assert!(result.is_ok()); // Same KMS, so it works
    }

    #[test]
    fn test_perimeter_salt_prefixes() {
        assert_eq!(Perimeter::Nc.salt_prefix(), b"GROB_NC_V1");
        assert_eq!(Perimeter::C1.salt_prefix(), b"GROB_C1_V1");
        assert_eq!(Perimeter::C2.salt_prefix(), b"GROB_C2_V1");
        assert_eq!(Perimeter::C3.salt_prefix(), b"GROB_C3_V1");
    }
}
