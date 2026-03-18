//! Virtual API key management for multi-tenant access control.
//!
//! Generates `grob_`-prefixed keys, stores SHA-256 hashes, and provides
//! per-key budget, rate-limit, and model-allowlist enforcement.

use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Persistent record stored in the database for each virtual key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualKeyRecord {
    /// Unique identifier for this key.
    pub id: Uuid,
    /// Human-readable name (e.g. "ci-pipeline", "dev-team-alpha").
    pub name: String,
    /// First 12 characters of the full key (for display / lookup).
    pub prefix: String,
    /// SHA-256 hex digest of the full key (used for authentication).
    pub key_hash: String,
    /// Tenant identifier this key belongs to.
    pub tenant_id: String,
    /// Optional per-key monthly budget in USD.
    pub budget_usd: Option<f64>,
    /// Optional per-key rate limit in requests per second.
    pub rate_limit_rps: Option<u32>,
    /// Optional allowlist of model names this key may access.
    pub allowed_models: Option<Vec<String>>,
    /// Timestamp when the key was created.
    pub created_at: DateTime<Utc>,
    /// Optional expiration timestamp.
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the key has been revoked.
    pub revoked: bool,
    /// Timestamp of the most recent request authenticated with this key.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Lightweight context attached to request extensions after authentication.
#[derive(Debug, Clone)]
pub struct VirtualKeyContext {
    /// Key record identifier.
    pub key_id: Uuid,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Human-readable key name.
    pub name: String,
    /// Per-key monthly budget in USD (if set).
    pub budget_usd: Option<f64>,
    /// Per-key rate limit in requests per second (if set).
    pub rate_limit_rps: Option<u32>,
    /// Model allowlist (if set).
    pub allowed_models: Option<Vec<String>>,
}

/// Generates a new virtual API key and its SHA-256 hash.
///
/// Returns `(full_key, sha256_hex)`. The full key has format `grob_` followed
/// by 32 random lowercase hex characters (44 chars total).
///
/// # Examples
///
/// ```
/// let (key, hash) = grob::auth::virtual_keys::generate_key();
/// assert!(key.starts_with("grob_"));
/// assert_eq!(key.len(), 37);
/// assert_eq!(hash.len(), 64);
/// ```
pub fn generate_key() -> (String, String) {
    let mut rng = rand::thread_rng();
    let mut hex_bytes = [0u8; 16];
    rng.fill(&mut hex_bytes);
    let hex_part = hex::encode(hex_bytes);
    let full_key = format!("grob_{hex_part}");

    let mut hasher = Sha256::new();
    hasher.update(full_key.as_bytes());
    let hash_hex = format!("{:x}", hasher.finalize());

    (full_key, hash_hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_format() {
        let (key, hash) = generate_key();
        assert!(key.starts_with("grob_"), "key must start with grob_");
        assert_eq!(key.len(), 37, "grob_ (5) + 32 hex chars = 37");
        assert_eq!(hash.len(), 64, "SHA-256 hex digest is 64 chars");
    }

    #[test]
    fn generate_key_uniqueness() {
        let (k1, h1) = generate_key();
        let (k2, h2) = generate_key();
        assert_ne!(k1, k2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn generate_key_hash_matches() {
        let (key, hash) = generate_key();
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let recomputed = format!("{:x}", hasher.finalize());
        assert_eq!(hash, recomputed);
    }

    #[test]
    fn prefix_extraction() {
        let (key, _) = generate_key();
        let prefix = &key[..12];
        assert!(prefix.starts_with("grob_"));
        assert_eq!(prefix.len(), 12);
    }

    #[test]
    fn virtual_key_record_serde_roundtrip() {
        let record = VirtualKeyRecord {
            id: Uuid::new_v4(),
            name: "test-key".to_string(),
            prefix: "grob_abc1234".to_string(),
            key_hash: "a".repeat(64),
            tenant_id: "tenant-1".to_string(),
            budget_usd: Some(10.0),
            rate_limit_rps: Some(100),
            allowed_models: Some(vec!["claude-sonnet".to_string()]),
            created_at: Utc::now(),
            expires_at: None,
            revoked: false,
            last_used_at: None,
        };

        let json = serde_json::to_vec(&record).unwrap();
        let deserialized: VirtualKeyRecord = serde_json::from_slice(&json).unwrap();
        assert_eq!(deserialized.id, record.id);
        assert_eq!(deserialized.name, record.name);
        assert_eq!(deserialized.tenant_id, record.tenant_id);
        assert_eq!(deserialized.budget_usd, record.budget_usd);
    }
}
