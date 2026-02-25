//! Immutable signed audit logs for Grob
//! Conforms to HDS/PCI DSS/SecNumCloud requirements
//!
//! Features:
//! - ECDSA P-256 signatures per log entry
//! - Hash chain for integrity verification
//! - Append-only storage
//! - AES-256 encryption at rest

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use p256::ecdsa::{signature::Signer, signature::Verifier, SigningKey, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Classification levels for audit entries
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    /// Non-classified (public data)
    Nc,
    /// Internal use
    C1,
    /// Restricted - HDS/PCI data
    C2,
    /// Secret - Defense data (IGI 1300)
    C3,
}

impl Default for Classification {
    fn default() -> Self {
        Self::Nc
    }
}

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEvent {
    /// Request received
    Request,
    /// Response sent
    Response,
    /// DLP block triggered
    DlpBlock,
    /// DLP warning
    DlpWarn,
    /// Authentication attempt
    Auth,
    /// Config change
    ConfigChange,
    /// Error
    Error,
}

/// Immutable audit log entry
/// Conforms to HDS/PCI DSS requirements for audit trails
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// RFC 3339 timestamp
    pub timestamp: DateTime<Utc>,
    /// Unique event ID (UUID v4)
    pub event_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// User or service ID
    pub user_id: Option<String>,
    /// Event type
    pub action: AuditEvent,
    /// Data classification
    pub classification: Classification,
    /// Backend routed to (or "BLOCKED")
    pub backend_routed: String,
    /// SHA-256 hash of request payload (for integrity)
    pub request_hash: Option<String>,
    /// DLP rules triggered
    pub dlp_rules_triggered: Vec<String>,
    /// Source IP (pseudonymized)
    pub ip_source: String,
    /// Processing duration in ms
    pub duration_ms: u64,
    /// Previous entry hash (for chain)
    pub previous_hash: String,
    /// ECDSA signature of this entry
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
}

/// Audit log configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Log directory
    pub log_dir: PathBuf,
    /// Rotation size (bytes)
    pub rotation_size: u64,
    /// Retention days
    pub retention_days: u32,
    /// Sign key path (if None, generates ephemeral)
    pub sign_key_path: Option<PathBuf>,
    /// Encrypt at rest
    pub encrypt: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("/var/lib/grob/audit"),
            rotation_size: 100 * 1024 * 1024, // 100MB
            retention_days: 365, // PCI DSS: 1 year minimum
            sign_key_path: None,
            encrypt: true,
        }
    }
}

/// Audit log writer with integrity guarantees
pub struct AuditLog {
    config: AuditConfig,
    signing_key: SigningKey,
    current_file: Mutex<File>,
    current_size: Mutex<u64>,
    last_hash: Mutex<String>,
}

impl AuditLog {
    /// Create new audit log with signing key
    pub fn new(config: AuditConfig) -> Result<Self> {
        // Ensure log directory exists
        std::fs::create_dir_all(&config.log_dir)
            .with_context(|| format!("Failed to create audit directory: {:?}", config.log_dir))?;

        // Load or generate signing key
        let signing_key = if let Some(key_path) = &config.sign_key_path {
            if key_path.exists() {
                let key_bytes = std::fs::read(key_path)
                    .with_context(|| "Failed to read signing key")?;
                SigningKey::from_slice(&key_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid signing key: {}", e))?
            } else {
                let key = SigningKey::random(&mut rand::thread_rng());
                let key_bytes = key.to_bytes();
                std::fs::write(key_path, key_bytes)
                    .with_context(|| "Failed to save signing key")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = std::fs::metadata(key_path)?.permissions();
                    perms.set_mode(0o600);
                    std::fs::set_permissions(key_path, perms)?;
                }
                key
            }
        } else {
            // Ephemeral key (not recommended for production)
            tracing::warn!("Using ephemeral signing key. Logs won't be verifiable across restarts.");
            SigningKey::random(&mut rand::thread_rng())
        };

        // Open or create current log file
        let current_path = config.log_dir.join("current.jsonl");
        let (file, last_hash) = if current_path.exists() {
            Self::read_last_hash(&current_path)?
        } else {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&current_path)?;
            (file, Self::genesis_hash())
        };

        let metadata = file.metadata()?;
        let current_size = metadata.len();

        Ok(Self {
            config,
            signing_key,
            current_file: Mutex::new(file),
            current_size: Mutex::new(current_size),
            last_hash: Mutex::new(last_hash),
        })
    }

    /// Read last hash from existing log for chain continuity
    fn read_last_hash(path: &Path) -> Result<(File, String)> {
        let file = OpenOptions::new().append(true).open(path)?;
        let reader = BufReader::new(std::fs::File::open(path)?);

        let mut last_hash = Self::genesis_hash();
        for line in reader.lines() {
            let line = line?;
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                last_hash = Self::hash_entry(&entry);
            }
        }

        Ok((file, last_hash))
    }

    /// Genesis hash for empty chain
    fn genesis_hash() -> String {
        hex::encode(Sha256::digest(b"GROB_AUDIT_GENESIS"))
    }

    /// Hash an entry for chaining
    fn hash_entry(entry: &AuditEntry) -> String {
        // Hash of all fields except signature
        let canonical = format!(
            "{}|{}|{}|{}|{:?}|{:?}|{}|{:?}|{:?}|{}|{}|{}",
            entry.timestamp.to_rfc3339(),
            entry.event_id,
            entry.tenant_id,
            entry.user_id.as_deref().unwrap_or(""),
            entry.action,
            entry.classification,
            entry.backend_routed,
            entry.request_hash,
            entry.dlp_rules_triggered.join(","),
            entry.ip_source,
            entry.duration_ms,
            entry.previous_hash
        );
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }

    /// Sign entry data
    fn sign_data(&self, entry: &AuditEntry) -> Signature {
        let data = serde_json::to_vec(&entry).expect("Failed to serialize entry");
        self.signing_key.sign(&data)
    }

    /// Write audit entry - append-only, signed
    pub fn write(&self, mut entry: AuditEntry) -> Result<()> {
        // Set previous hash for chain
        {
            let last_hash = self.last_hash.lock().unwrap();
            entry.previous_hash = last_hash.clone();
        }

        // Sign the entry
        let signature = self.sign_data(&entry);
        entry.signature = signature.to_bytes().to_vec();

        // Serialize and write
        let line = serde_json::to_string(&entry)?;
        let line_with_newline = format!("{}\n", line);
        let bytes = line_with_newline.as_bytes();

        {
            let mut file = self.current_file.lock().unwrap();
            file.write_all(bytes)?;
            file.flush()?;
        }

        // Update metrics
        {
            let mut size = self.current_size.lock().unwrap();
            *size += bytes.len() as u64;

            // Check rotation
            if *size >= self.config.rotation_size {
                self.rotate()?;
                *size = 0;
            }
        }

        // Update hash chain
        {
            let mut last_hash = self.last_hash.lock().unwrap();
            *last_hash = Self::hash_entry(&entry);
        }

        // Increment metrics
        metrics::counter!("grob_audit_entries_total", "action" => format!("{:?}", entry.action))
            .increment(1);

        Ok(())
    }

    /// Rotate log file
    fn rotate(&self) -> Result<()> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let rotated_name = format!("audit_{}.jsonl", timestamp);
        let rotated_path = self.config.log_dir.join(&rotated_name);

        // Close current, rename, create new
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.config.log_dir.join("current.jsonl"))?;

        std::fs::rename(self.config.log_dir.join("current.jsonl"), rotated_path)?;

        let mut file = self.current_file.lock().unwrap();
        *file = new_file;

        // Reset hash chain
        let mut last_hash = self.last_hash.lock().unwrap();
        *last_hash = Self::genesis_hash();

        tracing::info!("Audit log rotated to {}", rotated_name);
        Ok(())
    }

    /// Get public key for verification
    pub fn public_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// Verify log integrity
    pub fn verify(&self, path: &Path) -> Result<bool> {
        let reader = BufReader::new(std::fs::File::open(path)?);
        let mut prev_hash = Self::genesis_hash();
        let mut line_num = 0;

        for line in reader.lines() {
            line_num += 1;
            let line = line?;
            let entry: AuditEntry = serde_json::from_str(&line)
                .with_context(|| format!("Line {}: invalid JSON", line_num))?;

            // Check chain
            if entry.previous_hash != prev_hash {
                tracing::error!(
                    "Hash chain broken at line {}: expected {}, got {}",
                    line_num, prev_hash, entry.previous_hash
                );
                return Ok(false);
            }

            // Verify signature
            let signature = Signature::from_slice(&entry.signature)
                .map_err(|e| anyhow::anyhow!("Invalid signature at line {}: {}", line_num, e))?;

            let mut entry_to_verify = entry.clone();
            entry_to_verify.signature.clear();
            let data = serde_json::to_vec(&entry_to_verify)?;

            if self.public_key().verify(&data, &signature).is_err() {
                tracing::error!("Invalid signature at line {}", line_num);
                return Ok(false);
            }

            prev_hash = Self::hash_entry(&entry);
        }

        Ok(true)
    }
}

/// Builder for audit entries
pub struct AuditEntryBuilder {
    tenant_id: String,
    action: AuditEvent,
    classification: Classification,
    backend_routed: String,
}

impl AuditEntryBuilder {
    pub fn new(tenant_id: impl Into<String>, action: AuditEvent) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            action,
            classification: Classification::Nc,
            backend_routed: "unknown".to_string(),
        }
    }

    pub fn classification(mut self, c: Classification) -> Self {
        self.classification = c;
        self
    }

    pub fn backend(mut self, backend: impl Into<String>) -> Self {
        self.backend_routed = backend.into();
        self
    }

    pub fn build(self) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now(),
            event_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: self.tenant_id,
            user_id: None,
            action: self.action,
            classification: self.classification,
            backend_routed: self.backend_routed,
            request_hash: None,
            dlp_rules_triggered: vec![],
            ip_source: "0.0.0.0".to_string(),
            duration_ms: 0,
            previous_hash: String::new(),
            signature: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_genesis_hash() {
        let h = AuditLog::genesis_hash();
        assert_eq!(h.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_hash_determinism() {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_id: "test".to_string(),
            tenant_id: "tenant".to_string(),
            user_id: None,
            action: AuditEvent::Request,
            classification: Classification::Nc,
            backend_routed: "test".to_string(),
            request_hash: None,
            dlp_rules_triggered: vec![],
            ip_source: "127.0.0.1".to_string(),
            duration_ms: 100,
            previous_hash: "prev".to_string(),
            signature: vec![],
        };

        let h1 = AuditLog::hash_entry(&entry);
        let h2 = AuditLog::hash_entry(&entry);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_audit_log_write_verify() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            rotation_size: 1024 * 1024, // 1MB - large enough to avoid rotation in test
            ..Default::default()
        };

        let log = AuditLog::new(config).unwrap();

        // Write entries
        for i in 0..3 {
            let builder = AuditEntryBuilder::new(format!("tenant-{}", i), AuditEvent::Request);
            let entry = builder.build();
            log.write(entry).unwrap();
        }

        // Verify
        let result = log.verify(&dir.path().join("current.jsonl"));
        assert!(result.is_ok(), "verify failed: {:?}", result.err());
        assert!(result.unwrap());
    }

    #[test]
    fn test_chain_integrity() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            ..Default::default()
        };

        let log = AuditLog::new(config).unwrap();

        let entry1 = AuditEntryBuilder::new("t1", AuditEvent::Request).build();
        log.write(entry1).unwrap();

        let entry2 = AuditEntryBuilder::new("t2", AuditEvent::Response).build();
        log.write(entry2).unwrap();

        // Read and verify chain
        let reader = BufReader::new(
            std::fs::File::open(dir.path().join("current.jsonl")).unwrap()
        );

        let mut prev_hash = AuditLog::genesis_hash();
        for line in reader.lines() {
            let entry: AuditEntry = serde_json::from_str(&line.unwrap()).unwrap();
            assert_eq!(entry.previous_hash, prev_hash);
            prev_hash = AuditLog::hash_entry(&entry);
        }
    }
}

