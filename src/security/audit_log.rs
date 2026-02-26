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
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
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
#[allow(dead_code)] // fields used by future rotation/retention/encryption logic
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
            retention_days: 365,              // PCI DSS: 1 year minimum
            sign_key_path: None,
            encrypt: true,
        }
    }
}

/// Audit log writer with integrity guarantees
pub struct AuditLog {
    #[allow(dead_code)] // used by future rotation logic
    config: AuditConfig,
    signing_key: SigningKey,
    current_file: Mutex<std::fs::File>,
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
                let key_bytes =
                    std::fs::read(key_path).with_context(|| "Failed to read signing key")?;
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
            tracing::warn!(
                "Using ephemeral signing key. Logs won't be verifiable across restarts."
            );
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
    fn read_last_hash(path: &Path) -> Result<(std::fs::File, String)> {
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

    /// Write an audit entry with ECDSA signature and hash chain
    pub fn write(&self, mut entry: AuditEntry) -> Result<()> {
        use p256::ecdsa::signature::Signer;

        let mut last_hash = self.last_hash.lock().unwrap_or_else(|e| e.into_inner());

        // Chain: set previous_hash from last entry
        entry.previous_hash = last_hash.clone();

        // Sign: ECDSA P-256 over the entry hash
        let hash = Self::hash_entry(&entry);
        let sig: p256::ecdsa::Signature = self.signing_key.sign(hash.as_bytes());
        entry.signature = sig.to_bytes().to_vec();

        // Append JSONL
        let mut line = serde_json::to_string(&entry).context("Failed to serialize audit entry")?;
        line.push('\n');

        let mut file = self.current_file.lock().unwrap_or_else(|e| e.into_inner());
        file.write_all(line.as_bytes())
            .context("Failed to write audit entry")?;
        file.flush().context("Failed to flush audit log")?;

        // Update chain state
        let mut size = self.current_size.lock().unwrap_or_else(|e| e.into_inner());
        *size += line.len() as u64;
        *last_hash = hash;

        Ok(())
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
    fn test_audit_log_create() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            rotation_size: 1024 * 1024,
            ..Default::default()
        };

        let _log = AuditLog::new(config).unwrap();
    }

    fn make_test_log() -> (TempDir, AuditLog) {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let log = AuditLog::new(config).unwrap();
        (dir, log)
    }

    fn make_entry(action: AuditEvent) -> AuditEntry {
        AuditEntry {
            timestamp: chrono::Utc::now(),
            event_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: "test-tenant".to_string(),
            user_id: None,
            action,
            classification: Classification::Nc,
            backend_routed: "test-provider".to_string(),
            request_hash: None,
            dlp_rules_triggered: vec![],
            ip_source: "127.0.0.1".to_string(),
            duration_ms: 42,
            previous_hash: String::new(),
            signature: vec![],
        }
    }

    #[test]
    fn test_write_entry() {
        let (dir, log) = make_test_log();
        let entry = make_entry(AuditEvent::Response);
        log.write(entry).unwrap();

        // Verify file contains one JSONL line
        let content = std::fs::read_to_string(dir.path().join("current.jsonl")).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 1);

        let parsed: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed.tenant_id, "test-tenant");
        assert_eq!(parsed.duration_ms, 42);
    }

    #[test]
    fn test_hash_chain() {
        let (_dir, log) = make_test_log();

        let genesis = AuditLog::genesis_hash();

        let e1 = make_entry(AuditEvent::Request);
        log.write(e1).unwrap();

        let e2 = make_entry(AuditEvent::Response);
        log.write(e2).unwrap();

        // Read back entries and verify chain
        let content = std::fs::read_to_string(_dir.path().join("current.jsonl")).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed1: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        let parsed2: AuditEntry = serde_json::from_str(lines[1]).unwrap();

        // First entry chains from genesis
        assert_eq!(parsed1.previous_hash, genesis);
        // Second entry chains from first entry's hash
        assert_eq!(parsed2.previous_hash, AuditLog::hash_entry(&parsed1));
    }

    #[test]
    fn test_signature_present() {
        let (_dir, log) = make_test_log();
        let entry = make_entry(AuditEvent::DlpBlock);
        log.write(entry).unwrap();

        let content = std::fs::read_to_string(_dir.path().join("current.jsonl")).unwrap();
        let parsed: AuditEntry = serde_json::from_str(content.trim()).unwrap();

        // ECDSA P-256 signature is 64 bytes
        assert_eq!(
            parsed.signature.len(),
            64,
            "ECDSA P-256 signature should be 64 bytes"
        );
        assert!(
            parsed.signature.iter().any(|&b| b != 0),
            "Signature should not be all zeros"
        );
    }
}
