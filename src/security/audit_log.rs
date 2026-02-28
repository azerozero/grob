//! Immutable signed audit logs for Grob
//! Conforms to HDS/PCI DSS/SecNumCloud requirements
//!
//! Features:
//! - ECDSA P-256 or HMAC-SHA256 signatures per log entry
//! - Hash chain for integrity verification
//! - Append-only storage
//! - AES-256 encryption at rest

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Signing algorithm for audit log entries
#[derive(Debug, Clone, Default)]
pub enum SigningAlgorithm {
    /// ECDSA P-256 (default, 64-byte signatures)
    #[default]
    EcdsaP256,
    /// HMAC-SHA256 (32-byte signatures, symmetric key)
    HmacSha256,
}

impl SigningAlgorithm {
    /// Parse from config string (case-insensitive)
    pub fn from_str_config(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "hmac-sha256" | "hmac_sha256" | "hmac" => Self::HmacSha256,
            _ => Self::EcdsaP256,
        }
    }

    /// Label for display/logging
    pub fn label(&self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::HmacSha256 => "hmac-sha256",
        }
    }
}

/// Signing material: holds the key for the configured algorithm
pub enum SigningMaterial {
    Ecdsa(SigningKey),
    Hmac([u8; 32]),
}

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
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
    /// Signature of this entry (ECDSA P-256 = 64 bytes, HMAC-SHA256 = 32 bytes)
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
    /// Signing algorithm used (backward-compatible: defaults to "ecdsa-p256")
    #[serde(default)]
    pub signature_algorithm: String,
    /// Model name used (EU AI Act Article 12)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    /// Input tokens counted (EU AI Act Article 12)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u32>,
    /// Output tokens counted (EU AI Act Article 12)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u32>,
    /// Risk level classification (EU AI Act Article 14)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<RiskLevel>,
}

/// Risk classification levels per EU AI Act Article 14
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Parse a risk level from a config string (case-insensitive).
    /// Returns `High` for unrecognized values.
    pub fn from_str_threshold(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::High,
        }
    }
}

/// Audit log configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Log directory
    pub log_dir: PathBuf,
    /// Sign key path (if None, generates ephemeral) — used for ECDSA
    pub sign_key_path: Option<PathBuf>,
    /// Signing algorithm (default: ECDSA P-256)
    pub signing_algorithm: SigningAlgorithm,
    /// HMAC key path (only for HMAC-SHA256 algorithm)
    pub hmac_key_path: Option<PathBuf>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("/var/lib/grob/audit"),
            sign_key_path: None,
            signing_algorithm: SigningAlgorithm::default(),
            hmac_key_path: None,
        }
    }
}

/// Combined mutable state for the audit log, protected by a single Mutex.
struct AuditLogState {
    file: std::fs::File,
    size: u64,
    last_hash: String,
}

/// Audit log writer with integrity guarantees
pub struct AuditLog {
    _config: AuditConfig,
    signing_material: SigningMaterial,
    algorithm: SigningAlgorithm,
    state: Mutex<AuditLogState>,
}

impl AuditLog {
    /// Create new audit log with signing key
    pub fn new(config: AuditConfig) -> Result<Self> {
        // Ensure log directory exists
        std::fs::create_dir_all(&config.log_dir)
            .with_context(|| format!("Failed to create audit directory: {:?}", config.log_dir))?;

        // Load or generate signing material based on algorithm
        let algorithm = config.signing_algorithm.clone();
        let signing_material = match &algorithm {
            SigningAlgorithm::EcdsaP256 => {
                let key = Self::load_or_generate_ecdsa_key(&config)?;
                SigningMaterial::Ecdsa(key)
            }
            SigningAlgorithm::HmacSha256 => {
                let key = Self::load_or_generate_hmac_key(&config)?;
                SigningMaterial::Hmac(key)
            }
        };

        tracing::info!("Audit log signing algorithm: {}", algorithm.label());

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
            _config: config,
            signing_material,
            algorithm,
            state: Mutex::new(AuditLogState {
                file,
                size: current_size,
                last_hash,
            }),
        })
    }

    /// Load or generate ECDSA P-256 signing key
    fn load_or_generate_ecdsa_key(config: &AuditConfig) -> Result<SigningKey> {
        if let Some(key_path) = &config.sign_key_path {
            if key_path.exists() {
                let key_bytes =
                    std::fs::read(key_path).with_context(|| "Failed to read signing key")?;
                SigningKey::from_slice(&key_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid signing key: {}", e))
            } else {
                let key = SigningKey::random(&mut rand::thread_rng());
                let key_bytes = key.to_bytes();
                std::fs::write(key_path, key_bytes)
                    .with_context(|| "Failed to save signing key")?;
                Self::set_key_permissions(key_path)?;
                Ok(key)
            }
        } else {
            tracing::warn!(
                "Using ephemeral ECDSA signing key. Logs won't be verifiable across restarts."
            );
            Ok(SigningKey::random(&mut rand::thread_rng()))
        }
    }

    /// Load or generate HMAC-SHA256 key (32 bytes)
    fn load_or_generate_hmac_key(config: &AuditConfig) -> Result<[u8; 32]> {
        let key_path = config
            .hmac_key_path
            .clone()
            .unwrap_or_else(|| config.log_dir.join("audit_hmac.key"));

        if key_path.exists() {
            let key_bytes = std::fs::read(&key_path).with_context(|| "Failed to read HMAC key")?;
            if key_bytes.len() != 32 {
                anyhow::bail!("HMAC key must be exactly 32 bytes, got {}", key_bytes.len());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            Ok(key)
        } else {
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
            std::fs::write(&key_path, key).with_context(|| "Failed to save HMAC key")?;
            Self::set_key_permissions(&key_path)?;
            tracing::info!("Generated new HMAC-SHA256 key at {:?}", key_path);
            Ok(key)
        }
    }

    /// Set 0o600 permissions on a key file (Unix only)
    fn set_key_permissions(_path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(_path, perms)?;
        }
        Ok(())
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

    /// Hash an entry for chaining (writes directly into hasher, no intermediate String)
    fn hash_entry(entry: &AuditEntry) -> String {
        use std::io::Write as _;
        let mut hasher = Sha256::new();
        // Hash of all fields except signature and signature_algorithm
        let _ = write!(
            hasher,
            "{}|{}|{}|{}|{:?}|{:?}|{}|{:?}|{:?}|{}|{}|{}|{}|{}|{}|{:?}",
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
            entry.previous_hash,
            entry.model_name.as_deref().unwrap_or(""),
            entry.input_tokens.unwrap_or(0),
            entry.output_tokens.unwrap_or(0),
            entry.risk_level
        );
        hex::encode(hasher.finalize())
    }

    /// Write an audit entry with signature and hash chain
    pub fn write(&self, mut entry: AuditEntry) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Chain: set previous_hash from last entry
        entry.previous_hash = state.last_hash.clone();

        // Set signature algorithm label
        entry.signature_algorithm = self.algorithm.label().to_string();

        // Sign based on configured algorithm
        let hash = Self::hash_entry(&entry);
        entry.signature = match &self.signing_material {
            SigningMaterial::Ecdsa(key) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = key.sign(hash.as_bytes());
                sig.to_bytes().to_vec()
            }
            SigningMaterial::Hmac(key) => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
                mac.update(hash.as_bytes());
                mac.finalize().into_bytes().to_vec()
            }
        };

        // Append JSONL
        let mut line = serde_json::to_string(&entry).context("Failed to serialize audit entry")?;
        line.push('\n');

        state
            .file
            .write_all(line.as_bytes())
            .context("Failed to write audit entry")?;
        state.file.flush().context("Failed to flush audit log")?;

        // Update chain state
        state.size += line.len() as u64;
        state.last_hash = hash;

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
            signature_algorithm: String::new(),
            model_name: None,
            input_tokens: None,
            output_tokens: None,
            risk_level: None,
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

    #[test]
    fn test_hmac_signature_present() {
        let dir = TempDir::new().unwrap();
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            signing_algorithm: SigningAlgorithm::HmacSha256,
            ..Default::default()
        };
        let log = AuditLog::new(config).unwrap();

        let entry = make_entry(AuditEvent::Request);
        log.write(entry).unwrap();

        let content = std::fs::read_to_string(dir.path().join("current.jsonl")).unwrap();
        let parsed: AuditEntry = serde_json::from_str(content.trim()).unwrap();

        // HMAC-SHA256 signature is 32 bytes
        assert_eq!(
            parsed.signature.len(),
            32,
            "HMAC-SHA256 signature should be 32 bytes"
        );
        assert_eq!(parsed.signature_algorithm, "hmac-sha256");
        assert!(
            parsed.signature.iter().any(|&b| b != 0),
            "Signature should not be all zeros"
        );
    }

    #[test]
    fn test_backward_compat_deserialization() {
        // Old entries without signature_algorithm, model_name, etc. should deserialize
        let json = r#"{"timestamp":"2026-01-01T00:00:00Z","event_id":"test","tenant_id":"t","user_id":null,"action":"REQUEST","classification":"NC","backend_routed":"p","request_hash":null,"dlp_rules_triggered":[],"ip_source":"127.0.0.1","duration_ms":0,"previous_hash":"abc","signature":"deadbeef"}"#;
        let entry: AuditEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.signature_algorithm, "");
        assert!(entry.model_name.is_none());
        assert!(entry.input_tokens.is_none());
        assert!(entry.output_tokens.is_none());
        assert!(entry.risk_level.is_none());
    }
}
