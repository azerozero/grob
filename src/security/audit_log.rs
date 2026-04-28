//! Immutable signed audit logs for Grob.
//!
//! Supports per-entry signing (batch_size=1) and Merkle-tree batch
//! signing (batch_size>1) with configurable algorithm via [`AuditSigner`].
//!
//! Conforms to HDS/PCI DSS/SecNumCloud requirements.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use super::audit_signer::AuditSigner;
use super::merkle::{MerkleTree, ProofStep};

/// Signing algorithm selection for config parsing.
#[derive(Debug, Clone, Default)]
pub enum SigningAlgorithm {
    /// ECDSA P-256 (default, 64-byte signatures).
    #[default]
    EcdsaP256,
    /// Ed25519 (64-byte signatures, faster than P-256).
    Ed25519,
    /// HMAC-SHA256 (32-byte MACs, symmetric key).
    HmacSha256,
}

impl SigningAlgorithm {
    /// Parses from a config string (case-insensitive).
    pub fn from_str_config(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "hmac-sha256" | "hmac_sha256" | "hmac" => Self::HmacSha256,
            "ed25519" => Self::Ed25519,
            _ => Self::EcdsaP256,
        }
    }

    /// Label for display/logging.
    pub fn label(&self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::Ed25519 => "ed25519",
            Self::HmacSha256 => "hmac-sha256",
        }
    }
}

/// Classification levels for audit entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    /// Non-classified (public data).
    Nc,
    /// Internal use.
    C1,
    /// Restricted — HDS/PCI data.
    C2,
    /// Secret — Defense data (IGI 1300).
    C3,
}

/// Audit event types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEvent {
    /// Request received.
    Request,
    /// Response sent.
    Response,
    /// DLP block triggered.
    DlpBlock,
    /// DLP warning.
    DlpWarn,
    /// Authentication attempt.
    Auth,
    /// Config change.
    ConfigChange,
    /// Error.
    Error,
    /// HIT Gateway per-action authorization receipt.
    HitApproval,
    /// TEE attestation report generated at startup.
    TeeAttestation,
    /// Credential rotation (secret atomically replaced).
    CredentialRotated,
}

/// Immutable audit log entry.
///
/// Conforms to HDS/PCI DSS requirements for audit trails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// RFC 3339 timestamp.
    pub timestamp: DateTime<Utc>,
    /// Unique event ID (UUID v4).
    pub event_id: String,
    /// Tenant ID.
    pub tenant_id: String,
    /// User or service ID.
    pub user_id: Option<String>,
    /// Event type.
    pub action: AuditEvent,
    /// Data classification.
    pub classification: Classification,
    /// Backend routed to (or "BLOCKED").
    pub backend_routed: String,
    /// SHA-256 hash of request payload (for integrity).
    pub request_hash: Option<String>,
    /// DLP rules triggered.
    pub dlp_rules_triggered: Vec<String>,
    /// Source IP (pseudonymized).
    pub ip_source: String,
    /// Processing duration in ms.
    pub duration_ms: u64,
    /// Previous entry hash (for chain).
    pub previous_hash: String,
    /// Signature bytes (ECDSA/Ed25519 = 64, HMAC = 32).
    #[serde(with = "hex")]
    pub signature: Vec<u8>,
    /// Signing algorithm used (backward-compatible default).
    #[serde(default)]
    pub signature_algorithm: String,
    /// Model name used (EU AI Act Article 12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    /// Input tokens counted (EU AI Act Article 12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u32>,
    /// Output tokens counted (EU AI Act Article 12).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u32>,
    /// Risk level classification (EU AI Act Article 14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<RiskLevel>,

    // ── Merkle batch fields ──
    /// Batch ID (UUID v4). Present when batch_size > 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,
    /// Zero-based index of this entry within its batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_index: Option<u32>,
    /// Hex-encoded Merkle root signed for this batch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
    /// Inclusion proof from this leaf to the Merkle root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_proof: Option<Vec<ProofStep>>,
}

/// Risk classification levels per EU AI Act Article 14.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Minimal risk, no intervention needed.
    Low,
    /// Moderate risk, may warrant monitoring.
    Medium,
    /// Elevated risk, requires attention.
    High,
    /// Severe risk, immediate action required.
    Critical,
}

impl RiskLevel {
    /// Parses a risk level from a config string (case-insensitive).
    ///
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

/// Audit log configuration.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Log directory.
    pub log_dir: PathBuf,
    /// Sign key path (if None, generates ephemeral) — used for ECDSA/Ed25519.
    pub sign_key_path: Option<PathBuf>,
    /// Signing algorithm.
    pub signing_algorithm: SigningAlgorithm,
    /// HMAC key path (only for HMAC-SHA256 algorithm).
    pub hmac_key_path: Option<PathBuf>,
    /// Entries per Merkle batch (1 = per-entry signing, >1 = batch).
    pub batch_size: usize,
    /// Max milliseconds before flushing an incomplete batch.
    pub flush_interval_ms: u64,
    /// Include Merkle inclusion proof in each entry.
    pub include_merkle_proof: bool,
}

/// Returns the platform-appropriate default audit log directory.
fn default_audit_dir() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/grob/audit")
    }
    #[cfg(windows)]
    {
        crate::home_dir()
            .map(|h| h.join("AppData").join("Local"))
            .unwrap_or_else(|| PathBuf::from("C:\\ProgramData"))
            .join("grob")
            .join("audit")
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_dir: default_audit_dir(),
            sign_key_path: None,
            signing_algorithm: SigningAlgorithm::default(),
            hmac_key_path: None,
            batch_size: 1,
            flush_interval_ms: 5000,
            include_merkle_proof: false,
        }
    }
}

/// Pending entry in the batch buffer: entry + its content hash.
struct PendingEntry {
    entry: AuditEntry,
    hash: String,
}

/// Combined mutable state for the audit log, protected by a single Mutex.
struct AuditLogState {
    file: std::fs::File,
    size: u64,
    last_hash: String,
    /// Pending entries waiting for the batch to fill.
    batch_buffer: Vec<PendingEntry>,
    /// When the current batch started accumulating.
    batch_start: Instant,
}

/// Audit log writer with integrity guarantees.
///
/// When `batch_size == 1` (default), each entry is individually signed
/// and hash-chained — identical to the pre-batch behavior.
///
/// When `batch_size > 1`, entries accumulate until the batch is full
/// or `flush_interval_ms` elapses, then a Merkle tree is built over
/// the batch, the root is signed once, and all entries are written
/// with their batch metadata.
pub struct AuditLog {
    _config: AuditConfig,
    signer: Box<dyn AuditSigner>,
    batch_size: usize,
    flush_interval: std::time::Duration,
    include_merkle_proof: bool,
    state: Mutex<AuditLogState>,
}

impl AuditLog {
    /// Creates a new audit log with the configured signing backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the log directory cannot be created, the
    /// signing key cannot be loaded or generated, or the existing log
    /// file cannot be read for chain continuity.
    pub fn new(config: AuditConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.log_dir)
            .with_context(|| format!("Failed to create audit directory: {:?}", config.log_dir))?;

        let signer: Box<dyn AuditSigner> = match &config.signing_algorithm {
            SigningAlgorithm::EcdsaP256 => {
                Box::new(super::audit_signer::EcdsaP256Signer::load_or_generate(
                    config.sign_key_path.as_deref(),
                )?)
            }
            SigningAlgorithm::Ed25519 => {
                Box::new(super::audit_signer::Ed25519Signer::load_or_generate(
                    config.sign_key_path.as_deref(),
                )?)
            }
            SigningAlgorithm::HmacSha256 => {
                let key_path = config
                    .hmac_key_path
                    .clone()
                    .unwrap_or_else(|| config.log_dir.join("audit_hmac.key"));
                Box::new(super::audit_signer::HmacSha256Signer::load_or_generate(
                    &key_path,
                )?)
            }
        };

        tracing::info!(
            "Audit log: algorithm={}, batch_size={}, flush_interval={}ms, merkle_proof={}",
            signer.algorithm(),
            config.batch_size,
            config.flush_interval_ms,
            config.include_merkle_proof,
        );

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

        let current_size = file.metadata()?.len();

        Ok(Self {
            batch_size: config.batch_size.max(1),
            flush_interval: std::time::Duration::from_millis(config.flush_interval_ms),
            include_merkle_proof: config.include_merkle_proof,
            _config: config,
            signer,
            state: Mutex::new(AuditLogState {
                file,
                size: current_size,
                last_hash,
                batch_buffer: Vec::new(),
                batch_start: Instant::now(),
            }),
        })
    }

    /// Read last hash from existing log for chain continuity.
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

    /// Genesis hash for empty chain.
    fn genesis_hash() -> String {
        hex::encode(Sha256::digest(b"GROB_AUDIT_GENESIS"))
    }

    /// Hashes an entry for chaining (writes directly into hasher).
    fn hash_entry(entry: &AuditEntry) -> String {
        use std::io::Write as _;
        let mut hasher = Sha256::new();
        // Excludes signature, signature_algorithm, and batch metadata.
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

    /// Writes an audit entry.
    ///
    /// In per-entry mode (batch_size=1), signs and appends immediately.
    /// In batch mode, buffers the entry and flushes when the batch is
    /// full or the flush interval has elapsed.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be serialized or written
    /// to the log file.
    pub fn write(&self, mut entry: AuditEntry) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Chain: set previous_hash from last written entry.
        entry.previous_hash = state.last_hash.clone();

        let hash = Self::hash_entry(&entry);
        state.last_hash = hash.clone();

        if self.batch_size <= 1 {
            // Per-entry signing (original behavior).
            entry.signature_algorithm = self.signer.algorithm().to_string();
            entry.signature = self.signer.sign(hash.as_bytes());
            Self::append_entry(&mut state, &entry)?;
        } else {
            // Batch mode: accumulate.
            state.batch_buffer.push(PendingEntry { entry, hash });

            let batch_full = state.batch_buffer.len() >= self.batch_size;
            let interval_elapsed = state.batch_start.elapsed() >= self.flush_interval;

            if batch_full || interval_elapsed {
                self.flush_batch(&mut state)?;
            }
        }

        Ok(())
    }

    /// Flushes any pending batch entries. Safe to call even if buffer is empty.
    ///
    /// # Errors
    ///
    /// Returns an error if buffered entries cannot be written to the
    /// log file.
    pub fn flush(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.batch_buffer.is_empty() {
            self.flush_batch(&mut state)?;
        }
        Ok(())
    }

    /// Builds the Merkle tree, signs the root, and writes all buffered entries.
    fn flush_batch(&self, state: &mut AuditLogState) -> Result<()> {
        let batch: Vec<PendingEntry> = state.batch_buffer.drain(..).collect();
        state.batch_start = Instant::now();

        if batch.is_empty() {
            return Ok(());
        }

        let leaf_hashes: Vec<String> = batch.iter().map(|p| p.hash.clone()).collect();
        let tree = MerkleTree::from_leaves(&leaf_hashes);
        let merkle_root = tree.root().to_string();

        // Sign the Merkle root once for the entire batch.
        let root_signature = self.signer.sign(merkle_root.as_bytes());
        let batch_id = uuid::Uuid::new_v4().to_string();
        let algorithm = self.signer.algorithm().to_string();

        for (i, pending) in batch.into_iter().enumerate() {
            let mut entry = pending.entry;
            entry.signature_algorithm = algorithm.clone();
            entry.signature = root_signature.clone();
            entry.batch_id = Some(batch_id.clone());
            entry.batch_index = Some(i as u32);
            entry.merkle_root = Some(merkle_root.clone());

            if self.include_merkle_proof {
                entry.merkle_proof = tree.proof(i);
            }

            Self::append_entry(state, &entry)?;
        }

        Ok(())
    }

    /// Serializes and appends a single entry to the JSONL file.
    fn append_entry(state: &mut AuditLogState, entry: &AuditEntry) -> Result<()> {
        let mut line = serde_json::to_string(entry).context("Failed to serialize audit entry")?;
        line.push('\n');
        state
            .file
            .write_all(line.as_bytes())
            .context("Failed to write audit entry")?;
        state.size += line.len() as u64;
        Ok(())
    }
}

// ── Trait implementation ──

#[cfg(feature = "compliance")]
impl crate::traits::AuditWriter for AuditLog {
    fn write(&self, entry: AuditEntry) -> anyhow::Result<()> {
        self.write(entry)
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
        let dir = TempDir::new().expect("tempdir");
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let _log = AuditLog::new(config).expect("audit log");
    }

    fn make_test_log() -> (TempDir, AuditLog) {
        let dir = TempDir::new().expect("tempdir");
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let log = AuditLog::new(config).expect("audit log");
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
            batch_id: None,
            batch_index: None,
            merkle_root: None,
            merkle_proof: None,
        }
    }

    #[test]
    fn test_write_entry() {
        let (dir, log) = make_test_log();
        let entry = make_entry(AuditEvent::Response);
        log.write(entry).expect("write");

        let content =
            std::fs::read_to_string(dir.path().join("current.jsonl")).expect("read log file");
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 1);

        let parsed: AuditEntry = serde_json::from_str(lines[0]).expect("parse line 0");
        assert_eq!(parsed.tenant_id, "test-tenant");
        assert_eq!(parsed.duration_ms, 42);
    }

    #[test]
    fn test_hash_chain() {
        let (_dir, log) = make_test_log();
        let genesis = AuditLog::genesis_hash();

        log.write(make_entry(AuditEvent::Request))
            .expect("write entry");
        log.write(make_entry(AuditEvent::Response))
            .expect("write entry");

        let content =
            std::fs::read_to_string(_dir.path().join("current.jsonl")).expect("read log file");
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        let parsed1: AuditEntry = serde_json::from_str(lines[0]).expect("parse line 0");
        let parsed2: AuditEntry = serde_json::from_str(lines[1]).expect("parse line 1");

        assert_eq!(parsed1.previous_hash, genesis);
        assert_eq!(parsed2.previous_hash, AuditLog::hash_entry(&parsed1));
    }

    #[test]
    fn test_signature_present() {
        let (_dir, log) = make_test_log();
        log.write(make_entry(AuditEvent::DlpBlock))
            .expect("write entry");

        let content =
            std::fs::read_to_string(_dir.path().join("current.jsonl")).expect("read log file");
        let parsed: AuditEntry = serde_json::from_str(content.trim()).expect("parse entry");

        assert_eq!(parsed.signature.len(), 64, "ECDSA P-256 = 64 bytes");
        assert!(parsed.signature.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_hmac_signature_present() {
        let dir = TempDir::new().expect("tempdir");
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            signing_algorithm: SigningAlgorithm::HmacSha256,
            ..Default::default()
        };
        let log = AuditLog::new(config).expect("audit log");
        log.write(make_entry(AuditEvent::Request))
            .expect("write entry");

        let content =
            std::fs::read_to_string(dir.path().join("current.jsonl")).expect("read log file");
        let parsed: AuditEntry = serde_json::from_str(content.trim()).expect("parse entry");

        assert_eq!(parsed.signature.len(), 32, "HMAC-SHA256 = 32 bytes");
        assert_eq!(parsed.signature_algorithm, "hmac-sha256");
    }

    #[test]
    fn test_ed25519_signature() {
        let dir = TempDir::new().expect("tempdir");
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            signing_algorithm: SigningAlgorithm::Ed25519,
            ..Default::default()
        };
        let log = AuditLog::new(config).expect("audit log");
        log.write(make_entry(AuditEvent::Auth))
            .expect("write entry");

        let content =
            std::fs::read_to_string(dir.path().join("current.jsonl")).expect("read log file");
        let parsed: AuditEntry = serde_json::from_str(content.trim()).expect("parse entry");

        assert_eq!(parsed.signature.len(), 64, "Ed25519 = 64 bytes");
        assert_eq!(parsed.signature_algorithm, "ed25519");
    }

    #[test]
    fn test_batch_signing() {
        let dir = TempDir::new().expect("tempdir");
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            batch_size: 3,
            include_merkle_proof: true,
            ..Default::default()
        };
        let log = AuditLog::new(config).expect("audit log");

        // Write 3 entries — batch should flush automatically.
        for _ in 0..3 {
            log.write(make_entry(AuditEvent::Response))
                .expect("write entry");
        }

        let content =
            std::fs::read_to_string(dir.path().join("current.jsonl")).expect("read log file");
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 3);

        let entries: Vec<AuditEntry> = lines
            .iter()
            .map(|l| serde_json::from_str(l).expect("parse line"))
            .collect();

        // All entries share the same batch_id and merkle_root.
        let batch_id = entries[0].batch_id.as_ref().expect("batch_id");
        let merkle_root = entries[0].merkle_root.as_ref().expect("merkle_root");
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.batch_id.as_ref().expect("batch_id"), batch_id);
            assert_eq!(e.batch_index, Some(i as u32));
            assert_eq!(e.merkle_root.as_ref().expect("merkle_root"), merkle_root);
            assert!(e.merkle_proof.is_some(), "proof should be included");
        }

        // All entries share the same signature (root signature).
        assert_eq!(entries[0].signature, entries[1].signature);
        assert_eq!(entries[1].signature, entries[2].signature);
    }

    #[test]
    fn test_batch_merkle_proof_verifiable() {
        let dir = TempDir::new().expect("tempdir");
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            batch_size: 4,
            include_merkle_proof: true,
            ..Default::default()
        };
        let log = AuditLog::new(config).expect("audit log");

        for _ in 0..4 {
            log.write(make_entry(AuditEvent::Request))
                .expect("write entry");
        }

        let content =
            std::fs::read_to_string(dir.path().join("current.jsonl")).expect("read log file");
        let entries: Vec<AuditEntry> = content
            .trim()
            .lines()
            .map(|l| serde_json::from_str(l).expect("parse line"))
            .collect();

        let merkle_root = entries[0].merkle_root.as_ref().expect("merkle_root");

        for entry in &entries {
            let leaf_hash = AuditLog::hash_entry(entry);
            let proof = entry.merkle_proof.as_ref().expect("merkle_proof");
            assert!(
                MerkleTree::verify(merkle_root, &leaf_hash, proof),
                "Merkle proof failed for entry {}",
                entry.event_id
            );
        }
    }

    #[test]
    fn test_batch_flush_partial() {
        let dir = TempDir::new().expect("tempdir");
        let config = AuditConfig {
            log_dir: dir.path().to_path_buf(),
            batch_size: 10,
            include_merkle_proof: false,
            ..Default::default()
        };
        let log = AuditLog::new(config).expect("audit log");

        // Write fewer entries than batch_size, then flush explicitly.
        log.write(make_entry(AuditEvent::Request))
            .expect("write entry");
        log.write(make_entry(AuditEvent::Response))
            .expect("write entry");

        // Nothing written yet (batch incomplete).
        let content =
            std::fs::read_to_string(dir.path().join("current.jsonl")).expect("read log file");
        assert!(content.is_empty(), "batch should not be flushed yet");

        // Explicit flush.
        log.flush().expect("flush");

        let content =
            std::fs::read_to_string(dir.path().join("current.jsonl")).expect("read log file");
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_backward_compat_deserialization() {
        // Old entries without batch fields should deserialize fine.
        let json = r#"{"timestamp":"2026-01-01T00:00:00Z","event_id":"test","tenant_id":"t","user_id":null,"action":"REQUEST","classification":"NC","backend_routed":"p","request_hash":null,"dlp_rules_triggered":[],"ip_source":"127.0.0.1","duration_ms":0,"previous_hash":"abc","signature":"deadbeef"}"#;
        let entry: AuditEntry = serde_json::from_str(json).expect("parse json");
        assert_eq!(entry.signature_algorithm, "");
        assert!(entry.batch_id.is_none());
        assert!(entry.merkle_root.is_none());
        assert!(entry.merkle_proof.is_none());
    }
}
