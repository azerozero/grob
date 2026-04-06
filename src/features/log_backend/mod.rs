//! Log backend abstraction for querying external log systems.
//!
//! Provides the [`LogBackend`] trait and concrete implementations for
//! sokolsky-collector, with role-based field filtering and DLP integration.

pub mod sokolsky;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Core types ──

/// Log plane separation (mirrors sokolsky wire format).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plane {
    /// Infrastructure and OS-level logs (journald, auditd).
    Machine,
    /// Application-level logs (container stdout/stderr).
    App,
    /// Compliance and security audit logs (grob ECDSA-P256 signed).
    Audit,
}

impl Plane {
    /// Returns the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Plane::Machine => "machine",
            Plane::App => "app",
            Plane::Audit => "audit",
        }
    }

    /// All planes in quorum order.
    pub fn all() -> &'static [Plane] {
        &[Plane::Machine, Plane::App, Plane::Audit]
    }
}

impl std::fmt::Display for Plane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Plane {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "machine" => Ok(Plane::Machine),
            "app" => Ok(Plane::App),
            "audit" => Ok(Plane::Audit),
            _ => Err(format!("unknown plane: {s}")),
        }
    }
}

/// Role with access control for log queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRole {
    /// Role name (admin, devops, dev, auditor).
    pub name: String,
    /// Allowed backend names.
    pub backends: Vec<String>,
    /// Allowed planes.
    pub planes: Vec<Plane>,
    /// Visible field names ("*" = all).
    pub fields_visible: FieldSpec,
    /// Fields to redact (applied after visibility filter).
    #[serde(default)]
    pub fields_redacted: Vec<String>,
    /// Allowed actions (read, export, verify).
    pub actions: Vec<String>,
    /// Tenant filter (restricts queries to a specific tenant).
    #[serde(default)]
    pub tenant_filter: Option<String>,
    /// Whether DLP bypass is enabled (always false for safety).
    #[serde(default)]
    pub dlp_bypass: bool,
    /// Whether each access generates an audit-of-audit entry.
    #[serde(default)]
    pub audit_of_audit: bool,
}

/// Specifies which fields are visible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldSpec {
    /// All fields visible.
    All(String),
    /// Only these fields visible.
    List(Vec<String>),
}

impl FieldSpec {
    /// Returns true if this spec allows all fields.
    pub fn is_all(&self) -> bool {
        matches!(self, FieldSpec::All(s) if s == "*")
    }

    /// Returns true if the given field name is visible.
    pub fn allows(&self, field: &str) -> bool {
        match self {
            FieldSpec::All(s) if s == "*" => true,
            FieldSpec::All(_) => false,
            FieldSpec::List(fields) => fields.iter().any(|f| f == field),
        }
    }
}

impl Default for FieldSpec {
    fn default() -> Self {
        FieldSpec::List(Vec::new())
    }
}

/// Query parameters for log retrieval.
#[derive(Debug, Clone, Default)]
pub struct LogQuery {
    /// Target plane.
    pub plane: Option<Plane>,
    /// Target backend name.
    pub backend: Option<String>,
    /// Trace ID filter.
    pub trace_id: Option<String>,
    /// Time range start (ISO-8601).
    pub from: Option<String>,
    /// Time range end (ISO-8601).
    pub to: Option<String>,
    /// Whether to verify N-of-N signatures.
    pub verify_signatures: bool,
    /// Whether to aggregate across backends.
    pub aggregate: bool,
    /// Maximum number of entries to return.
    pub limit: Option<usize>,
}

/// A single log entry returned by a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Log entry ID.
    pub id: String,
    /// Timestamp (ISO-8601 or nanos).
    pub timestamp: String,
    /// Source plane.
    pub plane: Plane,
    /// Source backend name.
    pub backend: String,
    /// Source identifier.
    pub source: String,
    /// Key-value fields (filtered by role).
    pub fields: HashMap<String, serde_json::Value>,
    /// Signature verification status.
    #[serde(default)]
    pub signature_status: SignatureStatus,
}

/// N-of-N signature verification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Not yet verified.
    #[default]
    Unverified,
    /// All N-of-N signatures valid.
    Valid,
    /// One or more signatures missing or invalid.
    IntegrityViolation,
}

/// Errors from log backend operations.
#[derive(Debug, thiserror::Error)]
pub enum LogBackendError {
    /// Indicates the role lacks permission to query the requested backend.
    #[error("backend not allowed for role: {0}")]
    BackendDenied(String),
    /// Indicates the role lacks permission to access the requested plane.
    #[error("plane not allowed for role: {0}")]
    PlaneDenied(String),
    /// Indicates the role lacks permission for the requested action.
    #[error("action not allowed: {0}")]
    ActionDenied(String),
    /// Indicates N-of-N signature verification or hash-chain failure.
    #[error("integrity violation: {0}")]
    IntegrityViolation(String),
    /// Indicates the backend is unreachable or degraded.
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    /// Indicates a transport or deserialization error during query.
    #[error("query error: {0}")]
    QueryError(String),
}

// ── Trait ──

/// Abstraction for querying external log backends.
///
/// Implementations handle transport, authentication, and signature
/// verification. The caller is responsible for role-based field
/// filtering via [`filter_fields`].
#[async_trait]
pub trait LogBackend: Send + Sync {
    /// Returns the backend name (e.g. "victorialogs", "journald", "s3").
    fn name(&self) -> &str;

    /// Queries logs from this backend.
    ///
    /// # Errors
    ///
    /// Returns [`LogBackendError`] on transport failures or query issues.
    async fn query(&self, query: &LogQuery) -> Result<Vec<LogEntry>, LogBackendError>;

    /// Verifies N-of-N cross-plane signatures on a log entry.
    ///
    /// # Errors
    ///
    /// Returns [`LogBackendError::IntegrityViolation`] if any signature is missing or invalid.
    async fn verify_signatures(&self, entry: &LogEntry)
        -> Result<SignatureStatus, LogBackendError>;

    /// Returns true if the backend is reachable.
    async fn health_check(&self) -> bool;
}

// ── Field filtering ──

/// Filters log entry fields according to role visibility and redaction rules.
pub fn filter_fields(entry: &mut LogEntry, role: &LogRole) {
    if role.fields_visible.is_all() {
        // Redact specific fields even for full-access roles.
        for pattern in &role.fields_redacted {
            redact_matching_fields(&mut entry.fields, pattern);
        }
    } else {
        // Keep only visible fields, then redact.
        let visible: Vec<String> = entry
            .fields
            .keys()
            .filter(|k| role.fields_visible.allows(k))
            .cloned()
            .collect();
        entry.fields.retain(|k, _| visible.contains(k));
        for pattern in &role.fields_redacted {
            redact_matching_fields(&mut entry.fields, pattern);
        }
    }
}

/// Redacts fields matching a glob pattern (supports `*` prefix/suffix).
fn redact_matching_fields(fields: &mut HashMap<String, serde_json::Value>, pattern: &str) {
    let keys: Vec<String> = fields
        .keys()
        .filter(|k| field_glob_match(pattern, k))
        .cloned()
        .collect();
    for key in keys {
        fields.insert(key, serde_json::Value::String("[REDACTED]".to_string()));
    }
}

/// Simple glob match for field names.
fn field_glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    pattern == value
}

// ── Access control ──

/// Checks whether a role is allowed to query a specific plane and backend.
///
/// # Errors
///
/// Returns [`LogBackendError::PlaneDenied`] or [`LogBackendError::BackendDenied`].
pub fn check_access(
    role: &LogRole,
    plane: Option<&Plane>,
    backend: Option<&str>,
) -> Result<(), LogBackendError> {
    if let Some(plane) = plane {
        if !role.planes.contains(plane) {
            return Err(LogBackendError::PlaneDenied(format!(
                "{} cannot access {} plane",
                role.name, plane
            )));
        }
    }
    if let Some(backend) = backend {
        if !role.backends.iter().any(|b| b == backend) {
            return Err(LogBackendError::BackendDenied(format!(
                "{} cannot access {} backend",
                role.name, backend
            )));
        }
    }
    Ok(())
}

/// DLP configuration for cross-plan PII redaction.
///
/// When active, applies additional redaction patterns on top of role-based
/// field filtering. This ensures PII is redacted even for full-access roles.
#[derive(Debug, Clone, Default)]
pub struct DlpConfig {
    /// Whether the DLP engine is active.
    pub active: bool,
    /// Glob patterns for fields to redact (e.g. "user_*", "*_pii").
    pub pii_patterns: Vec<String>,
}

/// Applies DLP redaction to a log entry.
///
/// Redacts fields matching PII patterns regardless of role permissions.
/// Only applies when `dlp.active` is true and the role has not been
/// granted `dlp_bypass`.
pub fn apply_dlp(entry: &mut LogEntry, dlp: &DlpConfig, role: &LogRole) {
    if !dlp.active || role.dlp_bypass {
        return;
    }
    for pattern in &dlp.pii_patterns {
        redact_matching_fields(&mut entry.fields, pattern);
    }
}

/// Record of an audit-of-audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditOfAuditEntry {
    /// Identity of the accessor.
    pub accessor: String,
    /// Role name.
    pub role: String,
    /// Plane queried.
    pub plane: Option<Plane>,
    /// Backend queried.
    pub backend: Option<String>,
    /// Number of results returned.
    pub results_count: usize,
}

/// Queries logs with role-based access control and field filtering.
///
/// # Errors
///
/// Returns access denied errors or backend query errors.
pub async fn query_with_role(
    backends: &[&dyn LogBackend],
    role: &LogRole,
    query: &LogQuery,
) -> Result<Vec<LogEntry>, LogBackendError> {
    query_with_role_dlp(backends, role, query, &DlpConfig::default()).await
}

/// Queries logs with role-based access control, field filtering, and DLP.
///
/// Returns the log entries along with an optional audit-of-audit record
/// when the role has `audit_of_audit` enabled.
///
/// # Errors
///
/// Returns access denied errors or backend query errors.
pub async fn query_with_role_dlp(
    backends: &[&dyn LogBackend],
    role: &LogRole,
    query: &LogQuery,
    dlp: &DlpConfig,
) -> Result<Vec<LogEntry>, LogBackendError> {
    // Check plane access.
    check_access(role, query.plane.as_ref(), query.backend.as_deref())?;

    let mut results = Vec::new();

    if query.aggregate {
        // Query all allowed backends.
        for backend in backends {
            if !role.backends.iter().any(|b| b == backend.name()) {
                continue;
            }
            match backend.query(query).await {
                Ok(mut entries) => results.append(&mut entries),
                Err(LogBackendError::Unavailable(msg)) => {
                    tracing::warn!("Backend {} degraded: {}", backend.name(), msg);
                }
                Err(e) => return Err(e),
            }
        }
        // Sort by timestamp.
        results.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        // Deduplicate by entry ID (keeps first occurrence).
        deduplicate_entries(&mut results);
    } else {
        // Query specific backend or first available.
        let target_name = query.backend.as_deref();
        for backend in backends {
            let matches = match target_name {
                Some(name) => backend.name() == name,
                None => role.backends.iter().any(|b| b == backend.name()),
            };
            if matches {
                results = backend.query(query).await?;
                break;
            }
        }
    }

    // Verify signatures if requested.
    if query.verify_signatures {
        if !role.actions.iter().any(|a| a == "verify") {
            return Err(LogBackendError::ActionDenied(
                "verify action not allowed".into(),
            ));
        }
        for entry in &mut results {
            for backend in backends {
                if backend.name() == entry.backend {
                    entry.signature_status = backend.verify_signatures(entry).await?;
                }
            }
        }
    }

    // Apply field filtering.
    for entry in &mut results {
        filter_fields(entry, role);
    }

    // Apply DLP redaction (cross-plan, even for full-access roles).
    for entry in &mut results {
        apply_dlp(entry, dlp, role);
    }

    Ok(results)
}

/// Generates an audit-of-audit record for the given query.
pub fn generate_audit_of_audit(
    role: &LogRole,
    query: &LogQuery,
    results_count: usize,
) -> Option<AuditOfAuditEntry> {
    if !role.audit_of_audit {
        return None;
    }
    Some(AuditOfAuditEntry {
        accessor: role.name.clone(),
        role: role.name.clone(),
        plane: query.plane,
        backend: query.backend.clone(),
        results_count,
    })
}

/// Removes duplicate entries by ID, keeping the first occurrence.
fn deduplicate_entries(entries: &mut Vec<LogEntry>) {
    let mut seen = std::collections::HashSet::new();
    entries.retain(|e| seen.insert(e.id.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_role() -> LogRole {
        LogRole {
            name: "admin".into(),
            backends: vec!["victorialogs".into(), "journald".into(), "s3".into()],
            planes: vec![Plane::Machine, Plane::App, Plane::Audit],
            fields_visible: FieldSpec::All("*".into()),
            fields_redacted: vec![],
            actions: vec!["read".into(), "export".into(), "verify".into()],
            tenant_filter: None,
            dlp_bypass: false,
            audit_of_audit: false,
        }
    }

    fn devops_role() -> LogRole {
        LogRole {
            name: "devops".into(),
            backends: vec!["victorialogs".into(), "journald".into()],
            planes: vec![Plane::Machine, Plane::App],
            fields_visible: FieldSpec::List(vec![
                "timestamp".into(),
                "level".into(),
                "service".into(),
                "message".into(),
                "trace_id".into(),
            ]),
            fields_redacted: vec![
                "user_email".into(),
                "ip_address".into(),
                "session_id".into(),
                "ciphertext".into(),
            ],
            actions: vec!["read".into(), "export".into()],
            tenant_filter: None,
            dlp_bypass: false,
            audit_of_audit: false,
        }
    }

    fn dev_role() -> LogRole {
        LogRole {
            name: "dev".into(),
            backends: vec!["victorialogs".into()],
            planes: vec![Plane::App],
            fields_visible: FieldSpec::List(vec![
                "timestamp".into(),
                "level".into(),
                "service".into(),
                "message".into(),
            ]),
            fields_redacted: vec!["*_pii".into(), "user_*".into(), "ip_*".into()],
            actions: vec!["read".into()],
            tenant_filter: Some("staging".into()),
            dlp_bypass: false,
            audit_of_audit: false,
        }
    }

    fn auditor_role() -> LogRole {
        LogRole {
            name: "auditor".into(),
            backends: vec!["victorialogs".into(), "journald".into(), "s3".into()],
            planes: vec![Plane::Machine, Plane::App, Plane::Audit],
            fields_visible: FieldSpec::All("*".into()),
            fields_redacted: vec![],
            actions: vec!["read".into(), "verify".into()],
            tenant_filter: None,
            dlp_bypass: false,
            audit_of_audit: true,
        }
    }

    // ── Access control tests (T-SOK-1) ──

    #[test]
    fn admin_can_access_all_planes() {
        let role = admin_role();
        for plane in Plane::all() {
            assert!(check_access(&role, Some(plane), None).is_ok());
        }
    }

    #[test]
    fn devops_cannot_access_audit_plane() {
        let role = devops_role();
        assert!(check_access(&role, Some(&Plane::Machine), None).is_ok());
        assert!(check_access(&role, Some(&Plane::App), None).is_ok());
        assert!(check_access(&role, Some(&Plane::Audit), None).is_err());
    }

    #[test]
    fn dev_can_only_access_app_plane() {
        let role = dev_role();
        assert!(check_access(&role, Some(&Plane::App), None).is_ok());
        assert!(check_access(&role, Some(&Plane::Machine), None).is_err());
        assert!(check_access(&role, Some(&Plane::Audit), None).is_err());
    }

    #[test]
    fn auditor_can_access_all_planes() {
        let role = auditor_role();
        for plane in Plane::all() {
            assert!(check_access(&role, Some(plane), None).is_ok());
        }
    }

    #[test]
    fn dev_cannot_access_journald_backend() {
        let role = dev_role();
        assert!(check_access(&role, None, Some("victorialogs")).is_ok());
        assert!(check_access(&role, None, Some("journald")).is_err());
        assert!(check_access(&role, None, Some("s3")).is_err());
    }

    // ── Field filtering tests (T-SOK-3) ──

    #[test]
    fn devops_gets_pii_fields_redacted() {
        let role = devops_role();
        let mut entry = LogEntry {
            id: "1".into(),
            timestamp: "2026-04-06T10:00:00Z".into(),
            plane: Plane::App,
            backend: "victorialogs".into(),
            source: "node-1".into(),
            fields: HashMap::from([
                (
                    "timestamp".into(),
                    serde_json::json!("2026-04-06T10:00:00Z"),
                ),
                ("level".into(), serde_json::json!("error")),
                ("service".into(), serde_json::json!("api-gateway")),
                ("message".into(), serde_json::json!("timeout")),
                ("user_email".into(), serde_json::json!("john@acme.com")),
                ("ip_address".into(), serde_json::json!("192.168.1.1")),
                ("ciphertext".into(), serde_json::json!("encrypted_blob")),
                ("trace_id".into(), serde_json::json!("abc123")),
            ]),
            signature_status: SignatureStatus::Unverified,
        };

        filter_fields(&mut entry, &role);

        // Only visible fields remain.
        assert_eq!(entry.fields.len(), 5);
        assert!(entry.fields.contains_key("timestamp"));
        assert!(entry.fields.contains_key("trace_id"));
        // PII fields are gone (not in fields_visible list).
        assert!(!entry.fields.contains_key("user_email"));
        assert!(!entry.fields.contains_key("ip_address"));
        assert!(!entry.fields.contains_key("ciphertext"));
    }

    #[test]
    fn admin_sees_all_fields() {
        let role = admin_role();
        let mut entry = LogEntry {
            id: "1".into(),
            timestamp: "2026-04-06T10:00:00Z".into(),
            plane: Plane::App,
            backend: "victorialogs".into(),
            source: "node-1".into(),
            fields: HashMap::from([
                ("user_email".into(), serde_json::json!("john@acme.com")),
                ("trace_id".into(), serde_json::json!("abc123")),
                ("ciphertext".into(), serde_json::json!("blob")),
            ]),
            signature_status: SignatureStatus::Unverified,
        };

        filter_fields(&mut entry, &role);

        assert_eq!(entry.fields.len(), 3);
        assert_eq!(
            entry.fields["user_email"],
            serde_json::json!("john@acme.com")
        );
    }

    #[test]
    fn dev_gets_glob_pattern_redaction() {
        let role = dev_role();
        let mut entry = LogEntry {
            id: "1".into(),
            timestamp: "2026-04-06T10:00:00Z".into(),
            plane: Plane::App,
            backend: "victorialogs".into(),
            source: "node-1".into(),
            fields: HashMap::from([
                (
                    "timestamp".into(),
                    serde_json::json!("2026-04-06T10:00:00Z"),
                ),
                ("level".into(), serde_json::json!("info")),
                ("message".into(), serde_json::json!("hello")),
                ("service".into(), serde_json::json!("api")),
            ]),
            signature_status: SignatureStatus::Unverified,
        };

        filter_fields(&mut entry, &role);

        // All visible fields kept, none match redaction globs.
        assert_eq!(entry.fields.len(), 4);
    }

    // ── Plane parsing ──

    #[test]
    fn plane_roundtrip() {
        for plane in Plane::all() {
            let s = plane.to_string();
            let parsed: Plane = s.parse().unwrap();
            assert_eq!(*plane, parsed);
        }
    }

    // ── FieldSpec ──

    #[test]
    fn field_spec_all_allows_everything() {
        let spec = FieldSpec::All("*".into());
        assert!(spec.is_all());
        assert!(spec.allows("anything"));
    }

    #[test]
    fn field_spec_list_only_allows_listed() {
        let spec = FieldSpec::List(vec!["timestamp".into(), "level".into()]);
        assert!(!spec.is_all());
        assert!(spec.allows("timestamp"));
        assert!(spec.allows("level"));
        assert!(!spec.allows("ciphertext"));
    }

    // ── Glob matching ──

    #[test]
    fn glob_prefix_match() {
        assert!(field_glob_match("user_*", "user_email"));
        assert!(field_glob_match("user_*", "user_name"));
        assert!(!field_glob_match("user_*", "trace_id"));
    }

    #[test]
    fn glob_suffix_match() {
        assert!(field_glob_match("*_pii", "name_pii"));
        assert!(field_glob_match("*_pii", "address_pii"));
        assert!(!field_glob_match("*_pii", "trace_id"));
    }

    #[test]
    fn glob_exact_match() {
        assert!(field_glob_match("ciphertext", "ciphertext"));
        assert!(!field_glob_match("ciphertext", "plaintext"));
    }

    // ── T-SOK-5: Multi-backend aggregation with deduplication ──

    #[test]
    fn deduplicate_entries_removes_dupes_keeps_order() {
        let mut entries = vec![
            LogEntry {
                id: "a".into(),
                timestamp: "2026-04-06T10:00:00Z".into(),
                plane: Plane::App,
                backend: "victorialogs".into(),
                source: "node-1".into(),
                fields: HashMap::new(),
                signature_status: SignatureStatus::Unverified,
            },
            LogEntry {
                id: "b".into(),
                timestamp: "2026-04-06T10:01:00Z".into(),
                plane: Plane::App,
                backend: "journald".into(),
                source: "node-1".into(),
                fields: HashMap::new(),
                signature_status: SignatureStatus::Unverified,
            },
            LogEntry {
                id: "a".into(),
                timestamp: "2026-04-06T10:00:00Z".into(),
                plane: Plane::App,
                backend: "journald".into(),
                source: "node-1".into(),
                fields: HashMap::new(),
                signature_status: SignatureStatus::Unverified,
            },
        ];
        deduplicate_entries(&mut entries);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "a");
        assert_eq!(entries[1].id, "b");
    }

    #[tokio::test]
    async fn aggregated_query_deduplicates_across_backends() {
        use crate::features::log_backend::sokolsky::MockLogBackend;

        let shared_entry = LogEntry {
            id: "shared-1".into(),
            timestamp: "2026-04-06T10:00:00Z".into(),
            plane: Plane::App,
            backend: "victorialogs".into(),
            source: "node-1".into(),
            fields: HashMap::from([("message".into(), serde_json::json!("hello"))]),
            signature_status: SignatureStatus::Unverified,
        };
        let mut shared_entry_jd = shared_entry.clone();
        shared_entry_jd.backend = "journald".into();

        let unique_vl = LogEntry {
            id: "vl-only".into(),
            timestamp: "2026-04-06T10:01:00Z".into(),
            plane: Plane::App,
            backend: "victorialogs".into(),
            source: "node-1".into(),
            fields: HashMap::from([("message".into(), serde_json::json!("world"))]),
            signature_status: SignatureStatus::Unverified,
        };

        let vl = MockLogBackend::new("victorialogs", vec![shared_entry, unique_vl]);
        let jd = MockLogBackend::new("journald", vec![shared_entry_jd]);
        let backends: Vec<&dyn LogBackend> = vec![&vl, &jd];

        let role = admin_role();
        let query = LogQuery {
            plane: Some(Plane::App),
            aggregate: true,
            ..Default::default()
        };

        let results = query_with_role(&backends, &role, &query).await.unwrap();
        assert_eq!(results.len(), 2);
        // No duplicate IDs.
        let ids: Vec<&str> = results.iter().map(|e| e.id.as_str()).collect();
        assert!(ids.contains(&"shared-1"));
        assert!(ids.contains(&"vl-only"));
    }

    // ── T-SOK-6: Backend graceful degradation ──

    #[tokio::test]
    async fn degraded_backend_does_not_block_aggregate() {
        use crate::features::log_backend::sokolsky::MockLogBackend;

        let entry = LogEntry {
            id: "1".into(),
            timestamp: "2026-04-06T10:00:00Z".into(),
            plane: Plane::App,
            backend: "victorialogs".into(),
            source: "node-1".into(),
            fields: HashMap::from([("message".into(), serde_json::json!("ok"))]),
            signature_status: SignatureStatus::Unverified,
        };
        let vl = MockLogBackend::new("victorialogs", vec![entry]);
        let jd = MockLogBackend::unavailable("journald");
        let backends: Vec<&dyn LogBackend> = vec![&vl, &jd];

        let role = LogRole {
            name: "admin".into(),
            backends: vec!["victorialogs".into(), "journald".into()],
            planes: vec![Plane::Machine, Plane::App, Plane::Audit],
            fields_visible: FieldSpec::All("*".into()),
            fields_redacted: vec![],
            actions: vec!["read".into()],
            tenant_filter: None,
            dlp_bypass: false,
            audit_of_audit: false,
        };

        let query = LogQuery {
            plane: Some(Plane::App),
            aggregate: true,
            ..Default::default()
        };

        let results = query_with_role(&backends, &role, &query).await.unwrap();
        // VictoriaLogs entries returned despite journald being down.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].backend, "victorialogs");
    }

    // ── T-SOK-7: Audit-of-audit ──

    #[test]
    fn auditor_generates_audit_of_audit_entry() {
        let role = auditor_role();
        let query = LogQuery {
            plane: Some(Plane::Machine),
            ..Default::default()
        };
        let audit = generate_audit_of_audit(&role, &query, 42);
        assert!(audit.is_some());
        let audit = audit.unwrap();
        assert_eq!(audit.accessor, "auditor");
        assert_eq!(audit.role, "auditor");
        assert_eq!(audit.plane, Some(Plane::Machine));
        assert_eq!(audit.results_count, 42);
    }

    #[test]
    fn non_auditor_does_not_generate_audit_of_audit() {
        let role = admin_role();
        let query = LogQuery {
            plane: Some(Plane::Machine),
            ..Default::default()
        };
        assert!(generate_audit_of_audit(&role, &query, 10).is_none());
    }

    // ── T-SOK-8: DLP field redaction cross-plan ──

    #[test]
    fn dlp_redacts_pii_even_for_admin() {
        let role = admin_role();
        let dlp = DlpConfig {
            active: true,
            pii_patterns: vec!["user_*".into(), "ip_*".into(), "ciphertext".into()],
        };
        let mut entry = LogEntry {
            id: "1".into(),
            timestamp: "2026-04-06T10:00:00Z".into(),
            plane: Plane::App,
            backend: "victorialogs".into(),
            source: "node-1".into(),
            fields: HashMap::from([
                ("user_email".into(), serde_json::json!("john@acme.com")),
                ("ip_address".into(), serde_json::json!("192.168.1.1")),
                ("ciphertext".into(), serde_json::json!("secret")),
                ("trace_id".into(), serde_json::json!("abc123")),
                ("message".into(), serde_json::json!("hello")),
            ]),
            signature_status: SignatureStatus::Unverified,
        };

        // Role filter passes everything (admin has full access).
        filter_fields(&mut entry, &role);
        assert_eq!(entry.fields.len(), 5);

        // DLP redacts PII fields on top of role filtering.
        apply_dlp(&mut entry, &dlp, &role);
        assert_eq!(entry.fields["user_email"], serde_json::json!("[REDACTED]"));
        assert_eq!(entry.fields["ip_address"], serde_json::json!("[REDACTED]"));
        assert_eq!(entry.fields["ciphertext"], serde_json::json!("[REDACTED]"));
        // Non-PII fields untouched.
        assert_eq!(entry.fields["trace_id"], serde_json::json!("abc123"));
        assert_eq!(entry.fields["message"], serde_json::json!("hello"));
    }

    #[test]
    fn dlp_inactive_does_not_redact() {
        let role = admin_role();
        let dlp = DlpConfig {
            active: false,
            pii_patterns: vec!["user_*".into()],
        };
        let mut entry = LogEntry {
            id: "1".into(),
            timestamp: "2026-04-06T10:00:00Z".into(),
            plane: Plane::App,
            backend: "victorialogs".into(),
            source: "node-1".into(),
            fields: HashMap::from([("user_email".into(), serde_json::json!("john@acme.com"))]),
            signature_status: SignatureStatus::Unverified,
        };

        apply_dlp(&mut entry, &dlp, &role);
        assert_eq!(
            entry.fields["user_email"],
            serde_json::json!("john@acme.com")
        );
    }

    #[tokio::test]
    async fn dlp_applied_in_query_with_role_dlp() {
        use crate::features::log_backend::sokolsky::MockLogBackend;

        let entry = LogEntry {
            id: "1".into(),
            timestamp: "2026-04-06T10:00:00Z".into(),
            plane: Plane::App,
            backend: "victorialogs".into(),
            source: "node-1".into(),
            fields: HashMap::from([
                ("user_email".into(), serde_json::json!("jane@acme.com")),
                ("trace_id".into(), serde_json::json!("xyz789")),
            ]),
            signature_status: SignatureStatus::Unverified,
        };
        let vl = MockLogBackend::new("victorialogs", vec![entry]);
        let backends: Vec<&dyn LogBackend> = vec![&vl];

        let role = admin_role();
        let dlp = DlpConfig {
            active: true,
            pii_patterns: vec!["user_*".into()],
        };
        let query = LogQuery {
            plane: Some(Plane::App),
            backend: Some("victorialogs".into()),
            ..Default::default()
        };

        let results = query_with_role_dlp(&backends, &role, &query, &dlp)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].fields["user_email"],
            serde_json::json!("[REDACTED]")
        );
        assert_eq!(results[0].fields["trace_id"], serde_json::json!("xyz789"));
    }
}
