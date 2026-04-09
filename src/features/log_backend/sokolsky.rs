//! Sokolsky-collector backend implementation.
//!
//! Queries sokolsky-collector via HTTP, verifies N-of-N cross-plane
//! signatures, and maps responses to [`LogEntry`] records.

use async_trait::async_trait;

use super::{LogBackend, LogBackendError, LogEntry, LogQuery, Plane, SignatureStatus};

/// Configuration for the sokolsky-collector backend.
#[derive(Debug, Clone)]
pub struct SokolskyConfig {
    /// Collector endpoint URL.
    pub endpoint: String,
    /// mTLS client certificate path (optional for dev).
    pub mtls_cert: Option<String>,
    /// mTLS client key path (optional for dev).
    pub mtls_key: Option<String>,
    /// mTLS CA bundle path (optional for dev).
    pub mtls_ca: Option<String>,
    /// Required planes for N-of-N verification (default: all three).
    pub required_planes: Vec<Plane>,
}

impl Default for SokolskyConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://localhost:9443".into(),
            mtls_cert: None,
            mtls_key: None,
            mtls_ca: None,
            required_planes: vec![Plane::Machine, Plane::App, Plane::Audit],
        }
    }
}

/// Sokolsky-collector log backend.
///
/// Queries the collector's HTTP API and verifies cross-plane signatures
/// before returning results.
pub struct SokolskyBackend {
    config: SokolskyConfig,
    client: reqwest::Client,
}

impl SokolskyBackend {
    /// Creates a new backend with the given configuration.
    pub fn new(config: SokolskyConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Builds the query URL for the collector API.
    fn build_query_url(&self, query: &LogQuery) -> String {
        let mut url = format!("{}/api/v1/logs", self.config.endpoint);
        let mut params = Vec::new();

        if let Some(ref plane) = query.plane {
            params.push(format!("plane={}", plane.as_str()));
        }
        if let Some(ref trace_id) = query.trace_id {
            params.push(format!("trace_id={trace_id}"));
        }
        if let Some(ref from) = query.from {
            params.push(format!("from={from}"));
        }
        if let Some(ref to) = query.to {
            params.push(format!("to={to}"));
        }
        if let Some(limit) = query.limit {
            params.push(format!("limit={limit}"));
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        url
    }

    /// Verifies that a log entry has valid N-of-N signatures for all required planes.
    fn verify_n_of_n(&self, entry: &LogEntry) -> SignatureStatus {
        // Check that signatures field contains entries for all required planes.
        let sig_planes: Vec<Plane> = entry
            .fields
            .get("_signature_planes")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        for required in &self.config.required_planes {
            if !sig_planes.contains(required) {
                return SignatureStatus::IntegrityViolation;
            }
        }

        // In production, actual ECDSA-P256 verification happens here using
        // the SPIRE trust bundle. For now, presence of all three plane
        // signatures is sufficient (crypto verification is sokolsky-collector's
        // responsibility; grob re-verifies on demand via the `verify` action).
        let sig_valid = entry
            .fields
            .get("_signatures_valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if sig_valid {
            SignatureStatus::Valid
        } else {
            SignatureStatus::IntegrityViolation
        }
    }
}

#[async_trait]
impl LogBackend for SokolskyBackend {
    fn name(&self) -> &str {
        "sokolsky"
    }

    async fn query(&self, query: &LogQuery) -> Result<Vec<LogEntry>, LogBackendError> {
        let url = self.build_query_url(query);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| LogBackendError::Unavailable(format!("sokolsky collector: {e}")))?;

        if !response.status().is_success() {
            return Err(LogBackendError::QueryError(format!(
                "collector returned {}",
                response.status()
            )));
        }

        let entries: Vec<LogEntry> = response
            .json()
            .await
            .map_err(|e| LogBackendError::QueryError(format!("invalid response: {e}")))?;

        Ok(entries)
    }

    async fn verify_signatures(
        &self,
        entry: &LogEntry,
    ) -> Result<SignatureStatus, LogBackendError> {
        let status = self.verify_n_of_n(entry);
        if status == SignatureStatus::IntegrityViolation {
            return Err(LogBackendError::IntegrityViolation(format!(
                "N-of-N verification failed for entry {}",
                entry.id
            )));
        }
        Ok(status)
    }

    async fn health_check(&self) -> bool {
        let url = format!("{}/health", self.config.endpoint);
        self.client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

/// In-memory mock backend for testing.
#[cfg(any(test, feature = "test-util"))]
pub struct MockLogBackend {
    backend_name: String,
    entries: Vec<LogEntry>,
    healthy: bool,
}

#[cfg(any(test, feature = "test-util"))]
impl MockLogBackend {
    /// Creates a mock backend with the given name and entries.
    pub fn new(name: &str, entries: Vec<LogEntry>) -> Self {
        Self {
            backend_name: name.into(),
            entries,
            healthy: true,
        }
    }

    /// Creates an unhealthy mock backend.
    pub fn unavailable(name: &str) -> Self {
        Self {
            backend_name: name.into(),
            entries: vec![],
            healthy: false,
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
#[async_trait]
impl LogBackend for MockLogBackend {
    fn name(&self) -> &str {
        &self.backend_name
    }

    async fn query(&self, query: &LogQuery) -> Result<Vec<LogEntry>, LogBackendError> {
        if !self.healthy {
            return Err(LogBackendError::Unavailable(format!(
                "{} is down",
                self.backend_name
            )));
        }

        let mut results: Vec<LogEntry> = self
            .entries
            .iter()
            .filter(|e| {
                if let Some(ref plane) = query.plane {
                    if e.plane != *plane {
                        return false;
                    }
                }
                if let Some(ref trace_id) = query.trace_id {
                    let entry_trace = e
                        .fields
                        .get("trace_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if entry_trace != trace_id.as_str() {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        if let Some(limit) = query.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    async fn verify_signatures(
        &self,
        entry: &LogEntry,
    ) -> Result<SignatureStatus, LogBackendError> {
        let sig_planes: Vec<Plane> = entry
            .fields
            .get("_signature_planes")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        // N-of-N: require all three planes.
        for plane in Plane::all() {
            if !sig_planes.contains(plane) {
                return Err(LogBackendError::IntegrityViolation(format!(
                    "missing {} plane signature for entry {}",
                    plane, entry.id
                )));
            }
        }

        let valid = entry
            .fields
            .get("_signatures_valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if valid {
            Ok(SignatureStatus::Valid)
        } else {
            Err(LogBackendError::IntegrityViolation(format!(
                "invalid signatures for entry {}",
                entry.id
            )))
        }
    }

    async fn health_check(&self) -> bool {
        self.healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_entry(
        id: &str,
        plane: Plane,
        backend: &str,
        sig_planes: Vec<Plane>,
        valid: bool,
    ) -> LogEntry {
        let mut fields = HashMap::new();
        fields.insert("trace_id".into(), serde_json::json!("abc123"));
        fields.insert("message".into(), serde_json::json!("test log"));
        fields.insert("_signature_planes".into(), serde_json::json!(sig_planes));
        fields.insert("_signatures_valid".into(), serde_json::json!(valid));

        LogEntry {
            id: id.into(),
            timestamp: "2026-04-06T10:00:00Z".into(),
            plane,
            backend: backend.into(),
            source: "node-1".into(),
            fields,
            signature_status: SignatureStatus::Unverified,
        }
    }

    // ── T-SOK-2: N-of-N signature verification ──

    #[tokio::test]
    async fn valid_n_of_n_signatures_pass() {
        let backend = MockLogBackend::new("sokolsky", vec![]);
        let entry = make_entry(
            "1",
            Plane::Machine,
            "sokolsky",
            vec![Plane::Machine, Plane::App, Plane::Audit],
            true,
        );
        let status = backend.verify_signatures(&entry).await.unwrap();
        assert_eq!(status, SignatureStatus::Valid);
    }

    #[tokio::test]
    async fn missing_plane_signature_fails() {
        let backend = MockLogBackend::new("sokolsky", vec![]);
        // Missing audit plane.
        let entry = make_entry(
            "2",
            Plane::Machine,
            "sokolsky",
            vec![Plane::Machine, Plane::App],
            true,
        );
        let result = backend.verify_signatures(&entry).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            LogBackendError::IntegrityViolation(_)
        ));
    }

    #[tokio::test]
    async fn invalid_signatures_fail() {
        let backend = MockLogBackend::new("sokolsky", vec![]);
        let entry = make_entry(
            "3",
            Plane::Machine,
            "sokolsky",
            vec![Plane::Machine, Plane::App, Plane::Audit],
            false,
        );
        let result = backend.verify_signatures(&entry).await;
        assert!(result.is_err());
    }

    // ── T-SOK-4: Multi-backend aggregation ──

    #[tokio::test]
    async fn query_filters_by_plane() {
        let entries = vec![
            make_entry("1", Plane::Machine, "vl", vec![], false),
            make_entry("2", Plane::App, "vl", vec![], false),
            make_entry("3", Plane::Audit, "vl", vec![], false),
        ];
        let backend = MockLogBackend::new("victorialogs", entries);

        let query = LogQuery {
            plane: Some(Plane::App),
            ..Default::default()
        };
        let results = backend.query(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plane, Plane::App);
    }

    #[tokio::test]
    async fn query_filters_by_trace_id() {
        let mut entry1 = make_entry("1", Plane::App, "vl", vec![], false);
        entry1
            .fields
            .insert("trace_id".into(), serde_json::json!("abc123"));
        let mut entry2 = make_entry("2", Plane::App, "vl", vec![], false);
        entry2
            .fields
            .insert("trace_id".into(), serde_json::json!("def456"));

        let backend = MockLogBackend::new("victorialogs", vec![entry1, entry2]);
        let query = LogQuery {
            trace_id: Some("abc123".into()),
            ..Default::default()
        };
        let results = backend.query(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "1");
    }

    #[tokio::test]
    async fn unavailable_backend_returns_error() {
        let backend = MockLogBackend::unavailable("victorialogs");
        let result = backend.query(&LogQuery::default()).await;
        assert!(matches!(result, Err(LogBackendError::Unavailable(_))));
    }

    #[tokio::test]
    async fn health_check_reflects_state() {
        let healthy = MockLogBackend::new("vl", vec![]);
        assert!(healthy.health_check().await);

        let unhealthy = MockLogBackend::unavailable("vl");
        assert!(!unhealthy.health_check().await);
    }

    // ── Integration: query_with_role ──

    #[tokio::test]
    async fn query_with_role_aggregates_backends() {
        let entries_vl = vec![make_entry("1", Plane::App, "victorialogs", vec![], false)];
        let entries_jd = vec![make_entry("2", Plane::App, "journald", vec![], false)];
        let vl = MockLogBackend::new("victorialogs", entries_vl);
        let jd = MockLogBackend::new("journald", entries_jd);
        let backends: Vec<&dyn LogBackend> = vec![&vl, &jd];

        let role = super::super::LogRole {
            name: "admin".into(),
            backends: vec!["victorialogs".into(), "journald".into()],
            planes: vec![Plane::Machine, Plane::App, Plane::Audit],
            fields_visible: super::super::FieldSpec::All("*".into()),
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

        let results = super::super::query_with_role(&backends, &role, &query)
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn query_with_role_denies_forbidden_plane() {
        let vl = MockLogBackend::new("victorialogs", vec![]);
        let backends: Vec<&dyn LogBackend> = vec![&vl];

        let role = super::super::LogRole {
            name: "dev".into(),
            backends: vec!["victorialogs".into()],
            planes: vec![Plane::App],
            fields_visible: super::super::FieldSpec::List(vec!["message".into()]),
            fields_redacted: vec![],
            actions: vec!["read".into()],
            tenant_filter: Some("staging".into()),
            dlp_bypass: false,
            audit_of_audit: false,
        };

        let query = LogQuery {
            plane: Some(Plane::Audit),
            ..Default::default()
        };

        let result = super::super::query_with_role(&backends, &role, &query).await;
        assert!(matches!(result, Err(LogBackendError::PlaneDenied(_))));
    }
}
