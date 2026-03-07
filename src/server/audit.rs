use crate::security::AuditLog;
use tracing::error;

/// Builder for constructing AuditEntry with optional EU AI Act fields.
pub struct AuditEntryBuilder {
    tenant_id: String,
    action: crate::security::audit_log::AuditEvent,
    backend: String,
    dlp_rules: Vec<String>,
    ip: String,
    duration_ms: u64,
    model_name: Option<String>,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    risk_level: Option<crate::security::audit_log::RiskLevel>,
}

impl AuditEntryBuilder {
    /// Creates a builder with required audit fields populated.
    pub fn new(
        tenant_id: &str,
        action: crate::security::audit_log::AuditEvent,
        backend: &str,
        ip: &str,
        duration_ms: u64,
    ) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            action,
            backend: backend.to_string(),
            dlp_rules: vec![],
            ip: ip.to_string(),
            duration_ms,
            model_name: None,
            input_tokens: None,
            output_tokens: None,
            risk_level: None,
        }
    }

    /// Sets the DLP rules triggered during the request.
    pub fn dlp_rules(mut self, rules: Vec<String>) -> Self {
        self.dlp_rules = rules;
        self
    }

    /// Sets the model name for EU AI Act audit compliance.
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model_name = Some(model.into());
        self
    }

    /// Sets input and output token counts for audit logging.
    pub fn tokens(mut self, input: u32, output: u32) -> Self {
        self.input_tokens = Some(input);
        self.output_tokens = Some(output);
        self
    }

    /// Sets the risk level classification for the audit entry.
    pub fn risk(mut self, level: crate::security::audit_log::RiskLevel) -> Self {
        self.risk_level = Some(level);
        self
    }

    /// Consumes the builder and produces a finalized audit entry.
    pub fn build(self) -> crate::security::audit_log::AuditEntry {
        use crate::security::audit_log::{AuditEntry, Classification};
        AuditEntry {
            timestamp: chrono::Utc::now(),
            event_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: self.tenant_id,
            user_id: None,
            action: self.action,
            classification: Classification::Nc,
            backend_routed: self.backend,
            request_hash: None,
            dlp_rules_triggered: self.dlp_rules,
            ip_source: self.ip,
            duration_ms: self.duration_ms,
            previous_hash: String::new(),       // filled by write()
            signature: vec![],                  // filled by write()
            signature_algorithm: String::new(), // filled by write()
            model_name: self.model_name,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            risk_level: self.risk_level,
        }
    }
}

/// EU AI Act compliance fields for audit log entries.
pub(crate) struct AuditCompliance<'a> {
    pub config: &'a crate::cli::ComplianceConfig,
    pub model_name: Option<&'a str>,
    pub token_counts: Option<(u32, u32)>,
    pub risk_level: Option<crate::security::audit_log::RiskLevel>,
}

/// Parameters for writing an audit log entry.
pub(crate) struct AuditParams<'a> {
    pub audit_log: &'a AuditLog,
    pub tenant_id: &'a str,
    pub action: crate::security::audit_log::AuditEvent,
    pub backend: &'a str,
    pub dlp_rules: Vec<String>,
    pub ip: &'a str,
    pub duration_ms: u64,
    pub eu: AuditCompliance<'a>,
}

/// Fire-and-forget audit log entry writer.
/// Builds an `AuditEntry` and writes it; errors are logged but never propagate.
/// When EU AI Act compliance is enabled, conditionally records model name, token counts,
/// and risk level per Articles 12 and 14.
pub(crate) fn log_audit(p: &AuditParams<'_>) {
    let mut builder = AuditEntryBuilder::new(p.tenant_id, p.action, p.backend, p.ip, p.duration_ms)
        .dlp_rules(p.dlp_rules.clone());
    if p.eu.config.enabled && p.eu.config.audit_model_name {
        if let Some(m) = p.eu.model_name {
            builder = builder.model(m);
        }
    }
    if p.eu.config.enabled && p.eu.config.audit_token_counts {
        if let Some((i, o)) = p.eu.token_counts {
            builder = builder.tokens(i, o);
        }
    }
    if p.eu.config.enabled && p.eu.config.risk_classification {
        if let Some(r) = p.eu.risk_level {
            builder = builder.risk(r);
        }
    }
    if let Err(e) = p.audit_log.write(builder.build()) {
        error!("Audit write failed: {}", e);
    }
}
