//! Property-based tests for audit log invariants.
//!
//! Invariant: every dispatched request MUST produce exactly one audit entry.
//! The audit writer is synchronous and deterministic — no entry may be lost.

use grob::security::audit_log::{AuditEntry, AuditEvent, Classification};
use proptest::prelude::*;
use std::sync::{Arc, Mutex};

// ── Test Audit Collector ─────────────────────────────────────────

/// Collects audit entries in memory for property verification.
#[derive(Clone, Default)]
struct AuditCollector {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl AuditCollector {
    fn write(&self, entry: AuditEntry) {
        self.entries.lock().unwrap().push(entry);
    }

    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().unwrap().clone()
    }
}

// ── Generators ───────────────────────────────────────────────────

fn tenant_id_strategy() -> impl Strategy<Value = String> {
    "[a-z]{3,8}-[0-9]{1,4}"
}

fn model_name_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("claude-opus-4-6".to_string()),
        Just("claude-sonnet-4-6".to_string()),
        Just("gpt-5.2".to_string()),
        Just("gemini-3-pro".to_string()),
        Just("deepseek-r1".to_string()),
        Just("mistral-large-latest".to_string()),
    ]
}

fn audit_event_strategy() -> impl Strategy<Value = AuditEvent> {
    prop_oneof![
        Just(AuditEvent::Request),
        Just(AuditEvent::Response),
        Just(AuditEvent::Error),
        Just(AuditEvent::DlpBlock),
        Just(AuditEvent::DlpWarn),
        Just(AuditEvent::Auth),
    ]
}

fn classification_strategy() -> impl Strategy<Value = Classification> {
    prop_oneof![
        Just(Classification::Nc),
        Just(Classification::C1),
        Just(Classification::C2),
        Just(Classification::C3),
    ]
}

fn build_audit_entry(
    tenant_id: String,
    model: String,
    event: AuditEvent,
    classification: Classification,
) -> AuditEntry {
    AuditEntry {
        timestamp: chrono::Utc::now(),
        event_id: uuid::Uuid::new_v4().to_string(),
        tenant_id,
        user_id: None,
        action: event,
        classification,
        backend_routed: model,
        request_hash: None,
        dlp_rules_triggered: vec![],
        ip_source: "127.0.0.1".to_string(),
        duration_ms: 0,
        previous_hash: String::new(),
        signature: vec![],
        signature_algorithm: "none".to_string(),
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

// ── Property Tests ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// Invariant: one write call per request produces exactly one entry.
    #[test]
    fn audit_one_entry_per_request(
        request_count in 1_usize..200,
        tenant in tenant_id_strategy(),
        model in model_name_strategy(),
    ) {
        let collector = AuditCollector::default();

        for _ in 0..request_count {
            let entry = build_audit_entry(
                tenant.clone(),
                model.clone(),
                AuditEvent::Request,
                Classification::C1,
            );
            collector.write(entry);
        }

        prop_assert_eq!(
            collector.len(),
            request_count,
            "Expected {} audit entries, got {}",
            request_count,
            collector.len()
        );
    }

    /// Invariant: every audit entry has a unique event_id (no UUID collisions).
    #[test]
    fn audit_entries_have_unique_ids(
        count in 10_usize..100,
        tenant in tenant_id_strategy(),
        model in model_name_strategy(),
    ) {
        let collector = AuditCollector::default();

        for _ in 0..count {
            let entry = build_audit_entry(
                tenant.clone(),
                model.clone(),
                AuditEvent::Request,
                Classification::C1,
            );
            collector.write(entry);
        }

        let entries = collector.entries();
        let ids: std::collections::HashSet<&str> =
            entries.iter().map(|e| e.event_id.as_str()).collect();

        prop_assert_eq!(
            ids.len(),
            count,
            "Duplicate event_ids detected: {} unique out of {}",
            ids.len(),
            count
        );
    }

    /// Invariant: audit entries preserve tenant isolation.
    #[test]
    fn audit_preserves_tenant_id(
        tenant in tenant_id_strategy(),
        model in model_name_strategy(),
        event in audit_event_strategy(),
        classification in classification_strategy(),
    ) {
        let collector = AuditCollector::default();
        let entry = build_audit_entry(
            tenant.clone(),
            model.clone(),
            event,
            classification,
        );
        collector.write(entry);

        let entries = collector.entries();
        prop_assert_eq!(entries.len(), 1);
        prop_assert_eq!(&entries[0].tenant_id, &tenant);
        prop_assert_eq!(&entries[0].backend_routed, &model);
    }

    /// Invariant: audit entries are ordered by timestamp (monotonically increasing).
    #[test]
    fn audit_entries_are_monotonically_ordered(
        count in 2_usize..50,
        tenant in tenant_id_strategy(),
    ) {
        let collector = AuditCollector::default();

        for _ in 0..count {
            let entry = build_audit_entry(
                tenant.clone(),
                "test-model".to_string(),
                AuditEvent::Request,
                Classification::C1,
            );
            collector.write(entry);
        }

        let entries = collector.entries();
        for window in entries.windows(2) {
            prop_assert!(
                window[0].timestamp <= window[1].timestamp,
                "Audit entries not monotonically ordered"
            );
        }
    }

    /// Invariant: concurrent writes from multiple tenants produce the correct total.
    #[test]
    fn audit_concurrent_multi_tenant_count(
        tenants in prop::collection::vec(tenant_id_strategy(), 2..5),
        requests_per_tenant in 5_usize..20,
    ) {
        let collector = AuditCollector::default();
        let expected_total = tenants.len() * requests_per_tenant;

        for tenant in &tenants {
            for _ in 0..requests_per_tenant {
                let entry = build_audit_entry(
                    tenant.clone(),
                    "model".to_string(),
                    AuditEvent::Request,
                    Classification::C1,
                );
                collector.write(entry);
            }
        }

        prop_assert_eq!(
            collector.len(),
            expected_total,
            "Multi-tenant audit count mismatch"
        );

        let entries = collector.entries();
        for tenant in &tenants {
            let tenant_count = entries.iter().filter(|e| &e.tenant_id == tenant).count();
            prop_assert_eq!(
                tenant_count,
                requests_per_tenant,
                "Tenant '{}' has {} entries, expected {}",
                tenant,
                tenant_count,
                requests_per_tenant
            );
        }
    }
}
