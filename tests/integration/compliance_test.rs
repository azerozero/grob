//! Compliance integration tests
//!
//! Verifies EU AI Act compliance features: audit logging with model name,
//! token counts, risk classification, and audit entry signing.

use grob::security::audit_log::{AuditConfig, AuditEvent, AuditLog, RiskLevel, SigningAlgorithm};
use grob::server::AuditEntryBuilder;
use tempfile::TempDir;

fn create_audit_log(temp_dir: &TempDir) -> AuditLog {
    let log_dir = temp_dir.path().to_path_buf();
    AuditLog::new(AuditConfig {
        log_dir,
        sign_key_path: None,
        signing_algorithm: SigningAlgorithm::default(),
        hmac_key_path: None,
    })
    .expect("Should create audit log")
}

#[test]
fn test_audit_log_creates_successfully() {
    let temp_dir = TempDir::new().unwrap();
    let _audit = create_audit_log(&temp_dir);
    assert!(temp_dir.path().exists());
}

#[test]
fn test_audit_log_writes_entry() {
    let temp_dir = TempDir::new().unwrap();
    let audit = create_audit_log(&temp_dir);

    let entry = AuditEntryBuilder::new(
        "tenant-1",
        AuditEvent::Response,
        "anthropic",
        "127.0.0.1",
        42,
    )
    .build();
    audit.write(entry).expect("Should write audit entry");

    // Verify log file was created with content
    let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !entries.is_empty(),
        "Should have created at least one audit log file"
    );
}

#[test]
fn test_audit_log_with_compliance_fields() {
    let temp_dir = TempDir::new().unwrap();
    let audit = create_audit_log(&temp_dir);

    // Log with model name, token counts, and risk level (EU AI Act fields)
    let entry = AuditEntryBuilder::new(
        "tenant-1",
        AuditEvent::Response,
        "anthropic",
        "127.0.0.1",
        150,
    )
    .model("claude-3-5-sonnet-20241022") // Article 12
    .tokens(1000, 500) // Article 12
    .risk(RiskLevel::Low) // Article 14
    .build();
    audit.write(entry).expect("Should write audit entry");

    // Read and verify the log entry contains compliance fields
    let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();

    if let Some(entry) = entries.first() {
        let content = std::fs::read_to_string(entry.path()).unwrap();
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("Audit entry should be valid JSON");
            // Verify compliance fields are present
            assert_eq!(
                parsed["model_name"].as_str(),
                Some("claude-3-5-sonnet-20241022"),
                "Should contain model_name"
            );
            assert_eq!(
                parsed["input_tokens"].as_u64(),
                Some(1000),
                "Should contain input_tokens"
            );
            assert_eq!(
                parsed["output_tokens"].as_u64(),
                Some(500),
                "Should contain output_tokens"
            );
        }
    }
}

#[test]
fn test_audit_chain_integrity() {
    let temp_dir = TempDir::new().unwrap();
    let audit = create_audit_log(&temp_dir);

    // Write two entries — second should chain from first
    let entry1 = AuditEntryBuilder::new(
        "tenant-1",
        AuditEvent::Request,
        "anthropic",
        "127.0.0.1",
        10,
    )
    .build();
    let entry2 = AuditEntryBuilder::new(
        "tenant-1",
        AuditEvent::Response,
        "anthropic",
        "127.0.0.1",
        50,
    )
    .build();

    audit.write(entry1).expect("Should write first entry");
    audit.write(entry2).expect("Should write second entry");

    let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "jsonl")
                .unwrap_or(false)
        })
        .collect();

    if let Some(entry) = entries.first() {
        let content = std::fs::read_to_string(entry.path()).unwrap();
        let lines: Vec<_> = content.lines().filter(|l| !l.is_empty()).collect();
        assert!(lines.len() >= 2, "Should have at least 2 entries");

        // Second entry should have a non-empty previous_hash (chained)
        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let prev_hash = second["previous_hash"].as_str().unwrap_or("");
        assert!(
            !prev_hash.is_empty(),
            "Second entry should chain from first"
        );
    }
}

#[test]
fn test_risk_level_ordering() {
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::High < RiskLevel::Critical);
}

#[test]
fn test_risk_assessment() {
    // No violations → Low risk
    let risk = grob::security::risk::assess_risk(0, false, false, false);
    assert_eq!(risk, RiskLevel::Low);

    // DLP violations → Medium or higher
    let risk = grob::security::risk::assess_risk(3, true, false, false);
    assert!(
        risk >= RiskLevel::Medium,
        "DLP violations should raise risk"
    );

    // Injection attempt → High or higher
    let risk = grob::security::risk::assess_risk(1, true, true, false);
    assert!(
        risk >= RiskLevel::High,
        "Injection should raise risk to High+"
    );
}
