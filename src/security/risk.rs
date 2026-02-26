//! Risk classification for EU AI Act Article 14 compliance
//!
//! Assesses risk level based on DLP outcomes and request characteristics.

use crate::security::audit_log::RiskLevel;

/// Assess risk level for a request based on DLP and security outcomes.
///
/// - `dlp_rules_triggered`: number of DLP rules that fired
/// - `was_blocked`: whether the request was blocked by DLP
/// - `had_injection`: whether prompt injection was detected
/// - `had_pii`: whether PII was detected in the request
pub fn assess_risk(
    dlp_rules_triggered: usize,
    was_blocked: bool,
    had_injection: bool,
    had_pii: bool,
) -> RiskLevel {
    if had_injection || (was_blocked && had_pii) {
        RiskLevel::Critical
    } else if was_blocked {
        RiskLevel::High
    } else if had_pii || dlp_rules_triggered > 2 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

/// Escalate risk events above threshold: emit metrics and optional webhook.
pub fn maybe_escalate(
    risk: RiskLevel,
    threshold: RiskLevel,
    webhook_url: &Option<String>,
    event_id: &str,
    tenant_id: &str,
    model: &str,
) {
    if risk < threshold {
        return;
    }

    metrics::counter!("grob_risk_escalation_total", "level" => format!("{:?}", risk)).increment(1);
    tracing::warn!(
        risk = ?risk,
        event_id = event_id,
        tenant_id = tenant_id,
        model = model,
        "EU AI Act risk escalation triggered"
    );

    if let Some(url) = webhook_url {
        let url = url.clone();
        let payload = serde_json::json!({
            "type": "risk_escalation",
            "risk_level": format!("{:?}", risk),
            "event_id": event_id,
            "tenant_id": tenant_id,
            "model": model,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        tokio::spawn(async move {
            if let Err(e) = reqwest::Client::new()
                .post(&url)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
            {
                tracing::error!("Risk escalation webhook failed: {}", e);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_low() {
        assert_eq!(assess_risk(0, false, false, false), RiskLevel::Low);
        assert_eq!(assess_risk(1, false, false, false), RiskLevel::Low);
    }

    #[test]
    fn test_risk_medium_pii() {
        assert_eq!(assess_risk(0, false, false, true), RiskLevel::Medium);
    }

    #[test]
    fn test_risk_medium_many_rules() {
        assert_eq!(assess_risk(3, false, false, false), RiskLevel::Medium);
    }

    #[test]
    fn test_risk_high_blocked() {
        assert_eq!(assess_risk(1, true, false, false), RiskLevel::High);
    }

    #[test]
    fn test_risk_critical_injection() {
        assert_eq!(assess_risk(0, false, true, false), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_critical_blocked_pii() {
        assert_eq!(assess_risk(1, true, false, true), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }
}
