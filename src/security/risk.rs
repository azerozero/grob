//! Risk classification for EU AI Act Article 14 compliance
//!
//! Assesses risk level based on DLP outcomes and request characteristics.

use crate::security::audit_log::RiskLevel;

/// DLP/security outcome for a single request, used as input to risk classification.
pub struct SecurityOutcome {
    pub dlp_rules_triggered: usize,
    pub was_blocked: bool,
    pub had_injection: bool,
    pub had_pii: bool,
}

/// Assess risk level for a request based on DLP and security outcomes.
pub fn assess_risk(outcome: &SecurityOutcome) -> RiskLevel {
    if outcome.had_injection || (outcome.was_blocked && outcome.had_pii) {
        RiskLevel::Critical
    } else if outcome.was_blocked {
        RiskLevel::High
    } else if outcome.had_pii || outcome.dlp_rules_triggered > 2 {
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
                metrics::counter!("grob_escalation_webhook_failures_total").increment(1);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(
        dlp_rules_triggered: usize,
        was_blocked: bool,
        had_injection: bool,
        had_pii: bool,
    ) -> SecurityOutcome {
        SecurityOutcome {
            dlp_rules_triggered,
            was_blocked,
            had_injection,
            had_pii,
        }
    }

    #[test]
    fn test_risk_low() {
        assert_eq!(
            assess_risk(&outcome(0, false, false, false)),
            RiskLevel::Low
        );
        assert_eq!(
            assess_risk(&outcome(1, false, false, false)),
            RiskLevel::Low
        );
    }

    #[test]
    fn test_risk_medium_pii() {
        assert_eq!(
            assess_risk(&outcome(0, false, false, true)),
            RiskLevel::Medium
        );
    }

    #[test]
    fn test_risk_medium_many_rules() {
        assert_eq!(
            assess_risk(&outcome(3, false, false, false)),
            RiskLevel::Medium
        );
    }

    #[test]
    fn test_risk_high_blocked() {
        assert_eq!(
            assess_risk(&outcome(1, true, false, false)),
            RiskLevel::High
        );
    }

    #[test]
    fn test_risk_critical_injection() {
        assert_eq!(
            assess_risk(&outcome(0, false, true, false)),
            RiskLevel::Critical
        );
    }

    #[test]
    fn test_risk_critical_blocked_pii() {
        assert_eq!(
            assess_risk(&outcome(1, true, false, true)),
            RiskLevel::Critical
        );
    }

    #[test]
    fn test_risk_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }
}
