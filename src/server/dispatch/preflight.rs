//! Request security and tool preflight stages that run before routing.

use super::{AuditEntry, DispatchContext};
use crate::features::watch::events::{DlpDirection, WatchEvent};
use crate::models::CanonicalRequest;
use crate::server::RequestError;

/// Runs the security and tool stages that must complete before routing.
///
/// Returns whether DLP acted on the request so post-route policy matching can
/// include the `dlp_triggered` signal.
pub(super) fn run(
    ctx: &DispatchContext<'_>,
    request: &mut CanonicalRequest,
) -> Result<bool, RequestError> {
    let dlp_triggered = scan_dlp_input(ctx, request)?;

    // Never forward a verbatim Responses body after mutating the canonical
    // request, otherwise the original unredacted bytes could bypass DLP.
    if dlp_triggered {
        request.extensions.responses_passthrough_body = None;
    }

    check_tool_spike(ctx, request)?;

    #[cfg(feature = "mcp")]
    if let Some(ref mcp) = ctx.state.security.mcp {
        crate::features::mcp::calibration::calibrate_tools(mcp, request);
    }

    match crate::features::tool_validation::validate_inbound_tools(
        request,
        &ctx.inner.config.tool_validation,
    ) {
        Ok(stripped) => warn_stripped_tools(&stripped),
        Err(reason) => return Err(RequestError::BadRequest(reason)),
    }

    if ctx.inner.config.pledge.enabled {
        let filter = crate::features::pledge::PledgeFilter::new(&ctx.inner.config.pledge);
        let token = ctx
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| ctx.headers.get("x-api-key").and_then(|v| v.to_str().ok()));
        filter.apply(request, ctx.tenant_id.as_deref(), token);
    }

    Ok(dlp_triggered)
}

#[inline]
pub(super) fn dlp_input_scan_disabled(scan_input: bool) -> bool {
    !scan_input
}

#[inline]
pub(super) fn should_escalate_compliance(enabled: bool, risk_classification: bool) -> bool {
    enabled && risk_classification
}

#[inline]
pub(super) fn dlp_reports_triggered<T>(reports: &[T]) -> bool {
    !reports.is_empty()
}

#[inline]
pub(super) fn redaction_audit_rules(
    reports: &[crate::features::dlp::DlpActionReport],
) -> Vec<String> {
    reports
        .iter()
        .map(|r| format!("{}: {}", r.rule_type, r.detail))
        .collect()
}

#[inline]
pub(super) fn reports_have_pii(reports: &[crate::features::dlp::DlpActionReport]) -> bool {
    reports
        .iter()
        .any(|r| matches!(r.rule_type, crate::features::dlp::DlpRuleType::Pii))
}

#[inline]
pub(super) fn warn_stripped_tools(stripped: &[String]) {
    if !stripped.is_empty() {
        tracing::warn!(
            tools = ?stripped,
            "tool validation: stripped malformed inbound tools"
        );
    }
}

fn scan_dlp_input(
    ctx: &DispatchContext<'_>,
    request: &mut CanonicalRequest,
) -> Result<bool, RequestError> {
    let Some(ref dlp_engine) = ctx.dlp else {
        return Ok(false);
    };
    if dlp_input_scan_disabled(dlp_engine.config.scan_input) {
        return Ok(false);
    }

    match dlp_engine.sanitize_request_checked(request) {
        Ok(reports) => {
            let triggered = dlp_reports_triggered(&reports);
            ctx.emit_dlp_events(&reports, DlpDirection::Request);
            if triggered {
                ctx.log_audit_if_enabled(AuditEntry {
                    action: crate::security::audit_log::AuditEvent::DlpWarn,
                    backend: "REDACTED",
                    dlp_rules: redaction_audit_rules(&reports),
                    duration_ms: ctx.start_time.elapsed().as_millis() as u64,
                    model_name: Some(&ctx.model),
                    token_counts: None,
                    risk_level: Some(crate::security::audit_log::RiskLevel::Medium),
                    dlp_blocked: false,
                    dlp_had_injection: false,
                    dlp_had_pii: reports_have_pii(&reports),
                    dlp_had_redact_or_warn: true,
                });
            }
            Ok(triggered)
        }
        Err(block_err) => {
            let (block_rule_type, block_detail) = match &block_err {
                crate::features::dlp::DlpBlockError::InjectionBlocked(dets) => {
                    ("injection", format!("{} injection(s) detected", dets.len()))
                }
                crate::features::dlp::DlpBlockError::UrlExfilBlocked(dets) => (
                    "url_exfil",
                    format!("{} exfiltration URL(s) detected", dets.len()),
                ),
                crate::features::dlp::DlpBlockError::IndirectInjectionBlocked(dets) => (
                    "indirect_injection",
                    format!("{} indirect injection(s) detected", dets.len()),
                ),
            };
            ctx.state.event_bus.emit(WatchEvent::DlpAction {
                request_id: ctx.req_id.to_string(),
                direction: DlpDirection::Request,
                action: "block".into(),
                rule_type: block_rule_type.into(),
                detail: block_detail,
                timestamp: chrono::Utc::now(),
            });

            let had_injection = matches!(
                &block_err,
                crate::features::dlp::DlpBlockError::InjectionBlocked(_)
                    | crate::features::dlp::DlpBlockError::IndirectInjectionBlocked(_)
            );
            let risk =
                crate::security::risk::assess_risk(&crate::security::risk::SecurityOutcome {
                    dlp_rules_triggered: 1,
                    was_blocked: true,
                    had_injection,
                    had_pii: false,
                });

            let compliance = &ctx.inner.config.compliance;
            if should_escalate_compliance(compliance.enabled, compliance.risk_classification) {
                let threshold = crate::security::audit_log::RiskLevel::from_str_threshold(
                    &compliance.escalation_threshold,
                );
                crate::security::risk::maybe_escalate(&crate::security::risk::EscalationEvent {
                    risk,
                    threshold,
                    webhook_url: &compliance.escalation_webhook,
                    event_id: ctx.req_id,
                    tenant_id: ctx.tenant_id.as_deref().unwrap_or("anon"),
                    model: &ctx.model,
                });
            }

            ctx.log_audit_if_enabled(AuditEntry {
                action: crate::security::audit_log::AuditEvent::DlpBlock,
                backend: "BLOCKED",
                dlp_rules: vec![block_err.to_string()],
                duration_ms: ctx.start_time.elapsed().as_millis() as u64,
                model_name: Some(&ctx.model),
                token_counts: None,
                risk_level: Some(risk),
                dlp_blocked: true,
                dlp_had_injection: had_injection,
                dlp_had_pii: false,
                dlp_had_redact_or_warn: false,
            });
            Err(RequestError::DlpBlocked(block_err.to_string()))
        }
    }
}

fn check_tool_spike(
    ctx: &DispatchContext<'_>,
    request: &CanonicalRequest,
) -> Result<(), RequestError> {
    use crate::security::tool_spike::{count_tool_blocks, resolve_key};
    use crate::security::SpikeAction;

    let Some(detector) = ctx.state.security.tool_spike_detector.as_ref() else {
        return Ok(());
    };

    let count = count_tool_blocks(request);
    let key = resolve_key(request, ctx.tenant_id.as_deref());

    match detector.observe(&key, count) {
        SpikeAction::Allow => Ok(()),
        SpikeAction::Warn => {
            metrics::counter!("grob_tool_spike_warn_total").increment(1);
            tracing::warn!(
                session = %key,
                rolling_total = detector.current_total(&key),
                threshold = detector.config().warn_per_min,
                "tool_spike: warn threshold crossed"
            );
            Ok(())
        }
        SpikeAction::Block => {
            metrics::counter!("grob_tool_spike_blocked_total").increment(1);
            let total = detector.current_total(&key);
            let block_threshold = detector.config().block_per_min;
            tracing::warn!(
                session = %key,
                rolling_total = total,
                threshold = block_threshold,
                "tool_spike: block threshold crossed, returning 429"
            );

            ctx.log_audit_if_enabled(AuditEntry {
                action: crate::security::audit_log::AuditEvent::ToolSpikeBlocked,
                backend: "BLOCKED",
                dlp_rules: vec![format!(
                    "tool_spike: {} tool calls in 60s window (threshold {})",
                    total, block_threshold
                )],
                duration_ms: ctx.start_time.elapsed().as_millis() as u64,
                model_name: Some(&ctx.model),
                token_counts: None,
                risk_level: Some(crate::security::audit_log::RiskLevel::High),
                dlp_blocked: true,
                dlp_had_injection: false,
                dlp_had_pii: false,
                dlp_had_redact_or_warn: false,
            });

            Err(RequestError::ToolSpikeBlocked(format!(
                "tool-call spike anomaly: {} tool calls observed in 60s window for session {} (block threshold {})",
                total, key, block_threshold
            )))
        }
    }
}
