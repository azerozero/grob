//! Data Loss Prevention engine: PII redaction, secret scanning, prompt injection detection.

/// Built-in secret detection rules shipped with the engine.
pub mod builtins;
/// Canary token generation for watermarking redacted secrets.
pub mod canary;
/// Configuration structs for all DLP subsystems.
pub mod config;
/// DFA-based secret scanner with prefix-gated matching.
pub mod dfa;
/// Hot-reloadable runtime config for domain lists and patterns.
pub mod hot_config;
mod injection_patterns;
/// Name anonymization with reversible pseudonym mapping.
pub mod names;
/// PII detection for credit cards, IBANs, and BICs.
pub mod pii;
/// Prompt injection detection and blocking.
pub mod prompt_injection;
/// Per-session DLP state for multi-turn conversations.
pub mod session;
/// Cryptographically signed DLP config verification.
pub mod signed_config;
/// Sequential Probability Ratio Test for entropy-based leak detection.
pub mod sprt;
/// Streaming DLP support for SSE delta processing.
pub mod stream;
/// URL exfiltration detection and prevention (anti-EchoLeak).
pub mod url_exfil;

use crate::models::{
    CanonicalRequest, ContentBlock, KnownContentBlock, MessageContent, SystemPrompt,
};
use config::DlpConfig;
use std::borrow::Cow;
use std::sync::Arc;

/// Action performed by the DLP engine during sanitization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpAction {
    /// Strips or masks the offending content in-place.
    Redact,
    /// Replaces a secret with a traceable canary token.
    Canary,
    /// Rejects the entire request or response.
    Block,
    /// Logs the finding without altering the payload.
    Log,
    /// Replaces a real name with a reversible pseudonym.
    Pseudonym,
    /// Emits a warning without blocking.
    Warn,
    /// Restores pseudonyms back to real names in responses.
    Deanonymize,
}

impl std::fmt::Display for DlpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DlpAction::Redact => write!(f, "redact"),
            DlpAction::Canary => write!(f, "canary"),
            DlpAction::Block => write!(f, "block"),
            DlpAction::Log => write!(f, "log"),
            DlpAction::Pseudonym => write!(f, "pseudonym"),
            DlpAction::Warn => write!(f, "warn"),
            DlpAction::Deanonymize => write!(f, "deanonymize"),
        }
    }
}

/// Rule category that triggered a DLP action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpRuleType {
    /// API keys, tokens, PEM blocks, and other secrets.
    Secret,
    /// Personally identifiable information (credit cards, IBANs, BICs).
    Pii,
    /// Prompt injection attempts.
    Injection,
    /// URL-based data exfiltration (anti-EchoLeak).
    UrlExfil,
    /// Real-name anonymization or deanonymization.
    Name,
    /// SPRT entropy-based leak detection.
    Entropy,
}

impl std::fmt::Display for DlpRuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DlpRuleType::Secret => write!(f, "secret"),
            DlpRuleType::Pii => write!(f, "pii"),
            DlpRuleType::Injection => write!(f, "injection"),
            DlpRuleType::UrlExfil => write!(f, "url_exfil"),
            DlpRuleType::Name => write!(f, "name"),
            DlpRuleType::Entropy => write!(f, "entropy"),
        }
    }
}

/// Describes a single DLP action taken during sanitization.
#[derive(Debug, Clone)]
pub struct DlpActionReport {
    /// Action performed by the DLP engine.
    pub action: DlpAction,
    /// Rule category that triggered the action.
    pub rule_type: DlpRuleType,
    /// Human-readable detail (rule name, PII type, etc.).
    pub detail: String,
}

/// Error returned when DLP blocks a request or response.
#[derive(Debug)]
pub enum DlpBlockError {
    /// Indicates one or more prompt injection attempts were detected.
    InjectionBlocked(Vec<prompt_injection::InjectionDetection>),
    /// Indicates one or more URL exfiltration attempts were detected.
    UrlExfilBlocked(Vec<url_exfil::UrlExfilDetection>),
}

impl std::fmt::Display for DlpBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DlpBlockError::InjectionBlocked(dets) => {
                write!(f, "Prompt injection detected: ")?;
                for (i, d) in dets.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", d)?;
                }
                Ok(())
            }
            DlpBlockError::UrlExfilBlocked(dets) => {
                write!(f, "URL exfiltration detected: ")?;
                for (i, d) in dets.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", d)?;
                }
                Ok(())
            }
        }
    }
}

/// Central DLP engine combining all detection and replacement components.
pub struct DlpEngine {
    /// Resolved DLP configuration used to build all sub-scanners.
    pub config: DlpConfig,
    /// DFA-based scanner for secret patterns (API keys, tokens, PEM blocks).
    pub scanner: dfa::SecretScanner,
    /// Reversible name anonymizer mapping real names to pseudonyms.
    pub anonymizer: names::NameAnonymizer,
    /// Shared canary token generator for watermarking redacted secrets.
    pub canary_gen: Arc<canary::CanaryGenerator>,
    /// SPRT entropy detector, active only when entropy scanning is enabled.
    pub sprt: Option<sprt::SprtDetector>,
    /// PII scanner for credit cards, IBANs, and BICs with checksum validation.
    pub pii_scanner: Option<pii::PiiScanner>,
    /// URL exfiltration scanner, active only when url_exfil is enabled.
    pub url_exfil_scanner: Option<url_exfil::UrlExfilScanner>,
    /// Prompt injection detector, active only when injection scanning is enabled.
    pub injection_detector: Option<prompt_injection::InjectionDetector>,
    /// Shared hot-reloadable config for domain lists and injection patterns.
    pub hot_config: hot_config::SharedHotConfig,
}

impl DlpEngine {
    /// Build a DLP engine from config. Returns None if DLP is disabled.
    pub fn from_config(mut config: DlpConfig) -> Option<Arc<Self>> {
        if !config.enabled {
            return None;
        }

        // Load external rules if configured
        if let Err(e) = config.load_external_rules() {
            tracing::warn!("Failed to load external DLP rules: {}", e);
        }

        // Resolve builtins + user rules
        config.resolve_all_rules();

        let scanner = dfa::SecretScanner::new(&config.secrets, &config.custom_prefixes);
        let anonymizer = match config.names_mode {
            config::NamesMode::Manual => names::NameAnonymizer::new(&config.names),
            config::NamesMode::AutoDetect => names::NameAnonymizer::new_auto_detect(
                &config.names,
                config.auto_detect_cache_limit,
            ),
        };
        let canary_gen = Arc::new(canary::CanaryGenerator::new());
        let sprt = if config.entropy.enabled {
            Some(sprt::SprtDetector::new())
        } else {
            None
        };
        let pii_scanner = pii::PiiScanner::from_config(&config.pii);

        // Build shared hot config from inline lists
        let shared_hot = hot_config::build_initial_hot_config(
            &config.url_exfil.whitelist_domains,
            &config.url_exfil.blacklist_domains,
            &config.url_exfil.domain_match_mode,
            &config.prompt_injection.custom_patterns,
        );

        // Build URL exfiltration scanner
        let url_exfil_scanner = if config.url_exfil.enabled {
            Some(url_exfil::UrlExfilScanner::new(
                config.url_exfil.clone(),
                Arc::clone(&shared_hot),
            ))
        } else {
            None
        };

        // Build prompt injection detector
        let injection_detector = if config.prompt_injection.enabled {
            Some(prompt_injection::InjectionDetector::new(
                config.prompt_injection.clone(),
                Arc::clone(&shared_hot),
            ))
        } else {
            None
        };

        let secret_count = config.secrets.len() + config.custom_prefixes.len();
        let name_count = config.names.len();
        let pii_active = pii_scanner.is_some();
        tracing::info!(
            "DLP engine initialized: {} secret rules, {} name rules, entropy={}, pii={}, url_exfil={}, injection={}",
            secret_count,
            name_count,
            config.entropy.enabled,
            pii_active,
            config.url_exfil.enabled,
            config.prompt_injection.enabled,
        );

        metrics::gauge!("grob_dlp_rules_loaded", "type" => "secret").set(secret_count as f64);
        metrics::gauge!("grob_dlp_rules_loaded", "type" => "name").set(name_count as f64);

        Some(Arc::new(Self {
            config,
            scanner,
            anonymizer,
            canary_gen,
            sprt,
            pii_scanner,
            url_exfil_scanner,
            injection_detector,
            hot_config: shared_hot,
        }))
    }

    /// Sanitizes an outgoing request (prompt to LLM).
    ///
    /// Caller must check `config.scan_input` before calling.
    pub fn sanitize_request(&self, request: &mut CanonicalRequest) {
        let _ = self.sanitize_request_reported(request);
    }

    /// Sanitizes an outgoing request and collects action reports.
    ///
    /// Returns a list of [`DlpActionReport`]s describing every action taken.
    pub fn sanitize_request_reported(
        &self,
        request: &mut CanonicalRequest,
    ) -> Vec<DlpActionReport> {
        let mut reports = Vec::new();

        // Sanitize system prompt
        if let Some(ref mut system) = request.system {
            match system {
                SystemPrompt::Text(text) => {
                    let (new_text, r) = self.sanitize_text_reported(text);
                    reports.extend(r);
                    if let Cow::Owned(s) = new_text {
                        *text = s;
                    }
                }
                SystemPrompt::Blocks(blocks) => {
                    for block in blocks {
                        let (new_text, r) = self.sanitize_text_reported(&block.text);
                        reports.extend(r);
                        if let Cow::Owned(s) = new_text {
                            block.text = s;
                        }
                    }
                }
            }
        }

        // Sanitize messages
        for msg in &mut request.messages {
            match &mut msg.content {
                MessageContent::Text(text) => {
                    let (new_text, r) = self.sanitize_text_reported(text);
                    reports.extend(r);
                    if let Cow::Owned(s) = new_text {
                        *text = s;
                    }
                }
                MessageContent::Blocks(blocks) => {
                    for block in blocks {
                        if let ContentBlock::Known(KnownContentBlock::Text { text, .. }) = block {
                            let (new_text, r) = self.sanitize_text_reported(text);
                            reports.extend(r);
                            if let Cow::Owned(s) = new_text {
                                *text = s;
                            }
                        }
                    }
                }
            }
        }

        reports
    }

    /// Sanitize an outgoing request with block support.
    ///
    /// Returns `Err(DlpBlockError)` if prompt injection or URL exfiltration
    /// is detected with `action: block`. The request must NOT proceed to
    /// any provider when this returns an error.
    pub fn sanitize_request_checked(
        &self,
        request: &mut CanonicalRequest,
    ) -> Result<(), DlpBlockError> {
        let all_text = Self::extract_request_text(request);

        // Stage 0: Prompt injection detection (before name anonymization)
        if let Some(ref detector) = self.injection_detector {
            for text in &all_text {
                match detector.scan(text) {
                    prompt_injection::InjectionResult::Blocked(dets) => {
                        return Err(DlpBlockError::InjectionBlocked(dets));
                    }
                    prompt_injection::InjectionResult::Logged
                    | prompt_injection::InjectionResult::Clean => {}
                }
            }
        }

        // Stage 0.5: URL exfiltration detection on inbound requests
        if let Some(ref exfil) = self.url_exfil_scanner {
            for text in &all_text {
                if let Some(dets) = exfil.is_blocked(text) {
                    return Err(DlpBlockError::UrlExfilBlocked(dets));
                }
            }
        }

        // Then do normal sanitization (names, secrets, PII)
        self.sanitize_request(request);
        Ok(())
    }

    /// Extract all text content from a request for scanning.
    fn extract_request_text(request: &CanonicalRequest) -> Vec<&str> {
        let mut texts = Vec::new();
        if let Some(ref system) = request.system {
            match system {
                SystemPrompt::Text(text) => texts.push(text.as_str()),
                SystemPrompt::Blocks(blocks) => {
                    for block in blocks {
                        texts.push(block.text.as_str());
                    }
                }
            }
        }
        for msg in &request.messages {
            match &msg.content {
                MessageContent::Text(text) => texts.push(text.as_str()),
                MessageContent::Blocks(blocks) => {
                    for block in blocks {
                        if let ContentBlock::Known(KnownContentBlock::Text { text, .. }) = block {
                            texts.push(text.as_str());
                        }
                    }
                }
            }
        }
        texts
    }

    /// Sanitizes a single text string: names to pseudonyms, secrets to canary/redact.
    ///
    /// Returns `Cow::Borrowed` if no modifications were needed (zero allocation).
    /// Returns `Cow::Owned` only when text was actually modified.
    pub fn sanitize_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.sanitize_text_reported(text).0
    }

    /// Sanitizes a single text string and collects action reports.
    ///
    /// Returns the sanitized text and a list of [`DlpActionReport`]s.
    pub fn sanitize_text_reported<'a>(
        &self,
        text: &'a str,
    ) -> (Cow<'a, str>, Vec<DlpActionReport>) {
        let mut modified: Option<String> = None;
        let mut reports = Vec::new();

        // 1. Anonymize names first (before secret scan, in case names overlap)
        if !self.anonymizer.is_empty() {
            let current = modified.as_deref().unwrap_or(text);
            if let Some((anonymized, replacements)) = self.anonymizer.anonymize_if_match(current) {
                for (real, pseudo) in &replacements {
                    tracing::debug!("DLP name anonymized: '{}' → '{}'", real, pseudo);
                    metrics::counter!(
                        "grob_dlp_detections_total",
                        "type" => "name",
                        "rule" => real.clone(),
                        "action" => "pseudonym"
                    )
                    .increment(1);
                    reports.push(DlpActionReport {
                        action: DlpAction::Pseudonym,
                        rule_type: DlpRuleType::Name,
                        detail: format!("'{}' → '{}'", real, pseudo),
                    });
                }
                modified = Some(anonymized);
            }
        }

        // 2. Scan and replace secrets (only if prefix bytes present)
        if !self.scanner.is_empty() {
            let current = modified.as_deref().unwrap_or(text);
            if self.scanner.might_contain_secret(current) {
                if let Some((redacted, events)) = self.scanner.redact(current, &self.canary_gen) {
                    for event in &events {
                        tracing::debug!(
                            "DLP secret detected: rule='{}' action='{}'",
                            event.rule_name,
                            event.action
                        );
                        metrics::counter!(
                            "grob_dlp_detections_total",
                            "type" => "secret",
                            "rule" => event.rule_name.clone(),
                            "action" => event.action.clone()
                        )
                        .increment(1);
                        reports.push(DlpActionReport {
                            action: secret_action_to_dlp_action(&event.action),
                            rule_type: DlpRuleType::Secret,
                            detail: format!("rule={}", event.rule_name),
                        });
                    }
                    modified = Some(redacted);
                }
            }
        }

        // 3. Scan for PII (credit cards, IBAN, BIC) with mathematical validation
        if let Some(ref pii) = self.pii_scanner {
            let current = modified.as_deref().unwrap_or(text);
            if pii.might_contain_pii(current) {
                if let Some((redacted, detections)) = pii.redact(current) {
                    for det in &detections {
                        tracing::debug!("DLP PII detected: type='{}'", det.pii_type);
                        metrics::counter!(
                            "grob_dlp_detections_total",
                            "type" => "pii",
                            "rule" => det.pii_type.to_string(),
                            "action" => "redact"
                        )
                        .increment(1);
                        reports.push(DlpActionReport {
                            action: DlpAction::Redact,
                            rule_type: DlpRuleType::Pii,
                            detail: format!("type={}", det.pii_type),
                        });
                    }
                    modified = Some(redacted);
                }
            }
        }

        let result = match modified {
            Some(s) => Cow::Owned(s),
            None => Cow::Borrowed(text),
        };
        (result, reports)
    }

    /// De-anonymizes response text: pseudonyms to real names (for LLM to user).
    /// Also scans for secrets leaked in the response.
    ///
    /// Returns `Cow::Borrowed` if no modifications were needed (zero allocation).
    pub fn sanitize_response_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.sanitize_response_text_reported(text).0
    }

    /// De-anonymizes response text and collects action reports.
    ///
    /// Returns the sanitized text and a list of [`DlpActionReport`]s.
    pub fn sanitize_response_text_reported<'a>(
        &self,
        text: &'a str,
    ) -> (Cow<'a, str>, Vec<DlpActionReport>) {
        let mut modified: Option<String> = None;
        let mut reports = Vec::new();

        // 1. De-anonymize names (pseudonyms back to real names)
        if !self.anonymizer.is_empty() {
            let current = modified.as_deref().unwrap_or(text);
            if let Some(deanonymized) = self.anonymizer.deanonymize_if_match(current) {
                reports.push(DlpActionReport {
                    action: DlpAction::Deanonymize,
                    rule_type: DlpRuleType::Name,
                    detail: "pseudonyms restored".into(),
                });
                modified = Some(deanonymized);
            }
        }

        // 2. Scan response for secrets (LLM might have generated/leaked one)
        if !self.scanner.is_empty() {
            let current = modified.as_deref().unwrap_or(text);
            if self.scanner.might_contain_secret(current) {
                if let Some((redacted, events)) = self.scanner.redact(current, &self.canary_gen) {
                    for event in &events {
                        tracing::warn!(
                            "DLP secret in response: rule='{}' action='{}'",
                            event.rule_name,
                            event.action
                        );
                        metrics::counter!(
                            "grob_dlp_detections_total",
                            "type" => "secret",
                            "rule" => event.rule_name.clone(),
                            "action" => event.action.clone()
                        )
                        .increment(1);
                        reports.push(DlpActionReport {
                            action: secret_action_to_dlp_action(&event.action),
                            rule_type: DlpRuleType::Secret,
                            detail: format!("rule={}", event.rule_name),
                        });
                    }
                    modified = Some(redacted);
                }
            }
        }

        // 3. Scan response for PII
        if let Some(ref pii) = self.pii_scanner {
            let current = modified.as_deref().unwrap_or(text);
            if pii.might_contain_pii(current) {
                if let Some((redacted, detections)) = pii.redact(current) {
                    for det in &detections {
                        tracing::warn!("DLP PII in response: type='{}'", det.pii_type);
                        metrics::counter!(
                            "grob_dlp_detections_total",
                            "type" => "pii",
                            "rule" => det.pii_type.to_string(),
                            "action" => "redact"
                        )
                        .increment(1);
                        reports.push(DlpActionReport {
                            action: DlpAction::Redact,
                            rule_type: DlpRuleType::Pii,
                            detail: format!("type={}", det.pii_type),
                        });
                    }
                    modified = Some(redacted);
                }
            }
        }

        // 4. URL exfiltration scan (anti-EchoLeak)
        if let Some(ref exfil) = self.url_exfil_scanner {
            let current = modified.as_deref().unwrap_or(text);
            if let Cow::Owned(sanitized) = exfil.sanitize_response(current) {
                reports.push(DlpActionReport {
                    action: DlpAction::Redact,
                    rule_type: DlpRuleType::UrlExfil,
                    detail: "suspicious URL sanitized".into(),
                });
                modified = Some(sanitized);
            }
        }

        let result = match modified {
            Some(s) => Cow::Owned(s),
            None => Cow::Borrowed(text),
        };
        (result, reports)
    }

    /// Check response text for URL exfiltration block. Returns error if blocked.
    pub fn check_response_url_exfil(&self, text: &str) -> Result<(), DlpBlockError> {
        if let Some(ref exfil) = self.url_exfil_scanner {
            if let Some(dets) = exfil.is_blocked(text) {
                return Err(DlpBlockError::UrlExfilBlocked(dets));
            }
        }
        Ok(())
    }

    /// End-of-stream scan: detect cross-chunk secrets and pseudonyms that
    /// were split across SSE deltas. Can't unsend bytes, but emits alerts + metrics.
    pub fn scan_end_of_stream(&self, full_text: &str) {
        // DFA scan for cross-chunk secrets
        if !self.scanner.is_empty() && self.scanner.might_contain_secret(full_text) {
            if let Some((_, events)) = self.scanner.redact(full_text, &self.canary_gen) {
                for event in &events {
                    tracing::warn!(
                        "DLP cross-chunk secret detected: rule='{}'",
                        event.rule_name
                    );
                    metrics::counter!(
                        "grob_dlp_cross_chunk_total",
                        "rule" => event.rule_name.clone()
                    )
                    .increment(1);
                }
            }
        }
        // Name check: pseudonyms that weren't deanonymized per-delta (cross-chunk)
        if !self.anonymizer.is_empty() && self.anonymizer.deanonymize_if_match(full_text).is_some()
        {
            tracing::warn!("DLP cross-chunk pseudonym detected in final buffer");
            metrics::counter!("grob_dlp_cross_chunk_total", "rule" => "pseudonym").increment(1);
        }
        // URL exfil cross-chunk scan
        if let Some(ref exfil) = self.url_exfil_scanner {
            if exfil.might_contain_url(full_text) {
                let result = exfil.scan(full_text);
                if !matches!(result, url_exfil::UrlExfilResult::Clean) {
                    tracing::warn!("DLP cross-chunk URL exfiltration detected in final buffer");
                    metrics::counter!("grob_dlp_cross_chunk_total", "rule" => "url_exfil")
                        .increment(1);
                }
            }
        }
    }

    /// Run async SPRT entropy scan on completed response text.
    /// Spawns a tokio task, never blocks.
    pub fn scan_entropy_async(self: &Arc<Self>, full_text: String) {
        if self.sprt.is_some() {
            let engine = Arc::clone(self);
            tokio::spawn(async move {
                if let Some(ref sprt) = engine.sprt {
                    let alerts = sprt.scan(&full_text);
                    for alert in &alerts {
                        tracing::warn!(
                            "DLP entropy alert: entropy={:.2} at [{}-{}]: {}",
                            alert.entropy,
                            alert.start,
                            alert.end,
                            alert.text_snippet
                        );
                        metrics::counter!(
                            "grob_dlp_detections_total",
                            "type" => "entropy",
                            "rule" => "sprt",
                            "action" => "log"
                        )
                        .increment(1);
                    }
                }
            });
        }
    }
}

/// Maps a secret scanner action string to the corresponding [`DlpAction`] enum variant.
fn secret_action_to_dlp_action(action: &str) -> DlpAction {
    match action {
        "canary" => DlpAction::Canary,
        "redact" => DlpAction::Redact,
        "log" => DlpAction::Log,
        "block" => DlpAction::Block,
        "warn" => DlpAction::Warn,
        _ => DlpAction::Redact,
    }
}

// ── Trait implementation ──

#[cfg(feature = "dlp")]
impl crate::traits::DlpPipeline for DlpEngine {
    fn sanitize_request(&self, request: &mut CanonicalRequest) {
        self.sanitize_request(request);
    }

    fn sanitize_request_checked(
        &self,
        request: &mut CanonicalRequest,
    ) -> Result<(), DlpBlockError> {
        self.sanitize_request_checked(request)
    }

    fn sanitize_response_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        self.sanitize_response_text(text)
    }

    fn check_response_url_exfil(&self, text: &str) -> Result<(), DlpBlockError> {
        self.check_response_url_exfil(text)
    }

    fn scan_end_of_stream(&self, full_text: &str) {
        self.scan_end_of_stream(full_text);
    }

    fn scan_input_enabled(&self) -> bool {
        self.config.scan_input
    }

    fn scan_output_enabled(&self) -> bool {
        self.config.scan_output
    }
}

#[cfg(test)]
mod tests;
