pub mod builtins;
pub mod canary;
pub mod config;
pub mod dfa;
pub mod hot_config;
mod injection_patterns;
pub mod names;
pub mod pii;
pub mod prompt_injection;
pub mod session;
pub mod signed_config;
pub mod sprt;
pub mod stream;
pub mod url_exfil;

use crate::models::{
    AnthropicRequest, ContentBlock, KnownContentBlock, MessageContent, SystemPrompt,
};
use config::DlpConfig;
use std::borrow::Cow;
use std::sync::Arc;

/// Error returned when DLP blocks a request or response.
#[derive(Debug)]
pub enum DlpBlockError {
    InjectionBlocked(Vec<prompt_injection::InjectionDetection>),
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
    pub config: DlpConfig,
    pub scanner: dfa::SecretScanner,
    pub anonymizer: names::NameAnonymizer,
    pub canary_gen: Arc<canary::CanaryGenerator>,
    pub sprt: Option<sprt::SprtDetector>,
    pub pii_scanner: Option<pii::PiiScanner>,
    pub url_exfil_scanner: Option<url_exfil::UrlExfilScanner>,
    pub injection_detector: Option<prompt_injection::InjectionDetector>,
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
        let anonymizer = names::NameAnonymizer::new(&config.names);
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

    /// Sanitize an outgoing request (prompt → LLM).
    /// Caller must check `config.scan_input` before calling.
    pub fn sanitize_request(&self, request: &mut AnthropicRequest) {
        // Sanitize system prompt
        if let Some(ref mut system) = request.system {
            match system {
                SystemPrompt::Text(text) => {
                    if let Cow::Owned(s) = self.sanitize_text(text) {
                        *text = s;
                    }
                }
                SystemPrompt::Blocks(blocks) => {
                    for block in blocks {
                        if let Cow::Owned(s) = self.sanitize_text(&block.text) {
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
                    if let Cow::Owned(s) = self.sanitize_text(text) {
                        *text = s;
                    }
                }
                MessageContent::Blocks(blocks) => {
                    for block in blocks {
                        if let ContentBlock::Known(KnownContentBlock::Text { text, .. }) = block {
                            if let Cow::Owned(s) = self.sanitize_text(text) {
                                *text = s;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Sanitize an outgoing request with block support.
    /// Returns `Err(DlpBlockError)` if prompt injection is detected with `action: block`.
    pub fn sanitize_request_checked(
        &self,
        request: &mut AnthropicRequest,
    ) -> Result<(), DlpBlockError> {
        // Stage 0: Prompt injection detection (before name anonymization)
        if let Some(ref detector) = self.injection_detector {
            let all_text = Self::extract_request_text(request);
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

        // Then do normal sanitization (names, secrets, PII)
        self.sanitize_request(request);
        Ok(())
    }

    /// Extract all text content from a request for scanning.
    fn extract_request_text(request: &AnthropicRequest) -> Vec<&str> {
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

    /// Sanitize a single text string: names → pseudonyms, secrets → canary/redact.
    ///
    /// Returns `Cow::Borrowed` if no modifications were needed (zero allocation).
    /// Returns `Cow::Owned` only when text was actually modified.
    pub fn sanitize_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut modified: Option<String> = None;

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
                    }
                    modified = Some(redacted);
                }
            }
        }

        match modified {
            Some(s) => Cow::Owned(s),
            None => Cow::Borrowed(text),
        }
    }

    /// De-anonymize response text: pseudonyms → real names (for LLM → user).
    /// Also scans for secrets leaked in the response.
    ///
    /// Returns `Cow::Borrowed` if no modifications were needed (zero allocation).
    pub fn sanitize_response_text<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut modified: Option<String> = None;

        // 1. De-anonymize names (pseudonyms back to real names)
        if !self.anonymizer.is_empty() {
            let current = modified.as_deref().unwrap_or(text);
            if let Some(deanonymized) = self.anonymizer.deanonymize_if_match(current) {
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
                    }
                    modified = Some(redacted);
                }
            }
        }

        // 4. URL exfiltration scan (anti-EchoLeak)
        if let Some(ref exfil) = self.url_exfil_scanner {
            let current = modified.as_deref().unwrap_or(text);
            if let Cow::Owned(sanitized) = exfil.sanitize_response(current) {
                modified = Some(sanitized);
            }
        }

        match modified {
            Some(s) => Cow::Owned(s),
            None => Cow::Borrowed(text),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use config::*;

    fn test_config() -> DlpConfig {
        DlpConfig {
            enabled: true,
            scan_input: true,
            scan_output: true,
            rules_file: String::new(),
            no_builtins: true, // disable builtins for focused unit tests
            secrets: vec![SecretRule {
                name: "github_token".into(),
                prefix: "ghp_".into(),
                pattern: "ghp_[A-Za-z0-9]{36}".into(),
                action: SecretAction::Canary,
            }],
            custom_prefixes: vec![],
            names: vec![NameRule {
                term: "Thales".into(),
                action: NameAction::Pseudonym,
            }],
            entropy: EntropyConfig::default(),
            pii: Default::default(),
            enable_sessions: false,
            url_exfil: Default::default(),
            prompt_injection: Default::default(),
            signed_config: Default::default(),
        }
    }

    #[test]
    fn test_sanitize_text_names() {
        let config = test_config();
        let engine = DlpEngine::from_config(config).unwrap();
        let result = engine.sanitize_text("Working at Thales");
        assert!(!result.contains("Thales"));
        assert!(matches!(result, Cow::Owned(_)));
    }

    #[test]
    fn test_sanitize_text_no_match_is_borrowed() {
        let config = test_config();
        let engine = DlpEngine::from_config(config).unwrap();
        let result = engine.sanitize_text("Hello world, nothing secret here");
        // No name, no secret prefix → should be Cow::Borrowed (zero alloc)
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_sanitize_text_secrets() {
        let config = test_config();
        let engine = DlpEngine::from_config(config).unwrap();
        let result = engine.sanitize_text("token: ghp_abcdefghijklmnopqrstuvwxyz1234567890");
        assert!(!result.contains("ghp_abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(result.contains("ghp_~CANARY"));
    }

    #[test]
    fn test_response_deanonymize() {
        let config = test_config();
        let engine = DlpEngine::from_config(config).unwrap();

        let anonymized = engine.sanitize_text("Working at Thales");
        assert!(!anonymized.contains("Thales"));

        let restored = engine.sanitize_response_text(&anonymized);
        assert!(restored.contains("Thales"));
    }

    #[test]
    fn test_disabled_returns_none() {
        let config = DlpConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(DlpEngine::from_config(config).is_none());
    }

    #[test]
    fn test_builtins_loaded_by_default() {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();
        // Should have loaded builtin rules (at least 20)
        assert!(
            engine.scanner.rules.len() >= 20,
            "Expected >= 20 builtin rules, got {}",
            engine.scanner.rules.len()
        );
    }

    #[test]
    fn test_builtins_opt_out() {
        let config = DlpConfig {
            enabled: true,
            no_builtins: true,
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();
        assert_eq!(engine.scanner.rules.len(), 0);
    }

    #[test]
    fn test_builtin_detects_openai_key() {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();
        let text = "my key is sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD";
        let result = engine.sanitize_text(text);
        assert!(
            result.contains("[REDACTED]"),
            "OpenAI key should be redacted, got: {}",
            result
        );
    }

    #[test]
    fn test_builtin_detects_pem_header() {
        let config = DlpConfig {
            enabled: true,
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();
        let text =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAHudeSA/x3hB2f-----END RSA PRIVATE KEY-----";
        let result = engine.sanitize_text(text);
        assert!(
            result.contains("[REDACTED]"),
            "PEM key should be redacted, got: {}",
            result
        );
    }
}
