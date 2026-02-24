use super::config::DlpConfig;
use super::DlpEngine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Manages per-API-key DLP engine instances for session isolation.
///
/// When sessions are enabled, each unique API key gets its own `DlpEngine`
/// with a session-specific `NameAnonymizer` (different pseudonyms) and
/// a fresh `CanaryGenerator` (independent counter). When disabled, all
/// requests share the global engine.
pub struct DlpSessionManager {
    global_engine: Arc<DlpEngine>,
    sessions: RwLock<HashMap<String, Arc<DlpEngine>>>,
    config: DlpConfig,
    sessions_enabled: bool,
}

impl DlpSessionManager {
    /// Build a session manager from config. Returns `None` if DLP is disabled.
    pub fn from_config(config: DlpConfig) -> Option<Arc<Self>> {
        let global_engine = DlpEngine::from_config(config.clone())?;
        Some(Arc::new(Self {
            global_engine,
            sessions: RwLock::new(HashMap::new()),
            sessions_enabled: config.enable_sessions,
            config,
        }))
    }

    /// Get the DLP engine for a given API key.
    ///
    /// - Sessions disabled → returns global engine
    /// - No API key → returns global engine
    /// - Sessions enabled + key → returns cached or newly-created session engine
    pub fn engine_for(&self, api_key: Option<&str>) -> Arc<DlpEngine> {
        if !self.sessions_enabled {
            return Arc::clone(&self.global_engine);
        }

        let key = match api_key {
            Some(k) if !k.is_empty() => k,
            _ => return Arc::clone(&self.global_engine),
        };

        let session_id = Self::hash_key(key);

        // Fast path: read lock
        {
            let sessions = self.sessions.read().unwrap();
            if let Some(engine) = sessions.get(&session_id) {
                return Arc::clone(engine);
            }
        }

        // Slow path: write lock (first request for this key)
        let mut sessions = self.sessions.write().unwrap();
        // Double-check after acquiring write lock
        if let Some(engine) = sessions.get(&session_id) {
            return Arc::clone(engine);
        }

        let engine = self.build_session_engine(&session_id);
        sessions.insert(session_id, Arc::clone(&engine));
        engine
    }

    /// Get a reference to the global engine (useful for test assertions).
    #[cfg(test)]
    pub fn global_engine(&self) -> &Arc<DlpEngine> {
        &self.global_engine
    }

    /// SHA256 hash of API key → hex string (session identifier).
    fn hash_key(api_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Build a new DLP engine with session-specific anonymizer and canary generator.
    fn build_session_engine(&self, session_id: &str) -> Arc<DlpEngine> {
        let scanner =
            super::dfa::SecretScanner::new(&self.config.secrets, &self.config.custom_prefixes);
        let anonymizer = super::names::NameAnonymizer::new_with_session(
            &self.config.names,
            session_id.as_bytes(),
        );
        let canary_gen = Arc::new(super::canary::CanaryGenerator::new());
        let sprt = if self.config.entropy.enabled {
            Some(super::sprt::SprtDetector::new())
        } else {
            None
        };
        let pii_scanner = super::pii::PiiScanner::from_config(&self.config.pii);

        tracing::debug!(
            "DLP: created session engine for key hash {}",
            &session_id[..8]
        );

        Arc::new(DlpEngine {
            config: self.config.clone(),
            scanner,
            anonymizer,
            canary_gen,
            sprt,
            pii_scanner,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::dlp::config::*;

    fn test_config(enable_sessions: bool) -> DlpConfig {
        DlpConfig {
            enabled: true,
            scan_input: true,
            scan_output: true,
            rules_file: String::new(),
            no_builtins: true,
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
            enable_sessions,
        }
    }

    #[test]
    fn test_sessions_disabled_returns_global() {
        let mgr = DlpSessionManager::from_config(test_config(false)).unwrap();
        let e1 = mgr.engine_for(Some("key-a"));
        let e2 = mgr.engine_for(Some("key-b"));
        assert!(Arc::ptr_eq(&e1, &e2), "Should return same global engine");
        assert!(
            Arc::ptr_eq(&e1, mgr.global_engine()),
            "Should be the global engine"
        );
    }

    #[test]
    fn test_sessions_enabled_isolates_keys() {
        let mgr = DlpSessionManager::from_config(test_config(true)).unwrap();
        let e_a = mgr.engine_for(Some("key-a"));
        let e_b = mgr.engine_for(Some("key-b"));
        assert!(
            !Arc::ptr_eq(&e_a, &e_b),
            "Different keys should get different engines"
        );

        // Same key returns same engine
        let e_a2 = mgr.engine_for(Some("key-a"));
        assert!(
            Arc::ptr_eq(&e_a, &e_a2),
            "Same key should return cached engine"
        );
    }

    #[test]
    fn test_no_key_returns_global() {
        let mgr = DlpSessionManager::from_config(test_config(true)).unwrap();
        let e_none = mgr.engine_for(None);
        let e_empty = mgr.engine_for(Some(""));
        assert!(
            Arc::ptr_eq(&e_none, mgr.global_engine()),
            "None key should return global"
        );
        assert!(
            Arc::ptr_eq(&e_empty, mgr.global_engine()),
            "Empty key should return global"
        );
    }

    #[test]
    fn test_different_pseudonyms_per_session() {
        let mgr = DlpSessionManager::from_config(test_config(true)).unwrap();
        let e_a = mgr.engine_for(Some("key-a"));
        let e_b = mgr.engine_for(Some("key-b"));

        let text_a = e_a.sanitize_text("Thales");
        let text_b = e_b.sanitize_text("Thales");

        assert_ne!(
            text_a.as_ref(),
            text_b.as_ref(),
            "Different sessions should produce different pseudonyms"
        );
        assert!(
            !text_a.contains("Thales"),
            "Session A should anonymize Thales"
        );
        assert!(
            !text_b.contains("Thales"),
            "Session B should anonymize Thales"
        );
    }

    #[test]
    fn test_session_deterministic() {
        let mgr = DlpSessionManager::from_config(test_config(true)).unwrap();
        let e1 = mgr.engine_for(Some("stable-key"));
        let e2 = mgr.engine_for(Some("stable-key"));

        let text1 = e1.sanitize_text("Thales");
        let text2 = e2.sanitize_text("Thales");
        assert_eq!(
            text1.as_ref(),
            text2.as_ref(),
            "Same session should produce same pseudonyms"
        );
    }

    #[test]
    fn test_session_roundtrip() {
        let mgr = DlpSessionManager::from_config(test_config(true)).unwrap();
        let engine = mgr.engine_for(Some("roundtrip-key"));

        let anonymized = engine.sanitize_text("Working at Thales");
        assert!(!anonymized.contains("Thales"));

        let restored = engine.sanitize_response_text(&anonymized);
        assert!(
            restored.contains("Thales"),
            "Deanonymize should restore original name"
        );
    }

    #[test]
    fn test_session_produces_different_pseudonyms() {
        use crate::features::dlp::names::NameAnonymizer;
        let rules = vec![NameRule {
            term: "Thales".into(),
            action: NameAction::Pseudonym,
        }];

        let anon_a = NameAnonymizer::new_with_session(&rules, b"seed-a");
        let anon_b = NameAnonymizer::new_with_session(&rules, b"seed-b");

        let (text_a, _) = anon_a.anonymize_if_match("Thales").unwrap();
        let (text_b, _) = anon_b.anonymize_if_match("Thales").unwrap();

        assert_ne!(
            text_a, text_b,
            "Different seeds should produce different pseudonyms"
        );
    }

    #[test]
    fn test_hash_key_deterministic() {
        let h1 = DlpSessionManager::hash_key("test-api-key");
        let h2 = DlpSessionManager::hash_key("test-api-key");
        assert_eq!(h1, h2, "Same key should produce same hash");
        assert_eq!(h1.len(), 64, "SHA256 hex should be 64 chars");
        assert!(
            h1.chars().all(|c| c.is_ascii_hexdigit()),
            "Should be hex chars only"
        );
    }
}
