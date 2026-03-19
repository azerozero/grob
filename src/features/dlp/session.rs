use super::config::DlpConfig;
use super::hot_config::SharedHotConfig;
use super::DlpEngine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

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
    /// Shared hot config (same Arc across all session engines).
    hot_config: SharedHotConfig,
    /// Tracks when the session seed was last rotated.
    last_rotation: Mutex<Instant>,
    /// How often to rotate the session seed (zero = never).
    rotation_interval: Duration,
}

impl DlpSessionManager {
    /// Build a session manager from config. Returns `None` if DLP is disabled.
    pub fn from_config(config: DlpConfig) -> Option<Arc<Self>> {
        let global_engine = DlpEngine::from_config(config.clone())?;
        let hot_config = Arc::clone(&global_engine.hot_config);
        let rotation_interval = if config.key_rotation_hours == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs(config.key_rotation_hours * 3600)
        };
        Some(Arc::new(Self {
            global_engine,
            sessions: RwLock::new(HashMap::new()),
            sessions_enabled: config.enable_sessions,
            config,
            hot_config,
            last_rotation: Mutex::new(Instant::now()),
            rotation_interval,
        }))
    }

    /// Get a reference to the shared hot config (for spawning hot-reload tasks).
    pub fn hot_config(&self) -> &SharedHotConfig {
        &self.hot_config
    }

    /// Get a reference to the DLP config.
    pub fn config(&self) -> &DlpConfig {
        &self.config
    }

    /// Get the DLP engine for a given session identifier.
    ///
    /// The `session_key` can be a tenant_id (from JWT), an API key hash,
    /// or None for the global engine.
    ///
    /// - Sessions disabled → returns global engine
    /// - No key → returns global engine
    /// - Sessions enabled + key → returns cached or newly-created session engine
    pub fn engine_for(&self, session_key: Option<&str>) -> Arc<DlpEngine> {
        self.maybe_rotate_key();

        if !self.sessions_enabled {
            return Arc::clone(&self.global_engine);
        }

        let key = match session_key {
            Some(k) if !k.is_empty() => k,
            _ => return Arc::clone(&self.global_engine),
        };

        let session_id = Self::hash_key(key);

        // Fast path: read lock
        {
            let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
            if let Some(engine) = sessions.get(&session_id) {
                return Arc::clone(engine);
            }
        }

        // Slow path: write lock (first request for this key)
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
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

    /// Rotates the session seed if the rotation interval has elapsed.
    ///
    /// Clears the session cache so new engines pick up the fresh seed.
    /// No-op when `key_rotation_hours` is 0.
    fn maybe_rotate_key(&self) {
        if self.rotation_interval.is_zero() {
            return;
        }

        let mut last = self.last_rotation.lock().unwrap_or_else(|e| e.into_inner());
        if last.elapsed() < self.rotation_interval {
            return;
        }

        // Clear session cache so new engines are built with a fresh random seed.
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        sessions.clear();
        *last = Instant::now();

        tracing::info!(
            "DLP key rotated (pseudonyms from previous session are no longer reversible)"
        );
    }

    /// Forces an immediate key rotation (test helper).
    #[cfg(test)]
    fn force_rotate(&self) {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        sessions.clear();
        let mut last = self.last_rotation.lock().unwrap_or_else(|e| e.into_inner());
        *last = Instant::now();
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

        // Share the same hot_config across all session engines
        let hot = Arc::clone(&self.hot_config);

        let url_exfil_scanner = if self.config.url_exfil.enabled {
            Some(super::url_exfil::UrlExfilScanner::new(
                self.config.url_exfil.clone(),
                Arc::clone(&hot),
            ))
        } else {
            None
        };

        let injection_detector = if self.config.prompt_injection.enabled {
            Some(super::prompt_injection::InjectionDetector::new(
                self.config.prompt_injection.clone(),
                Arc::clone(&hot),
            ))
        } else {
            None
        };

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
            url_exfil_scanner,
            injection_detector,
            hot_config: hot,
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
            url_exfil: Default::default(),
            prompt_injection: Default::default(),
            signed_config: Default::default(),
            key_rotation_hours: 24,
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

    #[test]
    fn test_rotation_clears_session_cache() {
        let mgr = DlpSessionManager::from_config(test_config(true)).unwrap();

        let e_before = mgr.engine_for(Some("key-rotate"));
        let _text_before = e_before.sanitize_text("Thales");

        // Force rotation: clears cache, so next engine_for creates a new engine.
        mgr.force_rotate();

        let e_after = mgr.engine_for(Some("key-rotate"));
        assert!(
            !Arc::ptr_eq(&e_before, &e_after),
            "After rotation, a new engine should be created"
        );
    }

    #[test]
    fn test_no_rotation_when_disabled() {
        let mut cfg = test_config(true);
        cfg.key_rotation_hours = 0;
        let mgr = DlpSessionManager::from_config(cfg).unwrap();

        let e1 = mgr.engine_for(Some("key-stable"));
        // Calling maybe_rotate_key should be a no-op when interval is zero.
        mgr.maybe_rotate_key();
        let e2 = mgr.engine_for(Some("key-stable"));

        assert!(
            Arc::ptr_eq(&e1, &e2),
            "With rotation disabled, same engine should be reused"
        );
    }
}
