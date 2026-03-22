//! HIT authorization: per-action cryptographic proof of human approval.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signed authorization for a single tool_use action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitAuthorization {
    /// Request ID this authorization belongs to.
    pub request_id: String,
    /// Tool name that was authorized.
    pub tool_name: String,
    /// SHA-256 hash of the tool_use input.
    pub tool_input_hash: String,
    /// Decision: "approve" or "deny".
    pub decision: String,
    /// Authentication method used (prompt, touchid, yubikey, etc.).
    pub auth_method: String,
    /// Who approved (user identifier).
    pub signer: String,
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// SHA-256 hash of the previous authorization (chain link).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    /// SHA-256 hash of this authorization entry.
    pub hash: String,
}

impl HitAuthorization {
    /// Creates a new authorization entry, chained to the previous one.
    pub fn new(
        request_id: String,
        tool_name: String,
        tool_input: &str,
        decision: &str,
        auth_method: String,
        signer: String,
        previous_hash: Option<String>,
    ) -> Self {
        let tool_input_hash = hex::encode(Sha256::digest(tool_input.as_bytes()));
        let timestamp = chrono::Utc::now().to_rfc3339();

        let mut entry = Self {
            request_id,
            tool_name,
            tool_input_hash,
            decision: decision.to_string(),
            auth_method,
            signer,
            timestamp,
            previous_hash,
            hash: String::new(),
        };

        entry.hash = entry.compute_hash();
        entry
    }

    /// Computes the SHA-256 hash of this entry (for chain integrity).
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.request_id.as_bytes());
        hasher.update(self.tool_name.as_bytes());
        hasher.update(self.tool_input_hash.as_bytes());
        hasher.update(self.decision.as_bytes());
        hasher.update(self.timestamp.as_bytes());
        if let Some(ref prev) = self.previous_hash {
            hasher.update(prev.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Verifies the hash chain integrity of this entry.
    pub fn verify(&self) -> bool {
        self.hash == self.compute_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_sign_verify() {
        let auth = HitAuthorization::new(
            "req-123".into(),
            "Bash".into(),
            "echo hello",
            "approve",
            "prompt".into(),
            "clement@company.com".into(),
            None,
        );

        assert!(auth.verify());
        assert_eq!(auth.decision, "approve");
        assert!(!auth.hash.is_empty());
        assert!(auth.previous_hash.is_none());
    }

    #[test]
    fn test_authorization_hash_chain() {
        let auth1 = HitAuthorization::new(
            "req-1".into(),
            "Read".into(),
            "/etc/passwd",
            "approve",
            "prompt".into(),
            "user".into(),
            None,
        );

        let auth2 = HitAuthorization::new(
            "req-2".into(),
            "Edit".into(),
            "config.toml",
            "approve",
            "touchid".into(),
            "user".into(),
            Some(auth1.hash.clone()),
        );

        let auth3 = HitAuthorization::new(
            "req-3".into(),
            "Bash".into(),
            "rm -rf /tmp",
            "deny",
            "prompt".into(),
            "user".into(),
            Some(auth2.hash.clone()),
        );

        // Chain integrity.
        assert!(auth1.verify());
        assert!(auth2.verify());
        assert!(auth3.verify());
        assert_eq!(auth2.previous_hash.as_ref().unwrap(), &auth1.hash);
        assert_eq!(auth3.previous_hash.as_ref().unwrap(), &auth2.hash);

        // Hashes are unique.
        assert_ne!(auth1.hash, auth2.hash);
        assert_ne!(auth2.hash, auth3.hash);
    }

    #[test]
    fn test_authorization_tamper_detection() {
        let mut auth = HitAuthorization::new(
            "req-1".into(),
            "Bash".into(),
            "safe command",
            "approve",
            "prompt".into(),
            "user".into(),
            None,
        );

        assert!(auth.verify());

        // Tamper with the decision.
        auth.decision = "deny".to_string();
        assert!(!auth.verify());
    }

    #[test]
    fn test_authorization_serialization() {
        let auth = HitAuthorization::new(
            "req-1".into(),
            "Edit".into(),
            "file.rs",
            "approve",
            "yubikey".into(),
            "admin".into(),
            None,
        );

        let json = serde_json::to_string(&auth).unwrap();
        let deserialized: HitAuthorization = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hash, auth.hash);
        assert!(deserialized.verify());
    }
}
