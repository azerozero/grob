//! HIT authorization: per-action cryptographic proof of human approval.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Authorization decision for a tool_use action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthDecision {
    /// Human approved the action.
    Approve,
    /// Human denied the action.
    Deny,
}

impl std::fmt::Display for AuthDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approve => write!(f, "approve"),
            Self::Deny => write!(f, "deny"),
        }
    }
}

/// Authentication method used for the authorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// Text approval in grob watch terminal.
    Prompt,
    /// FIDO2 YubiKey hardware key (cross-platform).
    Yubikey,
    /// M-of-N human co-signing.
    Multisig,
    /// Automated machine key (CI/CD).
    MachineKey,
    /// HTTP webhook to external system.
    Webhook,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prompt => write!(f, "prompt"),
            Self::Yubikey => write!(f, "yubikey"),
            Self::Multisig => write!(f, "multisig"),
            Self::MachineKey => write!(f, "machine_key"),
            Self::Webhook => write!(f, "webhook"),
        }
    }
}

/// Parameters for creating a new authorization entry.
pub struct HitAuthParams {
    /// Request ID this authorization belongs to.
    pub request_id: String,
    /// Tool name that was authorized.
    pub tool_name: String,
    /// Raw tool_use input (hashed, not stored).
    pub tool_input: String,
    /// Authorization decision.
    pub decision: AuthDecision,
    /// Authentication method used.
    pub auth_method: AuthMethod,
    /// Who approved (user identifier).
    pub signer: String,
    /// SHA-256 hash of the previous authorization (chain link).
    pub previous_hash: Option<String>,
}

/// Signed authorization for a single tool_use action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitAuthorization {
    /// Request ID this authorization belongs to.
    pub request_id: String,
    /// Tool name that was authorized.
    pub tool_name: String,
    /// SHA-256 hash of the tool_use input.
    pub tool_input_hash: String,
    /// Authorization decision.
    pub decision: AuthDecision,
    /// Authentication method used.
    pub auth_method: AuthMethod,
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
    pub fn new(params: HitAuthParams) -> Self {
        let tool_input_hash = hex::encode(Sha256::digest(params.tool_input.as_bytes()));
        let timestamp = chrono::Utc::now().to_rfc3339();

        let mut entry = Self {
            request_id: params.request_id,
            tool_name: params.tool_name,
            tool_input_hash,
            decision: params.decision,
            auth_method: params.auth_method,
            signer: params.signer,
            timestamp,
            previous_hash: params.previous_hash,
            hash: String::new(),
        };

        entry.hash = entry.compute_hash();
        entry
    }

    /// Computes the SHA-256 hash of this entry (for chain integrity).
    ///
    /// NOTE: auth_method and signer were added to the hash input in v0.x.
    /// This is a breaking change: hashes computed before this change will
    /// not match hashes computed after it. Existing chains must be
    /// re-hashed or treated as legacy.
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.request_id.as_bytes());
        hasher.update(self.tool_name.as_bytes());
        hasher.update(self.tool_input_hash.as_bytes());
        hasher.update(self.decision.to_string().as_bytes());
        hasher.update(self.auth_method.to_string().as_bytes());
        hasher.update(self.signer.as_bytes());
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

    fn test_params(signer: &str, decision: AuthDecision) -> HitAuthParams {
        HitAuthParams {
            request_id: "req-123".into(),
            tool_name: "Bash".into(),
            tool_input: "echo hello".into(),
            decision,
            auth_method: AuthMethod::Prompt,
            signer: signer.into(),
            previous_hash: None,
        }
    }

    #[test]
    fn test_authorization_sign_verify() {
        let auth = HitAuthorization::new(test_params("clement@company.com", AuthDecision::Approve));
        assert!(auth.verify());
        assert_eq!(auth.decision, AuthDecision::Approve);
        assert!(!auth.hash.is_empty());
        assert!(auth.previous_hash.is_none());
    }

    #[test]
    fn test_authorization_hash_chain() {
        let auth1 = HitAuthorization::new(HitAuthParams {
            request_id: "req-1".into(),
            tool_name: "Read".into(),
            tool_input: "/etc/passwd".into(),
            decision: AuthDecision::Approve,
            auth_method: AuthMethod::Prompt,
            signer: "user".into(),
            previous_hash: None,
        });

        let auth2 = HitAuthorization::new(HitAuthParams {
            request_id: "req-2".into(),
            tool_name: "Edit".into(),
            tool_input: "config.toml".into(),
            decision: AuthDecision::Approve,
            auth_method: AuthMethod::Yubikey,
            signer: "user".into(),
            previous_hash: Some(auth1.hash.clone()),
        });

        let auth3 = HitAuthorization::new(HitAuthParams {
            request_id: "req-3".into(),
            tool_name: "Bash".into(),
            tool_input: "rm -rf /tmp".into(),
            decision: AuthDecision::Deny,
            auth_method: AuthMethod::Prompt,
            signer: "user".into(),
            previous_hash: Some(auth2.hash.clone()),
        });

        assert!(auth1.verify());
        assert!(auth2.verify());
        assert!(auth3.verify());
        assert_eq!(auth2.previous_hash.as_ref().unwrap(), &auth1.hash);
        assert_eq!(auth3.previous_hash.as_ref().unwrap(), &auth2.hash);
        assert_ne!(auth1.hash, auth2.hash);
    }

    #[test]
    fn test_authorization_tamper_detection() {
        let mut auth = HitAuthorization::new(test_params("user", AuthDecision::Approve));
        assert!(auth.verify());

        auth.decision = AuthDecision::Deny;
        assert!(!auth.verify());
    }

    #[test]
    fn test_hash_includes_auth_method_and_signer() {
        let auth_prompt = HitAuthorization::new(HitAuthParams {
            request_id: "req-1".into(),
            tool_name: "Bash".into(),
            tool_input: "echo hello".into(),
            decision: AuthDecision::Approve,
            auth_method: AuthMethod::Prompt,
            signer: "alice".into(),
            previous_hash: None,
        });

        let auth_yubikey = HitAuthorization::new(HitAuthParams {
            request_id: "req-1".into(),
            tool_name: "Bash".into(),
            tool_input: "echo hello".into(),
            decision: AuthDecision::Approve,
            auth_method: AuthMethod::Yubikey,
            signer: "alice".into(),
            previous_hash: None,
        });

        let auth_bob = HitAuthorization::new(HitAuthParams {
            request_id: "req-1".into(),
            tool_name: "Bash".into(),
            tool_input: "echo hello".into(),
            decision: AuthDecision::Approve,
            auth_method: AuthMethod::Prompt,
            signer: "bob".into(),
            previous_hash: None,
        });

        // Changing auth_method must produce a different hash.
        assert_ne!(auth_prompt.hash, auth_yubikey.hash);
        // Changing signer must produce a different hash.
        assert_ne!(auth_prompt.hash, auth_bob.hash);
        // All must still verify.
        assert!(auth_prompt.verify());
        assert!(auth_yubikey.verify());
        assert!(auth_bob.verify());
    }

    #[test]
    fn test_authorization_serialization() {
        let auth = HitAuthorization::new(HitAuthParams {
            request_id: "req-1".into(),
            tool_name: "Edit".into(),
            tool_input: "file.rs".into(),
            decision: AuthDecision::Approve,
            auth_method: AuthMethod::Yubikey,
            signer: "admin".into(),
            previous_hash: None,
        });

        let json = serde_json::to_string(&auth).unwrap();
        let deserialized: HitAuthorization = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hash, auth.hash);
        assert!(deserialized.verify());
    }
}
