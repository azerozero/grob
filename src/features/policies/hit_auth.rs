//! HIT authorization: per-action keyed proof of human approval.
//!
//! Each [`HitAuthorization`] records that a human approved or denied a tool_use
//! action. Receipts are serialized to JSON, persisted to the audit log on disk,
//! and posted over HTTP to the approval endpoint, so they cross trust
//! boundaries: an adversary with write access to a persisted receipt could
//! otherwise flip `decision` (deny → approve) and recompute the hash.
//!
//! To make the proof meaningful against such an adversary, each receipt carries
//! a keyed HMAC-SHA256 tag (the `hash` field) over its fields and the previous
//! receipt's tag. Only a holder of the policy secret (see
//! [`crate::features::policies::signing`]) can mint a receipt or extend the
//! chain, so a forged or tampered receipt fails [`HitAuthorization::verify`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::signing;

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
    /// Keyed HMAC tag of the previous authorization (chain link).
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
    /// Keyed HMAC tag of the previous authorization (chain link).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    /// Keyed HMAC-SHA256 tag of this authorization entry.
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

        entry.hash = signing::compute_tag(&entry.signing_bytes());
        entry
    }

    /// Returns the canonical byte string the HMAC tag authenticates.
    ///
    /// The `\0` separator after each field prevents adjacent fields from being
    /// shifted across boundaries without changing the tag. Chaining the
    /// previous tag binds each receipt to its predecessor, so a tampered or
    /// reordered chain cannot be re-tagged without the policy key.
    ///
    /// NOTE: `auth_method` and `signer` are part of the signed input. Tags
    /// computed before they were added do not match; legacy chains must be
    /// re-signed or treated as legacy.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for part in [
            self.request_id.as_str(),
            self.tool_name.as_str(),
            self.tool_input_hash.as_str(),
            self.decision.to_string().as_str(),
            self.auth_method.to_string().as_str(),
            self.signer.as_str(),
            self.timestamp.as_str(),
            self.previous_hash.as_deref().unwrap_or(""),
        ] {
            data.extend_from_slice(part.as_bytes());
            data.push(0);
        }
        data
    }

    /// Verifies this entry's keyed HMAC tag against the policy key.
    ///
    /// Returns `true` only when `hash` is a valid HMAC-SHA256 over the entry
    /// fields (including the chained `previous_hash`) under the policy key.
    /// A tampered receipt, or one forged without the key, returns `false`.
    #[must_use]
    pub fn verify(&self) -> bool {
        signing::verify_tag(&self.signing_bytes(), &self.hash)
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
    fn test_forged_receipt_with_recomputed_plain_hash_rejected() {
        // The original attack: flip Deny -> Approve and recompute a *plain*
        // SHA-256 over the fields. Without the policy key the digest is not a
        // valid HMAC tag, so verification must still fail.
        let auth = HitAuthorization::new(test_params("user", AuthDecision::Deny));
        let mut forged = auth.clone();
        forged.decision = AuthDecision::Approve;

        let mut hasher = Sha256::new();
        hasher.update(forged.request_id.as_bytes());
        hasher.update(forged.tool_name.as_bytes());
        hasher.update(forged.tool_input_hash.as_bytes());
        hasher.update(forged.decision.to_string().as_bytes());
        hasher.update(forged.auth_method.to_string().as_bytes());
        hasher.update(forged.signer.as_bytes());
        hasher.update(forged.timestamp.as_bytes());
        forged.hash = hex::encode(hasher.finalize());

        assert!(
            !forged.verify(),
            "forged receipt with recomputed plain hash must be rejected"
        );
    }

    #[test]
    fn test_chain_tamper_rebuild_rejected() {
        // An adversary editing a persisted chain cannot re-tag it without the
        // key: re-running the unkeyed hash over a tampered chain still fails.
        let a1 = HitAuthorization::new(test_params("alice", AuthDecision::Approve));
        let mut a2 = HitAuthorization::new(HitAuthParams {
            request_id: "req-2".into(),
            tool_name: "Bash".into(),
            tool_input: "rm -rf /".into(),
            decision: AuthDecision::Deny,
            auth_method: AuthMethod::Prompt,
            signer: "bob".into(),
            previous_hash: Some(a1.hash.clone()),
        });
        assert!(a2.verify());

        // Flip the decision and naively re-tag with an unkeyed hash.
        a2.decision = AuthDecision::Approve;
        let mut hasher = Sha256::new();
        hasher.update(a2.request_id.as_bytes());
        hasher.update(a2.tool_name.as_bytes());
        hasher.update(a2.tool_input_hash.as_bytes());
        hasher.update(a2.decision.to_string().as_bytes());
        hasher.update(a2.auth_method.to_string().as_bytes());
        hasher.update(a2.signer.as_bytes());
        hasher.update(a2.timestamp.as_bytes());
        if let Some(ref prev) = a2.previous_hash {
            hasher.update(prev.as_bytes());
        }
        a2.hash = hex::encode(hasher.finalize());

        assert!(
            !a2.verify(),
            "re-tagged tampered chain link must be rejected"
        );
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
