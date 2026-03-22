//! Multi-sig co-signing: M-of-N distinct human approvals for high-stakes actions.

use std::collections::HashSet;

use super::hit_auth::HitAuthorization;

/// Collects M-of-N signatures for a single tool_use authorization.
pub struct MultiSigCollector {
    /// Number of required signatures.
    required: usize,
    /// Collected authorizations (hash-chained).
    received: Vec<HitAuthorization>,
    /// Signer identifiers that have already submitted (dedup).
    signers: HashSet<String>,
}

/// Result of submitting a signature.
#[derive(Debug, PartialEq)]
pub enum MultiSigStatus {
    /// Waiting for more signatures.
    Pending {
        /// Number of signatures received so far.
        received: usize,
        /// Number of signatures still needed.
        remaining: usize,
    },
    /// Quorum reached, action approved.
    Complete,
    /// Submission rejected (duplicate signer, invalid, etc.).
    Rejected(String),
}

impl MultiSigCollector {
    /// Creates a new collector requiring `required` distinct signatures.
    pub fn new(required: usize) -> Self {
        Self {
            required,
            received: Vec::with_capacity(required),
            signers: HashSet::with_capacity(required),
        }
    }

    /// Submits a signature. Returns the current status.
    pub fn submit(&mut self, auth: HitAuthorization) -> MultiSigStatus {
        // Reject duplicate signers.
        if self.signers.contains(&auth.signer) {
            return MultiSigStatus::Rejected(format!(
                "Signer '{}' has already submitted",
                auth.signer
            ));
        }

        // Reject if hash chain is broken (must link to previous).
        if !self.received.is_empty() {
            let expected_prev = &self.received.last().unwrap().hash;
            match auth.previous_hash {
                Some(ref prev) if prev == expected_prev => {}
                _ => {
                    return MultiSigStatus::Rejected(
                        "Hash chain broken: previous_hash does not match".to_string(),
                    );
                }
            }
        }

        // Reject if tampered.
        if !auth.verify() {
            return MultiSigStatus::Rejected("Authorization hash verification failed".to_string());
        }

        self.signers.insert(auth.signer.clone());
        self.received.push(auth);

        if self.received.len() >= self.required {
            MultiSigStatus::Complete
        } else {
            MultiSigStatus::Pending {
                received: self.received.len(),
                remaining: self.required - self.received.len(),
            }
        }
    }

    /// Returns the collected authorizations (for audit logging).
    pub fn authorizations(&self) -> &[HitAuthorization] {
        &self.received
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_auth(signer: &str, tool: &str, previous_hash: Option<String>) -> HitAuthorization {
        use crate::features::policies::hit_auth::{AuthDecision, AuthMethod, HitAuthParams};
        HitAuthorization::new(HitAuthParams {
            request_id: "req-1".into(),
            tool_name: tool.into(),
            tool_input: "input data".into(),
            decision: AuthDecision::Approve,
            auth_method: AuthMethod::Prompt,
            signer: signer.into(),
            previous_hash,
        })
    }

    #[test]
    fn test_2_of_3_approve() {
        let mut collector = MultiSigCollector::new(2);
        let auth1 = make_auth("alice", "Bash", None);
        let hash1 = auth1.hash.clone();

        assert_eq!(
            collector.submit(auth1),
            MultiSigStatus::Pending {
                received: 1,
                remaining: 1,
            }
        );

        let auth2 = make_auth("bob", "Bash", Some(hash1));
        assert_eq!(collector.submit(auth2), MultiSigStatus::Complete);
    }

    #[test]
    fn test_duplicate_signer_rejected() {
        let mut collector = MultiSigCollector::new(2);
        let auth1 = make_auth("alice", "Bash", None);
        let hash1 = auth1.hash.clone();
        collector.submit(auth1);

        let auth2 = make_auth("alice", "Bash", Some(hash1));
        match collector.submit(auth2) {
            MultiSigStatus::Rejected(msg) => assert!(msg.contains("already submitted")),
            other => panic!("Expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn test_broken_hash_chain_rejected() {
        let mut collector = MultiSigCollector::new(2);
        let auth1 = make_auth("alice", "Bash", None);
        collector.submit(auth1);

        // Wrong previous hash.
        let auth2 = make_auth("bob", "Bash", Some("wrong_hash".into()));
        match collector.submit(auth2) {
            MultiSigStatus::Rejected(msg) => assert!(msg.contains("Hash chain")),
            other => panic!("Expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn test_tampered_auth_rejected() {
        let mut collector = MultiSigCollector::new(2);
        let auth1 = make_auth("alice", "Bash", None);
        let hash1 = auth1.hash.clone();
        collector.submit(auth1);

        let mut auth2 = make_auth("bob", "Bash", Some(hash1));
        auth2.decision = crate::features::policies::hit_auth::AuthDecision::Deny; // Tamper.
        match collector.submit(auth2) {
            MultiSigStatus::Rejected(msg) => assert!(msg.contains("hash verification")),
            other => panic!("Expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn test_3_of_3_complete() {
        let mut collector = MultiSigCollector::new(3);
        let auth1 = make_auth("alice", "Bash", None);
        let h1 = auth1.hash.clone();
        collector.submit(auth1);

        let auth2 = make_auth("bob", "Bash", Some(h1));
        let h2 = auth2.hash.clone();
        collector.submit(auth2);

        let auth3 = make_auth("charlie", "Bash", Some(h2));
        assert_eq!(collector.submit(auth3), MultiSigStatus::Complete);
        assert_eq!(collector.authorizations().len(), 3);
    }
}
