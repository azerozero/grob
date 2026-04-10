//! Decision tokens for transparent agent routing.
//!
//! A decision token is an MCP token emitted by a boss agent, invisible to the
//! target agent. Grob reads the `mode` claim to route toward the correct backend
//! (paper for training, real for live). The agent cannot read or modify this token.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Operating mode carried by a decision token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionMode {
    /// Routes to paper/simulated backend.
    Training,
    /// Routes to real/production backend.
    Live,
}

impl std::fmt::Display for DecisionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Training => write!(f, "training"),
            Self::Live => write!(f, "live"),
        }
    }
}

impl std::str::FromStr for DecisionMode {
    type Err = DecisionTokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "training" => Ok(Self::Training),
            "live" => Ok(Self::Live),
            "" => Err(DecisionTokenError::EmptyMode),
            other => Err(DecisionTokenError::UnknownMode(other.to_string())),
        }
    }
}

/// Backend target resolved from a decision token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendTarget {
    /// Paper/simulated trading backend.
    Paper,
    /// Real/production backend.
    Real,
    /// Token was invalid; deny the request.
    Deny,
}

/// Errors from decision token validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecisionTokenError {
    /// Mode claim is empty.
    #[error("decision token mode claim is empty")]
    EmptyMode,
    /// Mode claim has an unrecognized value.
    #[error("unknown decision token mode: {0}")]
    UnknownMode(String),
    /// Token hash does not match computed hash (tampered).
    #[error("decision token integrity check failed")]
    IntegrityFailure,
    /// Token issuer is not authorized.
    #[error("decision token issuer '{0}' is not authorized")]
    UnauthorizedIssuer(String),
    /// Token has expired.
    #[error("decision token has expired")]
    Expired,
}

/// Claims carried inside a decision token.
///
/// Only grob reads these claims. The target agent sees an opaque session
/// identifier but never the mode or issuer fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionClaims {
    /// Operating mode: training or live.
    pub mode: DecisionMode,
    /// Boss agent that issued this token.
    pub issuer: String,
    /// Glob pattern matching target agent identifiers.
    pub audience: String,
    /// Optional expiry as RFC-3339 timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// A decision token issued by a boss agent.
///
/// Contains claims readable only by grob, plus a SHA-256 integrity hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionToken {
    /// Unique token identifier.
    pub token_id: String,
    /// Token type discriminator.
    pub token_type: TokenType,
    /// Claims (mode, issuer, audience).
    pub claims: DecisionClaims,
    /// ISO-8601 timestamp of issuance.
    pub issued_at: String,
    /// SHA-256 integrity hash.
    pub hash: String,
}

/// Discriminates session tokens from decision tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Visible to the agent — carries identity and scope.
    Session,
    /// Invisible to the agent — carries routing decisions.
    Decision,
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session => write!(f, "session"),
            Self::Decision => write!(f, "decision"),
        }
    }
}

/// View of a token exposed to the agent (hides decision claims).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVisibleToken {
    /// Opaque token identifier.
    pub token_id: String,
    /// Token type (always "session" from the agent's perspective).
    pub token_type: String,
    /// Session scope information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl DecisionToken {
    /// Creates a new decision token with computed integrity hash.
    pub fn new(token_id: String, claims: DecisionClaims) -> Self {
        let issued_at = chrono::Utc::now().to_rfc3339();
        let mut token = Self {
            token_id,
            token_type: TokenType::Decision,
            claims,
            issued_at,
            hash: String::new(),
        };
        token.hash = token.compute_hash();
        token
    }

    /// Computes SHA-256 hash over token fields for integrity verification.
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.token_id.as_bytes());
        hasher.update(self.token_type.to_string().as_bytes());
        hasher.update(self.claims.mode.to_string().as_bytes());
        hasher.update(self.claims.issuer.as_bytes());
        hasher.update(self.claims.audience.as_bytes());
        hasher.update(self.issued_at.as_bytes());
        if let Some(ref exp) = self.claims.expires_at {
            hasher.update(exp.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Verifies token integrity (hash matches computed value).
    ///
    /// # Errors
    ///
    /// Returns [`DecisionTokenError::IntegrityFailure`] if the stored
    /// hash does not match the recomputed hash.
    pub fn verify_integrity(&self) -> Result<(), DecisionTokenError> {
        if self.hash != self.compute_hash() {
            return Err(DecisionTokenError::IntegrityFailure);
        }
        Ok(())
    }

    /// Resolves the backend target from this token's mode.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionTokenError::IntegrityFailure`] if integrity
    /// verification fails before resolving the backend.
    pub fn resolve_backend(&self) -> Result<BackendTarget, DecisionTokenError> {
        self.verify_integrity()?;
        Ok(match self.claims.mode {
            DecisionMode::Training => BackendTarget::Paper,
            DecisionMode::Live => BackendTarget::Real,
        })
    }

    /// Returns the agent-visible representation (hides decision claims).
    pub fn to_agent_view(&self) -> AgentVisibleToken {
        AgentVisibleToken {
            token_id: self.token_id.clone(),
            token_type: "session".to_string(),
            scope: None,
        }
    }

    /// Checks whether the given agent ID matches the audience pattern.
    pub fn matches_audience(&self, agent_id: &str) -> bool {
        // Simple glob: "trader-agent-*" matches "trader-agent-42"
        if self.claims.audience.ends_with('*') {
            let prefix = &self.claims.audience[..self.claims.audience.len() - 1];
            agent_id.starts_with(prefix)
        } else {
            self.claims.audience == agent_id
        }
    }
}

/// Routes a request based on the decision token's mode claim.
///
/// Returns [`BackendTarget::Deny`] if the mode is invalid or the token
/// fails integrity verification.
pub fn route_by_decision_token(token: &DecisionToken) -> BackendTarget {
    match token.resolve_backend() {
        Ok(target) => target,
        Err(_) => BackendTarget::Deny,
    }
}

/// Strips decision claims from a token before forwarding to the agent.
///
/// The agent receives an opaque session-like view. It cannot determine
/// whether it is operating in training or live mode.
pub fn strip_decision_claims(token: &DecisionToken) -> AgentVisibleToken {
    token.to_agent_view()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boss_claims(mode: DecisionMode) -> DecisionClaims {
        DecisionClaims {
            mode,
            issuer: "boss-agent".to_string(),
            audience: "trader-agent-*".to_string(),
            expires_at: None,
        }
    }

    #[test]
    fn test_training_routes_to_paper() {
        let token = DecisionToken::new("tok-1".to_string(), boss_claims(DecisionMode::Training));
        assert_eq!(route_by_decision_token(&token), BackendTarget::Paper);
    }

    #[test]
    fn test_live_routes_to_real() {
        let token = DecisionToken::new("tok-2".to_string(), boss_claims(DecisionMode::Live));
        assert_eq!(route_by_decision_token(&token), BackendTarget::Real);
    }

    #[test]
    fn test_decision_token_invisible() {
        let token = DecisionToken::new("tok-3".to_string(), boss_claims(DecisionMode::Live));
        let agent_view = strip_decision_claims(&token);

        // Agent sees "session" type, not "decision".
        assert_eq!(agent_view.token_type, "session");
        // Agent view has no mode claim.
        let json = serde_json::to_string(&agent_view).unwrap();
        assert!(!json.contains("training"));
        assert!(!json.contains("live"));
        assert!(!json.contains("decision"));
        assert!(!json.contains("boss-agent"));
    }

    #[test]
    fn test_mode_switch_transparent() {
        let training_token =
            DecisionToken::new("tok-4a".to_string(), boss_claims(DecisionMode::Training));
        let live_token = DecisionToken::new("tok-4b".to_string(), boss_claims(DecisionMode::Live));

        let view_training = strip_decision_claims(&training_token);
        let view_live = strip_decision_claims(&live_token);

        // Both views have the same schema structure.
        assert_eq!(view_training.token_type, view_live.token_type);
        // Neither reveals the actual mode.
        let json_t = serde_json::to_value(&view_training).unwrap();
        let json_l = serde_json::to_value(&view_live).unwrap();
        let keys_t: Vec<_> = json_t.as_object().unwrap().keys().collect();
        let keys_l: Vec<_> = json_l.as_object().unwrap().keys().collect();
        assert_eq!(keys_t, keys_l);
    }

    #[test]
    fn test_agent_cannot_read_decision_claim() {
        let token = DecisionToken::new("tok-5".to_string(), boss_claims(DecisionMode::Live));
        let agent_view = strip_decision_claims(&token);

        // Serialize to JSON — no mode field exists.
        let json = serde_json::to_string(&agent_view).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("mode").is_none());
        assert!(parsed.get("claims").is_none());
        assert!(parsed.get("issuer").is_none());
    }

    #[test]
    fn test_integrity_verification() {
        let token = DecisionToken::new("tok-6".to_string(), boss_claims(DecisionMode::Training));
        assert!(token.verify_integrity().is_ok());

        // Tamper with the token.
        let mut tampered = token.clone();
        tampered.claims.mode = DecisionMode::Live;
        assert_eq!(
            tampered.verify_integrity(),
            Err(DecisionTokenError::IntegrityFailure)
        );
    }

    #[test]
    fn test_tampered_token_denied() {
        let token = DecisionToken::new("tok-7".to_string(), boss_claims(DecisionMode::Training));
        let mut tampered = token.clone();
        tampered.claims.mode = DecisionMode::Live;
        // Tampered token routes to Deny.
        assert_eq!(route_by_decision_token(&tampered), BackendTarget::Deny);
    }

    #[test]
    fn test_mode_from_str() {
        assert_eq!(
            "training".parse::<DecisionMode>().unwrap(),
            DecisionMode::Training
        );
        assert_eq!("live".parse::<DecisionMode>().unwrap(), DecisionMode::Live);
        assert_eq!(
            "".parse::<DecisionMode>(),
            Err(DecisionTokenError::EmptyMode)
        );
        assert!(matches!(
            "unknown".parse::<DecisionMode>(),
            Err(DecisionTokenError::UnknownMode(_))
        ));
    }

    #[test]
    fn test_audience_matching() {
        let token = DecisionToken::new("tok-8".to_string(), boss_claims(DecisionMode::Training));
        assert!(token.matches_audience("trader-agent-42"));
        assert!(token.matches_audience("trader-agent-alpha"));
        assert!(!token.matches_audience("rogue-agent-1"));
    }

    #[test]
    fn test_token_type_discriminator() {
        let decision = DecisionToken::new("tok-9".to_string(), boss_claims(DecisionMode::Live));
        assert_eq!(decision.token_type, TokenType::Decision);

        // Agent view always says "session".
        let view = decision.to_agent_view();
        assert_eq!(view.token_type, "session");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let token = DecisionToken::new("tok-10".to_string(), boss_claims(DecisionMode::Training));
        let json = serde_json::to_string(&token).unwrap();
        let deserialized: DecisionToken = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.token_id, token.token_id);
        assert_eq!(deserialized.claims.mode, token.claims.mode);
        assert_eq!(deserialized.hash, token.hash);
        assert!(deserialized.verify_integrity().is_ok());
    }
}
