//! Decision tokens for transparent agent routing.
//!
//! A decision token is an MCP token emitted by a boss agent, invisible to the
//! target agent. Grob reads the `mode` claim to route toward the correct backend
//! (paper for training, real for live). The token travels over the MCP transport
//! and is serialized to JSON, so it crosses a trust boundary: an adversary on
//! that path could otherwise flip `mode` (training → live) to escape the paper
//! sandbox. To prevent this, each token carries an HMAC-SHA256 tag keyed by the
//! process policy secret (see [`crate::features::policies::signing`]); only a
//! holder of that secret can mint or alter a token, so a tampered token fails
//! [`DecisionToken::verify_integrity`].

use serde::{Deserialize, Serialize};

use super::signing;

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
    /// Token authentication tag does not match (tampered or wrong key).
    #[error("decision token authentication failed")]
    IntegrityFailure,
    /// Token issuer is not authorized.
    #[error("decision token issuer '{0}' is not authorized")]
    UnauthorizedIssuer(String),
    /// Token has expired.
    #[error("decision token has expired")]
    Expired,
    /// Token was minted for a different agent.
    #[error("decision token audience '{audience}' does not match agent '{agent_id}'")]
    AudienceMismatch {
        /// Audience pattern carried by the token.
        audience: String,
        /// Agent identifier that presented the token.
        agent_id: String,
    },
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
/// Contains claims readable only by grob, plus a keyed HMAC-SHA256 tag that
/// authenticates the claims against the policy secret.
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
    /// Hex-encoded HMAC-SHA256 authentication tag over the token fields.
    pub mac: String,
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
    /// Creates a new decision token signed with the policy key.
    pub fn new(token_id: String, claims: DecisionClaims) -> Self {
        let issued_at = chrono::Utc::now().to_rfc3339();
        let mut token = Self {
            token_id,
            token_type: TokenType::Decision,
            claims,
            issued_at,
            mac: String::new(),
        };
        token.mac = signing::compute_tag(&token.signing_bytes());
        token
    }

    /// Returns the canonical byte string the MAC authenticates.
    ///
    /// Field order and the `\0` separator are part of the wire contract: the
    /// separator prevents adjacent fields from being shifted across boundaries
    /// (e.g. issuer `"a"` + audience `"bc"` colliding with `"ab"` + `"c"`).
    fn signing_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for part in [
            self.token_id.as_str(),
            self.token_type.to_string().as_str(),
            self.claims.mode.to_string().as_str(),
            self.claims.issuer.as_str(),
            self.claims.audience.as_str(),
            self.issued_at.as_str(),
            self.claims.expires_at.as_deref().unwrap_or(""),
        ] {
            data.extend_from_slice(part.as_bytes());
            data.push(0);
        }
        data
    }

    /// Verifies the token's HMAC tag against the policy key.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionTokenError::IntegrityFailure`] if the stored tag is
    /// not a valid HMAC-SHA256 over the token fields under the policy key,
    /// i.e. the token was tampered with or signed with a different key.
    pub fn verify_integrity(&self) -> Result<(), DecisionTokenError> {
        if !signing::verify_tag(&self.signing_bytes(), &self.mac) {
            return Err(DecisionTokenError::IntegrityFailure);
        }
        Ok(())
    }

    /// Resolves the backend target from this token's mode.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionTokenError::IntegrityFailure`] if authentication
    /// fails before resolving the backend, or [`DecisionTokenError::Expired`]
    /// if the `expires_at` claim is in the past.
    pub fn resolve_backend(&self) -> Result<BackendTarget, DecisionTokenError> {
        self.verify_integrity()?;
        self.check_not_expired()?;
        Ok(match self.claims.mode {
            DecisionMode::Training => BackendTarget::Paper,
            DecisionMode::Live => BackendTarget::Real,
        })
    }

    /// Returns whether the `expires_at` claim is in the past.
    ///
    /// A token with no `expires_at` never expires. An unparseable timestamp is
    /// treated as expired: a malformed expiry must not silently grant
    /// unlimited validity.
    pub fn is_expired(&self) -> bool {
        let Some(raw) = self.claims.expires_at.as_deref() else {
            return false;
        };
        match chrono::DateTime::parse_from_rfc3339(raw) {
            Ok(deadline) => chrono::Utc::now() >= deadline.with_timezone(&chrono::Utc),
            Err(_) => true,
        }
    }

    /// Fails when the token has expired.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionTokenError::Expired`] if [`Self::is_expired`] holds.
    pub fn check_not_expired(&self) -> Result<(), DecisionTokenError> {
        if self.is_expired() {
            return Err(DecisionTokenError::Expired);
        }
        Ok(())
    }

    /// Full validation for a request presented by `agent_id`.
    ///
    /// Checks integrity, expiry, and audience together, so a caller cannot
    /// accidentally honour a token that was minted for a different agent.
    ///
    /// # Errors
    ///
    /// Returns [`DecisionTokenError::IntegrityFailure`] on a bad tag,
    /// [`DecisionTokenError::Expired`] past `expires_at`, or
    /// [`DecisionTokenError::AudienceMismatch`] when `agent_id` is outside the
    /// audience pattern.
    pub fn resolve_backend_for(&self, agent_id: &str) -> Result<BackendTarget, DecisionTokenError> {
        self.verify_integrity()?;
        self.check_not_expired()?;
        if !self.matches_audience(agent_id) {
            return Err(DecisionTokenError::AudienceMismatch {
                audience: self.claims.audience.clone(),
                agent_id: agent_id.to_string(),
            });
        }
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
    ///
    /// The pattern is a trailing-`*` prefix glob (`trader-agent-*`) or an exact
    /// match. A bare `*` matches nothing: an audience that matches everything
    /// is indistinguishable from no audience at all, and silently granting it
    /// would defeat the purpose of the claim.
    pub fn matches_audience(&self, agent_id: &str) -> bool {
        if agent_id.is_empty() {
            return false;
        }
        match self.claims.audience.strip_suffix('*') {
            // A wildcard-only audience is refused rather than treated as "all".
            Some("") => false,
            // The prefix must be followed by at least one character, so
            // "worker-*" does not match the bare prefix "worker-".
            Some(prefix) => agent_id.len() > prefix.len() && agent_id.starts_with(prefix),
            None => self.claims.audience == agent_id,
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

/// Routes a request based on the token's mode, scoped to the presenting agent.
///
/// Prefer this over [`route_by_decision_token`] wherever the agent identity is
/// known: it is the only variant that can enforce the `audience` claim, and an
/// audience that is never checked is not a security control.
/// Returns [`BackendTarget::Deny`] on any validation failure.
pub fn route_by_decision_token_for(token: &DecisionToken, agent_id: &str) -> BackendTarget {
    match token.resolve_backend_for(agent_id) {
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
    fn test_forged_token_with_recomputed_plain_hash_rejected() {
        // The original attack: flip Training -> Live and recompute a *plain*
        // SHA-256 over the fields. Without the policy key, the recomputed
        // digest is not a valid HMAC tag, so verification must still fail.
        use sha2::{Digest as _, Sha256};

        let token =
            DecisionToken::new("tok-forge".to_string(), boss_claims(DecisionMode::Training));
        let mut forged = token.clone();
        forged.claims.mode = DecisionMode::Live;

        // Attacker recomputes an unkeyed hash over the tampered fields.
        let mut hasher = Sha256::new();
        hasher.update(forged.token_id.as_bytes());
        hasher.update(forged.token_type.to_string().as_bytes());
        hasher.update(forged.claims.mode.to_string().as_bytes());
        hasher.update(forged.claims.issuer.as_bytes());
        hasher.update(forged.claims.audience.as_bytes());
        hasher.update(forged.issued_at.as_bytes());
        forged.mac = hex::encode(hasher.finalize());

        assert_eq!(
            forged.verify_integrity(),
            Err(DecisionTokenError::IntegrityFailure),
            "forged token with recomputed plain hash must be rejected"
        );
        assert_eq!(route_by_decision_token(&forged), BackendTarget::Deny);
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
        assert_eq!(deserialized.mac, token.mac);
        assert!(deserialized.verify_integrity().is_ok());
    }
}

#[cfg(test)]
mod expiry_and_audience_tests {
    use super::*;

    fn claims(audience: &str, expires_at: Option<&str>) -> DecisionClaims {
        DecisionClaims {
            mode: DecisionMode::Live,
            issuer: "boss-agent".to_string(),
            audience: audience.to_string(),
            expires_at: expires_at.map(str::to_string),
        }
    }

    #[test]
    fn expired_token_is_denied() {
        let token = DecisionToken::new("t".into(), claims("w-*", Some("2020-01-01T00:00:00Z")));
        // Integrity still holds: the token is authentic, just no longer valid.
        assert!(token.verify_integrity().is_ok());
        assert!(token.is_expired());
        assert_eq!(token.resolve_backend(), Err(DecisionTokenError::Expired));
        assert_eq!(route_by_decision_token(&token), BackendTarget::Deny);
    }

    #[test]
    fn future_expiry_is_accepted() {
        let later = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let token = DecisionToken::new("t".into(), claims("w-*", Some(&later)));
        assert!(!token.is_expired());
        assert_eq!(route_by_decision_token(&token), BackendTarget::Real);
    }

    #[test]
    fn absent_expiry_never_expires() {
        let token = DecisionToken::new("t".into(), claims("w-*", None));
        assert!(!token.is_expired());
    }

    #[test]
    fn malformed_expiry_is_treated_as_expired() {
        // Fail closed: a malformed expiry must not grant unlimited validity.
        let token = DecisionToken::new("t".into(), claims("w-*", Some("not-a-date")));
        assert!(token.is_expired());
        assert_eq!(route_by_decision_token(&token), BackendTarget::Deny);
    }

    #[test]
    fn audience_prefix_requires_a_suffix() {
        let token = DecisionToken::new("t".into(), claims("worker-*", None));
        assert!(token.matches_audience("worker-1"));
        assert!(token.matches_audience("worker-42"));
        // The bare prefix is not a member of "worker-*".
        assert!(!token.matches_audience("worker-"));
        assert!(!token.matches_audience("workerX"));
        assert!(!token.matches_audience(""));
    }

    #[test]
    fn wildcard_only_audience_matches_nothing() {
        let token = DecisionToken::new("t".into(), claims("*", None));
        assert!(!token.matches_audience("anyone"));
        assert_eq!(
            route_by_decision_token_for(&token, "anyone"),
            BackendTarget::Deny
        );
    }

    #[test]
    fn audience_is_enforced_when_routing_for_an_agent() {
        let token = DecisionToken::new("t".into(), claims("worker-*", None));
        assert_eq!(
            route_by_decision_token_for(&token, "worker-7"),
            BackendTarget::Real
        );
        assert_eq!(
            route_by_decision_token_for(&token, "intruder-7"),
            BackendTarget::Deny
        );
        assert!(matches!(
            token.resolve_backend_for("intruder-7"),
            Err(DecisionTokenError::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn expiry_is_checked_before_audience_on_the_agent_path() {
        let token =
            DecisionToken::new("t".into(), claims("worker-*", Some("2020-01-01T00:00:00Z")));
        assert_eq!(
            token.resolve_backend_for("worker-7"),
            Err(DecisionTokenError::Expired)
        );
    }
}
