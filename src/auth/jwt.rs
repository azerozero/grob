use anyhow::Result;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

/// JWT claims expected by Grob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrobClaims {
    /// Subject — user ID, used as tenant_id when no explicit tenant claim
    pub sub: String,
    /// Explicit tenant override (if set, takes precedence over sub)
    #[serde(default)]
    pub tenant: Option<String>,
    /// Expiration time (UNIX timestamp)
    pub exp: u64,
    /// Issuer
    #[serde(default)]
    pub iss: Option<String>,
    /// Audience
    #[serde(default)]
    pub aud: Option<String>,
}

impl GrobClaims {
    /// Returns the effective tenant ID: explicit `tenant` claim, or `sub`.
    pub fn tenant_id(&self) -> &str {
        self.tenant.as_deref().unwrap_or(&self.sub)
    }
}

/// Authentication error types
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Missing or invalid Authorization header")]
    #[allow(dead_code)]
    MissingToken,
    #[error("Invalid JWT: {0}")]
    InvalidToken(String),
    #[error("Token expired")]
    Expired,
}

/// JWT validator supporting HMAC-SHA256 and optional JWKS (RS256).
///
/// Uses separate Validation objects for HMAC and RSA because jsonwebtoken
/// requires ALL algorithms in the list to be compatible with the key family.
pub struct JwtValidator {
    hmac_key: Option<DecodingKey>,
    jwks_keys: RwLock<Vec<DecodingKey>>,
    jwks_url: Option<String>,
    hmac_validation: Validation,
    rsa_validation: Validation,
}

impl JwtValidator {
    /// Create a JwtValidator from config.
    pub fn from_config(config: &JwtConfig) -> Result<Self> {
        let hmac_key = if !config.hmac_secret.is_empty() {
            Some(DecodingKey::from_secret(config.hmac_secret.as_bytes()))
        } else {
            None
        };

        // Build base validation settings, then clone for each algorithm family
        let make_validation = |alg: Algorithm| {
            let mut v = Validation::new(alg);
            v.validate_exp = true;
            if let Some(ref iss) = config.issuer {
                if !iss.is_empty() {
                    v.set_issuer(&[iss]);
                }
            }
            if let Some(ref aud) = config.audience {
                if !aud.is_empty() {
                    v.set_audience(&[aud]);
                }
            } else {
                v.validate_aud = false;
            }
            v
        };

        let jwks_url = if config.jwks_url.is_empty() {
            None
        } else {
            Some(config.jwks_url.clone())
        };

        Ok(Self {
            hmac_key,
            jwks_keys: RwLock::new(Vec::new()),
            jwks_url,
            hmac_validation: make_validation(Algorithm::HS256),
            rsa_validation: make_validation(Algorithm::RS256),
        })
    }

    /// Validate a JWT token string and extract claims.
    pub fn validate(&self, token: &str) -> Result<GrobClaims, AuthError> {
        // Try HMAC first (most common for self-hosted)
        if let Some(ref key) = self.hmac_key {
            match decode::<GrobClaims>(token, key, &self.hmac_validation) {
                Ok(data) => return Ok(data.claims),
                Err(e) => {
                    // If HMAC fails and we have JWKS keys, try those
                    if !self.has_jwks_keys() {
                        return Err(map_jwt_error(e));
                    }
                }
            }
        }

        // Try JWKS keys (RS256)
        let keys = self.jwks_keys.read().unwrap_or_else(|e| e.into_inner());
        for key in keys.iter() {
            if let Ok(data) = decode::<GrobClaims>(token, key, &self.rsa_validation) {
                return Ok(data.claims);
            }
        }

        Err(AuthError::InvalidToken("No valid key found for token".to_string()))
    }

    fn has_jwks_keys(&self) -> bool {
        let keys = self.jwks_keys.read().unwrap_or_else(|e| e.into_inner());
        !keys.is_empty()
    }

    /// Refresh JWKS keys from the configured URL.
    pub async fn refresh_jwks(&self) -> Result<()> {
        let url = match &self.jwks_url {
            Some(url) => url.clone(),
            None => return Ok(()),
        };

        let resp = reqwest::Client::new()
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await?;

        let jwks: JwksResponse = resp.json().await?;
        let mut new_keys = Vec::new();

        for key in &jwks.keys {
            if key.kty == "RSA" {
                if let (Some(n), Some(e)) = (&key.n, &key.e) {
                    if let Ok(dk) = DecodingKey::from_rsa_components(n, e) {
                        new_keys.push(dk);
                    }
                }
            }
        }

        tracing::info!("Refreshed {} JWKS keys from {}", new_keys.len(), url);
        let mut keys = self.jwks_keys.write().unwrap_or_else(|e| e.into_inner());
        *keys = new_keys;

        Ok(())
    }

    /// Get the JWKS URL (for spawning background refresh).
    pub fn jwks_url(&self) -> Option<&str> {
        self.jwks_url.as_deref()
    }
}

fn map_jwt_error(e: jsonwebtoken::errors::Error) -> AuthError {
    use jsonwebtoken::errors::ErrorKind;
    match e.kind() {
        ErrorKind::ExpiredSignature => AuthError::Expired,
        _ => AuthError::InvalidToken(e.to_string()),
    }
}

/// JWKS response structure
#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize)]
struct JwkKey {
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

/// JWT configuration (deserialized from TOML)
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct JwtConfig {
    /// HMAC-SHA256 secret for self-signed tokens
    #[serde(default)]
    pub hmac_secret: String,
    /// URL to JWKS endpoint for RS256 validation (optional)
    #[serde(default)]
    pub jwks_url: String,
    /// Seconds between JWKS refreshes (default: 3600)
    #[serde(default = "default_jwks_refresh_interval")]
    pub jwks_refresh_interval: u64,
    /// Expected issuer claim (optional)
    #[serde(default)]
    pub issuer: Option<String>,
    /// Expected audience claim (optional)
    #[serde(default)]
    pub audience: Option<String>,
}

fn default_jwks_refresh_interval() -> u64 {
    3600
}

/// Auth mode configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AuthConfig {
    /// Auth mode: "none", "api_key", or "jwt"
    #[serde(default = "default_auth_mode")]
    pub mode: String,
    /// API key (for mode = "api_key", backward compat with server.api_key)
    #[serde(default)]
    pub api_key: Option<String>,
    /// JWT configuration (for mode = "jwt")
    #[serde(default)]
    pub jwt: JwtConfig,
}

fn default_auth_mode() -> String {
    "none".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token(claims: &GrobClaims, secret: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn test_valid_hmac_token() {
        let config = JwtConfig {
            hmac_secret: "test-secret-256-bits-minimum!!".to_string(),
            ..Default::default()
        };
        let validator = JwtValidator::from_config(&config).unwrap();

        let claims = GrobClaims {
            sub: "user-123".to_string(),
            tenant: None,
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
            iss: None,
            aud: None,
        };

        let token = make_token(&claims, "test-secret-256-bits-minimum!!");
        let result = validator.validate(&token).unwrap();
        assert_eq!(result.sub, "user-123");
        assert_eq!(result.tenant_id(), "user-123");
    }

    #[test]
    fn test_tenant_override() {
        let config = JwtConfig {
            hmac_secret: "test-secret-256-bits-minimum!!".to_string(),
            ..Default::default()
        };
        let validator = JwtValidator::from_config(&config).unwrap();

        let claims = GrobClaims {
            sub: "user-123".to_string(),
            tenant: Some("org-456".to_string()),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
            iss: None,
            aud: None,
        };

        let token = make_token(&claims, "test-secret-256-bits-minimum!!");
        let result = validator.validate(&token).unwrap();
        assert_eq!(result.tenant_id(), "org-456");
    }

    #[test]
    fn test_expired_token() {
        let config = JwtConfig {
            hmac_secret: "test-secret-256-bits-minimum!!".to_string(),
            ..Default::default()
        };
        let validator = JwtValidator::from_config(&config).unwrap();

        let claims = GrobClaims {
            sub: "user-123".to_string(),
            tenant: None,
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as u64,
            iss: None,
            aud: None,
        };

        let token = make_token(&claims, "test-secret-256-bits-minimum!!");
        let result = validator.validate(&token);
        assert!(matches!(result, Err(AuthError::Expired)));
    }

    #[test]
    fn test_wrong_secret() {
        let config = JwtConfig {
            hmac_secret: "correct-secret-256-bits-min!!".to_string(),
            ..Default::default()
        };
        let validator = JwtValidator::from_config(&config).unwrap();

        let claims = GrobClaims {
            sub: "user-123".to_string(),
            tenant: None,
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
            iss: None,
            aud: None,
        };

        let token = make_token(&claims, "wrong-secret-256-bits-minim!!");
        let result = validator.validate(&token);
        assert!(matches!(result, Err(AuthError::InvalidToken(_))));
    }

    #[test]
    fn test_issuer_validation() {
        let config = JwtConfig {
            hmac_secret: "test-secret-256-bits-minimum!!".to_string(),
            issuer: Some("grob-auth".to_string()),
            ..Default::default()
        };
        let validator = JwtValidator::from_config(&config).unwrap();

        // Correct issuer
        let claims = GrobClaims {
            sub: "user-123".to_string(),
            tenant: None,
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
            iss: Some("grob-auth".to_string()),
            aud: None,
        };
        let token = make_token(&claims, "test-secret-256-bits-minimum!!");
        assert!(validator.validate(&token).is_ok());

        // Wrong issuer
        let claims_bad = GrobClaims {
            iss: Some("wrong-issuer".to_string()),
            ..claims
        };
        let token_bad = make_token(&claims_bad, "test-secret-256-bits-minimum!!");
        assert!(validator.validate(&token_bad).is_err());
    }
}
