use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// Serialize SecretString for storage
fn serialize_secret<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

/// Deserialize SecretString from storage
fn deserialize_secret<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(SecretString::new(s))
}

/// OAuth token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthToken {
    /// Provider ID (e.g., "claude-max", "anthropic-oauth")
    pub provider_id: String,
    /// OAuth access token (stored securely)
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub access_token: SecretString,
    /// OAuth refresh token (stored securely)
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub refresh_token: SecretString,
    /// Token expiration time (UTC)
    pub expires_at: DateTime<Utc>,
    /// Optional enterprise URL for GitHub Copilot Enterprise
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_url: Option<String>,
    /// Optional Google Cloud project ID for Gemini Code Assist API
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
}

impl OAuthToken {
    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Check if token will expire soon (within 5 minutes)
    pub fn needs_refresh(&self) -> bool {
        let now = Utc::now();
        let buffer = chrono::Duration::minutes(5);
        now + buffer >= self.expires_at
    }
}

/// Token storage - persists to JSON file
#[derive(Debug, Clone)]
pub struct TokenStore {
    /// Path to token storage file
    file_path: PathBuf,
    /// In-memory cache of tokens
    tokens: Arc<RwLock<HashMap<String, OAuthToken>>>,
}

impl TokenStore {
    /// Create a new token store
    /// Loads existing tokens from file if it exists
    pub fn new(file_path: PathBuf) -> Result<Self> {
        let tokens = if file_path.exists() {
            let content = fs::read_to_string(&file_path).context("Failed to read token file")?;
            serde_json::from_str(&content).context("Failed to parse token file")?
        } else {
            HashMap::new()
        };

        Ok(Self {
            file_path,
            tokens: Arc::new(RwLock::new(tokens)),
        })
    }

    /// Get default token store path
    /// ~/.grob/oauth_tokens.json
    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Failed to get home directory")?;
        let config_dir = home.join(".grob");
        fs::create_dir_all(&config_dir).context("Failed to create config directory")?;
        Ok(config_dir.join("oauth_tokens.json"))
    }

    /// Create a token store at the default location
    pub fn at_default_path() -> Result<Self> {
        let path = Self::default_path()?;
        Self::new(path)
    }

    /// Save token for a provider
    pub fn save(&self, token: OAuthToken) -> Result<()> {
        let provider_id = token.provider_id.clone();

        // Update in-memory cache
        {
            let mut tokens = self
                .tokens
                .write()
                .expect("Token store lock poisoned during write - cannot proceed safely");
            tokens.insert(provider_id, token);
        }

        // Persist to file
        self.persist()?;

        Ok(())
    }

    /// Get token for a provider
    pub fn get(&self, provider_id: &str) -> Option<OAuthToken> {
        let tokens = self
            .tokens
            .read()
            .expect("Token store lock poisoned during read - cannot proceed safely");
        tokens.get(provider_id).cloned()
    }

    /// Remove token for a provider
    pub fn remove(&self, provider_id: &str) -> Result<()> {
        {
            let mut tokens = self
                .tokens
                .write()
                .expect("Token store lock poisoned during write - cannot proceed safely");
            tokens.remove(provider_id);
        }

        // Persist to file
        self.persist()?;

        Ok(())
    }

    /// List all provider IDs that have tokens
    pub fn list_providers(&self) -> Vec<String> {
        let tokens = self
            .tokens
            .read()
            .expect("Token store lock poisoned during read - cannot proceed safely");
        tokens.keys().cloned().collect()
    }

    /// Get all tokens
    pub fn all(&self) -> HashMap<String, OAuthToken> {
        let tokens = self
            .tokens
            .read()
            .expect("Token store lock poisoned during read - cannot proceed safely");
        tokens.clone()
    }

    /// Persist tokens to file
    fn persist(&self) -> Result<()> {
        let tokens = self
            .tokens
            .read()
            .expect("Token store lock poisoned during read - cannot proceed safely");
        let json = serde_json::to_string_pretty(&*tokens).context("Failed to serialize tokens")?;

        fs::write(&self.file_path, json).context("Failed to write token file")?;

        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&self.file_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&self.file_path, perms)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_token_store() {
        let temp_dir = TempDir::new().unwrap();
        let token_path = temp_dir.path().join("tokens.json");
        let store = TokenStore::new(token_path).unwrap();

        let token = OAuthToken {
            provider_id: "test-provider".to_string(),
            access_token: SecretString::new("access-123".to_string()),
            refresh_token: SecretString::new("refresh-456".to_string()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            enterprise_url: None,
            project_id: None,
        };

        store.save(token.clone()).unwrap();

        let retrieved = store.get("test-provider").unwrap();
        assert_eq!(retrieved.access_token.expose_secret(), "access-123");
        assert_eq!(retrieved.refresh_token.expose_secret(), "refresh-456");

        store.remove("test-provider").unwrap();
        assert!(store.get("test-provider").is_none());
    }

    #[test]
    fn test_token_expiration() {
        let expired_token = OAuthToken {
            provider_id: "test".to_string(),
            access_token: SecretString::new("token".to_string()),
            refresh_token: SecretString::new("refresh".to_string()),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            enterprise_url: None,
            project_id: None,
        };

        assert!(expired_token.is_expired());
        assert!(expired_token.needs_refresh());

        let valid_token = OAuthToken {
            provider_id: "test".to_string(),
            access_token: SecretString::new("token".to_string()),
            refresh_token: SecretString::new("refresh".to_string()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            enterprise_url: None,
            project_id: None,
        };

        assert!(!valid_token.is_expired());
        assert!(!valid_token.needs_refresh());
    }
}
