//! Authentication: JWT validation, OAuth flows, and token storage.

/// Automatic credential setup at startup.
pub mod auto_flow;
/// JWT validation and claims extraction.
pub mod jwt;
/// OAuth PKCE flows for Anthropic, OpenAI, and Gemini.
pub mod oauth;
/// Background daemon that proactively refreshes OAuth tokens.
pub mod refresh_daemon;
/// Persistent token storage for OAuth credentials.
pub mod token_store;
/// Virtual API key management for multi-tenant access control.
pub mod virtual_keys;

pub use jwt::{GrobClaims, JwtValidator};
pub use oauth::{OAuthClient, OAuthConfig, OAuthProviderType};
pub use token_store::TokenStore;
pub use virtual_keys::{VirtualKeyContext, VirtualKeyRecord};
