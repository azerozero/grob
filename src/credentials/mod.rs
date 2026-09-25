//! Scoped credential routing with local authority and optional Vault KV v2 recovery.

pub(crate) mod broker;
pub mod config;
pub(crate) mod filter;
pub mod record;
pub(crate) mod transport;

/// Reports failures without including credentials, upstream bodies or URLs.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// Rejects an unauthorized service, destination or credential state.
    #[error("credential access denied")]
    Denied,
    /// Rejects unavailable authorities without eligible recovery records.
    #[error("credential authority unavailable")]
    Unavailable,
    /// Rejects missing, unreadable or corrupt persistent state.
    #[error("credential state unavailable or invalid")]
    Storage,
    /// Rejects an outdated mutation after another process changed authority.
    #[error("credential changed; retry the request")]
    Changed,
}

pub(crate) type Result<T> = std::result::Result<T, CredentialError>;

#[cfg(test)]
mod tests;

pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
