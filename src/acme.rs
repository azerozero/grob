//! ACME (Let's Encrypt) auto-certificate provisioning.
//!
//! Uses TLS-ALPN-01 challenge on the same port as the main server.
//! Certificates are cached in `~/.grob/certs/` by default.

use crate::cli::AcmeConfig;
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Resolve the certificate cache directory.
/// Defaults to `~/.grob/certs/` if not specified.
pub fn resolve_cache_dir(config: &AcmeConfig) -> Result<PathBuf> {
    let dir = if config.cache_dir.is_empty() {
        let home = dirs::home_dir().context("Failed to get home directory")?;
        home.join(".grob").join("certs")
    } else if config.cache_dir.starts_with('~') {
        let home = dirs::home_dir().context("Failed to get home directory")?;
        home.join(&config.cache_dir[2..])
    } else {
        PathBuf::from(&config.cache_dir)
    };

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create ACME cache directory: {}", dir.display()))?;

    Ok(dir)
}

/// Build the rustls-acme AcmeConfig and return an AxumAcceptor.
///
/// Returns an `axum_server::accept::Accept`-compatible acceptor.
/// Spawns the ACME event loop in the background for certificate renewals.
#[cfg(feature = "acme")]
pub fn build_acme_acceptor(config: &AcmeConfig) -> Result<rustls_acme::axum::AxumAcceptor> {
    use futures::StreamExt;

    let cache_dir = resolve_cache_dir(config)?;

    let mut acme_cfg = rustls_acme::AcmeConfig::new(config.domains.clone())
        .contact(
            config
                .contacts
                .iter()
                .map(|c| format!("mailto:{}", c))
                .collect::<Vec<_>>(),
        )
        .cache(rustls_acme::caches::DirCache::new(cache_dir));

    if config.staging {
        acme_cfg = acme_cfg.directory_lets_encrypt(false);
        tracing::info!("🔒 ACME: using Let's Encrypt STAGING environment");
    } else {
        acme_cfg = acme_cfg.directory_lets_encrypt(true);
        tracing::info!("🔒 ACME: using Let's Encrypt PRODUCTION environment");
    }

    let mut acme_state = acme_cfg.state();
    let rustls_config = acme_state.default_rustls_config();

    #[allow(deprecated)] // axum_acceptor uses deprecated acceptor() internally
    let acceptor = acme_state.axum_acceptor(rustls_config);

    // Spawn ACME event loop (handles certificate renewals)
    tokio::spawn(async move {
        loop {
            match acme_state.next().await {
                Some(Ok(ok)) => tracing::info!("ACME event: {:?}", ok),
                Some(Err(err)) => tracing::error!("ACME error: {:?}", err),
                None => break,
            }
        }
    });

    tracing::info!(
        "🔒 ACME auto-certificates enabled for domains: {:?}",
        config.domains
    );

    Ok(acceptor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_cache_dir_default() {
        let config = AcmeConfig::default();
        let dir = resolve_cache_dir(&config).unwrap();
        assert!(dir.ends_with("certs"));
    }

    #[test]
    fn test_resolve_cache_dir_custom() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = AcmeConfig {
            cache_dir: dir.path().to_string_lossy().to_string(),
            ..Default::default()
        };
        let resolved = resolve_cache_dir(&config).unwrap();
        assert_eq!(resolved, dir.path());
    }
}
