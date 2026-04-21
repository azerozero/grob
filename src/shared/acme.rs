//! ACME (Let's Encrypt) auto-certificate provisioning.
//!
//! Uses TLS-ALPN-01 challenge on the same port as the main server.
//! Certificates are cached in `~/.grob/certs/` by default.

use crate::cli::AcmeConfig;
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Resolves and creates the ACME certificate cache directory, defaulting to `~/.grob/certs/` when unset.
///
/// Defaults to `~/.grob/certs/` if not specified.
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined or
/// the cache directory cannot be created.
pub fn resolve_cache_dir(config: &AcmeConfig) -> Result<PathBuf> {
    let dir = if config.cache_dir.is_empty() {
        crate::grob_home()
            .context("Failed to get home directory (set GROB_HOME)")?
            .join("certs")
    } else if config.cache_dir.starts_with('~') {
        crate::expand_tilde(&config.cache_dir)
    } else {
        PathBuf::from(&config.cache_dir)
    };

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create ACME cache directory: {}", dir.display()))?;

    Ok(dir)
}

/// Builds the rustls-acme AcmeConfig and returns an AxumAcceptor.
///
/// Returns an `axum_server::accept::Accept`-compatible acceptor.
/// Spawns the ACME event loop in the background for certificate renewals.
///
/// # Errors
///
/// Returns an error if the certificate cache directory cannot be
/// resolved or created.
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
