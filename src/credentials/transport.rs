//! Pins every credential-bearing connection to administrator-approved addresses.

use super::{CredentialError, Result};
use std::net::{IpAddr, SocketAddr};

pub(crate) fn endpoint(raw: &str, ips: &[IpAddr]) -> Result<reqwest::Url> {
    let url = crate::shared::credential_transport::validate_endpoint(raw)
        .map_err(|_| CredentialError::Denied)?;
    if ips.is_empty()
        || url.query().is_some()
        || url.fragment().is_some()
        || !super::config::canonical_path(url.path())
        || ips
            .iter()
            .any(|ip| ip.is_unspecified() || ip.is_multicast())
    {
        return Err(CredentialError::Denied);
    }
    let literal = match url.host() {
        Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
        Some(url::Host::Domain(_)) => None,
        None => return Err(CredentialError::Denied),
    };
    if literal.is_some_and(|ip| !ips.contains(&ip)) {
        return Err(CredentialError::Denied);
    }
    // HTTP loopback exceptions must also connect to loopback, including localhost overrides.
    if url.scheme() == "http" && ips.iter().any(|ip| !ip.is_loopback()) {
        return Err(CredentialError::Denied);
    }
    Ok(url)
}

pub(crate) fn client(url: &reqwest::Url, ips: &[IpAddr]) -> Result<reqwest::Client> {
    client_builder(url, ips)?
        .build()
        .map_err(|_| CredentialError::Denied)
}

fn client_builder(url: &reqwest::Url, ips: &[IpAddr]) -> Result<reqwest::ClientBuilder> {
    let port = url.port_or_known_default().ok_or(CredentialError::Denied)?;
    let addresses: Vec<_> = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
    Ok(crate::shared::credential_transport::client_builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(60))
        .resolve_to_addrs(url.host_str().ok_or(CredentialError::Denied)?, &addresses))
}

pub(crate) fn vault_client(
    config: &super::config::VaultConfig,
    url: &reqwest::Url,
) -> Result<reqwest::Client> {
    if let Some(path) = &config.proxy_socket {
        #[cfg(unix)]
        {
            // The socket may appear after Grob starts. Its permissions are checked
            // on each authoritative refresh, including after companion restarts.
            return crate::shared::credential_transport::client_builder()
                .no_proxy()
                .unix_socket(path.clone())
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .map_err(|_| CredentialError::Denied);
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(CredentialError::Denied);
        }
    }
    client(url, &config.allowed_ips)
}

pub(crate) fn check_proxy_socket(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                CredentialError::Unavailable
            } else {
                CredentialError::Denied
            }
        })?;
        if !metadata.file_type().is_socket() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(CredentialError::Denied);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(CredentialError::Denied)
    }
}

pub(crate) fn unavailable(error: &reqwest::Error) -> bool {
    if error.is_timeout() {
        return true;
    }
    let mut cause = std::error::Error::source(error);
    while let Some(e) = cause {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::TimedOut
            ) {
                return true;
            }
        }
        cause = e.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{ConnectInfo, State},
        routing::get,
        Router,
    };
    use std::{
        collections::HashSet,
        sync::{Arc, Mutex},
    };

    #[tokio::test]
    async fn connection_baseline_fresh_clients_and_reused_client() {
        let peers = Arc::new(Mutex::new(HashSet::<SocketAddr>::new()));
        let app = Router::new()
            .route(
                "/",
                get(
                    |State(peers): State<Arc<Mutex<HashSet<SocketAddr>>>>,
                     ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
                        peers.lock().unwrap().insert(peer);
                        "ok"
                    },
                ),
            )
            .with_state(peers.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let url = endpoint(&format!("http://{addr}"), &[addr.ip()]).unwrap();
        for _ in 0..32 {
            assert_eq!(
                client(&url, &[addr.ip()])
                    .unwrap()
                    .get(url.clone())
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap(),
                "ok"
            );
        }
        let fresh = peers.lock().unwrap().len();
        peers.lock().unwrap().clear();
        let shared = client(&url, &[addr.ip()]).unwrap();
        for _ in 0..32 {
            assert_eq!(
                shared
                    .clone()
                    .get(url.clone())
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap(),
                "ok"
            );
        }
        let reused = peers.lock().unwrap().len();
        println!(
            "32 requests: fresh_clients_connections={fresh}, reused_client_connections={reused}"
        );
        assert_eq!(fresh, 32);
        assert_eq!(reused, 1);
        server.abort();
    }
}

#[cfg(all(test, feature = "tls"))]
mod tls_tests;
