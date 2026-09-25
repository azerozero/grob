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
    let port = url.port_or_known_default().ok_or(CredentialError::Denied)?;
    let addresses: Vec<_> = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
    crate::shared::credential_transport::client_builder()
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(60))
        .resolve_to_addrs(url.host_str().ok_or(CredentialError::Denied)?, &addresses)
        .build()
        .map_err(|_| CredentialError::Denied)
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
