//! SO_REUSEPORT listener builder for zero-downtime restarts.
//!
//! Allows both old and new processes to bind the same port simultaneously
//! during hot restart. The kernel load-balances new connections between them.

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

/// Create a tokio TcpListener with SO_REUSEPORT + SO_REUSEADDR.
pub async fn bind_reuseport(addr: &str) -> Result<tokio::net::TcpListener> {
    let std_listener = bind_reuseport_std(addr)?;
    std_listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(std_listener)
        .context("Failed to convert std::net::TcpListener to tokio")
}

/// Create a std::net::TcpListener with SO_REUSEPORT + SO_REUSEADDR.
/// Suitable for passing to axum_server::from_tcp_rustls().
pub fn bind_reuseport_std(addr: &str) -> Result<std::net::TcpListener> {
    let socket_addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("Invalid bind address: {}", addr))?;

    let domain = if socket_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .context("Failed to create socket")?;

    // Allow address reuse (TIME_WAIT sockets)
    socket
        .set_reuse_address(true)
        .context("Failed to set SO_REUSEADDR")?;

    // Allow multiple processes to bind the same port
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .context("Failed to set SO_REUSEPORT")?;

    // Allow dual-stack IPv6 to also accept IPv4
    if socket_addr.is_ipv6() {
        socket.set_only_v6(false).ok(); // best-effort
    }

    socket
        .bind(&socket_addr.into())
        .with_context(|| format!("Failed to bind to {}", addr))?;

    socket
        .listen(1024)
        .context("Failed to listen on socket")?;

    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_reuseport_std_ipv4() {
        // Bind to random port
        let listener = bind_reuseport_std("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[test]
    fn test_bind_reuseport_std_ipv6() {
        let listener = bind_reuseport_std("[::1]:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_two_listeners_same_port() {
        let l1 = bind_reuseport_std("127.0.0.1:0").unwrap();
        let port = l1.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{}", port);

        // Second listener on the same port should succeed with SO_REUSEPORT
        let l2 = bind_reuseport_std(&addr).unwrap();
        assert_eq!(l2.local_addr().unwrap().port(), port);
    }

    #[test]
    fn test_invalid_addr() {
        assert!(bind_reuseport_std("not_an_addr").is_err());
    }
}
