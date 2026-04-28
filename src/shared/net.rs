//! Listener builder for zero-downtime restarts.
//!
//! With the `socket-opts` feature (default), uses `socket2` to set
//! `SO_REUSEPORT` + `SO_REUSEADDR` so both old and new processes can bind
//! the same port simultaneously during hot restart.
//!
//! When `socket-opts` is disabled, falls back to plain
//! `tokio::net::TcpListener::bind`.

use anyhow::{Context, Result};

/// Creates a tokio TcpListener, with SO_REUSEPORT when available.
///
/// # Errors
///
/// Returns an error if the address cannot be parsed or the socket
/// cannot be bound.
pub async fn bind_reuseport(addr: &str) -> Result<tokio::net::TcpListener> {
    #[cfg(feature = "socket-opts")]
    {
        let std_listener = bind_reuseport_std(addr)?;
        std_listener.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(std_listener)
            .context("Failed to convert std::net::TcpListener to tokio")
    }

    #[cfg(not(feature = "socket-opts"))]
    {
        tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind to {}", addr))
    }
}

/// Creates a std::net::TcpListener, with SO_REUSEPORT when available.
///
/// Suitable for passing to `axum_server::from_tcp_rustls()`.
///
/// # Errors
///
/// Returns an error if the address is invalid, socket creation fails,
/// socket options cannot be set, or binding fails.
#[cfg(feature = "socket-opts")]
pub fn bind_reuseport_std(addr: &str) -> Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

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

    socket.listen(1024).context("Failed to listen on socket")?;

    Ok(socket.into())
}

/// Fallback: plain std TcpListener without socket options.
///
/// # Errors
///
/// Returns an error if the address cannot be bound.
#[cfg(not(feature = "socket-opts"))]
pub fn bind_reuseport_std(addr: &str) -> Result<std::net::TcpListener> {
    use std::net::TcpListener;
    TcpListener::bind(addr).with_context(|| format!("Failed to bind to {}", addr))
}

/// Default maximum bind attempts for [`bind_with_port_retry`] (base port plus 9 fallbacks).
pub const DEFAULT_PORT_RETRY_ATTEMPTS: u16 = 10;

/// Binds to `host:base_port`, falling back to adjacent ports up to `max_attempts` total.
///
/// Tries `base_port`, `base_port + 1`, ..., `base_port + max_attempts - 1` in order
/// and returns the first listener that binds successfully along with its actual port.
/// Uses plain `tokio::net::TcpListener::bind` (no `SO_REUSEPORT`) so a busy port is
/// reliably detected and the next candidate is tried. Useful for ephemeral local
/// servers — like the OAuth callback — where a stable port is preferred but a free
/// adjacent port is acceptable when the default is occupied.
///
/// # Errors
///
/// Returns an error if every port in `base_port..base_port + max_attempts` is busy
/// or otherwise unbindable, or if `max_attempts` is zero.
pub async fn bind_with_port_retry(
    host: &str,
    base_port: u16,
    max_attempts: u16,
) -> Result<(tokio::net::TcpListener, u16)> {
    if max_attempts == 0 {
        anyhow::bail!("bind_with_port_retry: max_attempts must be > 0");
    }

    let end_port = base_port.saturating_add(max_attempts);
    let mut last_err: Option<anyhow::Error> = None;
    for offset in 0..max_attempts {
        let Some(port) = base_port.checked_add(offset) else {
            // NOTE: Stop early if we would overflow u16 (e.g. base_port=65535).
            break;
        };
        let addr = crate::cli::format_bind_addr(host, port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                return Ok((listener, port));
            }
            Err(e) => {
                last_err = Some(anyhow::Error::new(e).context(format!("bind {}", addr)));
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("bind_with_port_retry: no attempts made for {}", host))
        .context(format!(
            "Could not bind any port in range {}..{}",
            base_port, end_port
        )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_reuseport_std_ipv4() {
        let listener = bind_reuseport_std("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[test]
    fn test_bind_reuseport_std_ipv6() {
        // NOTE: Skip gracefully when IPv6 is unavailable (Windows CI, some containers).
        match bind_reuseport_std("[::1]:0") {
            Ok(listener) => {
                let addr = listener.local_addr().unwrap();
                assert!(addr.port() > 0);
            }
            Err(e) => {
                eprintln!("IPv6 not available, skipping: {e}");
            }
        }
    }

    #[cfg(all(unix, feature = "socket-opts"))]
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

    #[tokio::test]
    async fn test_bind_with_port_retry_uses_base_port_when_free() {
        // Pick an ephemeral port to use as our "base", then immediately drop it
        // so the retry helper can claim it on the first try.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_port = probe.local_addr().unwrap().port();
        drop(probe);

        let (_listener, port) = bind_with_port_retry("127.0.0.1", base_port, 5)
            .await
            .expect("bind should succeed when base port is free");
        assert_eq!(port, base_port);
    }

    #[tokio::test]
    async fn test_bind_with_port_retry_falls_back_to_next_port() {
        // Hold the base port so the retry helper has to advance to base+1.
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_port = blocker.local_addr().unwrap().port();
        // Keep the blocker alive to ensure base_port stays busy for the test.

        let (_listener, port) = bind_with_port_retry("127.0.0.1", base_port, 5)
            .await
            .expect("bind should succeed on a fallback port");
        assert!(
            port > base_port && port < base_port.saturating_add(5),
            "expected fallback port in range, got {port} (base {base_port})"
        );
        drop(blocker);
    }

    #[tokio::test]
    async fn test_bind_with_port_retry_zero_attempts_errors() {
        let err = bind_with_port_retry("127.0.0.1", 50_000, 0)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("max_attempts must be > 0"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_bind_with_port_retry_reports_range_when_all_busy() {
        // Hold a contiguous block of ports so every retry attempt must fail.
        let blockers: Vec<std::net::TcpListener> = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();

        // Find a contiguous run of busy ports we already hold.
        let ports: Vec<u16> = blockers
            .iter()
            .map(|l| l.local_addr().unwrap().port())
            .collect();
        let mut sorted_ports = ports.clone();
        sorted_ports.sort_unstable();

        // NOTE: We can't guarantee the OS gave us contiguous ports, so we
        // verify the error path by trying to bind a single busy port with
        // attempts=1, which deterministically fails with the range message.
        let busy_port = sorted_ports[0];
        let err = bind_with_port_retry("127.0.0.1", busy_port, 1)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Could not bind any port in range"),
            "unexpected error: {msg}"
        );
        drop(blockers);
    }
}
