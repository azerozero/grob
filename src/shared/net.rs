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

/// Default span of ports [`bind_with_port_retry`] tries: the base plus 9 fallbacks.
pub const DEFAULT_PORT_RETRY_ATTEMPTS: u16 = 10;

/// Binds `host:base_port`, falling back to adjacent ports up to `attempts` total.
///
/// Tries `base_port`, then `base_port + 1`, up to `base_port + attempts - 1`, and
/// returns the first listener that binds along with the port it claimed. A plain
/// `tokio::net::TcpListener` is used deliberately: unlike [`bind_reuseport`], it does
/// **not** set `SO_REUSEPORT`, so a busy port reliably fails and the next candidate is
/// tried. This suits ephemeral local servers — such as the OAuth callback — where a
/// stable port is preferred but any free adjacent port is acceptable.
///
/// # Errors
///
/// Returns an error if `attempts` is zero, if the port range would overflow `u16`, or
/// if every port in `base_port..base_port + attempts` is already in use.
pub async fn bind_with_port_retry(
    host: &str,
    base_port: u16,
    attempts: u16,
) -> Result<(tokio::net::TcpListener, u16)> {
    if attempts == 0 {
        anyhow::bail!("bind_with_port_retry: attempts must be greater than zero");
    }

    let mut last_err: Option<anyhow::Error> = None;
    let mut last_port = base_port;
    for offset in 0..attempts {
        // NOTE: Stop before wrapping past u16::MAX (e.g. base_port near 65535).
        let Some(port) = base_port.checked_add(offset) else {
            break;
        };
        last_port = port;
        let addr = crate::cli::format_bind_addr(host, port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => return Ok((listener, port)),
            Err(e) => last_err = Some(anyhow::Error::new(e).context(format!("bind {}", addr))),
        }
    }

    let err = last_err
        .unwrap_or_else(|| anyhow::anyhow!("bind_with_port_retry: no ports attempted on {}", host));
    Err(err.context(format!(
        "could not bind any port in range {}..={} on {}",
        base_port, last_port, host
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
        // Grab an ephemeral port to use as the base, then release it so the
        // retry helper can claim that exact port on its first attempt.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_port = probe.local_addr().unwrap().port();
        drop(probe);

        let (_listener, port) = bind_with_port_retry("127.0.0.1", base_port, 5)
            .await
            .expect("base port should be free");
        assert_eq!(port, base_port);
    }

    #[tokio::test]
    async fn test_bind_with_port_retry_falls_back_to_next_port() {
        // Hold the base port for the whole test so the helper must advance.
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base_port = blocker.local_addr().unwrap().port();

        let (_listener, port) = bind_with_port_retry("127.0.0.1", base_port, 5)
            .await
            .expect("a fallback port should be free");
        assert!(
            port > base_port && port < base_port.saturating_add(5),
            "expected fallback in {}..{}, got {port}",
            base_port + 1,
            base_port + 5
        );
        drop(blocker);
    }

    #[tokio::test]
    async fn test_bind_with_port_retry_zero_attempts_errors() {
        let err = bind_with_port_retry("127.0.0.1", 50_000, 0)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("attempts must be greater than zero"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_bind_with_port_retry_reports_range_when_busy() {
        // A single busy port with attempts=1 deterministically exhausts the
        // range and yields the range-exhausted context message.
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let busy_port = blocker.local_addr().unwrap().port();

        let err = bind_with_port_retry("127.0.0.1", busy_port, 1)
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("could not bind any port in range"),
            "unexpected error: {msg}"
        );
        drop(blocker);
    }
}
