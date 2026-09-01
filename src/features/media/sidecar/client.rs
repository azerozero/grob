//! Sidecar client: newline-delimited JSON over a unix socket or loopback TCP.
//!
//! One request, one response, one connection. No pooling and no session, which
//! keeps the client as stateless as the contract it speaks and makes a wedged
//! sidecar impossible to inherit on a later call.

use super::config::{Endpoint, SidecarConfig};
use super::proto::{Capability, SidecarError, SidecarRequest, SidecarResponse, PROTOCOL_VERSION};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};

/// Consecutive failures after which a sidecar is left alone.
const TRIP_THRESHOLD: u32 = 5;

/// Talks to the configured sidecars.
#[derive(Debug)]
pub struct SidecarClient {
    config: SidecarConfig,
    /// Consecutive failures, for the trip decision.
    ///
    /// A single counter for all capabilities: they are separate processes in
    /// principle, but a shared counter fails safe, and the alternative is
    /// per-capability state that has to be kept in sync for little gain.
    failures: AtomicU32,
}

impl SidecarClient {
    /// Builds a client over the given configuration.
    #[must_use]
    pub fn new(config: SidecarConfig) -> Self {
        Self {
            config,
            failures: AtomicU32::new(0),
        }
    }

    /// Returns whether a capability is configured.
    #[must_use]
    pub fn is_enabled(&self, capability: Capability) -> bool {
        self.config.is_enabled(capability)
    }

    /// Returns whether the breaker has tripped.
    #[must_use]
    pub fn is_tripped(&self) -> bool {
        self.failures.load(Ordering::Relaxed) >= TRIP_THRESHOLD
    }

    /// Resets the failure counter, re-admitting a recovered sidecar.
    pub fn reset(&self) {
        self.failures.store(0, Ordering::Relaxed);
    }

    /// Sends one request and returns the validated response.
    ///
    /// # Errors
    ///
    /// Returns [`SidecarError::NotConfigured`] when the capability is off,
    /// [`SidecarError::CircuitOpen`] after repeated failures,
    /// [`SidecarError::Timeout`] past the deadline, and
    /// [`SidecarError::Unreachable`], [`SidecarError::Malformed`] or
    /// [`SidecarError::VersionMismatch`] for transport and envelope problems.
    pub async fn call(&self, request: &SidecarRequest) -> Result<SidecarResponse, SidecarError> {
        let capability = request.capability;
        let Some(endpoint) = self.config.endpoint(capability) else {
            // Not an error condition: an unconfigured capability is off, and
            // callers degrade rather than fail.
            return Err(SidecarError::NotConfigured(capability.as_str()));
        };
        if self.is_tripped() {
            return Err(SidecarError::CircuitOpen);
        }

        let timeout = self.config.timeout();
        let result = tokio::time::timeout(timeout, Self::exchange(endpoint, request)).await;

        match result {
            Ok(Ok(response)) => {
                self.reset();
                response.validate()?;
                Ok(response)
            }
            Ok(Err(err)) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
            Err(_elapsed) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                Err(SidecarError::Timeout(timeout.as_millis() as u64))
            }
        }
    }

    /// Writes the request line and reads the response line.
    async fn exchange(
        endpoint: &Endpoint,
        request: &SidecarRequest,
    ) -> Result<SidecarResponse, SidecarError> {
        let mut line =
            serde_json::to_string(request).map_err(|e| SidecarError::Malformed(e.to_string()))?;
        line.push('\n');

        match endpoint {
            Endpoint::Unix { path } => {
                let stream = UnixStream::connect(path)
                    .await
                    .map_err(|e| SidecarError::Unreachable(e.to_string()))?;
                Self::round_trip(stream, line.as_bytes()).await
            }
            Endpoint::Tcp { address } => {
                let stream = TcpStream::connect(address)
                    .await
                    .map_err(|e| SidecarError::Unreachable(e.to_string()))?;
                Self::round_trip(stream, line.as_bytes()).await
            }
        }
    }

    /// Sends `payload` and parses one newline-delimited response.
    async fn round_trip<S>(stream: S, payload: &[u8]) -> Result<SidecarResponse, SidecarError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (reader, mut writer) = tokio::io::split(stream);
        writer
            .write_all(payload)
            .await
            .map_err(|e| SidecarError::Unreachable(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| SidecarError::Unreachable(e.to_string()))?;

        let mut line = String::new();
        BufReader::new(reader)
            .read_line(&mut line)
            .await
            .map_err(|e| SidecarError::Unreachable(e.to_string()))?;
        if line.trim().is_empty() {
            return Err(SidecarError::Malformed("empty response".into()));
        }
        serde_json::from_str(&line).map_err(|e| SidecarError::Malformed(e.to_string()))
    }

    /// Extracts text from an image via the OCR sidecar.
    ///
    /// # Errors
    ///
    /// See [`Self::call`].
    pub async fn ocr(&self, payload_base64: &str) -> Result<String, SidecarError> {
        let request = SidecarRequest::new(Capability::Ocr, payload_base64);
        self.call(&request).await?.into_text()
    }

    /// Protocol version this client speaks.
    #[must_use]
    pub const fn protocol_version() -> u32 {
        PROTOCOL_VERSION
    }
}
