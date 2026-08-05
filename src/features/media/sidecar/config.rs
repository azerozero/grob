//! Sidecar configuration.
//!
//! Absent configuration means the capability is switched off, not that
//! startup fails. Grob must serve traffic whether or not any media
//! apparatus is installed.

use super::proto::Capability;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Default per-call deadline.
///
/// Generous enough for OCR on a large screenshot (measured around 320 ms with
/// `ocrs`), short enough that a wedged sidecar cannot hold a request open.
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// How to reach one sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
    /// Unix domain socket. The default and the recommended form.
    ///
    /// Sidecars receive payloads that may contain secrets; a filesystem
    /// socket keeps them off the network and under ordinary file permissions.
    Unix {
        /// Filesystem path of the socket.
        path: String,
    },
    /// Loopback TCP, for platforms or deployments without unix sockets.
    Tcp {
        /// `host:port`, expected to be loopback.
        address: String,
    },
}

impl Endpoint {
    /// Returns whether this endpoint is reachable from outside the host.
    ///
    /// Used to warn rather than to forbid: an operator may have a reason, but
    /// should never expose a sidecar unknowingly.
    #[must_use]
    pub fn is_potentially_remote(&self) -> bool {
        match self {
            Self::Unix { .. } => false,
            Self::Tcp { address } => {
                let host = address
                    .rsplit_once(':')
                    .map_or(address.as_str(), |(h, _)| h);
                let host = host.trim_start_matches('[').trim_end_matches(']');
                !matches!(host, "localhost" | "127.0.0.1" | "::1" | "")
            }
        }
    }
}

/// Configuration for the sidecar layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SidecarConfig {
    /// Endpoint per capability. Absent capabilities are disabled.
    pub endpoints: HashMap<String, Endpoint>,
    /// Per-call deadline in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl SidecarConfig {
    /// Returns the endpoint configured for `capability`, if any.
    #[must_use]
    pub fn endpoint(&self, capability: Capability) -> Option<&Endpoint> {
        self.endpoints.get(capability.as_str())
    }

    /// Returns whether `capability` is available.
    #[must_use]
    pub fn is_enabled(&self, capability: Capability) -> bool {
        self.endpoint(capability).is_some()
    }

    /// Per-call deadline.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS))
    }

    /// Endpoints that may be reachable beyond the host, for startup warnings.
    #[must_use]
    pub fn externally_reachable(&self) -> Vec<&str> {
        self.endpoints
            .iter()
            .filter(|(_, endpoint)| endpoint.is_potentially_remote())
            .map(|(capability, _)| capability.as_str())
            .collect()
    }
}
