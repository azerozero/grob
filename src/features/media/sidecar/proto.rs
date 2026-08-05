//! Wire protocol for media sidecars.
//!
//! Sidecars are **stateless by contract**: bytes in, bytes or text out. They
//! never receive a tenant, a session, a policy or a trace identifier, and they
//! are never asked to remember anything between calls.
//!
//! That is not a stylistic preference. A sidecar that retained payloads would
//! be a second copy of exactly the data the media slice exists to protect, on
//! a component with a different lifecycle and a different threat model. The
//! request type below has no field that could carry correlating context, so
//! the property is enforced by the type rather than by reviewer discipline.
//!
//! Everything stateful stays in Grob: the `trace_id` mapping, the observation
//! journal, and any deny-lists all live under `~/.grob/media/`.

use serde::{Deserialize, Serialize};

/// Protocol version understood by this build.
///
/// Sent on every request and checked on every response. Versioning from the
/// first release is deliberate: a protocol that ships unversioned can never
/// be changed without breaking deployments that are already in the field.
pub const PROTOCOL_VERSION: u32 = 1;

/// A capability a sidecar may offer.
///
/// One protocol serves all of them, rather than three ad-hoc integrations
/// that drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Extract text from an image, for reinjection into the DLP engine.
    Ocr,
    /// Embed or read a soft-binding watermark.
    Watermark,
    /// Sign or verify a content provenance manifest.
    Provenance,
}

impl Capability {
    /// Stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ocr => "ocr",
            Self::Watermark => "watermark",
            Self::Provenance => "provenance",
        }
    }
}

/// A unit of work for a sidecar.
///
/// Deliberately minimal. There is no tenant, session, model or trace field,
/// and none should be added: the sidecar's ignorance of who is asking is what
/// keeps it out of the blast radius.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarRequest {
    /// Protocol version of the caller.
    pub version: u32,
    /// Capability being invoked.
    pub capability: Capability,
    /// Base64-encoded payload.
    pub payload: String,
    /// Optional opaque argument, such as the bits to embed.
    ///
    /// Opaque on purpose: the sidecar treats it as data, never as identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argument: Option<String>,
}

impl SidecarRequest {
    /// Builds a request at the current protocol version.
    #[must_use]
    pub fn new(capability: Capability, payload: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            capability,
            payload: payload.into(),
            argument: None,
        }
    }

    /// Attaches the opaque argument.
    #[must_use]
    pub fn with_argument(mut self, argument: impl Into<String>) -> Self {
        self.argument = Some(argument.into());
        self
    }
}

/// A sidecar's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarResponse {
    /// Protocol version of the responder.
    pub version: u32,
    /// Extracted text, for [`Capability::Ocr`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Base64-encoded output payload, for transforming capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Error reported by the sidecar.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Why a sidecar call did not produce a usable answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SidecarError {
    /// No sidecar is configured for this capability.
    ///
    /// Not a failure: an unconfigured capability is simply switched off.
    #[error("no sidecar configured for capability '{0}'")]
    NotConfigured(&'static str),
    /// The sidecar did not answer within the deadline.
    #[error("sidecar timed out after {0} ms")]
    Timeout(u64),
    /// The sidecar could not be reached.
    #[error("sidecar unreachable: {0}")]
    Unreachable(String),
    /// The circuit breaker is open after repeated failures.
    #[error("sidecar circuit open; not retrying")]
    CircuitOpen,
    /// Protocol versions do not match.
    #[error("sidecar protocol version {actual} is not the expected {expected}")]
    VersionMismatch {
        /// Version this build speaks.
        expected: u32,
        /// Version the sidecar answered with.
        actual: u32,
    },
    /// The sidecar answered, but reported a failure.
    #[error("sidecar reported an error: {0}")]
    Reported(String),
    /// The response could not be understood.
    #[error("malformed sidecar response: {0}")]
    Malformed(String),
}

impl SidecarResponse {
    /// Validates the response envelope before its contents are trusted.
    ///
    /// # Errors
    ///
    /// Returns [`SidecarError::VersionMismatch`] on a version disagreement,
    /// or [`SidecarError::Reported`] when the sidecar signalled a failure.
    pub fn validate(&self) -> Result<(), SidecarError> {
        if self.version != PROTOCOL_VERSION {
            return Err(SidecarError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: self.version,
            });
        }
        if let Some(error) = &self.error {
            return Err(SidecarError::Reported(error.clone()));
        }
        Ok(())
    }

    /// Returns the extracted text, validating the envelope first.
    ///
    /// # Errors
    ///
    /// See [`Self::validate`], plus [`SidecarError::Malformed`] when the
    /// capability's expected field is absent.
    pub fn into_text(self) -> Result<String, SidecarError> {
        self.validate()?;
        self.text
            .ok_or_else(|| SidecarError::Malformed("response carries no text".into()))
    }

    /// Returns the output payload, validating the envelope first.
    ///
    /// # Errors
    ///
    /// See [`Self::into_text`].
    pub fn into_payload(self) -> Result<String, SidecarError> {
        self.validate()?;
        self.payload
            .ok_or_else(|| SidecarError::Malformed("response carries no payload".into()))
    }
}
