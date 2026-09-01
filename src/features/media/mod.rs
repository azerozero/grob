//! Media scanning and provenance primitives (feature `media`).
//!
//! Skeleton slice: it decodes nothing it has not first bounded, fingerprints
//! images perceptually, and journals what it saw. No verdicts, no blocking, no
//! marking yet — those land in later slices.
//!
//! The design and the measurements behind the thresholds live in
//! `docs/design/001-image-dlp-provenance.md`.

pub mod blocking;
pub mod config;
pub mod decode;
pub mod observe;
pub mod phash;
pub mod registry;
pub mod scan;
pub mod sidecar;
#[cfg(test)]
mod tests;
pub mod trace;

use crate::models::ImageSource;

/// Borrowed reference to a media payload awaiting inspection.
///
/// Inline base64 is borrowed rather than copied; remote URLs are *not*
/// fetched here. Deciding to pull bytes from a client-supplied URL is a
/// security choice that belongs to a policy layer, not to a decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaRef<'a> {
    /// Inline base64 payload, with the declared MIME type when present.
    Inline {
        /// Base64-encoded payload exactly as received.
        data: &'a str,
        /// Declared MIME type, which is a hint and never a proof.
        declared_type: Option<&'a str>,
    },
    /// Remote payload, deliberately left unfetched.
    Remote {
        /// URL as received.
        url: &'a str,
    },
}

impl<'a> MediaRef<'a> {
    /// Builds a reference from an Anthropic-style [`ImageSource`].
    ///
    /// Returns `None` when the source carries neither inline data nor a URL,
    /// which is a malformed block rather than a media item.
    #[must_use]
    pub fn from_image_source(source: &'a ImageSource) -> Option<Self> {
        match source.r#type.as_str() {
            "base64" => source.data.as_deref().map(|data| Self::Inline {
                data,
                declared_type: source.media_type.as_deref(),
            }),
            "url" => source.url.as_deref().map(|url| Self::Remote { url }),
            _ => None,
        }
    }

    /// Returns whether this reference points at bytes we already hold.
    #[must_use]
    pub const fn is_inline(&self) -> bool {
        matches!(self, Self::Inline { .. })
    }
}

/// Errors raised while inspecting a media payload.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MediaError {
    /// Payload is not valid base64.
    #[error("media payload is not valid base64")]
    InvalidBase64,
    /// Format is not in the allow-list, or was not recognised at all.
    #[error("unsupported or unrecognised media format")]
    UnsupportedFormat,
    /// Header is truncated or malformed.
    #[error("malformed media header")]
    MalformedHeader,
    /// Encoded payload exceeds the configured byte budget.
    #[error("media payload too large: {actual} bytes exceeds limit of {limit}")]
    TooLarge {
        /// Observed size in bytes.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// Declared pixel count exceeds the configured budget.
    ///
    /// This is the decompression-bomb guard: a few kilobytes of PNG can
    /// declare a canvas of billions of pixels.
    #[error("media declares too many pixels: {width}x{height} exceeds limit of {limit}")]
    TooManyPixels {
        /// Declared width.
        width: u32,
        /// Declared height.
        height: u32,
        /// Configured maximum pixel count.
        limit: u64,
    },
    /// The payload is a remote URL and remote fetching is disabled.
    #[error("remote media is not fetched")]
    RemoteNotFetched,
}
