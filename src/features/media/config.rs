//! Configuration for the media slice.

use serde::{Deserialize, Serialize};

/// Default encoded-payload budget: 8 MiB.
const DEFAULT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Default pixel budget: 40 megapixels, comfortably above a 6K screenshot
/// and far below what a decompression bomb asks for.
const DEFAULT_MAX_PIXELS: u64 = 40_000_000;

/// How media inspection participates in the request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaMode {
    /// Do nothing. The default: a slice that is off cannot regress anything.
    #[default]
    Off,
    /// Inspect out of band. Never adds latency, never blocks.
    Async,
}

/// Media slice configuration.
///
/// Reachable from `~/.grob/config.toml` as `[media]`:
///
/// ```toml
/// [media]
/// mode = "async"          # off (default) | async
/// max_bytes = 8388608
/// max_pixels = 40000000
/// fetch_remote = false    # leave off: fetching client URLs is an SSRF primitive
///
/// [media.sidecar.endpoints.ocr]
/// unix = { path = "/tmp/grob-ocr.sock" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaConfig {
    /// Participation mode.
    pub mode: MediaMode,
    /// Maximum accepted size of the *encoded* payload, in bytes.
    pub max_bytes: usize,
    /// Maximum accepted `width * height`, checked before any decode.
    pub max_pixels: u64,
    /// Whether remote (URL) media may be fetched.
    ///
    /// Off by default: fetching a client-supplied URL from inside the proxy
    /// is an SSRF primitive, and it is not one this slice needs.
    pub fetch_remote: bool,
    /// Whether observations are appended to the media journal.
    pub journal: bool,
    /// Out-of-process capabilities (OCR, watermarking, provenance).
    pub sidecar: super::sidecar::SidecarConfig,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            mode: MediaMode::Off,
            max_bytes: DEFAULT_MAX_BYTES,
            max_pixels: DEFAULT_MAX_PIXELS,
            fetch_remote: false,
            journal: true,
            sidecar: super::sidecar::SidecarConfig::default(),
        }
    }
}

impl MediaConfig {
    /// Returns whether the slice does anything at all.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        !matches!(self.mode, MediaMode::Off)
    }
}
