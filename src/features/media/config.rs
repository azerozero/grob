//! Configuration for the media slice.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default encoded-payload budget: 8 MiB.
const DEFAULT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Default pixel budget: 40 megapixels, comfortably above a 6K screenshot
/// and far below what a decompression bomb asks for.
const DEFAULT_MAX_PIXELS: u64 = 40_000_000;

/// Default deadline for a blocking inspection.
///
/// Sized from the measured OCR cost (~320 ms for `ocrs` on a screenshot),
/// with enough headroom for a cold sidecar without letting a wedged one hold
/// a request open.
const DEFAULT_BLOCKING_TIMEOUT_MS: u64 = 5_000;

/// How media inspection participates in the request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaMode {
    /// Do nothing. The default: a slice that is off cannot regress anything.
    #[default]
    Off,
    /// Inspect out of band. Never adds latency, never blocks.
    Async,
    /// Inspect before the request is dispatched, and act on the verdict.
    ///
    /// Adds the inspection cost to the request path, which is the price of
    /// being able to refuse. See [`OnFailure`] for what happens when the
    /// inspection itself cannot complete.
    Blocking,
}

/// What to do when an inspection cannot reach a verdict in `blocking` mode.
///
/// A timeout, an unreachable sidecar, or an open circuit all mean the same
/// thing: the image was never examined. The question is whether an
/// un-examined image is allowed through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    /// Refuse the request. The default.
    ///
    /// An operator who turned on `blocking` asked for images to be examined
    /// before they leave. Silently forwarding the ones we failed to examine
    /// would answer a different question than the one they asked, and would
    /// do it precisely when something is already wrong.
    #[default]
    Deny,
    /// Forward the request anyway.
    ///
    /// For deployments where a stalled sidecar must not become an outage.
    /// The trade is explicit: availability is preserved and some images pass
    /// unexamined, so it belongs in configuration rather than in a default.
    Allow,
}

impl OnFailure {
    /// Returns whether an un-examined image is forwarded.
    #[must_use]
    pub const fn allows_unexamined(self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Media slice configuration.
///
/// Reachable from `~/.grob/config.toml` as `[media]`:
///
/// ```toml
/// [media]
/// mode = "async"          # off (default) | async | blocking
/// on_failure = "deny"     # deny (default) | allow -- blocking mode only
/// timeout_ms = 5000       # blocking mode only
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
    /// What to do when a blocking inspection cannot reach a verdict.
    ///
    /// Ignored unless `mode = "blocking"`, since nothing is refused otherwise.
    pub on_failure: OnFailure,
    /// Deadline for a blocking inspection, in milliseconds.
    ///
    /// Bounds how long a request can wait on inspection. Past it,
    /// [`Self::on_failure`] decides.
    pub blocking_timeout_ms: u64,
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
            on_failure: OnFailure::Deny,
            blocking_timeout_ms: DEFAULT_BLOCKING_TIMEOUT_MS,
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

    /// Returns whether inspection happens before dispatch.
    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self.mode, MediaMode::Blocking)
    }

    /// Deadline for a blocking inspection.
    #[must_use]
    pub const fn blocking_timeout(&self) -> Duration {
        Duration::from_millis(self.blocking_timeout_ms)
    }
}
