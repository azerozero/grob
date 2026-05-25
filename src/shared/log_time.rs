//! Consistent log timestamp formatting.
//!
//! All tracing subscribers use [`UtcTimer`] so timestamps are rendered in UTC
//! with an explicit `Z`, regardless of the host timezone or which init path
//! (plain, JSON, or OpenTelemetry) was taken. This removes the cross-run
//! inconsistency that arises when some output is local-time and some is UTC,
//! and it sidesteps the well-known unsoundness of reading the local UTC offset
//! from a multi-threaded process.

use std::fmt;

use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;

/// Renders event timestamps as RFC 3339 UTC with millisecond precision.
///
/// Example output: `2026-05-25T16:14:32.481Z`.
#[derive(Clone, Copy, Debug, Default)]
pub struct UtcTimer;

impl FormatTime for UtcTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        write!(w, "{}", chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"))
    }
}
