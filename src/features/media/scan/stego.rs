//! Crude concealment detectors.
//!
//! Two techniques, both cheap and both aimed at carelessness rather than
//! craft: data appended past a container's end marker, and printable strings
//! hidden where no printable string belongs.
//!
//! This does not detect real steganography. LSB embedding by a competent tool
//! is statistically indistinguishable without a decoder and a model, and
//! claiming otherwise would be worse than not looking at all: it would
//! manufacture confidence.

use super::super::decode::{MediaFormat, MediaProbe};
use super::{Finding, Severity};

/// Trailing bytes below this are container padding, not a payload.
const TRAILER_NOISE_FLOOR: usize = 16;

/// Shortest run of printable bytes worth reporting inside a trailer.
const MIN_STRING_RUN: usize = 12;

/// Runs the concealment detectors.
#[must_use]
pub fn detect(bytes: &[u8], probe: &MediaProbe) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(trailer) = trailing_payload(bytes, probe.format) {
        out.push(Finding::new(
            "appended_payload",
            Severity::Suspicious,
            format!(
                "{} bytes follow the {} end marker",
                trailer.len(),
                probe.format.mime()
            ),
        ));
        if let Some(run) = longest_printable_run(trailer) {
            if run >= MIN_STRING_RUN {
                out.push(Finding::new(
                    "appended_text",
                    Severity::Suspicious,
                    format!("appended data contains a {run}-byte printable run"),
                ));
            }
        }
    }
    out
}

/// Returns the bytes following a container's end marker, when meaningful.
///
/// Only formats with an unambiguous terminator are checked. WebP is skipped:
/// RIFF is chunked, so "extra" bytes are a normal extension mechanism rather
/// than a signal.
#[must_use]
pub fn trailing_payload(bytes: &[u8], format: MediaFormat) -> Option<&[u8]> {
    let end = match format {
        MediaFormat::Jpeg => find_last(bytes, &[0xFF, 0xD9])? + 2,
        MediaFormat::Png => find_iend(bytes)?,
        MediaFormat::Gif => find_last(bytes, &[0x3B])? + 1,
        MediaFormat::Webp => return None,
    };
    let trailer = bytes.get(end..)?;
    (trailer.len() > TRAILER_NOISE_FLOOR).then_some(trailer)
}

/// Offset just past the PNG IEND chunk (type, length and CRC included).
fn find_iend(bytes: &[u8]) -> Option<usize> {
    // IEND is preceded by its 4-byte length and followed by a 4-byte CRC.
    find_last(bytes, b"IEND").map(|i| i + 8)
}

/// Index of the last occurrence of `needle`.
fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Longest run of printable ASCII (plus tab, LF and CR) in `bytes`.
#[must_use]
pub fn longest_printable_run(bytes: &[u8]) -> Option<usize> {
    let mut best = 0usize;
    let mut run = 0usize;
    for &b in bytes {
        if (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    (best > 0).then_some(best)
}
