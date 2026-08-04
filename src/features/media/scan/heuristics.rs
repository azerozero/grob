//! Shape and metadata heuristics.
//!
//! The cheapest signals available, and among the most telling. An image
//! carrying GPS coordinates on its way to a third-party model is a leak
//! whether or not it also contains a secret, and it costs a header walk to
//! notice.

use super::super::decode::{MediaFormat, MediaProbe};
use super::{Finding, Severity};

/// Aspect ratio beyond which an image is more likely a stitched capture or a
/// crafted payload than a photograph.
const EXTREME_RATIO: f64 = 20.0;

/// Below this, an "image" is too small to be worth sending anywhere.
const TINY_PIXELS: u64 = 64;

/// Runs the metadata and shape heuristics.
#[must_use]
pub fn detect(bytes: &[u8], probe: &MediaProbe) -> Vec<Finding> {
    let mut out = Vec::new();

    if let Some(finding) = extreme_ratio(probe) {
        out.push(finding);
    }
    if probe.pixels() <= TINY_PIXELS {
        out.push(Finding::new(
            "tiny_image",
            Severity::Notice,
            format!(
                "{}x{} is too small to carry visual meaning; often a tracking pixel",
                probe.width, probe.height
            ),
        ));
    }
    if probe.format == MediaFormat::Jpeg {
        out.extend(exif_findings(bytes));
    }
    out
}

/// Flags implausible aspect ratios.
fn extreme_ratio(probe: &MediaProbe) -> Option<Finding> {
    if probe.width == 0 || probe.height == 0 {
        return None;
    }
    let (w, h) = (f64::from(probe.width), f64::from(probe.height));
    let ratio = if w > h { w / h } else { h / w };
    (ratio >= EXTREME_RATIO).then(|| {
        Finding::new(
            "extreme_aspect_ratio",
            Severity::Notice,
            format!(
                "aspect ratio {ratio:.0}:1 ({}x{})",
                probe.width, probe.height
            ),
        )
    })
}

/// Scans JPEG APP1 segments for an EXIF block, reporting GPS presence.
///
/// Only the *presence* of GPS is reported, never the coordinates: a finding
/// that quotes the location would copy the leak into every log line that
/// records it.
fn exif_findings(bytes: &[u8]) -> Vec<Finding> {
    let Some(exif) = find_exif_segment(bytes) else {
        return Vec::new();
    };
    let mut out = vec![Finding::new(
        "exif_present",
        Severity::Info,
        format!("{} byte EXIF block", exif.len()),
    )];
    if exif_has_gps(exif) {
        out.push(Finding::new(
            "exif_gps",
            Severity::Suspicious,
            "EXIF contains GPS tags; location would leave with the image",
        ));
    }
    out
}

/// Locates the payload of the first APP1/Exif segment.
fn find_exif_segment(bytes: &[u8]) -> Option<&[u8]> {
    let mut i = 2; // skip SOI
    while i + 3 < bytes.len() {
        if bytes[i] != 0xFF {
            return None;
        }
        let marker = bytes[i + 1];
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            i += 2;
            continue;
        }
        // Start of scan: entropy-coded data follows, no more segment headers.
        if marker == 0xDA {
            return None;
        }
        let len = u16::from_be_bytes([*bytes.get(i + 2)?, *bytes.get(i + 3)?]) as usize;
        if len < 2 {
            return None;
        }
        if marker == 0xE1 {
            let payload = bytes.get(i + 4..i + 2 + len)?;
            if payload.starts_with(b"Exif\0\0") {
                return payload.get(6..);
            }
        }
        i += 2 + len;
    }
    None
}

/// Returns whether the TIFF IFD0 inside `exif` references a GPS sub-IFD.
///
/// Walks only IFD0's tag list, which is bounded by the entry count and the
/// buffer, so a malformed block terminates instead of looping.
fn exif_has_gps(exif: &[u8]) -> bool {
    /// TIFF tag pointing at the GPS sub-IFD.
    const GPS_IFD_TAG: u16 = 0x8825;

    let Some(order) = exif.get(0..2) else {
        return false;
    };
    let little = match order {
        b"II" => true,
        b"MM" => false,
        _ => return false,
    };

    let u16_at = |o: usize| -> Option<u16> {
        let b = exif.get(o..o + 2)?;
        Some(if little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };
    let u32_at = |o: usize| -> Option<u32> {
        let b = exif.get(o..o + 4)?;
        Some(if little {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };

    let Some(ifd0) = u32_at(4).map(|v| v as usize) else {
        return false;
    };
    let Some(count) = u16_at(ifd0) else {
        return false;
    };

    (0..count as usize).any(|n| {
        // Each IFD entry is 12 bytes, after the 2-byte count.
        u16_at(ifd0 + 2 + n * 12) == Some(GPS_IFD_TAG)
    })
}
