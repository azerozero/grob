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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::media::decode::MediaFormat;

    fn probe(w: u32, h: u32) -> MediaProbe {
        MediaProbe {
            format: MediaFormat::Png,
            width: w,
            height: h,
            byte_len: 1024,
        }
    }

    #[test]
    fn ratio_is_computed_as_the_longer_side_over_the_shorter() {
        // Division, not multiplication: a 20:1 image trips, 19:1 does not,
        // and orientation must not matter.
        assert!(extreme_ratio(&probe(2000, 100)).is_some());
        assert!(extreme_ratio(&probe(100, 2000)).is_some());
        assert!(extreme_ratio(&probe(1900, 100)).is_none());
        assert!(extreme_ratio(&probe(1920, 1080)).is_none());
        assert!(extreme_ratio(&probe(500, 500)).is_none());
    }

    #[test]
    fn ratio_threshold_is_inclusive_at_exactly_20() {
        assert!(extreme_ratio(&probe(2000, 100)).is_some());
        assert!(extreme_ratio(&probe(1999, 100)).is_none());
    }

    #[test]
    fn degenerate_dimensions_do_not_divide_by_zero() {
        // Either dimension zero must short-circuit, not produce infinity.
        assert!(extreme_ratio(&probe(0, 100)).is_none());
        assert!(extreme_ratio(&probe(100, 0)).is_none());
        assert!(extreme_ratio(&probe(0, 0)).is_none());
    }

    /// Builds a JPEG whose APP1/Exif payload is exactly `payload`.
    fn jpeg_with_app1(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE1];
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    #[test]
    fn exif_payload_is_located_past_the_six_byte_identifier() {
        // Pins the Exif\0\0 skip: the returned slice must start at the TIFF
        // header, not at the identifier.
        let mut payload = Vec::from(b"Exif\0\0".as_slice());
        payload.extend_from_slice(b"II\x2a\x00TIFFBODY");
        let jpeg = jpeg_with_app1(&payload);
        let exif = find_exif_segment(&jpeg).expect("exif");
        assert!(exif.starts_with(b"II\x2a\x00"), "got {:?}", &exif[..4]);
        assert_eq!(exif.len(), payload.len() - 6);
    }

    #[test]
    fn app1_without_the_exif_identifier_is_not_exif() {
        // XMP also lives in APP1; it must not be mistaken for EXIF.
        let jpeg = jpeg_with_app1(b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta/>");
        assert!(find_exif_segment(&jpeg).is_none());
    }

    #[test]
    fn segment_walk_skips_over_intervening_segments() {
        // Pins the 2 + len stride: an APP0/JFIF block before APP1 must be
        // stepped over exactly, or the walk desynchronises and finds nothing.
        let mut v = vec![0xFF, 0xD8];
        let app0 = b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0";
        v.extend_from_slice(&[0xFF, 0xE0]);
        v.extend_from_slice(&((app0.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(app0);
        let mut payload = Vec::from(b"Exif\0\0".as_slice());
        payload.extend_from_slice(b"II\x2a\x00rest");
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(&payload);
        v.extend_from_slice(&[0xFF, 0xD9]);

        assert!(
            find_exif_segment(&v).is_some(),
            "APP0 stride desynchronised the walk"
        );
    }

    #[test]
    fn walk_stops_at_start_of_scan() {
        // Past SOS the bytes are entropy-coded; treating them as segment
        // headers would read noise as structure.
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02];
        v.extend_from_slice(b"Exif\0\0II\x2a\x00");
        assert!(find_exif_segment(&v).is_none());
    }

    #[test]
    fn declared_segment_length_must_be_sane() {
        // A length below 2 cannot include its own field; the walk must stop
        // rather than step backwards forever.
        let v = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x01, 0x00];
        assert!(find_exif_segment(&v).is_none());
    }

    /// Little-endian TIFF block with the given IFD0 tags.
    fn tiff(tags: &[u16], little: bool) -> Vec<u8> {
        let mut t = Vec::from(if little {
            &b"II\x2a\x00"[..]
        } else {
            &b"MM\x00\x2a"[..]
        });
        let push16 = |v: &mut Vec<u8>, x: u16| {
            if little {
                v.extend_from_slice(&x.to_le_bytes());
            } else {
                v.extend_from_slice(&x.to_be_bytes());
            }
        };
        let push32 = |v: &mut Vec<u8>, x: u32| {
            if little {
                v.extend_from_slice(&x.to_le_bytes());
            } else {
                v.extend_from_slice(&x.to_be_bytes());
            }
        };
        push32(&mut t, 8); // IFD0 offset
        push16(&mut t, tags.len() as u16);
        for &tag in tags {
            push16(&mut t, tag);
            push16(&mut t, 3);
            push32(&mut t, 1);
            push32(&mut t, 0);
        }
        push32(&mut t, 0);
        t
    }

    #[test]
    fn gps_tag_is_found_at_any_entry_index() {
        // Pins the 12-byte entry stride: the tag must be found whether it is
        // first, last, or in the middle of the IFD.
        assert!(exif_has_gps(&tiff(&[0x8825], true)));
        assert!(exif_has_gps(&tiff(&[0x010F, 0x8825], true)));
        assert!(exif_has_gps(&tiff(&[0x010F, 0x0110, 0x8825], true)));
        assert!(exif_has_gps(&tiff(&[0x8825, 0x010F, 0x0110], true)));
    }

    #[test]
    fn absent_gps_tag_is_not_invented() {
        assert!(!exif_has_gps(&tiff(&[0x010F], true)));
        assert!(!exif_has_gps(&tiff(&[0x010F, 0x0110, 0x0112], true)));
        assert!(!exif_has_gps(&tiff(&[], true)));
        // 0x8824 and 0x8826 neighbour the GPS tag and must not match.
        assert!(!exif_has_gps(&tiff(&[0x8824, 0x8826], true)));
    }

    #[test]
    fn both_tiff_byte_orders_are_honoured() {
        assert!(exif_has_gps(&tiff(&[0x010F, 0x8825], false)));
        assert!(!exif_has_gps(&tiff(&[0x010F], false)));
    }

    #[test]
    fn unknown_byte_order_is_refused() {
        assert!(!exif_has_gps(b"XX\x2a\x00rest of block"));
        assert!(!exif_has_gps(b""));
        assert!(!exif_has_gps(b"I"));
    }

    #[test]
    fn standalone_markers_are_stepped_over_by_exactly_two_bytes() {
        // RST0-RST7, TEM and a stray SOI carry no length field. Each must
        // advance the cursor by exactly 2, or the walk lands mid-marker and
        // the EXIF block that follows is never found.
        let mut payload = Vec::from(b"Exif\0\0".as_slice());
        payload.extend_from_slice(b"II\x2a\x00rest");

        for standalone in [0xD8u8, 0x01, 0xD0, 0xD3, 0xD7] {
            let mut v = vec![0xFF, 0xD8, 0xFF, standalone];
            v.extend_from_slice(&[0xFF, 0xE1]);
            v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
            v.extend_from_slice(&payload);
            v.extend_from_slice(&[0xFF, 0xD9]);
            assert!(
                find_exif_segment(&v).is_some(),
                "standalone marker 0x{standalone:02X} desynchronised the walk"
            );
        }
    }

    #[test]
    fn markers_adjacent_to_the_standalone_range_still_carry_lengths() {
        // 0xCF and 0xD9 bracket the RST range. Treating either as standalone
        // would step 2 bytes into a length-bearing segment.
        let mut payload = Vec::from(b"Exif\0\0".as_slice());
        payload.extend_from_slice(b"II\x2a\x00rest");

        // 0xCF is a length-bearing SOF-family marker; skipping it as if it
        // were standalone would misread its length field as a marker.
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xCF, 0x00, 0x04, 0xAA, 0xBB];
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(&payload);
        assert!(
            find_exif_segment(&v).is_some(),
            "length-bearing marker 0xCF was mis-stepped"
        );
    }

    #[test]
    fn consecutive_standalone_markers_advance_additively() {
        // One standalone marker cannot distinguish `i += 2` from `i *= 2`,
        // because the cursor starts at 2 and both yield 4. Two in a row can:
        // additive reaches 6, multiplicative overshoots to 8.
        let mut payload = Vec::from(b"Exif\0\0".as_slice());
        payload.extend_from_slice(b"II\x2a\x00rest");

        let mut v = vec![0xFF, 0xD8, 0xFF, 0xD0, 0xFF, 0xD1];
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(&payload);
        v.extend_from_slice(&[0xFF, 0xD9]);

        assert!(
            find_exif_segment(&v).is_some(),
            "cursor did not advance additively across two standalone markers"
        );
    }

    #[test]
    fn an_empty_segment_is_valid_and_stepped_over() {
        // A declared length of exactly 2 is a well-formed segment with no
        // payload. Rejecting it (rather than only lengths below 2) would
        // abandon the walk before reaching the EXIF block that follows.
        let mut payload = Vec::from(b"Exif\0\0".as_slice());
        payload.extend_from_slice(b"II\x2a\x00rest");

        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE2, 0x00, 0x02];
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(&payload);
        v.extend_from_slice(&[0xFF, 0xD9]);

        assert!(
            find_exif_segment(&v).is_some(),
            "an empty but well-formed segment aborted the walk"
        );
    }

    #[test]
    fn a_lone_standalone_marker_run_terminates() {
        // Nothing but standalone markers: the walk must reach the end and
        // stop rather than loop or read past the buffer.
        let v = vec![0xFF, 0xD8, 0xFF, 0xD0, 0xFF, 0xD1, 0xFF, 0xD2, 0xFF, 0xD3];
        assert!(find_exif_segment(&v).is_none());
    }

    #[test]
    fn truncated_tiff_blocks_do_not_panic() {
        let full = tiff(&[0x010F, 0x8825], true);
        for cut in 0..=full.len() {
            let _ = exif_has_gps(&full[..cut]);
        }
    }
}
