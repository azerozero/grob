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

#[cfg(test)]
mod tests {
    use super::*;

    /// PNG whose IEND chunk ends at a known offset, followed by `trailer`.
    fn png_with_trailer(trailer: &[u8]) -> (Vec<u8>, usize) {
        let mut v = Vec::from(b"\x89PNG\r\n\x1a\n".as_slice());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(b"IEND");
        v.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);
        let end = v.len();
        v.extend_from_slice(trailer);
        (v, end)
    }

    #[test]
    fn png_trailer_starts_exactly_after_the_iend_crc() {
        // Pins the +8 offset: IEND's 4-byte type plus its 4-byte CRC. An
        // off-by-any-amount would shift the returned slice.
        let marker = b"0123456789ABCDEFGHIJ";
        let (bytes, end) = png_with_trailer(marker);
        let trailer = trailing_payload(&bytes, MediaFormat::Png).expect("trailer");
        assert_eq!(trailer, marker);
        assert_eq!(trailer.len(), bytes.len() - end);
    }

    #[test]
    fn jpeg_trailer_starts_exactly_after_the_eoi_marker() {
        // Pins the +2 offset past FF D9.
        let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xD9];
        let marker = b"TRAILING-PAYLOAD-DATA";
        bytes.extend_from_slice(marker);
        let trailer = trailing_payload(&bytes, MediaFormat::Jpeg).expect("trailer");
        assert_eq!(trailer, marker);
    }

    #[test]
    fn gif_trailer_starts_exactly_after_the_terminator() {
        // Pins the +1 offset past 0x3B.
        let mut bytes = Vec::from(b"GIF89a".as_slice());
        bytes.extend_from_slice(&[0, 0, 0, 0, 0x3B]);
        let marker = b"TRAILING-PAYLOAD-DATA";
        bytes.extend_from_slice(marker);
        let trailer = trailing_payload(&bytes, MediaFormat::Gif).expect("trailer");
        assert_eq!(trailer, marker);
    }

    #[test]
    fn trailer_noise_floor_is_strictly_greater_than() {
        // Exactly at the floor: padding. One byte more: a payload.
        let (at_floor, _) = png_with_trailer(&[b'x'; TRAILER_NOISE_FLOOR]);
        assert!(trailing_payload(&at_floor, MediaFormat::Png).is_none());

        let (over, _) = png_with_trailer(&[b'x'; TRAILER_NOISE_FLOOR + 1]);
        assert_eq!(
            trailing_payload(&over, MediaFormat::Png).map(<[u8]>::len),
            Some(TRAILER_NOISE_FLOOR + 1)
        );
    }

    #[test]
    fn webp_is_deliberately_exempt() {
        // RIFF is chunked, so trailing bytes are a normal extension mechanism.
        let mut bytes = Vec::from(b"RIFF____WEBPVP8 ".as_slice());
        bytes.extend_from_slice(&[b'x'; 64]);
        assert!(trailing_payload(&bytes, MediaFormat::Webp).is_none());
    }

    #[test]
    fn find_last_returns_the_final_occurrence() {
        assert_eq!(find_last(b"abcabcabc", b"abc"), Some(6));
        assert_eq!(find_last(b"abc", b"abc"), Some(0));
        assert_eq!(find_last(b"xxxabc", b"abc"), Some(3));
    }

    #[test]
    fn find_last_handles_degenerate_inputs() {
        // Needle longer than haystack must not underflow the range.
        assert_eq!(find_last(b"ab", b"abc"), None);
        assert_eq!(find_last(b"", b"a"), None);
        assert_eq!(find_last(b"abc", b""), None);
        assert_eq!(find_last(b"abc", b"z"), None);
    }

    #[test]
    fn printable_run_counts_only_maximal_runs() {
        assert_eq!(longest_printable_run(b"abc\0defgh"), Some(5));
        assert_eq!(longest_printable_run(b"\0\0\0"), None);
        assert_eq!(longest_printable_run(b""), None);
        // Runs reset on a non-printable byte rather than accumulating.
        assert_eq!(longest_printable_run(b"ab\0ab\0ab"), Some(2));
    }

    #[test]
    fn printable_run_boundaries_are_exact() {
        // 0x20 (space) and 0x7E (~) are printable; 0x1F and 0x7F are not.
        assert_eq!(longest_printable_run(&[0x20, 0x7E]), Some(2));
        assert_eq!(longest_printable_run(&[0x1F]), None);
        assert_eq!(longest_printable_run(&[0x7F]), None);
        // Whitespace counts, since it appears in real embedded text.
        assert_eq!(longest_printable_run(b"a\tb\nc\rd"), Some(7));
        // Each whitespace form individually, so none can be dropped silently.
        assert_eq!(longest_printable_run(b"\t"), Some(1));
        assert_eq!(longest_printable_run(b"\n"), Some(1));
        assert_eq!(longest_printable_run(b"\r"), Some(1));
    }
}
