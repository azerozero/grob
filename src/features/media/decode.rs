//! Format sniffing and pre-decode bounds.
//!
//! Everything here reads *headers*. No pixel buffer is ever allocated, which
//! is the entire point: a 10 KB PNG can declare a 50 000 x 50 000 canvas, and
//! the only safe moment to refuse it is before a decoder sees it.
//!
//! Formats are allow-listed. A deny-list would silently admit whatever gets
//! invented next.

use super::config::MediaConfig;
use super::{MediaError, MediaRef};
use base64::Engine as _;

/// Image container formats this slice accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaFormat {
    /// PNG.
    Png,
    /// JPEG.
    Jpeg,
    /// GIF (87a or 89a).
    Gif,
    /// WebP (RIFF container).
    Webp,
}

impl MediaFormat {
    /// Returns the canonical MIME type.
    #[must_use]
    pub const fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Webp => "image/webp",
        }
    }
}

/// What the headers say about a payload, without decoding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaProbe {
    /// Sniffed format, from magic bytes rather than the declared MIME type.
    pub format: MediaFormat,
    /// Declared width in pixels.
    pub width: u32,
    /// Declared height in pixels.
    pub height: u32,
    /// Size of the decoded (still encoded-on-disk) byte payload.
    pub byte_len: usize,
}

impl MediaProbe {
    /// Declared pixel count, widened so the multiplication cannot overflow.
    #[must_use]
    pub const fn pixels(&self) -> u64 {
        self.width as u64 * self.height as u64
    }
}

/// Decodes base64 and probes the payload against `config`'s bounds.
///
/// The size limit is checked on the *encoded* string first, so an oversized
/// payload is rejected without allocating its decoded form.
///
/// # Errors
///
/// Returns [`MediaError::RemoteNotFetched`] for URL sources when
/// `fetch_remote` is disabled, [`MediaError::TooLarge`] or
/// [`MediaError::TooManyPixels`] when a budget is exceeded, and
/// [`MediaError::InvalidBase64`], [`MediaError::UnsupportedFormat`] or
/// [`MediaError::MalformedHeader`] for payloads that cannot be understood.
pub fn probe(
    media: MediaRef<'_>,
    config: &MediaConfig,
) -> Result<(Vec<u8>, MediaProbe), MediaError> {
    let data = match media {
        MediaRef::Inline { data, .. } => data,
        // Fetching is a policy decision, and this slice never makes it.
        MediaRef::Remote { .. } => return Err(MediaError::RemoteNotFetched),
    };

    // Reject on the encoded length before allocating anything. Base64 inflates
    // by 4/3, so this is a conservative lower bound on the decoded size.
    let lower_bound = data.len() / 4 * 3;
    if lower_bound > config.max_bytes {
        return Err(MediaError::TooLarge {
            actual: lower_bound,
            limit: config.max_bytes,
        });
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .map_err(|_| MediaError::InvalidBase64)?;

    if bytes.len() > config.max_bytes {
        return Err(MediaError::TooLarge {
            actual: bytes.len(),
            limit: config.max_bytes,
        });
    }

    let probe = probe_bytes(&bytes, config)?;
    Ok((bytes, probe))
}

/// Probes already-decoded bytes against `config`'s bounds.
///
/// # Errors
///
/// See [`probe`].
pub fn probe_bytes(bytes: &[u8], config: &MediaConfig) -> Result<MediaProbe, MediaError> {
    if bytes.len() > config.max_bytes {
        return Err(MediaError::TooLarge {
            actual: bytes.len(),
            limit: config.max_bytes,
        });
    }

    let format = sniff(bytes).ok_or(MediaError::UnsupportedFormat)?;
    let (width, height) = dimensions(bytes, format)?;

    let probe = MediaProbe {
        format,
        width,
        height,
        byte_len: bytes.len(),
    };

    if probe.pixels() > config.max_pixels {
        return Err(MediaError::TooManyPixels {
            width,
            height,
            limit: config.max_pixels,
        });
    }

    Ok(probe)
}

/// Identifies the format from magic bytes.
///
/// The declared MIME type is deliberately ignored: a caller that lies about
/// `media_type` is exactly the caller worth catching.
#[must_use]
pub fn sniff(bytes: &[u8]) -> Option<MediaFormat> {
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
    if bytes.starts_with(PNG) {
        return Some(MediaFormat::Png);
    }
    if bytes.starts_with(b"\xff\xd8\xff") {
        return Some(MediaFormat::Jpeg);
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some(MediaFormat::Gif);
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some(MediaFormat::Webp);
    }
    None
}

/// Reads declared dimensions straight from the container header.
fn dimensions(bytes: &[u8], format: MediaFormat) -> Result<(u32, u32), MediaError> {
    match format {
        MediaFormat::Png => png_dimensions(bytes),
        MediaFormat::Jpeg => jpeg_dimensions(bytes),
        MediaFormat::Gif => gif_dimensions(bytes),
        MediaFormat::Webp => webp_dimensions(bytes),
    }
}

/// Reads a big-endian `u32` at `offset`.
fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Reads a big-endian `u16` at `offset`.
fn be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
}

/// Reads a little-endian `u16` at `offset`.
fn le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

/// PNG: IHDR is the first chunk, width and height at fixed offsets 16 and 20.
fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), MediaError> {
    if bytes.get(12..16) != Some(b"IHDR") {
        return Err(MediaError::MalformedHeader);
    }
    let w = be_u32(bytes, 16).ok_or(MediaError::MalformedHeader)?;
    let h = be_u32(bytes, 20).ok_or(MediaError::MalformedHeader)?;
    Ok((w, h))
}

/// GIF: logical screen descriptor, little-endian, right after the signature.
fn gif_dimensions(bytes: &[u8]) -> Result<(u32, u32), MediaError> {
    let w = le_u16(bytes, 6).ok_or(MediaError::MalformedHeader)?;
    let h = le_u16(bytes, 8).ok_or(MediaError::MalformedHeader)?;
    Ok((u32::from(w), u32::from(h)))
}

/// JPEG: walk segment markers to the frame header (SOFn).
///
/// The walk is bounded by the buffer, so a malformed or hostile segment chain
/// terminates rather than looping.
fn jpeg_dimensions(bytes: &[u8]) -> Result<(u32, u32), MediaError> {
    let mut i = 2; // skip SOI
    while i + 3 < bytes.len() {
        if bytes[i] != 0xFF {
            return Err(MediaError::MalformedHeader);
        }
        let marker = bytes[i + 1];
        // Standalone markers carry no length payload.
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            i += 2;
            continue;
        }
        let len = be_u16(bytes, i + 2).ok_or(MediaError::MalformedHeader)? as usize;
        if len < 2 {
            return Err(MediaError::MalformedHeader);
        }
        // SOF0..SOF15, excluding DHT (C4), JPG (C8) and DAC (CC).
        let is_sof =
            (0xC0..=0xCF).contains(&marker) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC;
        if is_sof {
            let h = be_u16(bytes, i + 5).ok_or(MediaError::MalformedHeader)?;
            let w = be_u16(bytes, i + 7).ok_or(MediaError::MalformedHeader)?;
            return Ok((u32::from(w), u32::from(h)));
        }
        i += 2 + len;
    }
    Err(MediaError::MalformedHeader)
}

/// WebP: lossy (`VP8 `), lossless (`VP8L`) and extended (`VP8X`) chunks each
/// encode dimensions differently.
fn webp_dimensions(bytes: &[u8]) -> Result<(u32, u32), MediaError> {
    let chunk = bytes.get(12..16).ok_or(MediaError::MalformedHeader)?;
    match chunk {
        b"VP8 " => {
            let w = le_u16(bytes, 26).ok_or(MediaError::MalformedHeader)?;
            let h = le_u16(bytes, 28).ok_or(MediaError::MalformedHeader)?;
            Ok((u32::from(w & 0x3FFF), u32::from(h & 0x3FFF)))
        }
        b"VP8L" => {
            let b = bytes.get(21..25).ok_or(MediaError::MalformedHeader)?;
            let bits = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            Ok(((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1))
        }
        b"VP8X" => {
            let b = bytes.get(24..30).ok_or(MediaError::MalformedHeader)?;
            let w = 1 + (u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16);
            let h = 1 + (u32::from(b[3]) | u32::from(b[4]) << 8 | u32::from(b[5]) << 16);
            Ok((w, h))
        }
        _ => Err(MediaError::MalformedHeader),
    }
}
