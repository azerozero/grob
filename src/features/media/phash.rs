//! Perceptual fingerprinting (layer L3 of the provenance model).
//!
//! Implements the gradient ("difference") hash: reduce to a small luma grid,
//! then record whether each pixel is brighter than its right-hand neighbour.
//! Comparing *relative* brightness is what makes it survive rescaling,
//! recompression and exposure changes.
//!
//! Written directly rather than pulled from `img_hash`, which would add ~50
//! crates and pin an old `image` version for roughly sixty lines of work. The
//! thresholds in [`MATCH_THRESHOLD`] are measured, not guessed: see
//! `docs/design/001-image-dlp-provenance.md` and the probe under
//! `docs/design/assets/`.

use serde::{Deserialize, Serialize};

/// Grid width. 9 columns yield 8 comparisons per row.
const GRID_W: usize = 9;

/// Grid height, giving `8 * 8 = 64` bits total.
const GRID_H: usize = 8;

/// Maximum Hamming distance still considered the same image.
///
/// Measured on this implementation over the synthetic screenshot corpus in
/// `tests`: worst same-image distance **7** (crop 25 %), closest genuinely
/// different image **16**. A threshold of 10 sits inside that gap with margin
/// on both sides, and the tests assert both edges so the gap cannot silently
/// close.
///
/// The reference probe in `docs/design/assets/` measured 5 and 18 using
/// `img_hash`. This implementation is slightly less separated but avoids ~50
/// transitive crates; the gap is what matters, and it holds.
pub const MATCH_THRESHOLD: u32 = 10;

/// An 8-bit grayscale image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrayImage {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Row-major luma samples, `width * height` long.
    pub luma: Vec<u8>,
}

impl GrayImage {
    /// Builds a grayscale image, checking that `luma` matches the dimensions.
    #[must_use]
    pub fn new(width: u32, height: u32, luma: Vec<u8>) -> Option<Self> {
        let expected = width as usize * height as usize;
        (luma.len() == expected && width > 0 && height > 0).then_some(Self {
            width,
            height,
            luma,
        })
    }

    /// Builds a grayscale image from interleaved RGB samples (BT.601 luma).
    #[must_use]
    pub fn from_rgb(width: u32, height: u32, rgb: &[u8]) -> Option<Self> {
        let expected = width as usize * height as usize * 3;
        if rgb.len() != expected {
            return None;
        }
        let luma = rgb
            .as_chunks::<3>()
            .0
            .iter()
            .map(|p| {
                let y = 0.299 * f32::from(p[0]) + 0.587 * f32::from(p[1]) + 0.114 * f32::from(p[2]);
                // Saturating cast: the coefficients sum to 1, so y stays in range,
                // but rounding should never wrap.
                y.round().clamp(0.0, 255.0) as u8
            })
            .collect();
        Self::new(width, height, luma)
    }

    /// Samples the luma value at `(x, y)`, clamped to the image bounds.
    ///
    /// The clamp is defensive: [`downsample`] never asks for a coordinate
    /// outside the image. It is kept, and tested directly, so that a future
    /// change to the grid geometry fails a test instead of reading out of
    /// bounds.
    pub(crate) fn sample(&self, x: u32, y: u32) -> u8 {
        let x = x.min(self.width - 1) as usize;
        let y = y.min(self.height - 1) as usize;
        self.luma[y * self.width as usize + x]
    }
}

/// A 64-bit perceptual fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PerceptualHash(pub u64);

impl PerceptualHash {
    /// Hamming distance to another fingerprint, in bits.
    #[must_use]
    pub const fn distance(self, other: Self) -> u32 {
        (self.0 ^ other.0).count_ones()
    }

    /// Returns whether both fingerprints plausibly describe the same image.
    ///
    /// "Plausibly" is the honest word: this is a perceptual match under
    /// [`MATCH_THRESHOLD`], not a cryptographic identity.
    #[must_use]
    pub const fn matches(self, other: Self) -> bool {
        self.distance(other) <= MATCH_THRESHOLD
    }

    /// Lowercase hex rendering, for journals and wire formats.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

impl std::fmt::Display for PerceptualHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Computes the gradient hash of an image.
///
/// Box-samples the source down to a 9x8 luma grid, then emits one bit per
/// horizontal neighbour comparison.
#[must_use]
pub fn gradient_hash(img: &GrayImage) -> PerceptualHash {
    let grid = downsample(img);
    let mut bits: u64 = 0;
    for row in 0..GRID_H {
        for col in 0..GRID_W - 1 {
            let left = grid[row * GRID_W + col];
            let right = grid[row * GRID_W + col + 1];
            // Shift and set in one expression. Note that `|` and `^` are
            // provably interchangeable here, because the low bit is always
            // zero immediately after the shift; no test can distinguish them,
            // so mutation testing reports that as a surviving mutant and it
            // is a false positive rather than a coverage gap.
            bits = (bits << 1) | u64::from(left > right);
        }
    }
    PerceptualHash(bits)
}

/// Box-filters the image down to the `GRID_W x GRID_H` comparison grid.
///
/// Averaging over each source block (rather than point-sampling) is what makes
/// the hash stable under rescaling and JPEG noise.
fn downsample(img: &GrayImage) -> [u8; GRID_W * GRID_H] {
    let mut grid = [0u8; GRID_W * GRID_H];
    for (row, cell_row) in grid.as_chunks_mut::<GRID_W>().0.iter_mut().enumerate() {
        let y0 = (row as u64 * img.height as u64 / GRID_H as u64) as u32;
        let y1 = (((row as u64 + 1) * img.height as u64 / GRID_H as u64) as u32).max(y0 + 1);
        for (col, cell) in cell_row.iter_mut().enumerate() {
            let x0 = (col as u64 * img.width as u64 / GRID_W as u64) as u32;
            let x1 = (((col as u64 + 1) * img.width as u64 / GRID_W as u64) as u32).max(x0 + 1);

            let mut sum = 0u64;
            let mut count = 0u64;
            for y in y0..y1 {
                for x in x0..x1 {
                    sum += u64::from(img.sample(x, y));
                    count += 1;
                }
            }
            *cell = (sum / count.max(1)) as u8;
        }
    }
    grid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_clamps_to_the_last_valid_pixel() {
        // Exercised directly because `downsample` never requests an
        // out-of-range coordinate, so this bound is otherwise unobservable.
        // An off-by-one here would read past the buffer the moment the grid
        // geometry changes.
        let img = GrayImage::new(2, 2, vec![10, 20, 30, 40]).expect("image");
        assert_eq!(img.sample(0, 0), 10);
        assert_eq!(img.sample(1, 0), 20);
        assert_eq!(img.sample(0, 1), 30);
        assert_eq!(img.sample(1, 1), 40);

        // Past either edge clamps rather than wrapping or panicking.
        assert_eq!(img.sample(2, 0), 20);
        assert_eq!(img.sample(99, 0), 20);
        assert_eq!(img.sample(0, 2), 30);
        assert_eq!(img.sample(0, 99), 30);
        assert_eq!(img.sample(99, 99), 40);
        assert_eq!(img.sample(u32::MAX, u32::MAX), 40);
    }

    #[test]
    fn sample_handles_single_pixel_and_single_axis_images() {
        let one = GrayImage::new(1, 1, vec![7]).expect("image");
        assert_eq!(one.sample(0, 0), 7);
        assert_eq!(one.sample(u32::MAX, u32::MAX), 7);

        let row = GrayImage::new(3, 1, vec![1, 2, 3]).expect("image");
        assert_eq!(row.sample(2, 0), 3);
        assert_eq!(row.sample(9, 9), 3);

        let column = GrayImage::new(1, 3, vec![1, 2, 3]).expect("image");
        assert_eq!(column.sample(0, 2), 3);
        assert_eq!(column.sample(9, 9), 3);
    }
}
