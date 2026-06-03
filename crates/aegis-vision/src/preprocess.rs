//! Image preprocessing: decode → resize → normalize → NCHW `f32` tensor.
//!
//! This module is **always compiled** (it does not depend on `ort`), so the
//! preprocessing pipeline and its unit test run on the default build with no
//! ONNX Runtime present. The `onnx` scorer feeds the [`Tensor`] produced here
//! straight into `ort`.
//!
//! Normalization defaults to the ImageNet mean/std used by the common ViT /
//! MobileNet NSFW model cards (e.g. Falconsai `nsfw_image_detection`). If you
//! drop in a model trained with `[0,1]` scaling instead, use
//! [`Normalization::unit`].

use image::imageops::FilterType;

/// Per-channel mean/std applied after scaling pixels to `[0, 1]`.
#[derive(Debug, Clone, Copy)]
pub struct Normalization {
    pub mean: [f32; 3],
    pub std: [f32; 3],
}
impl Normalization {
    /// ImageNet statistics (RGB). Matches most timm/ViT-based NSFW exports.
    pub const fn imagenet() -> Self {
        Self {
            mean: [0.485, 0.456, 0.406],
            std: [0.229, 0.224, 0.225],
        }
    }
    /// Plain `[0, 1]` scaling (mean 0, std 1) — for models that expect raw
    /// normalized pixels with no dataset statistics.
    pub const fn unit() -> Self {
        Self {
            mean: [0.0, 0.0, 0.0],
            std: [1.0, 1.0, 1.0],
        }
    }
    /// `[-1, 1]` scaling (mean/std 0.5) — what the Falconsai / onnx-community
    /// `nsfw_image_detection` ViT (and most HF `AutoImageProcessor` ViTs) expect.
    /// Using ImageNet stats with such a model skews its scores.
    pub const fn half() -> Self {
        Self {
            mean: [0.5, 0.5, 0.5],
            std: [0.5, 0.5, 0.5],
        }
    }
}
impl Default for Normalization {
    fn default() -> Self {
        Self::imagenet()
    }
}

/// A preprocessed input tensor in NCHW layout (batch = 1).
#[derive(Debug, Clone, PartialEq)]
pub struct Tensor {
    /// `[1, 3, size, size]`.
    pub shape: [usize; 4],
    /// Channel-major (NCHW) `f32` data, length `3 * size * size`.
    pub data: Vec<f32>,
}
impl Tensor {
    /// Shape as the `i64` vector `ort`'s `Tensor::from_array((shape, data))`
    /// expects.
    pub fn shape_i64(&self) -> Vec<i64> {
        self.shape.iter().map(|&d| d as i64).collect()
    }
}

/// Errors decoding or preprocessing image bytes.
#[derive(Debug, thiserror::Error)]
pub enum PreprocessError {
    #[error("image decode failed: {0}")]
    Decode(#[from] image::ImageError),
    #[error("invalid input size: {0} (must be > 0)")]
    InvalidSize(u32),
}

/// Decode `bytes`, resize to `size`×`size`, and normalize into an NCHW tensor.
///
/// * Decoding auto-detects the format from the byte content (JPEG/PNG/WebP/…).
/// * Resize uses a triangle (bilinear) filter to the exact square the model
///   expects — deterministic, no aspect-ratio preservation (matches the common
///   "resize to 224×224" model preprocessing).
/// * Pixels are converted to RGB8, scaled to `[0,1]`, then `(x - mean) / std`
///   per channel, and laid out channel-major (NCHW).
pub fn preprocess(
    bytes: &[u8],
    size: u32,
    norm: Normalization,
) -> std::result::Result<Tensor, PreprocessError> {
    if size == 0 {
        return Err(PreprocessError::InvalidSize(size));
    }
    let img = image::load_from_memory(bytes)?;
    let rgb = img
        .resize_exact(size, size, FilterType::Triangle)
        .to_rgb8();
    Ok(to_nchw(&rgb, size, norm))
}

/// Normalize an already-RGB, already-`size`×`size` image into an NCHW tensor.
/// Split out so the unit test can build a synthetic image without decoding.
pub fn to_nchw(rgb: &image::RgbImage, size: u32, norm: Normalization) -> Tensor {
    let s = size as usize;
    let plane = s * s;
    let mut data = vec![0f32; 3 * plane];
    for (x, y, px) in rgb.enumerate_pixels() {
        let idx = (y as usize) * s + (x as usize);
        for c in 0..3 {
            let v = px[c] as f32 / 255.0;
            data[c * plane + idx] = (v - norm.mean[c]) / norm.std[c];
        }
    }
    Tensor {
        shape: [1, 3, s, s],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic in-memory PNG → expected NCHW tensor shape and known values.
    #[test]
    fn preprocess_produces_nchw_tensor_of_expected_shape() {
        // 4×4 solid red image, encoded to PNG in memory (no model needed).
        let mut img = image::RgbImage::new(4, 4);
        for px in img.pixels_mut() {
            *px = image::Rgb([255, 0, 0]);
        }
        let mut png: Vec<u8> = Vec::new();
        {
            use image::ImageEncoder;
            image::codecs::png::PngEncoder::new(&mut png)
                .write_image(img.as_raw(), 4, 4, image::ExtendedColorType::Rgb8)
                .expect("encode synthetic png");
        }

        let size = 8u32;
        let t = preprocess(&png, size, Normalization::unit()).expect("preprocess");

        assert_eq!(t.shape, [1, 3, size as usize, size as usize]);
        assert_eq!(t.data.len(), 3 * (size as usize) * (size as usize));
        assert_eq!(t.shape_i64(), vec![1, 3, size as i64, size as i64]);

        // Unit normalization on a solid red image: R plane == 1.0, G/B == 0.0.
        let plane = (size as usize) * (size as usize);
        assert!((t.data[0] - 1.0).abs() < 1e-3, "red channel ~= 1.0");
        assert!(t.data[plane].abs() < 1e-3, "green channel ~= 0.0");
        assert!(t.data[2 * plane].abs() < 1e-3, "blue channel ~= 0.0");
    }

    #[test]
    fn imagenet_normalization_offsets_channels() {
        let mut img = image::RgbImage::new(2, 2);
        for px in img.pixels_mut() {
            *px = image::Rgb([0, 0, 0]); // black → (0 - mean)/std
        }
        let n = Normalization::imagenet();
        let t = to_nchw(&img, 2, n);
        let plane = 4;
        // black pixel, channel 0: (0 - 0.485) / 0.229
        let expected = (0.0 - n.mean[0]) / n.std[0];
        assert!((t.data[0] - expected).abs() < 1e-4);
        assert_eq!(t.shape, [1, 3, 2, 2]);
        let _ = plane;
    }

    #[test]
    fn zero_size_is_rejected() {
        assert!(matches!(
            preprocess(&[0u8; 0], 0, Normalization::unit()),
            Err(PreprocessError::InvalidSize(0))
        ));
    }
}
