//! Multi-hash indexing: generazione varianti e costruzione del DB da cartella.
use image::{imageops::FilterType, DynamicImage, GenericImageView, ImageFormat, ImageOutputFormat};
use std::io::Cursor;

use crate::{compute_pdq_from_image, PdqHash};

pub struct VariantConfig {
    pub jpeg_qualities: Vec<u8>,
    pub scale_factors: Vec<f32>,
    pub crop_factors: Vec<f32>,
    pub flip_horizontal: bool,
    pub grayscale: bool,
}

impl Default for VariantConfig {
    fn default() -> Self {
        Self {
            jpeg_qualities: vec![90, 70, 50, 30],
            scale_factors: vec![0.9, 0.75, 0.5],
            crop_factors: vec![0.92, 0.85, 0.75],
            flip_horizontal: true,
            grayscale: true,
        }
    }
}

fn jpeg_recompress(img: &DynamicImage, quality: u8) -> Option<DynamicImage> {
    let mut buf: Vec<u8> = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageOutputFormat::Jpeg(quality)).ok()?;
    image::load_from_memory(&buf).ok()
}

pub fn generate_variants(img: &DynamicImage, cfg: &VariantConfig) -> Vec<DynamicImage> {
    let mut out = vec![img.clone()];
    let (w, h) = img.dimensions();
    for &q in &cfg.jpeg_qualities {
        if let Some(r) = jpeg_recompress(img, q) { out.push(r); }
    }
    for &s in &cfg.scale_factors {
        out.push(img.resize(((w as f32) * s).max(1.0) as u32, ((h as f32) * s).max(1.0) as u32, FilterType::Lanczos3));
    }
    for &c in &cfg.crop_factors {
        let cw = ((w as f32) * c).max(1.0) as u32;
        let ch = ((h as f32) * c).max(1.0) as u32;
        let mut tmp = img.clone();
        let cropped = DynamicImage::ImageRgba8(
            image::imageops::crop(&mut tmp, (w - cw) / 2, (h - ch) / 2, cw, ch).to_image(),
        );
        out.push(cropped.clone());
        // e la sua ricompressione JPEG, per coprire crop+compressione insieme
        if let Some(rc) = jpeg_recompress(&cropped, 65) { out.push(rc); }
    }
    if cfg.flip_horizontal { out.push(img.fliph()); }
    if cfg.grayscale { out.push(img.grayscale()); }
    out
}

pub fn generate_variant_hashes(img: &DynamicImage, cfg: &VariantConfig) -> Vec<PdqHash> {
    generate_variants(img, cfg).iter()
        .filter_map(|v| compute_pdq_from_image(v).ok())
        .collect()
}

/// Lista piatta di hash (originale + varianti) di tutte le immagini nella cartella, ordinate.
pub fn build_hashes_from_dir(
    dir: &str,
    cfg: &VariantConfig,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| {
            let e = e.to_string_lossy().to_lowercase();
            matches!(e.as_str(), "jpg" | "jpeg" | "png" | "webp" | "bmp")
        }).unwrap_or(false))
        .collect();
    paths.sort();
    let mut hashes = Vec::new();
    for p in &paths {
        let img = image::io::Reader::open(p)?.decode()?;
        for h in generate_variant_hashes(&img, cfg) { hashes.push(h.0); }
    }
    if hashes.is_empty() { return Err("nessuna immagine trovata".into()); }
    Ok(hashes)
}