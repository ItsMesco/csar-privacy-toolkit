use serde::{Deserialize, Serialize};
use std::path::Path;
use image::EncodableLayout;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdqHash(pub [u8; 32]);

impl PdqHash {
    pub fn to_hex(&self)->String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, HashError> {
        let bytes = hex::decode(s)
            .map_err(|e| HashError::HashComputation(format!("Hex non valido: {}", e)))?;

        if bytes.len() != 32 {
            return Err(HashError::HashComputation(format!(
                "Lunghezza hash non valida: attesi 32 byte, ricevuti {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);

        Ok(PdqHash(arr))
    }

    pub fn hamming_distance(&self, other: &PdqHash) ->u32{
        self.0
            .iter()
            .zip(other.0.iter())
            .map(|(a,b)|(a^b).count_ones())
            .sum()
    }
}

#[derive(Debug)]
pub enum HashError{
    ImageLoad(image::ImageError),
    HashComputation(String),
}

impl std::fmt::Display for HashError{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)-> std::fmt::Result{
        match self{
            HashError::ImageLoad(e)=>write!(f,"Errore caricamento immagine: {}", e),
            HashError::HashComputation(e) => write!(f, "Errore calcolo hash PDQ: {}", e),
        }
    }
}

impl std::error::Error for HashError{}

pub fn compute_pdq_from_path<P: AsRef<Path>>(path:P)-> Result<PdqHash, HashError>{
    let img= image::open(path).map_err(HashError::ImageLoad)?;
    compute_pdq_from_image(&img)
}

pub fn compute_pdq_from_image(img: &image::DynamicImage)-> Result<PdqHash, HashError>{
    let (hash, _quality) = pdqhash::generate_pdq(img)
        .ok_or_else(|| HashError::HashComputation("generate_pdq ha restituito None".to_string()))?;

    let bits = hash.as_bytes();
    let mut arr = [0u8;32];
    let len = bits.len().min(32);
    arr[..len].copy_from_slice(&bits[..len]);

    Ok(PdqHash(arr))
}

pub const DEF_MATCH_THRESHOLD: u32=31;

pub fn is_match(a: &PdqHash, b: &PdqHash, threshold: u32) -> bool{
    a.hamming_distance(b) <= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_identical_is_zero() {
        let h1 = PdqHash([0xAB; 32]);
        let h2 = PdqHash([0xAB; 32]);
        assert_eq!(h1.hamming_distance(&h2), 0);
    }

    #[test]
    fn hamming_distance_all_bits_different() {
        let h1 = PdqHash([0x00; 32]);
        let h2 = PdqHash([0xFF; 32]);
        assert_eq!(h1.hamming_distance(&h2), 256);
    }

    #[test]
    fn hex_roundtrip() {
        let h1 = PdqHash([0x42; 32]);
        let hex_str = h1.to_hex();
        let h2 = PdqHash::from_hex(&hex_str).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn is_match_within_threshold() {
        let h1 = PdqHash([0x00; 32]);
        let mut bytes = [0x00; 32];
        bytes[0] = 0x0F; // 4 bit diversi
        let h2 = PdqHash(bytes);
        assert!(is_match(&h1, &h2, DEF_MATCH_THRESHOLD));
        assert!(!is_match(&h1, &h2, 2));
    }

    #[test]
    fn pdq_should_match_resized_and_recompressed_image() {
        let original = compute_pdq_from_path("tests/images/test.jpg").unwrap();
        let variant = compute_pdq_from_path("tests/images/testvar.jpg").unwrap();

        let distance = original.hamming_distance(&variant);

        println!("Original: {}", original.to_hex());
        println!("Variant:  {}", variant.to_hex());
        println!("Hamming distance: {}", distance);

        assert!(
            is_match(&original, &variant, DEF_MATCH_THRESHOLD),
            "Le immagini simili non hanno fatto match: distanza = {}",
            distance
        );
    }
}
