//! Motore PHE basato sulla crate kzen-paillier (nessuna crittografia homemade).
//! Protocollo: il client cifra i 256 bit; il provider somma omomorficamente
//! E(x_i) se y_i=0, altrimenti E(1-x_i) = E(1) + (n-1)*E(x_i); l'autorità decifra.

use kzen_paillier::{
    Add, BigInt, DecryptionKey, EncryptionKey, Encrypt, Decrypt, KeyGeneration, Mul,
    Paillier, RawCiphertext, RawPlaintext,
};
use std::borrow::Cow;
use curv::arithmetic::traits::Converter;
pub type Ct = RawCiphertext<'static>;

pub struct PaillierKeys {
    pub ek: EncryptionKey,
    pub dk: DecryptionKey,
}

impl PaillierKeys {
    /// KeyGen con modulo di `modulus_bits` bit (2048 -> 112 bit security, 3072 -> 128).
    pub fn generate(modulus_bits: usize) -> Self {
        let keypair = Paillier::keypair_with_modulus_size(modulus_bits);
        let (ek, dk) = keypair.keys();
        Self { ek, dk }
    }

    pub fn decrypt(&self, c: &Ct) -> BigInt {
        let pt: RawPlaintext<'static> = Paillier::decrypt(&self.dk, c);
        pt.0.into_owned()
    }
}

fn pt(v: u64) -> RawPlaintext<'static> {
    RawPlaintext(Cow::Owned(BigInt::from(v)))
}

fn clone_ct(c: &Ct) -> Ct {
    RawCiphertext(Cow::Owned(c.0.as_ref().clone()))
}

fn enc(ek: &EncryptionKey, v: u64) -> Ct {
    Paillier::encrypt(ek, pt(v))
}

fn ct_add(ek: &EncryptionKey, a: Ct, b: Ct) -> Ct {
    Paillier::add(ek, a, b)
}

/// E(k * m) a partire da E(m): serve per il complemento con k = n-1.
fn ct_mul_scalar(ek: &EncryptionKey, c: Ct, k: BigInt) -> Ct {
    Paillier::mul(ek, c, RawPlaintext(Cow::Owned(k)))
}

/// RUOLO CLIENT: cifra i 256 bit dell'hash (MSB-first per byte, come il circuito ZKP).
pub fn encrypt_hash(ek: &EncryptionKey, hash: &[u8; 32]) -> Vec<Ct> {
    let mut out = Vec::with_capacity(256);
    for byte in hash.iter() {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) as u64;
            out.push(enc(ek, bit));
        }
    }
    out
}

/// RUOLO PROVIDER: distanza di Hamming omomorfica contro un reference IN CHIARO.
pub fn homomorphic_hamming(ek: &EncryptionKey, encrypted: &[Ct], reference: &[u8; 32]) -> Ct {
    let n_minus_1 = &ek.n - BigInt::from(1u32); // E((n-1)*x) = E(-x mod n)
    let one = enc(ek, 1);
    let mut acc = enc(ek, 0);
    let mut idx = 0usize;
    for byte in reference.iter() {
        for i in (0..8).rev() {
            let y = (byte >> i) & 1;
            let factor = if y == 0 {
                clone_ct(&encrypted[idx]) // E(x_i)
            } else {
                // E(1 - x_i) = E(1) + E(-x_i)
                let neg = ct_mul_scalar(ek, clone_ct(&encrypted[idx]), n_minus_1.clone());
                ct_add(ek, clone_ct(&one), neg)
            };
            acc = ct_add(ek, acc, factor);
            idx += 1;
        }
    }
    acc
}

/// Byte di un vettore di 256 ciphertext (payload di rete, larghezza fissa).
pub fn serialize_vector(ek: &EncryptionKey, cts: &[Ct]) -> Vec<u8> {
    let width = ek.nn.to_bytes().len();
    let mut out = Vec::with_capacity(width * cts.len());
    for ct in cts {
        let b = ct.0.as_ref().to_bytes();
        out.extend(std::iter::repeat(0u8).take(width.saturating_sub(b.len())));
        out.extend_from_slice(&b);
    }
    out
}

pub fn payload_size_bytes(ek: &EncryptionKey) -> usize {
    256 * ek.nn.to_bytes().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> PaillierKeys {
        PaillierKeys::generate(1024) // modulo piccolo: i test restano veloci
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let keys = test_keys();
        let c = enc(&keys.ek, 42);
        assert_eq!(keys.decrypt(&c), BigInt::from(42u32));
    }

    #[test]
    fn additive_homomorphism() {
        let keys = test_keys();
        let sum = ct_add(&keys.ek, enc(&keys.ek, 7), enc(&keys.ek, 35));
        assert_eq!(keys.decrypt(&sum), BigInt::from(42u32));
    }

    #[test]
    fn homomorphic_hamming_distance() {
        let keys = test_keys();
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 0b0000_0111; // 3 bit
        b[31] = 0b1000_0000; // +1 bit => 4
        let ct = encrypt_hash(&keys.ek, &a);
        let enc_dist = homomorphic_hamming(&keys.ek, &ct, &b);
        assert_eq!(keys.decrypt(&enc_dist), BigInt::from(4u32));
    }

    #[test]
    fn threshold_boundary_31_vs_32() {
        let keys = test_keys();
        let a = [0u8; 32];
        let mut near = [0u8; 32];
        near[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0b1111_1110]); // 31 bit
        let mut far = [0u8; 32];
        far[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // 32 bit

        let ct = encrypt_hash(&keys.ek, &a);
        let d_near = keys.decrypt(&homomorphic_hamming(&keys.ek, &ct, &near));
        let d_far = keys.decrypt(&homomorphic_hamming(&keys.ek, &ct, &far));
        assert!(d_near <= BigInt::from(31u32));
        assert!(d_far > BigInt::from(31u32));
    }
}