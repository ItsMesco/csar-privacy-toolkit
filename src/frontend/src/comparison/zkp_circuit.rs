use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_relations::utils::error::SynthesisError;

/// ZKP circuit demonstrates that calculated hash has Hamming Distance <= threshold
pub struct HammingDistanceCircuit {
    pub local_hash: Option<[u8; 32]>, // Witness (Privato)
    pub reference_hash: [u8; 32],     // Input Pubblico
    pub threshold: u32,               // Input Pubblico
}

impl<F: PrimeField> ConstraintSynthesizer<F> for HammingDistanceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {

        let mut ref_bits = Vec::with_capacity(256);
        for byte in self.reference_hash.iter() {
            for i in (0..8).rev() {
                let b = (byte >> i) & 1 == 1;
                ref_bits.push(Boolean::new_input(cs.clone(), || Ok(b))?);
            }
        }

        let mut local_bits = Vec::with_capacity(256);
        let local_bytes = self.local_hash.unwrap_or([0u8; 32]);
        for byte in local_bytes.iter() {
            for i in (0..8).rev() {
                let b = (byte >> i) & 1 == 1;
                local_bits.push(Boolean::new_witness(cs.clone(), || Ok(b))?);
            }
        }

        let mut sum_diffs = FpVar::<F>::zero();
        for i in 0..256 {
            // XOR logico all'interno del circuito ZKP
            let is_diff = local_bits[i].is_neq(&ref_bits[i])?;
            // Converte il risultato booleano in una variabile numerica e somma
            sum_diffs += FpVar::from(is_diff);
        }

        let threshold_var = FpVar::<F>::new_input(cs.clone(), || Ok(F::from(self.threshold)))?;
        let diff = &threshold_var - &sum_diffs;
        let diff_bits = diff.to_bits_le()?;

        // Se sum_diffs > threshold, l'operazione in un campo finito va in "underflow"
        // generando un numero enorme (circa 2^254).
        // Poiché la distanza massima di Hamming è 256, se la soglia è rispettata,
        // (threshold - sum) sarà un numero piccolo esprimibile in massimo 9 bit.
        // Forziamo tutti i bit dal 9 in poi a essere ZERO.
        // Se c'è stato underflow (soglia superata), questo controllo fallirà matematicamente.
        for i in 9..diff_bits.len() {
            diff_bits[i].enforce_equal(&Boolean::FALSE)?;
        }

        Ok(())
    }
}