use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_relations::utils::error::SynthesisError;
// In ark-crypto-primitives 0.6 il trait si chiama CRHSchemeGadget (non più CRHGadget)
// ed è lui a fornire il metodo evaluate() a Sha256Gadget.
use ark_crypto_primitives::crh::{
    sha256::{constraints::Sha256Gadget, Sha256},
    CRHSchemeGadget,
};

pub struct MembershipCircuit {
    pub local_hash: Option<[u8; 32]>,
    pub reference_hash: Option<[u8; 32]>,
    pub merkle_path: Vec<([u8; 32], bool)>,
    pub db_root: [u8; 32],
    pub threshold: u32,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // --- Input pubblico: root del DB ---
        let root_var: Vec<UInt8<F>> = self.db_root.iter()
            .map(|b| UInt8::new_input(cs.clone(), || Ok(*b)))
            .collect::<Result<_, _>>()?;

        // --- Witness: reference hash ---
        let ref_bytes = self.reference_hash.unwrap_or([0u8; 32]);
        let ref_var: Vec<UInt8<F>> = ref_bytes.iter()
            .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)))
            .collect::<Result<_, _>>()?;

        // --- Bit MSB-first del reference ---
        // to_bits_be() su &UInt8 restituisce Result<Vec<Boolean<F>>, _>: serve il ?
        let mut ref_bits: Vec<Boolean<F>> = Vec::with_capacity(256);
        for byte in &ref_var {
            ref_bits.extend(byte.to_bits_be()?);
        }

        // --- Witness: bit del local hash (MSB-first) ---
        let local_bytes = self.local_hash.unwrap_or([0u8; 32]);
        let mut local_bits: Vec<Boolean<F>> = Vec::with_capacity(256);
        for byte in local_bytes.iter() {
            for i in (0..8).rev() {
                let b = (byte >> i) & 1 == 1;
                local_bits.push(Boolean::new_witness(cs.clone(), || Ok(b))?);
            }
        }

        // --- Membership: SHA-256 in-circuit ---

        let mut current: Vec<UInt8<F>> = ref_var.clone();
        for (sibling, node_is_left) in &self.merkle_path {
            let sib: Vec<UInt8<F>> = sibling.iter()
                .map(|b| UInt8::new_witness(cs.clone(), || Ok(*b)))
                .collect::<Result<_, _>>()?;
            let dir = Boolean::new_witness(cs.clone(), || Ok(*node_is_left))?;

            let mut left_vec: Vec<UInt8<F>> = Vec::with_capacity(32);
            let mut right_vec: Vec<UInt8<F>> = Vec::with_capacity(32);
            for (c, s) in current.iter().zip(sib.iter()) {
                left_vec.push(dir.select(c, s)?);
                right_vec.push(dir.select(s, c)?);
            }
            let mut preimage = left_vec;
            preimage.extend(right_vec);

            // Chiamata statica al trait, passando () come parametri dell'hash
            // 1. Otteniamo il tipo ParametersVar (che internamente è UnitVar) tramite il trait
            let params = <Sha256Gadget<F> as CRHSchemeGadget<Sha256, F>>::ParametersVar::default();

            // 2. Chiamiamo evaluate usando i parametri e l'input
            current = Sha256Gadget::<F>::evaluate(&params, &preimage)?.0.to_vec();       }
        for (c, r) in current.iter().zip(root_var.iter()) {
            c.enforce_equal(r)?;
        }

        // --- Distanza di Hamming ---
        let mut sum_diffs = FpVar::<F>::zero();
        for i in 0..256 {
            let is_diff = local_bits[i].is_neq(&ref_bits[i])?;
            sum_diffs += FpVar::from(is_diff);
        }

        // --- Threshold check ---
        let threshold_var = FpVar::<F>::new_input(cs.clone(), || Ok(F::from(self.threshold)))?;
        let diff = &threshold_var - &sum_diffs;
        let diff_bits = diff.to_bits_le()?;
        for i in 9..diff_bits.len() {
            diff_bits[i].enforce_equal(&Boolean::FALSE)?;
        }
        Ok(())
    }
}