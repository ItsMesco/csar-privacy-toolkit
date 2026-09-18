//! Strategia PHE: simula i tre ruoli (Client / Provider / Autorità) nello stesso
//! processo per il benchmarking. In deployment i ruoli sono separati sul backend.

use super::phe_engine::{self, PaillierKeys};
use super::{ComparisonContext, ComparisonError, ComparisonResult, ComparisonStrategy};
use crate::local_privacy_ledger::ScanOutcome;
use hash_engine::PdqHash;
use kzen_paillier::BigInt;

pub struct PheStrategy {
    keys: PaillierKeys,
}

impl PheStrategy {
    pub fn new(modulus_bits: usize) -> Self {
        Self { keys: PaillierKeys::generate(modulus_bits) }
    }

    pub fn payload_size(&self) -> usize {
        phe_engine::payload_size_bytes(&self.keys.ek)
    }
}

impl ComparisonStrategy for PheStrategy {
    fn name(&self) -> &'static str {
        "phe"
    }

    fn compare(
        &self,
        local_hash: &PdqHash,
        context: &ComparisonContext,
    ) -> Result<ComparisonResult, ComparisonError> {
        // CLIENT: cifra i propri 256 bit
        let ct = phe_engine::encrypt_hash(&self.keys.ek, &local_hash.0);

        // PROVIDER: distanza omomorfica contro il reference in chiaro
        let enc_dist =
            phe_engine::homomorphic_hamming(&self.keys.ek, &ct, &context.reference_hash.0);

        // AUTORITÀ: decifra la distanza e applica la soglia
        let dist = self.keys.decrypt(&enc_dist);
        let outcome = if dist <= BigInt::from(context.threshold) {
            ScanOutcome::Match
        } else {
            ScanOutcome::NoMatch
        };

        Ok(ComparisonResult {
            outcome,
            proof: Some(phe_engine::serialize_vector(&self.keys.ek, &ct)),
        })
    }
}