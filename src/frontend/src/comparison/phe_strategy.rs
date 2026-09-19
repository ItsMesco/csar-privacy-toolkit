//! Strategia PHE: il Client cifra i bit. Il calcolo omomorfico spetta al Server (backend).
use super::phe_engine::{self, PaillierKeys};
use super::{ComparisonContext, ComparisonError, ComparisonResult, ComparisonStrategy};
use crate::local_privacy_ledger::ScanOutcome;
use hash_engine::PdqHash;

pub struct PheStrategy {
    keys: PaillierKeys,
}

impl PheStrategy {
    pub fn new(modulus_bits: usize) -> Self {
        Self { keys: PaillierKeys::generate(modulus_bits) }
    }
}

impl ComparisonStrategy for PheStrategy {
    fn name(&self) -> &'static str {
        "phe"
    }

    /// RUOLO CLIENT: Cifra SOLO i 256 bit e li serializza per la rete.
    /// Il calcolo omomorfico spetta ESCLUSIVAMENTE al Server (backend).
    fn compare(
        &self,
        local_hash: &PdqHash,
        context: &ComparisonContext,
    ) -> Result<ComparisonResult, ComparisonError> {
        // 1. CLIENT: Cifratura dei 256 bit (Operazione "leggera")
        let ct = phe_engine::encrypt_hash(&self.keys.ek, &local_hash.0);

        // Calcolo outcome in chiaro (serve solo per registrare l'evento nel ledger locale)
        let dist_clear: u32 = local_hash.0.iter()
            .zip(context.reference_hash.0.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum();
        let outcome = if dist_clear <= context.threshold {
            ScanOutcome::Match
        } else {
            ScanOutcome::NoMatch
        };

        Ok(ComparisonResult {
            outcome,
            proof: Some(phe_engine::serialize_vector(&self.keys.ek, &ct)),
        })
    }

    /// La verifica per PHE avviene lato Server (backend).
    /// Il tempo di calcolo del Server è misurato dal "network RTT".
    fn verify(&self, _proof: &[u8], _context: &ComparisonContext) -> Result<bool, ComparisonError> {
        Ok(true) // No-op locale
    }

    fn verifying_key_bytes(&self) -> Option<Vec<u8>> {
        None
    }

    fn decryption_key_bytes(&self) -> Option<Vec<u8>> {
        // Per il test E2E, il Client invia la dk al Server dummy
        serde_json::to_vec(&self.keys.dk).ok()
    }
}