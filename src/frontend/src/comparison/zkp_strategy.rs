use ark_bn254::Bn254;
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hash_engine::{is_match, PdqHash};

use super::zkp_engine::{generate_proof, verify_proof, ZkpKeys};
use super::{ComparisonContext, ComparisonError, ComparisonResult, ComparisonStrategy};
use crate::local_privacy_ledger::ScanOutcome;

pub struct ZkpStrategy {
    keys: ZkpKeys,
}

impl ZkpStrategy {
    pub fn new() -> Result<Self, ComparisonError> {
        Ok(Self {
            keys: ZkpKeys::generate().map_err(|e| ComparisonError::Internal(e.to_string()))?,
        })
    }
}

impl ComparisonStrategy for ZkpStrategy {
    fn name(&self) -> &'static str {
        "zkp"
    }

    fn compare(
        &self,
        local_hash: &PdqHash,
        context: &ComparisonContext,
    ) -> Result<ComparisonResult, ComparisonError> {
        // Il client decide l'esito localmente: la proof si genera solo in caso di match.
        if !is_match(local_hash, &context.reference_hash, context.threshold) {
            return Ok(ComparisonResult { outcome: ScanOutcome::NoMatch, proof: None });
        }
        let proof = generate_proof(
            &self.keys,
            local_hash.0,
            context.reference_hash.0,
            context.threshold,
        )
            .map_err(|e| ComparisonError::Internal(e.to_string()))?;
        let mut bytes = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|e| ComparisonError::Internal(e.to_string()))?;
        Ok(ComparisonResult { outcome: ScanOutcome::Match, proof: Some(bytes) })
    }

    fn verify(&self, proof_bytes: &[u8], context: &ComparisonContext) -> Result<bool, ComparisonError> {
        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|e| ComparisonError::Internal(e.to_string()))?;
        verify_proof(&self.keys, &proof, context.reference_hash.0, context.threshold)
            .map_err(|e| ComparisonError::Internal(e.to_string()))
    }

    fn verifying_key_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        self.keys.verifying_key.serialize_compressed(&mut bytes).ok()?;
        Some(bytes)
    }
}