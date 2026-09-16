use ark_bn254::Bn254;
use ark_groth16::Proof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hash_engine::{is_match, PdqHash};

use super::zkp_membership_engine::{generate_membership_proof, verify_membership_proof, MembershipKeys};
use super::{ComparisonContext, ComparisonError, ComparisonResult, ComparisonStrategy};
use crate::local_privacy_ledger::ScanOutcome;

pub struct ZkpMembershipStrategy {
    keys: MembershipKeys,
}

impl ZkpMembershipStrategy {
    pub fn new(depth: usize) -> Result<Self, ComparisonError> {
        Ok(Self {
            keys: MembershipKeys::generate(depth)
                .map_err(|e| ComparisonError::Internal(e.to_string()))?,
        })
    }
}

impl ComparisonStrategy for ZkpMembershipStrategy {
    fn name(&self) -> &'static str {
        "zkp-membership"
    }

    fn compare(
        &self,
        local_hash: &PdqHash,
        context: &ComparisonContext,
    ) -> Result<ComparisonResult, ComparisonError> {
        if !is_match(local_hash, &context.reference_hash, context.threshold) {
            return Ok(ComparisonResult { outcome: ScanOutcome::NoMatch, proof: None });
        }
        let proof = generate_membership_proof(
            &self.keys,
            local_hash.0,
            context.reference_hash.0,
            context.merkle_path.clone(),
            context.db_root,
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
        verify_membership_proof(&self.keys, &proof, context.db_root, context.threshold)
            .map_err(|e| ComparisonError::Internal(e.to_string()))
    }

    fn verifying_key_bytes(&self) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        self.keys.verifying_key.serialize_compressed(&mut bytes).ok()?;
        Some(bytes)
    }
}