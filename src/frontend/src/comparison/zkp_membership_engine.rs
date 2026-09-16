use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use rand::rngs::OsRng;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};

use super::zkp_membership_circuit::MembershipCircuit;

pub struct MembershipKeys {
    pub proving_key: ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,
}

impl MembershipKeys {
    /// `depth` = log2(numero entry del DB): la struttura del circuito
    /// (e quindi il setup) dipende dalla lunghezza del Merkle path.
    pub fn generate(depth: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        let circuit = MembershipCircuit {
            local_hash: Some([0u8; 32]),
            reference_hash: Some([0u8; 32]),
            merkle_path: vec![([0u8; 32], true); depth],
            db_root: [0u8; 32],
            threshold: 31,
        };
        let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng)?;
        Ok(Self { proving_key: pk, verifying_key: vk })
    }
}

pub fn generate_membership_proof(
    keys: &MembershipKeys,
    local_hash: [u8; 32],
    reference_hash: [u8; 32],
    merkle_path: Vec<([u8; 32], bool)>,
    db_root: [u8; 32],
    threshold: u32,
) -> Result<Proof<Bn254>, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let circuit = MembershipCircuit {
        local_hash: Some(local_hash),
        reference_hash: Some(reference_hash),
        merkle_path,
        db_root,
        threshold,
    };
    Ok(Groth16::<Bn254>::prove(&keys.proving_key, circuit, &mut rng)?)
}

pub fn verify_membership_proof(
    keys: &MembershipKeys,
    proof: &Proof<Bn254>,
    db_root: [u8; 32],
    threshold: u32,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut public_inputs = Vec::new();
    for byte in db_root.iter() {
        for i in 0..8 { // LSB-first: ordine di allocazione di UInt8::new_input
            let b = (byte >> i) & 1 == 1;
            public_inputs.push(Fr::from(b as u64));
        }
    }
    public_inputs.push(Fr::from(threshold as u64));
    let pvk = Groth16::<Bn254>::process_vk(&keys.verifying_key)?;
    Ok(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, proof)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hash_engine::db_merkle::{db_merkle_root, merkle_path};

    fn dummy_db() -> Vec<[u8; 32]> {
        vec![[0x31u8; 32], [0xf0u8; 32]]
    }

    #[test]
    fn membership_proof_verifies_against_root() {
        let db = dummy_db();
        let root = db_merkle_root(&db);
        let path = merkle_path(&db, 0);
        let keys = MembershipKeys::generate(db.len().ilog2() as usize).unwrap();
        let proof = generate_membership_proof(&keys, db[0], db[0], path, root, 31).unwrap();
        assert!(verify_membership_proof(&keys, &proof, root, 31).unwrap());
    }

    #[test]
    fn membership_proof_fails_with_wrong_root() {
        let db = dummy_db();
        let root = db_merkle_root(&db);
        let path = merkle_path(&db, 0);
        let keys = MembershipKeys::generate(db.len().ilog2() as usize).unwrap();
        let proof = generate_membership_proof(&keys, db[0], db[0], path, root, 31).unwrap();
        assert!(!verify_membership_proof(&keys, &proof, [0xAAu8; 32], 31).unwrap());
    }

    #[test]
    fn entry_outside_db_cannot_prove_membership() {
        let db = dummy_db();
        let root = db_merkle_root(&db);
        let path = merkle_path(&db, 0); // path valido, ma l'entry non c'entra
        let keys = MembershipKeys::generate(db.len().ilog2() as usize).unwrap();
        let outsider = [0x11u8; 32];
        let result = generate_membership_proof(&keys, outsider, outsider, path, root, 31);
        assert!(result.is_err(), "Un entry fuori dal DB committed non deve essere provabile");
    }
}