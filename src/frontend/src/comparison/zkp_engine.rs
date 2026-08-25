use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use rand::rngs::OsRng;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};

use super::zkp_circuit::HammingDistanceCircuit;

pub struct ZkpKeys {
    pub proving_key: ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,
}

impl ZkpKeys {
    pub fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        let dummy_hash = [0u8; 32];

        let circuit = HammingDistanceCircuit {
            local_hash: Some(dummy_hash),
            reference_hash: dummy_hash,
            threshold: 31,
        };

        let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng)?;

        Ok(Self { proving_key: pk, verifying_key: vk })
    }
}

pub fn generate_proof(
    keys: &ZkpKeys,
    local_hash: [u8; 32],
    reference_hash: [u8; 32],
    threshold: u32,
) -> Result<Proof<Bn254>, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let circuit = HammingDistanceCircuit {
        local_hash: Some(local_hash),
        reference_hash,
        threshold,
    };
    let proof = Groth16::<Bn254>::prove(&keys.proving_key, circuit, &mut rng)?;
    Ok(proof)
}

pub fn verify_proof(
    keys: &ZkpKeys,
    proof: &Proof<Bn254>,
    reference_hash: [u8; 32],
    threshold: u32,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut public_inputs = Vec::new();


    for byte in reference_hash.iter() {
        for i in (0..8).rev() {
            let b = (byte >> i) & 1 == 1;
            public_inputs.push(Fr::from(b as u64));
        }
    }
    public_inputs.push(Fr::from(threshold as u64));
    
    let pvk = Groth16::<Bn254>::process_vk(&keys.verifying_key)?;
    
    let valid = Groth16::<Bn254>::verify_with_processed_vk(
        &pvk,
        &public_inputs,
        proof,
    )?;

    Ok(valid)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zkp_match_success() {
        let keys = ZkpKeys::generate().unwrap();
        let reference_hash = [0u8; 32];
        let threshold = 31;
        
        let local_hash_valid = [0u8; 32];
        
        let proof = generate_proof(&keys, local_hash_valid, reference_hash, threshold)
            .expect("La proof dovrebbe essere generata con successo");

        // 5. Il server verifica la proof e DEVE restituire true
        let is_valid = verify_proof(&keys, &proof, reference_hash, threshold).unwrap();
        assert!(is_valid, "La verifica della proof è fallita matematicamente");
    }

    #[test]
    #[should_panic(expected = "is_satisfied")]
    fn test_zkp_match_failure_over_threshold() {
        let keys = ZkpKeys::generate().unwrap();

        let reference_hash = [0u8; 32];
        let threshold = 31;
        
        let mut local_hash_invalid = [0u8; 32];
        local_hash_invalid[0] = 0xFF;
        local_hash_invalid[1] = 0xFF;
        local_hash_invalid[2] = 0xFF;
        local_hash_invalid[3] = 0xFF;
        
        let proof_result = generate_proof(&keys, local_hash_invalid, reference_hash, threshold);

        assert!(
            proof_result.is_err(),
            "ERRORE CRITICO: Il circuito ha generato una proof per un hash oltre la soglia!"
        );
    }
}