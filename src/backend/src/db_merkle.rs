use sha2::{Digest, Sha256};

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn db_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty() && leaves.len().is_power_of_two());
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
    }
    level[0]
}

/// Il database di riferimento pubblicato dall'autorità (dummy nel prototipo).
pub fn published_db() -> Vec<[u8; 32]> {
    vec![
        hex::decode("319016a7aab499193408ef3de4896df93ec84d5eea85c2e7af64726ea247ba05").unwrap()[..32].try_into().unwrap(),
        hex::decode("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0").unwrap()[..32].try_into().unwrap(),
    ]
}

