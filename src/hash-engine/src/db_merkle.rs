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

/// Path di inclusione bottom-up: (sibling, node_is_left).
pub fn merkle_path(leaves: &[[u8; 32]], index: usize) -> Vec<([u8; 32], bool)> {
    assert!(index < leaves.len());
    let mut path = Vec::new();
    let mut level = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let sib = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        path.push((level[sib], idx % 2 == 0));
        level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
        idx /= 2;
    }
    path
}