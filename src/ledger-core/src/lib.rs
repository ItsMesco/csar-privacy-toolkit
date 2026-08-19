use rs_merkle::{MerkleTree, algorithms::Sha256 as MerkleSha256};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub trait LedgerEvent: Serialize {
    fn canonical_representation(&self) -> String;
}

///returns SHA-256 leaf of an event
pub fn hash_event<T: LedgerEvent>(event: &T) -> [u8; 32] {
    let digest = Sha256::digest(event.canonical_representation().as_bytes());
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&digest);
    leaf
}

///returns merkle root from ordered leaves. Returns none if legder's empty.
pub fn merkle_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }

    let tree = MerkleTree::<MerkleSha256>::from_leaves(leaves);
    tree.root()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestEvent {
        id: i64,
        value: String,
    }

    impl LedgerEvent for TestEvent {
        fn canonical_representation(&self) -> String {
            format!("{}|{}", self.id, self.value)
        }
    }

    #[test]
    fn test_event_has_stable_representation() {
        let event = TestEvent {
            id: 1,
            value: "hello".to_string(),
        };

        assert_eq!(event.canonical_representation(), "1|hello");
    }
    #[test]
    fn same_event_produces_same_leaf() {
        let event = TestEvent {
            id: 1,
            value: "hello".to_string(),
        };

        assert_eq!(hash_event(&event), hash_event(&event));
    }

    #[test]
    fn changed_event_produces_different_leaf() {
        let first = TestEvent {
            id: 1,
            value: "hello".to_string(),
        };
        let second = TestEvent {
            id: 1,
            value: "changed".to_string(),
        };

        assert_ne!(hash_event(&first), hash_event(&second));
    }

    #[test]
    fn empty_ledger_has_no_merkle_root() {
        assert_eq!(merkle_root(&[]), None);
    }

    #[test]
    fn adding_an_event_changes_the_merkle_root() {
        let first = TestEvent {
            id: 1,
            value: "first".to_string(),
        };
        let second = TestEvent {
            id: 2,
            value: "second".to_string(),
        };

        let first_leaf = hash_event(&first);
        let second_leaf = hash_event(&second);

        let root_one_event = merkle_root(&[first_leaf]).unwrap();
        let root_two_events = merkle_root(&[first_leaf, second_leaf]).unwrap();

        assert_ne!(root_one_event, root_two_events);
    }

    #[test]
    fn changing_an_event_changes_the_merkle_root() {
        let original = TestEvent {
            id: 1,
            value: "original".to_string(),
        };
        let changed = TestEvent {
            id: 1,
            value: "modified".to_string(),
        };

        let root_original = merkle_root(&[hash_event(&original)]).unwrap();
        let root_changed = merkle_root(&[hash_event(&changed)]).unwrap();

        assert_ne!(root_original, root_changed);
    }
}
