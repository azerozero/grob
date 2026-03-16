//! SHA-256 Merkle tree for batch audit log signing.
//!
//! Computes a binary Merkle root over a batch of entry hashes and
//! optionally produces per-leaf inclusion proofs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Position of a sibling node in a Merkle proof step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// Sibling is on the left (prepend when hashing).
    Left,
    /// Sibling is on the right (append when hashing).
    Right,
}

/// One step in a Merkle inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    /// Hex-encoded SHA-256 hash of the sibling node.
    pub hash: String,
    /// Position of this sibling relative to the path node.
    pub side: Side,
}

/// Binary Merkle tree built from leaf hashes.
///
/// Internal nodes are `SHA-256(left || right)`. When a level has an
/// odd number of nodes the last node is promoted without hashing.
pub struct MerkleTree {
    /// All tree levels, bottom (leaves) to top (root).
    levels: Vec<Vec<String>>,
}

impl MerkleTree {
    /// Builds a Merkle tree from hex-encoded leaf hashes.
    ///
    /// # Panics
    ///
    /// Panics if `leaves` is empty.
    pub fn from_leaves(leaves: &[String]) -> Self {
        assert!(!leaves.is_empty(), "MerkleTree requires at least one leaf");

        let mut levels: Vec<Vec<String>> = Vec::new();
        levels.push(leaves.to_vec());

        let mut current = leaves.to_vec();
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for pair in current.chunks(2) {
                if pair.len() == 2 {
                    next.push(hash_pair(&pair[0], &pair[1]));
                } else {
                    // Odd node promoted.
                    next.push(pair[0].clone());
                }
            }
            levels.push(next.clone());
            current = next;
        }

        Self { levels }
    }

    /// Returns the hex-encoded Merkle root.
    pub fn root(&self) -> &str {
        &self.levels.last().expect("non-empty tree")[0]
    }

    /// Generates an inclusion proof for the leaf at `index`.
    ///
    /// Returns `None` if `index` is out of bounds.
    pub fn proof(&self, index: usize) -> Option<Vec<ProofStep>> {
        if index >= self.levels[0].len() {
            return None;
        }

        let mut steps = Vec::new();
        let mut idx = index;

        // Walk from leaf level up to (but not including) the root level.
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = idx ^ 1; // Toggle last bit.
            if sibling_idx < level.len() {
                let side = if sibling_idx < idx {
                    Side::Left
                } else {
                    Side::Right
                };
                steps.push(ProofStep {
                    hash: level[sibling_idx].clone(),
                    side,
                });
            }
            // Move up: parent index is idx / 2.
            idx /= 2;
        }

        Some(steps)
    }

    /// Verifies that `leaf_hash` at `index` is included under `expected_root`.
    pub fn verify(expected_root: &str, leaf_hash: &str, proof: &[ProofStep]) -> bool {
        let mut current = leaf_hash.to_string();
        for step in proof {
            current = match step.side {
                Side::Left => hash_pair(&step.hash, &current),
                Side::Right => hash_pair(&current, &step.hash),
            };
        }
        current == expected_root
    }
}

/// Hashes two hex-encoded values: `SHA-256(left_bytes || right_bytes)`.
fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn leaf(data: &str) -> String {
        hex::encode(Sha256::digest(data.as_bytes()))
    }

    #[test]
    fn single_leaf() {
        let leaves = vec![leaf("a")];
        let tree = MerkleTree::from_leaves(&leaves);
        assert_eq!(tree.root(), leaves[0]);
        let proof = tree.proof(0).unwrap();
        assert!(proof.is_empty());
        assert!(MerkleTree::verify(tree.root(), &leaves[0], &proof));
    }

    #[test]
    fn two_leaves() {
        let leaves = vec![leaf("a"), leaf("b")];
        let tree = MerkleTree::from_leaves(&leaves);
        assert_ne!(tree.root(), leaves[0]);
        assert_ne!(tree.root(), leaves[1]);

        for (i, l) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(MerkleTree::verify(tree.root(), l, &proof));
        }
    }

    #[test]
    fn four_leaves() {
        let leaves: Vec<String> = (0..4).map(|i| leaf(&format!("entry-{i}"))).collect();
        let tree = MerkleTree::from_leaves(&leaves);

        for (i, l) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert_eq!(proof.len(), 2, "depth should be 2 for 4 leaves");
            assert!(MerkleTree::verify(tree.root(), l, &proof));
        }
    }

    #[test]
    fn odd_leaves() {
        let leaves: Vec<String> = (0..5).map(|i| leaf(&format!("entry-{i}"))).collect();
        let tree = MerkleTree::from_leaves(&leaves);

        for (i, l) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(
                MerkleTree::verify(tree.root(), l, &proof),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn tampered_leaf_fails() {
        let leaves = vec![leaf("a"), leaf("b"), leaf("c")];
        let tree = MerkleTree::from_leaves(&leaves);
        let proof = tree.proof(0).unwrap();
        let fake = leaf("tampered");
        assert!(!MerkleTree::verify(tree.root(), &fake, &proof));
    }

    #[test]
    fn out_of_bounds_proof() {
        let leaves = vec![leaf("a")];
        let tree = MerkleTree::from_leaves(&leaves);
        assert!(tree.proof(1).is_none());
    }

    #[test]
    fn large_batch() {
        let leaves: Vec<String> = (0..1024).map(|i| leaf(&format!("entry-{i}"))).collect();
        let tree = MerkleTree::from_leaves(&leaves);

        // Spot-check first, middle, last.
        for &i in &[0, 512, 1023] {
            let proof = tree.proof(i).unwrap();
            assert!(MerkleTree::verify(tree.root(), &leaves[i], &proof));
        }
    }
}
