use super::hash::{combine_hashes, hash_bytes, Hash256};

/// A Merkle tree built from a list of leaf hashes.
/// Supports inclusion proofs for verifying transaction membership.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All layers of the tree, from leaves (index 0) to root (last).
    layers: Vec<Vec<Hash256>>,
}

/// A proof that a specific leaf is included in the Merkle root.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf hash being proved.
    pub leaf: Hash256,
    /// Sibling hashes along the path to the root, with direction (true = right).
    pub siblings: Vec<(Hash256, bool)>,
    /// The expected root hash.
    pub root: Hash256,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of data items.
    pub fn from_data<T: AsRef<[u8]>>(items: &[T]) -> Self {
        let leaves: Vec<Hash256> = items.iter().map(|i| hash_bytes(i.as_ref())).collect();
        Self::from_hashes(leaves)
    }

    /// Build a Merkle tree from pre-computed leaf hashes.
    pub fn from_hashes(leaves: Vec<Hash256>) -> Self {
        if leaves.is_empty() {
            return MerkleTree {
                layers: vec![vec![hash_bytes(b"empty")]],
            };
        }

        let mut layers = vec![leaves];

        loop {
            let current = layers.last().unwrap();
            if current.len() == 1 {
                break;
            }

            let mut next_layer = Vec::with_capacity((current.len() + 1) / 2);
            let mut i = 0;
            while i < current.len() {
                let left = &current[i];
                let right = if i + 1 < current.len() {
                    &current[i + 1]
                } else {
                    left // Duplicate last element if odd
                };
                next_layer.push(combine_hashes(left, right));
                i += 2;
            }
            layers.push(next_layer);
        }

        MerkleTree { layers }
    }

    /// Get the Merkle root.
    pub fn root(&self) -> Hash256 {
        self.layers
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or_else(Hash256::zero)
    }

    /// Get the number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.layers.first().map_or(0, |l| l.len())
    }

    /// Generate an inclusion proof for a leaf at the given index.
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaf_count() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut idx = leaf_index;

        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < layer.len() {
                layer[sibling_idx]
            } else {
                layer[idx] // Self-sibling when odd count
            };
            let is_right = idx % 2 == 0;
            siblings.push((sibling, is_right));
            idx /= 2;
        }

        Some(MerkleProof {
            leaf: self.layers[0][leaf_index],
            siblings,
            root: self.root(),
        })
    }

    /// Verify a Merkle proof.
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;

        for (sibling, sibling_is_right) in &proof.siblings {
            current = if *sibling_is_right {
                combine_hashes(&current, sibling)
            } else {
                combine_hashes(sibling, &current)
            };
        }

        current == proof.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let tree = MerkleTree::from_data(&[b"hello"]);
        assert_eq!(tree.leaf_count(), 1);
        assert_ne!(tree.root(), Hash256::zero());
    }

    #[test]
    fn test_two_leaves() {
        let tree = MerkleTree::from_data(&[b"hello", b"world"]);
        assert_eq!(tree.leaf_count(), 2);
    }

    #[test]
    fn test_proof_verification() {
        let items: Vec<&[u8]> = vec![b"tx1", b"tx2", b"tx3", b"tx4", b"tx5"];
        let tree = MerkleTree::from_data(&items);

        for i in 0..items.len() {
            let proof = tree.proof(i).unwrap();
            assert!(
                MerkleTree::verify_proof(&proof),
                "Proof for leaf {} failed",
                i
            );
        }
    }

    #[test]
    fn test_deterministic_root() {
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let tree1 = MerkleTree::from_data(&items);
        let tree2 = MerkleTree::from_data(&items);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_inputs_different_root() {
        let tree1 = MerkleTree::from_data(&[b"a", b"b"]);
        let tree2 = MerkleTree::from_data(&[b"c", b"d"]);
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::from_hashes(vec![]);
        assert_ne!(tree.root(), Hash256::zero());
    }
}
