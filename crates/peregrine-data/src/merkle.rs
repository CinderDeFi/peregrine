//! Minimal binary Merkle tree with inclusion proofs.
//!
//! Bootstrap-grade on purpose: rebuilt from leaves on every root() call at
//! the store layer. The interface — `root()`, `prove(i)`, `verify(...)` — is
//! the stable contract; the production replacement is an incrementally
//! maintained authenticated structure (Verkle multiproofs / IVC views) with
//! identical call shapes, so nothing upstream changes when we swap it.

use peregrine_core::Hash;
use serde::{Deserialize, Serialize};

/// Domain tag for leaf hashing (prevents leaf/interior second-preimage games).
const LEAF_DOMAIN: &[u8] = b"peregrine.merkle.leaf.v1";

/// Hash a leaf's raw bytes with domain separation.
pub fn leaf_hash(bytes: &[u8]) -> Hash {
    let mut hasher = blake3_hasher();
    hasher.update(LEAF_DOMAIN);
    hasher.update(bytes);
    Hash(*hasher.finalize().as_bytes())
}

fn blake3_hasher() -> blake3::Hasher {
    blake3::Hasher::new()
}

/// An inclusion proof: the sibling path from a leaf to the root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the proven leaf.
    pub leaf_index: u64,
    /// Sibling hashes, leaf level first.
    pub siblings: Vec<Hash>,
}

impl MerkleProof {
    /// Recompute the root implied by `leaf` under this proof.
    pub fn implied_root(&self, leaf: Hash) -> Hash {
        let mut acc = leaf;
        let mut index = self.leaf_index;
        for sib in &self.siblings {
            acc = if index.is_multiple_of(2) {
                Hash::combine(&acc, sib)
            } else {
                Hash::combine(sib, &acc)
            };
            index /= 2;
        }
        acc
    }

    /// Verify that `leaf_bytes` is included under `root`.
    pub fn verify(&self, root: &Hash, leaf_bytes: &[u8]) -> bool {
        self.implied_root(leaf_hash(leaf_bytes)) == *root
    }
}

/// A complete Merkle tree built over a list of leaves.
pub struct MerkleTree {
    /// levels[0] = leaf hashes, last level = [root]. Empty tree = ZERO root.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build from raw leaf byte-slices (zero-copy over the input).
    pub fn from_leaves<'a>(leaves: impl Iterator<Item = &'a [u8]>) -> Self {
        let level0: Vec<Hash> = leaves.map(leaf_hash).collect();
        Self::from_leaf_hashes(level0)
    }

    /// Build from pre-hashed leaves.
    pub fn from_leaf_hashes(level0: Vec<Hash>) -> Self {
        let mut levels = vec![level0];
        while levels.last().map(|l| l.len() > 1).unwrap_or(false) {
            let prev = levels.last().expect("non-empty");
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                let combined = if pair.len() == 2 {
                    Hash::combine(&pair[0], &pair[1])
                } else {
                    // Odd node promotes with itself as sibling (Bitcoin-style
                    // duplication is avoided by hashing with itself + domain).
                    Hash::combine(&pair[0], &pair[0])
                };
                next.push(combined);
            }
            levels.push(next);
        }
        Self { levels }
    }

    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or(Hash::ZERO)
    }

    pub fn len(&self) -> usize {
        self.levels.first().map(|l| l.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Produce an inclusion proof for leaf `index`.
    pub fn prove(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.len() {
            return None;
        }
        let mut siblings = Vec::new();
        let mut i = index;
        // Walk every level except the root level.
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            let sib_index = if i.is_multiple_of(2) { i + 1 } else { i - 1 };
            let sib = level.get(sib_index).copied().unwrap_or(level[i]); // odd tail: self
            siblings.push(sib);
            i /= 2;
        }
        Some(MerkleProof {
            leaf_index: index as u64,
            siblings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify_all_leaves() {
        for n in 1..=17usize {
            let leaves: Vec<Vec<u8>> = (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect();
            let tree = MerkleTree::from_leaves(leaves.iter().map(|l| l.as_slice()));
            let root = tree.root();
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = tree.prove(i).expect("proof");
                assert!(proof.verify(&root, leaf), "n={n} i={i}");
                // Tampered leaf must fail.
                assert!(!proof.verify(&root, b"evil"));
            }
        }
    }
}
