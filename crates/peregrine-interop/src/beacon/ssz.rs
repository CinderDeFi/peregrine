//! The slice of SSZ needed to verify beacon light-client data.
//!
//! Consensus-layer Ethereum commits to everything with SSZ merkleization over
//! SHA-256 (note: **not** keccak — the execution layer's hash. Mixing them up
//! is a classic way to get a beacon verifier confidently wrong).
//!
//! Only what the light client needs is implemented: fixed-size leaves,
//! `merkleize` with zero-padding, `mix_in_length` for variable-length lists,
//! and Merkle-branch verification by generalized index. Everything here is a
//! pure function over bytes, so it compiles into a zkVM guest unchanged.
//!
//! The implementation is self-checking in the strongest available way: the
//! beacon chain publishes the root it computed for a header, and our
//! [`hash_tree_root`](super::BeaconBlockHeader::hash_tree_root) must reproduce
//! it byte for byte (see `tests/beacon.rs`).

use sha2::{Digest, Sha256};

/// A 32-byte SSZ chunk / root.
pub type Node = [u8; 32];

pub fn sha256(bytes: &[u8]) -> Node {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// SSZ's internal node hash: `sha256(left ‖ right)`.
pub fn hash_pair(left: &Node, right: &Node) -> Node {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// A `uint64` leaf: little-endian, right-padded to 32 bytes.
pub fn uint64_leaf(v: u64) -> Node {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&v.to_le_bytes());
    out
}

/// A `uint256` leaf from a big-endian value, byte-reversed into SSZ's
/// little-endian encoding.
pub fn uint256_leaf_from_be(be: &[u8]) -> Node {
    let mut out = [0u8; 32];
    for (i, b) in be.iter().rev().enumerate() {
        if i < 32 {
            out[i] = *b;
        }
    }
    out
}

/// Right-pad up to 32 bytes (addresses, short byte strings).
pub fn bytes_leaf(bytes: &[u8]) -> Node {
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Split a byte string into 32-byte chunks, zero-padding the tail.
pub fn chunks(bytes: &[u8]) -> Vec<Node> {
    if bytes.is_empty() {
        return vec![[0u8; 32]];
    }
    bytes.chunks(32).map(bytes_leaf).collect()
}

/// Zero subtree root at `height` (`height == 0` → the zero chunk).
fn zero_hash(height: usize) -> Node {
    let mut node = [0u8; 32];
    for _ in 0..height {
        node = hash_pair(&node, &node);
    }
    node
}

/// Merkleize `leaves` into a root, padding with zero subtrees up to
/// `limit` chunks (default: the next power of two ≥ `leaves.len()`).
///
/// Padding with *zero subtree roots* rather than recomputing zero leaves is
/// what makes this cheap for things like a 256-byte bloom filter.
pub fn merkleize(leaves: &[Node], limit: Option<usize>) -> Node {
    let count = limit.unwrap_or(leaves.len()).max(1);
    let width = count.next_power_of_two();
    if width == 1 {
        return leaves.first().copied().unwrap_or([0u8; 32]);
    }
    let depth = width.trailing_zeros() as usize;

    let mut level: Vec<Node> = leaves.to_vec();
    for height in 0..depth {
        let pad = zero_hash(height);
        let expected = width >> height;
        // Pad this level out to its full width before combining.
        while level.len() < expected {
            level.push(pad);
        }
        let mut next = Vec::with_capacity(expected / 2);
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pad);
            next.push(hash_pair(&pair[0], &right));
        }
        level = next;
    }
    level[0]
}

/// `mix_in_length`: variable-length collections commit to their length, so a
/// truncated list cannot masquerade as a shorter valid one.
pub fn mix_in_length(root: &Node, length: usize) -> Node {
    hash_pair(root, &uint64_leaf(length as u64))
}

/// Verify an SSZ Merkle branch (the consensus-spec `is_valid_merkle_branch`).
///
/// `index` is the position within the level at `depth`; the generalized index
/// is `2^depth + index`. Getting these constants wrong is the single easiest
/// way to build a verifier that accepts the wrong field, so callers should use
/// the named constants in [`super`] rather than literals.
pub fn verify_merkle_branch(
    leaf: &Node,
    branch: &[Node],
    depth: usize,
    index: usize,
    root: &Node,
) -> bool {
    if branch.len() != depth {
        return false;
    }
    let mut value = *leaf;
    for (i, sibling) in branch.iter().enumerate() {
        // Bit `i` of the index selects which side we are on at this level.
        if (index >> i) & 1 == 1 {
            value = hash_pair(sibling, &value);
        } else {
            value = hash_pair(&value, sibling);
        }
    }
    value == *root
}

/// Split a generalized index into `(depth, index)`.
pub fn gindex_parts(gindex: usize) -> (usize, usize) {
    let depth = (usize::BITS - 1 - gindex.leading_zeros()) as usize;
    (depth, gindex - (1 << depth))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        // NIST: sha256("abc")
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn uint64_leaf_is_little_endian() {
        let leaf = uint64_leaf(1);
        assert_eq!(leaf[0], 1, "SSZ integers are little-endian");
        assert_eq!(leaf[1..], [0u8; 31]);
    }

    #[test]
    fn gindex_splits_correctly() {
        // The two constants this crate depends on.
        assert_eq!(gindex_parts(169), (7, 41)); // finalized root (Electra+)
        assert_eq!(gindex_parts(25), (4, 9)); // execution payload
        assert_eq!(gindex_parts(1), (0, 0)); // the root itself
    }

    #[test]
    fn merkleize_of_one_chunk_is_that_chunk() {
        let leaf = [7u8; 32];
        assert_eq!(merkleize(&[leaf], None), leaf);
    }

    #[test]
    fn merkleize_pads_with_zero_subtrees() {
        // Three leaves in a 4-wide tree: the fourth is the zero chunk.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let expected = hash_pair(&hash_pair(&a, &b), &hash_pair(&c, &[0u8; 32]));
        assert_eq!(merkleize(&[a, b, c], None), expected);
        // Explicit limit gives the same shape.
        assert_eq!(merkleize(&[a, b, c], Some(4)), expected);
    }

    #[test]
    fn branch_verification_round_trips() {
        // Build a 4-leaf tree and check the proof for leaf 2 (index 2, depth 2).
        let leaves = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let left = hash_pair(&leaves[0], &leaves[1]);
        let right = hash_pair(&leaves[2], &leaves[3]);
        let root = hash_pair(&left, &right);

        let branch = [leaves[3], left]; // sibling at each level, bottom-up
        assert!(verify_merkle_branch(&leaves[2], &branch, 2, 2, &root));

        // Wrong leaf, wrong index, and wrong length must all fail.
        assert!(!verify_merkle_branch(&leaves[1], &branch, 2, 2, &root));
        assert!(!verify_merkle_branch(&leaves[2], &branch, 2, 1, &root));
        assert!(!verify_merkle_branch(&leaves[2], &branch[..1], 2, 2, &root));
    }

    #[test]
    fn mix_in_length_binds_the_length() {
        let root = [9u8; 32];
        assert_ne!(mix_in_length(&root, 1), mix_in_length(&root, 2));
    }
}
