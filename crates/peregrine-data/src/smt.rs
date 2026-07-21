//! Incremental sparse Merkle tree (SMT) over `hash(key) -> H(key, value)`.
//!
//! # Why a sparse tree (vs. the sorted-leaf tree in [`crate::merkle`])
//! A first-class table is a *mutable* key/value map: `sys.stream_ticks` gets a
//! brand-new key on every committed record. In a sorted-array Merkle tree a
//! single insert renumbers every later leaf, so the whole tree recomputes —
//! `O(n)` per write, `O(n²)` over a run. Here each key lands at a **fixed**
//! position — the 256 bits of `blake3(key)` — so an insert only touches the
//! `O(depth)` nodes on that key's root-path. Sibling subtrees are untouched,
//! which is exactly what makes the update incremental.
//!
//! The tree is *sparse*: the vast majority of the 2²⁵⁶ positions are empty, so
//! empty subtrees collapse to per-height **default hashes** and we store only
//! the nodes that actually differ from their default. A node that falls back
//! to its default is dropped from the map, so an empty tree holds zero nodes
//! and roots at `default[DEPTH]`.
//!
//! # Proofs
//! Because every key owns a unique leaf slot, the same Merkle path proves
//! either **inclusion** (the slot commits to `H(key, value)`) or
//! **non-inclusion** (the slot is the empty default) — see [`SmtProof::verify`],
//! which takes `Option<value>`. Non-membership needs no adjacency argument.
//!
//! # Bootstrap simplification
//! Proofs carry the full `DEPTH` sibling path (a fixed 256 hashes). Real
//! deployments compress this to the `~log₂(n)` non-default siblings plus a
//! bitmap; the [`SmtProof`] shape is the stable contract, so that swap is
//! internal.

use peregrine_core::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

/// Tree depth = bits in the position hash.
const DEPTH: usize = 256;

/// Domain tags keep leaf, empty-leaf, and interior hashes in disjoint spaces
/// (second-preimage hygiene: an interior node can never be read as a leaf).
const LEAF_DOMAIN: &[u8] = b"peregrine.smt.leaf.v1";
const EMPTY_DOMAIN: &[u8] = b"peregrine.smt.empty.v1";

/// Hash of an occupied leaf. Binds **both** key and value, so a proof for one
/// key can never be replayed for another that happens to share tree structure.
pub fn leaf_hash(key: &[u8], value: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(LEAF_DOMAIN);
    h.update(&(key.len() as u32).to_le_bytes());
    h.update(key);
    h.update(&(value.len() as u32).to_le_bytes());
    h.update(value);
    Hash(*h.finalize().as_bytes())
}

/// Hash of an empty leaf slot (a nonzero constant, so it can't be confused
/// with `Hash::ZERO` sentinels elsewhere).
fn empty_leaf() -> Hash {
    Hash::digest(EMPTY_DOMAIN)
}

/// The i-th bit of a 32-byte position, MSB of byte 0 first (`i` in `0..256`).
#[inline]
fn bit(h: &[u8; 32], i: usize) -> u8 {
    (h[i / 8] >> (7 - (i % 8))) & 1
}

/// Copy of `h` with all bits from index `depth` onward cleared — the canonical
/// map key for the node at `depth` on `h`'s path.
#[inline]
fn prefix(h: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    // whole bytes fully inside the prefix
    let full = depth / 8;
    out[..full].copy_from_slice(&h[..full]);
    // partial trailing byte: keep the top `depth % 8` bits
    if full < 32 {
        let rem = depth % 8;
        if rem != 0 {
            let mask = 0xffu8 << (8 - rem);
            out[full] = h[full] & mask;
        }
    }
    out
}

/// Flip one bit (used to derive a sibling's prefix from ours).
#[inline]
fn with_bit_flipped(mut p: [u8; 32], i: usize) -> [u8; 32] {
    p[i / 8] ^= 1 << (7 - (i % 8));
    p
}

/// Node identity: `(depth, prefix)`. `depth == DEPTH` is a leaf; `depth == 0`
/// is the root. `prefix` has exactly `depth` significant leading bits.
type NodeId = (u16, [u8; 32]);

/// Hasher for [`NodeId`] keys.
///
/// The default `HashMap` hasher is SipHash, which exists to make user-supplied
/// keys collision-resistant. These keys are not user-supplied: a prefix is the
/// truncation of `blake3(key)`, so its bits are already uniform. Re-hashing 34
/// bytes with SipHash on every node touch was measured at roughly a fifth of
/// the whole insert path — pure overhead for a property the input already has.
///
/// So this reads the leading eight bytes of the prefix and mixes in the depth.
/// Depths above 64 are covered because those prefixes differ within their first
/// 64 bits; depths at or below 64 are fully determined by those bits.
///
/// Safety note: a collision here costs a bucket probe, never a wrong answer,
/// and forcing one would mean finding blake3 preimages that agree on 64 bits.
/// The tree's security rests on blake3, not on the map's hasher.
#[derive(Default)]
struct NodeIdHasher(u64);

impl Hasher for NodeIdHasher {
    fn write(&mut self, bytes: &[u8]) {
        // Called once with the prefix bytes and once with the depth, in the
        // order the tuple's `Hash` impl visits its fields.
        let mut lead = [0u8; 8];
        let n = bytes.len().min(8);
        lead[..n].copy_from_slice(&bytes[..n]);
        // fibonacci mixing: cheap, and spreads the low bits the map indexes on
        self.0 = (self.0 ^ u64::from_le_bytes(lead)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        self.0 ^= self.0 >> 29;
    }
    fn write_u16(&mut self, v: u16) {
        self.0 = (self.0 ^ v as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

type NodeMap = HashMap<NodeId, Hash, BuildHasherDefault<NodeIdHasher>>;

/// An incremental sparse Merkle tree. Cheap to clone-free update; keeps only
/// non-default nodes.
#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    /// Non-default nodes, including occupied leaves at `depth == DEPTH`.
    nodes: NodeMap,
    /// `defaults[h]` = root hash of a fully-empty subtree of height `h`
    /// (`defaults[0]` = empty leaf, `defaults[DEPTH]` = empty-tree root).
    defaults: Vec<Hash>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        let mut defaults = Vec::with_capacity(DEPTH + 1);
        defaults.push(empty_leaf());
        for h in 1..=DEPTH {
            let prev = defaults[h - 1];
            defaults.push(Hash::combine(&prev, &prev));
        }
        Self {
            nodes: NodeMap::default(),
            defaults,
        }
    }

    /// Default hash for a node at `depth` (height `DEPTH - depth` below it).
    #[inline]
    fn default_at(&self, depth: usize) -> Hash {
        self.defaults[DEPTH - depth]
    }

    /// The 32-byte root commitment.
    pub fn root(&self) -> Hash {
        self.nodes
            .get(&(0u16, [0u8; 32]))
            .copied()
            .unwrap_or_else(|| self.default_at(0))
    }

    /// Number of occupied leaves.
    pub fn len(&self) -> usize {
        self.nodes
            .keys()
            .filter(|(d, _)| *d as usize == DEPTH)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn pos(key: &[u8]) -> [u8; 32] {
        Hash::digest(key).0
    }

    /// Insert or overwrite `key -> value`. Recomputes only this key's path.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let pos = Self::pos(key);
        self.set_leaf(&pos, leaf_hash(key, value));
    }

    /// Remove `key` if present. Its slot returns to the empty default and the
    /// path collapses back toward defaults.
    pub fn remove(&mut self, key: &[u8]) {
        let pos = Self::pos(key);
        self.set_leaf(&pos, self.default_at(DEPTH));
    }

    /// Set the leaf at `pos` to `leaf` and repair the root-path bottom-up,
    /// dropping any node that has collapsed to its default.
    fn set_leaf(&mut self, pos: &[u8; 32], leaf: Hash) {
        self.put(DEPTH, *pos, leaf);
        let mut cur = leaf;
        for depth in (0..DEPTH).rev() {
            let child_depth = depth + 1;
            let sib_prefix = with_bit_flipped(prefix(pos, child_depth), depth);
            let sib = self
                .nodes
                .get(&(child_depth as u16, sib_prefix))
                .copied()
                .unwrap_or_else(|| self.default_at(child_depth));
            cur = if bit(pos, depth) == 0 {
                Hash::combine(&cur, &sib)
            } else {
                Hash::combine(&sib, &cur)
            };
            self.put(depth, prefix(pos, depth), cur);
        }
    }

    /// Store a node, or drop it if it equals its default (keeps the tree sparse).
    fn put(&mut self, depth: usize, prefix: [u8; 32], hash: Hash) {
        if hash == self.default_at(depth) {
            self.nodes.remove(&(depth as u16, prefix));
        } else {
            self.nodes.insert((depth as u16, prefix), hash);
        }
    }

    /// Produce a proof for `key` — valid whether the key is present or not.
    /// Siblings are ordered leaf-adjacent first (depth `DEPTH-1` down to `0`).
    pub fn prove(&self, key: &[u8]) -> SmtProof {
        let pos = Self::pos(key);
        let mut siblings = Vec::with_capacity(DEPTH);
        for depth in (0..DEPTH).rev() {
            let child_depth = depth + 1;
            let sib_prefix = with_bit_flipped(prefix(&pos, child_depth), depth);
            let sib = self
                .nodes
                .get(&(child_depth as u16, sib_prefix))
                .copied()
                .unwrap_or_else(|| self.default_at(child_depth));
            siblings.push(sib);
        }
        SmtProof {
            key: key.to_vec(),
            siblings,
        }
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// A membership / non-membership proof for one key against an SMT root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmtProof {
    /// The key this path addresses (binds the proof to a specific slot).
    pub key: Vec<u8>,
    /// Sibling hashes along the root-path, leaf-adjacent first.
    pub siblings: Vec<Hash>,
}

impl SmtProof {
    /// Climb from the (claimed) leaf to a root using the sibling path.
    fn climb(&self, leaf: Hash) -> Option<Hash> {
        if self.siblings.len() != DEPTH {
            return None;
        }
        let pos = Hash::digest(&self.key).0;
        let mut acc = leaf;
        // siblings[0] is at depth DEPTH-1, ... siblings[DEPTH-1] at depth 0.
        for (k, sib) in self.siblings.iter().enumerate() {
            let depth = DEPTH - 1 - k;
            acc = if bit(&pos, depth) == 0 {
                Hash::combine(&acc, sib)
            } else {
                Hash::combine(sib, &acc)
            };
        }
        Some(acc)
    }

    /// Verify against `root`. `value = Some(v)` checks **inclusion** of
    /// `(key, v)`; `value = None` checks **non-inclusion** of `key`.
    pub fn verify(&self, root: &Hash, value: Option<&[u8]>) -> bool {
        let leaf = match value {
            Some(v) => leaf_hash(&self.key, v),
            None => empty_leaf(),
        };
        self.climb(leaf).map(|r| r == *root).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(i: u32) -> (Vec<u8>, Vec<u8>) {
        (
            format!("key-{i}").into_bytes(),
            format!("val-{i}").into_bytes(),
        )
    }

    #[test]
    fn empty_tree_root_is_default() {
        let t = SparseMerkleTree::new();
        assert_eq!(t.root(), t.default_at(0));
        // Non-inclusion holds for any key in an empty tree.
        let p = t.prove(b"anything");
        assert!(p.verify(&t.root(), None));
        assert!(!p.verify(&t.root(), Some(b"x")));
    }

    #[test]
    fn inclusion_and_non_inclusion() {
        let mut t = SparseMerkleTree::new();
        for i in 0..200u32 {
            let (k, v) = kv(i);
            t.insert(&k, &v);
        }
        let root = t.root();
        for i in 0..200u32 {
            let (k, v) = kv(i);
            let p = t.prove(&k);
            assert!(p.verify(&root, Some(&v)), "inclusion i={i}");
            // wrong value / wrong root / claimed-absent all fail
            assert!(!p.verify(&root, Some(b"tampered")));
            assert!(!p.verify(&Hash::ZERO, Some(&v)));
            assert!(!p.verify(&root, None));
        }
        // Absent keys prove non-inclusion and cannot prove inclusion.
        for i in 200..260u32 {
            let (k, v) = kv(i);
            let p = t.prove(&k);
            assert!(p.verify(&root, None), "non-inclusion i={i}");
            assert!(!p.verify(&root, Some(&v)));
        }
    }

    #[test]
    fn update_changes_root_and_invalidates_old_proof() {
        let mut t = SparseMerkleTree::new();
        let (k, v) = kv(1);
        t.insert(&k, &v);
        let old_root = t.root();
        let old_proof = t.prove(&k);
        assert!(old_proof.verify(&old_root, Some(&v)));

        t.insert(&k, b"new-value");
        let new_root = t.root();
        assert_ne!(new_root, old_root);
        assert!(old_proof.verify(&old_root, Some(&v))); // still valid vs old root
        assert!(!old_proof.verify(&new_root, Some(&v))); // stale vs new root
        assert!(t.prove(&k).verify(&new_root, Some(b"new-value")));
    }

    #[test]
    fn remove_restores_non_inclusion_and_empty_root() {
        let mut t = SparseMerkleTree::new();
        let empty = t.root();
        let (k, v) = kv(42);
        t.insert(&k, &v);
        assert_ne!(t.root(), empty);
        t.remove(&k);
        assert_eq!(t.root(), empty, "insert+remove returns to empty root");
        assert!(t.prove(&k).verify(&t.root(), None));
    }

    #[test]
    fn order_independent_root() {
        let mut a = SparseMerkleTree::new();
        let mut b = SparseMerkleTree::new();
        for i in 0..64u32 {
            let (k, v) = kv(i);
            a.insert(&k, &v);
        }
        for i in (0..64u32).rev() {
            let (k, v) = kv(i);
            b.insert(&k, &v);
        }
        assert_eq!(
            a.root(),
            b.root(),
            "root is a pure function of the key/value set"
        );
    }
}
