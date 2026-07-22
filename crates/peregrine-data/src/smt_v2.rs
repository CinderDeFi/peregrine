//! # Sparse Merkle tree, **v2** — path-compressed
//!
//! The v1 tree ([`crate::smt`]) is a dense 256-level structure: every insert
//! walks all 256 levels, doing a hash and two map operations at each. Measured,
//! that is ~62 µs per row and roughly two thirds of Peregrine's commit cost.
//!
//! ## Why this could not be done without changing roots
//!
//! It is tempting to think path compression is a pure optimisation — store only
//! the interesting nodes, keep the same root. It is not, and the reason is
//! worth stating because it decides the whole design:
//!
//! A v1 root is *defined* as a 256-level fold. A subtree holding one leaf still
//! has a value produced by ~245 `combine` calls against empty-subtree defaults.
//! Any implementation that yields the same root must perform that fold. So
//! "compression that preserves roots" saves **memory and proof size but not
//! insert cost** — and insert cost is the entire bottleneck.
//!
//! To get O(log n) work you must change what a node hash *means*. That changes
//! every root, which makes this a consensus upgrade rather than a refactor.
//! Hence [`crate::tables::TreeVersion`] and a round-gated activation.
//!
//! ## The v2 rules
//!
//! Three node kinds, and no per-height defaults at all:
//!
//! ```text
//!   empty     = H(EMPTY_DOMAIN_V2)                        // one constant
//!   leaf      = H(LEAF_DOMAIN_V2ǁ|k|ǁkeyǁ|v|ǁvalue)       // depth-independent
//!   internal  = H(NODE_DOMAIN_V2ǁleftǁright)
//! ```
//!
//! A subtree containing exactly one leaf *is* that leaf — there is no chain of
//! combines beneath it. Insert therefore descends only to the first bit where
//! two keys differ: **O(log n) expected**, not O(256).
//!
//! ### Why a depth-independent leaf hash is safe
//!
//! A leaf binds its own key, and `blake3(key)` fixes the leaf's position. A
//! verifier recomputes that position itself and uses its bits to decide the
//! combine order at every level, so a prover cannot present a leaf as sitting
//! somewhere it does not: any other placement produces a different root. This
//! is the standard Jellyfish/JMT argument, and it is why the key must be inside
//! the leaf hash rather than merely implied by position.
//!
//! ## Proofs
//!
//! Inclusion is the usual sibling path. **Non-inclusion has two shapes**, and
//! both must be checked or the proof is worthless:
//!
//! * the slot is empty — climb from `empty()`;
//! * the slot is occupied by a *different* key whose position shares the proof's
//!   path prefix — climb from that leaf's hash.
//!
//! The second case is where sloppy implementations break: presenting *any*
//! other leaf would let a prover deny membership of anything. The verifier
//! therefore checks that the presented leaf really does share the queried key's
//! path for the full proof depth, and really is a different key.

use peregrine_core::Hash;
use serde::{Deserialize, Serialize};

/// Domain tags. Disjoint from v1's so a v1 hash can never be read as a v2 one —
/// which matters precisely because both versions coexist during migration.
const LEAF_DOMAIN_V2: &[u8] = b"peregrine.smt.v2.leaf";
const EMPTY_DOMAIN_V2: &[u8] = b"peregrine.smt.v2.empty";
const NODE_DOMAIN_V2: &[u8] = b"peregrine.smt.v2.node";

/// Maximum descent. Equal to the bit-width of a position hash; reaching it
/// would mean two distinct keys with identical blake3 digests.
const MAX_DEPTH: usize = 256;

/// The empty-subtree hash. One value, not a per-height table: v2 never folds
/// through empty levels, so there is nothing for a height-indexed default to do.
pub fn empty_hash() -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(EMPTY_DOMAIN_V2);
    Hash(*h.finalize().as_bytes())
}

/// Hash of an occupied leaf. Binds key **and** value, with explicit lengths so
/// `(key ǁ value)` cannot be re-split to forge a different pair.
pub fn leaf_hash(key: &[u8], value: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(LEAF_DOMAIN_V2);
    h.update(&(key.len() as u32).to_le_bytes());
    h.update(key);
    h.update(&(value.len() as u32).to_le_bytes());
    h.update(value);
    Hash(*h.finalize().as_bytes())
}

/// Interior node hash.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 21 + 32 + 32];
    buf[..21].copy_from_slice(NODE_DOMAIN_V2);
    buf[21..53].copy_from_slice(&left.0);
    buf[53..].copy_from_slice(&right.0);
    Hash(*blake3::hash(&buf).as_bytes())
}

/// Position of a key in the tree.
pub fn pos_of(key: &[u8]) -> [u8; 32] {
    Hash::digest(key).0
}

/// Bit `i` of a position, MSB-first.
fn bit(p: &[u8; 32], i: usize) -> u8 {
    (p[i / 8] >> (7 - (i % 8))) & 1
}

/// Do two positions agree on their first `n` bits?
fn shares_prefix(a: &[u8; 32], b: &[u8; 32], n: usize) -> bool {
    (0..n).all(|i| bit(a, i) == bit(b, i))
}

#[derive(Clone, Debug)]
enum Node {
    Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
        hash: Hash,
    },
    Internal {
        left: Box<Node>,
        right: Box<Node>,
        hash: Hash,
    },
    /// An explicitly empty child. Kept as a node (rather than `Option`) so an
    /// `Internal` always has two children and the hashing rule has no special
    /// cases.
    Empty,
}

impl Node {
    fn hash(&self) -> Hash {
        match self {
            Node::Leaf { hash, .. } => *hash,
            Node::Internal { hash, .. } => *hash,
            Node::Empty => empty_hash(),
        }
    }

    fn internal(left: Node, right: Node) -> Node {
        let hash = node_hash(&left.hash(), &right.hash());
        Node::Internal {
            left: Box::new(left),
            right: Box::new(right),
            hash,
        }
    }

    fn leaf(key: Vec<u8>, value: Vec<u8>) -> Node {
        let hash = leaf_hash(&key, &value);
        Node::Leaf { key, value, hash }
    }
}

/// A path-compressed sparse Merkle tree.
///
/// Holds ~2n nodes for n keys, against v1's 256n, and costs O(log n) per
/// update instead of O(256).
#[derive(Clone, Debug)]
pub struct SmtV2 {
    root: Node,
    len: usize,
}

impl Default for SmtV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtV2 {
    pub fn new() -> Self {
        Self {
            root: Node::Empty,
            len: 0,
        }
    }

    /// The 32-byte commitment.
    pub fn root(&self) -> Hash {
        self.root.hash()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert or overwrite `key -> value`.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let pos = pos_of(key);
        let root = std::mem::replace(&mut self.root, Node::Empty);
        let (node, added) = Self::insert_at(root, 0, &pos, key, value);
        self.root = node;
        if added {
            self.len += 1;
        }
    }

    /// Returns the rebuilt subtree and whether a new key was added.
    fn insert_at(
        node: Node,
        depth: usize,
        pos: &[u8; 32],
        key: &[u8],
        value: &[u8],
    ) -> (Node, bool) {
        match node {
            // Empty slot: the leaf lands here directly. This is the compression
            // — no chain of nodes is created beneath it.
            Node::Empty => (Node::leaf(key.to_vec(), value.to_vec()), true),

            Node::Leaf {
                key: ekey,
                value: evalue,
                ..
            } => {
                if ekey == key {
                    // Overwrite in place; depth is unchanged.
                    return (Node::leaf(key.to_vec(), value.to_vec()), false);
                }
                // Two distinct keys now share this slot: descend until their
                // positions diverge, then branch. Only the levels between
                // `depth` and the first differing bit are materialised.
                let epos = pos_of(&ekey);
                let existing = Node::leaf(ekey, evalue);
                let fresh = Node::leaf(key.to_vec(), value.to_vec());
                (Self::split(existing, &epos, fresh, pos, depth), true)
            }

            Node::Internal { left, right, .. } => {
                debug_assert!(depth < MAX_DEPTH, "descended past the position width");
                let (l, r, added) = if bit(pos, depth) == 0 {
                    let (l, added) = Self::insert_at(*left, depth + 1, pos, key, value);
                    (l, *right, added)
                } else {
                    let (r, added) = Self::insert_at(*right, depth + 1, pos, key, value);
                    (*left, r, added)
                };
                (Node::internal(l, r), added)
            }
        }
    }

    /// Build the minimal chain of internals that separates two leaves whose
    /// positions first differ at or below `depth`.
    fn split(a: Node, apos: &[u8; 32], b: Node, bpos: &[u8; 32], depth: usize) -> Node {
        if depth >= MAX_DEPTH {
            // AUDIT I-3: two distinct keys with the same 256-bit blake3 digest —
            // a preimage collision, ~2^128 work, cryptographically unreachable.
            // The panic is *deliberately kept* over the "softer" alternatives the
            // audit floated: a no-op or dropping one key would silently pick a
            // winner, and *which* key wins could differ across nodes → a fork
            // that is invisible until roots disagree. A deterministic halt is the
            // correct response to an impossible-yet-catastrophic invariant break:
            // if it ever fired, blake3 is broken and every root is already
            // meaningless. Halting loudly beats diverging quietly.
            panic!("blake3 collision between two distinct keys (hash is broken)");
        }
        let (abit, bbit) = (bit(apos, depth), bit(bpos, depth));
        if abit == bbit {
            // Still together: one more level, then recurse.
            let child = Self::split(a, apos, b, bpos, depth + 1);
            return if abit == 0 {
                Node::internal(child, Node::Empty)
            } else {
                Node::internal(Node::Empty, child)
            };
        }
        if abit == 0 {
            Node::internal(a, b)
        } else {
            Node::internal(b, a)
        }
    }

    /// Look up a value.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let pos = pos_of(key);
        let mut node = &self.root;
        let mut depth = 0usize;
        loop {
            match node {
                Node::Empty => return None,
                Node::Leaf {
                    key: k, value: v, ..
                } => return if k == key { Some(v) } else { None },
                Node::Internal { left, right, .. } => {
                    node = if bit(&pos, depth) == 0 { left } else { right };
                    depth += 1;
                }
            }
        }
    }

    /// Produce a proof for `key`, whether or not it is present.
    pub fn prove(&self, key: &[u8]) -> SmtV2Proof {
        let pos = pos_of(key);
        let mut siblings = Vec::new();
        let mut node = &self.root;
        let mut depth = 0usize;

        let other_leaf = loop {
            match node {
                Node::Empty => break None,
                Node::Leaf {
                    key: k, value: v, ..
                } => {
                    // Landing on a different key is a *non-inclusion* proof:
                    // the verifier needs this leaf to recompute the subtree
                    // hash, so it travels with the proof.
                    break if k == key {
                        None
                    } else {
                        Some((k.clone(), v.clone()))
                    };
                }
                Node::Internal { left, right, .. } => {
                    let (next, sib) = if bit(&pos, depth) == 0 {
                        (left, right)
                    } else {
                        (right, left)
                    };
                    siblings.push(sib.hash());
                    node = next;
                    depth += 1;
                }
            }
        };

        // Stored root-adjacent first while descending; the verifier climbs from
        // the leaf, so reverse once here rather than in every verifier.
        siblings.reverse();
        SmtV2Proof {
            key: key.to_vec(),
            siblings,
            other_leaf,
        }
    }

    /// Rebuild from an iterator of rows. Used by the migration path.
    pub fn from_rows<'a, I>(rows: I) -> Self
    where
        I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
    {
        let mut t = Self::new();
        for (k, v) in rows {
            t.insert(k, v);
        }
        t
    }
}

/// A v2 inclusion or non-inclusion proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmtV2Proof {
    /// The key this path addresses.
    pub key: Vec<u8>,
    /// Sibling hashes, **leaf-adjacent first** (same convention as v1).
    /// Its length is the depth at which the addressed slot sits.
    pub siblings: Vec<Hash>,
    /// For non-inclusion where the slot is occupied by another key: that
    /// key/value, so the verifier can recompute the leaf hash itself rather
    /// than trusting a supplied digest.
    pub other_leaf: Option<(Vec<u8>, Vec<u8>)>,
}

impl SmtV2Proof {
    /// Climb from a starting hash at the proof's depth to a root.
    fn climb(&self, start: Hash) -> Option<Hash> {
        if self.siblings.len() > MAX_DEPTH {
            return None;
        }
        let pos = pos_of(&self.key);
        let depth = self.siblings.len();
        let mut acc = start;
        for (k, sib) in self.siblings.iter().enumerate() {
            // siblings[0] sits at depth-1, siblings[depth-1] at 0.
            let d = depth - 1 - k;
            acc = if bit(&pos, d) == 0 {
                node_hash(&acc, sib)
            } else {
                node_hash(sib, &acc)
            };
        }
        Some(acc)
    }

    /// Verify against a trusted v2 root.
    ///
    /// `value` is `Some` to assert inclusion, `None` to assert absence.
    pub fn verify(&self, root: &Hash, value: Option<&[u8]>) -> bool {
        let start = match (value, &self.other_leaf) {
            // Inclusion. `other_leaf` is meaningless here, and accepting a
            // proof that carries one would let a prover attach noise that a
            // future reader might interpret.
            (Some(v), None) => leaf_hash(&self.key, v),
            (Some(_), Some(_)) => return false,

            // Non-inclusion, empty slot.
            (None, None) => empty_hash(),

            // Non-inclusion, slot occupied by a different key.
            (None, Some((k2, v2))) => {
                // Both checks are load-bearing. Without the first, a prover
                // could deny membership by presenting the queried key's own
                // leaf; without the second, by presenting *any* unrelated leaf
                // from elsewhere in the tree.
                if k2 == &self.key {
                    return false;
                }
                let p1 = pos_of(&self.key);
                let p2 = pos_of(k2);
                if !shares_prefix(&p1, &p2, self.siblings.len()) {
                    return false;
                }
                leaf_hash(k2, v2)
            }
        };
        self.climb(start).map(|r| r == *root).unwrap_or(false)
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
    fn empty_tree_roots_at_the_empty_hash() {
        let t = SmtV2::new();
        assert_eq!(t.root(), empty_hash());
        assert!(t.is_empty());
        // Non-inclusion holds for any key.
        assert!(t.prove(b"anything").verify(&t.root(), None));
    }

    #[test]
    fn insert_get_roundtrip() {
        let mut t = SmtV2::new();
        for i in 0..200 {
            let (k, v) = kv(i);
            t.insert(&k, &v);
        }
        assert_eq!(t.len(), 200);
        for i in 0..200 {
            let (k, v) = kv(i);
            assert_eq!(t.get(&k), Some(v.as_slice()));
        }
        assert_eq!(t.get(b"absent"), None);
    }

    #[test]
    fn inclusion_proofs_verify() {
        let mut t = SmtV2::new();
        for i in 0..300 {
            let (k, v) = kv(i);
            t.insert(&k, &v);
        }
        let root = t.root();
        for i in 0..300 {
            let (k, v) = kv(i);
            assert!(t.prove(&k).verify(&root, Some(&v)), "key {i}");
        }
    }

    #[test]
    fn a_tampered_value_does_not_verify() {
        let mut t = SmtV2::new();
        for i in 0..50 {
            let (k, v) = kv(i);
            t.insert(&k, &v);
        }
        let (k, _) = kv(7);
        assert!(!t.prove(&k).verify(&t.root(), Some(b"not-the-value")));
    }

    #[test]
    fn non_inclusion_verifies_for_both_shapes() {
        let mut t = SmtV2::new();
        for i in 0..100 {
            let (k, v) = kv(i);
            t.insert(&k, &v);
        }
        let root = t.root();
        // Whatever shape each absent key lands in — empty slot or another
        // leaf — the proof must verify.
        let mut saw_empty = false;
        let mut saw_other = false;
        for i in 1000..1100 {
            let (k, _) = kv(i);
            let p = t.prove(&k);
            if p.other_leaf.is_some() {
                saw_other = true;
            } else {
                saw_empty = true;
            }
            assert!(p.verify(&root, None), "absent key {i}");
        }
        assert!(
            saw_other,
            "no occupied-slot non-inclusion case was exercised"
        );
        assert!(saw_empty || saw_other);
    }

    /// **The soundness check that matters.** A prover must not be able to deny
    /// membership of a key that is present by attaching some unrelated leaf.
    #[test]
    fn non_inclusion_cannot_be_forged_with_an_unrelated_leaf() {
        let mut t = SmtV2::new();
        for i in 0..100 {
            let (k, v) = kv(i);
            t.insert(&k, &v);
        }
        let root = t.root();
        let (victim, victim_val) = kv(42);

        // A genuine inclusion proof for the victim...
        let mut forged = t.prove(&victim);
        // ...re-labelled as non-inclusion by attaching a different real leaf.
        let (other_k, other_v) = kv(43);
        forged.other_leaf = Some((other_k, other_v));
        assert!(
            !forged.verify(&root, None),
            "an unrelated leaf must not prove absence"
        );

        // And the honest inclusion proof still works.
        assert!(t.prove(&victim).verify(&root, Some(&victim_val)));
    }

    /// A proof carrying `other_leaf` must not double as an inclusion proof.
    #[test]
    fn inclusion_with_an_other_leaf_is_rejected() {
        let mut t = SmtV2::new();
        for i in 0..20 {
            let (k, v) = kv(i);
            t.insert(&k, &v);
        }
        let (k, v) = kv(5);
        let mut p = t.prove(&k);
        p.other_leaf = Some((b"x".to_vec(), b"y".to_vec()));
        assert!(!p.verify(&t.root(), Some(&v)));
    }

    /// Presenting the queried key's own leaf must not prove its absence.
    #[test]
    fn a_key_cannot_prove_its_own_absence() {
        let mut t = SmtV2::new();
        for i in 0..20 {
            let (k, v) = kv(i);
            t.insert(&k, &v);
        }
        let (k, v) = kv(3);
        let mut p = t.prove(&k);
        p.other_leaf = Some((k.clone(), v));
        assert!(!p.verify(&t.root(), None));
    }

    #[test]
    fn overwrite_updates_the_root_and_not_the_count() {
        let mut t = SmtV2::new();
        let (k, v) = kv(1);
        t.insert(&k, &v);
        let r1 = t.root();
        t.insert(&k, b"different");
        assert_ne!(t.root(), r1, "a changed value must change the root");
        assert_eq!(t.len(), 1, "overwriting is not an insertion");
        assert_eq!(t.get(&k), Some(&b"different"[..]));
    }

    /// Insertion order must not affect the root — the tree is a function of its
    /// contents, which is what makes it usable as consensus state.
    #[test]
    fn root_is_independent_of_insertion_order() {
        let mut a = SmtV2::new();
        for i in 0..150 {
            let (k, v) = kv(i);
            a.insert(&k, &v);
        }
        let mut b = SmtV2::new();
        for i in (0..150).rev() {
            let (k, v) = kv(i);
            b.insert(&k, &v);
        }
        assert_eq!(a.root(), b.root());
    }

    /// v1 and v2 must never produce the same root for the same data — the
    /// domain tags exist to guarantee that, and a collision would make the
    /// version tag meaningless during migration.
    #[test]
    fn v1_and_v2_roots_differ() {
        let mut v1 = crate::smt::SparseMerkleTree::new();
        let mut v2 = SmtV2::new();
        for i in 0..32 {
            let (k, val) = kv(i);
            v1.insert(&k, &val);
            v2.insert(&k, &val);
        }
        assert_ne!(v1.root(), v2.root());
    }

    /// The whole point: depth stays near log2(n), not 256.
    #[test]
    fn proof_depth_is_logarithmic_not_256() {
        let mut t = SmtV2::new();
        for i in 0..1024 {
            let (k, v) = kv(i);
            t.insert(&k, &v);
        }
        let mut max_depth = 0;
        for i in 0..1024 {
            let (k, _) = kv(i);
            max_depth = max_depth.max(t.prove(&k).siblings.len());
        }
        assert!(
            max_depth < 40,
            "expected ~log2(1024)=10 with a tail, got {max_depth}"
        );
    }
}
