//! First-class on-chain tables with verifiable reads.
//!
//! Bootstrap scope: byte-keyed / byte-valued rows with:
//! * a **per-table root** — an incremental [`SparseMerkleTree`] over the rows,
//!   maintained in `O(depth)` per write (see [`crate::smt`]); and
//! * a **store root** — a small sorted-leaf Merkle over `(table_id, table_root)`
//!   (one leaf per table, so recompute-on-demand is trivially cheap).
//!
//! A [`ProvenRead`] carries the value plus both proofs, so a light client
//! holding only the 32-byte store root can verify a row. The sparse tree also
//! yields [`ProvenAbsence`] (non-inclusion) for free — same path, empty slot —
//! and [`RangeProof`] batches inclusion over a key range.

use crate::merkle::{MerkleProof, MerkleTree};
use crate::smt::{SmtProof, SparseMerkleTree};
use peregrine_core::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Identifier for a table (hash of its creation descriptor in production;
/// human-readable string hash in bootstrap).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TableId(pub Hash);

impl TableId {
    pub fn named(name: &str) -> Self {
        TableId(Hash::digest(name.as_bytes()))
    }
}

impl std::fmt::Debug for TableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tbl:{}", self.0.short())
    }
}

/// Canonical leaf encoding for the store level: table id + table root.
/// A table's rows as flat key/value pairs, grouped by table — the durable
/// ground truth a store is snapshotted to and rebuilt from. Merkle trees are
/// derived from this, never stored alongside it.
pub type TableRows = Vec<(TableId, Vec<(Vec<u8>, Vec<u8>)>)>;

fn store_leaf_bytes(id: &TableId, root: &Hash) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.0 .0);
    out.extend_from_slice(&root.0);
    out
}

/// One table: the authoritative key-ordered rows plus the incremental sparse
/// Merkle tree that authenticates them. The two are updated together and stay
/// in lockstep; the `BTreeMap` also gives deterministic key-ordered iteration
/// for range queries, which the hash-keyed tree cannot provide.
#[derive(Default)]
struct Table {
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    tree: SparseMerkleTree,
}

impl Table {
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.tree.insert(&key, &value);
        self.rows.insert(key, value);
    }

    fn root(&self) -> Hash {
        self.tree.root()
    }
}

/// A verifiable point-read: value + row proof (against the table root) +
/// table proof (against the store root).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvenRead {
    pub table: TableId,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub table_root: Hash,
    /// Proves `(key, value)` occupies its slot under `table_root`.
    pub row_proof: SmtProof,
    /// Proves `(table, table_root)` is in the store under the store root.
    pub store_proof: MerkleProof,
}

impl ProvenRead {
    /// Verify this read against a trusted 32-byte store root. This is the
    /// entire trust surface of a Peregrine light client for point reads.
    pub fn verify(&self, store_root: &Hash) -> bool {
        if !self.row_proof.verify(&self.table_root, Some(&self.value)) {
            return false;
        }
        let store_leaf = store_leaf_bytes(&self.table, &self.table_root);
        self.store_proof.verify(store_root, &store_leaf)
    }
}

/// A verifiable **non-inclusion** proof: `key` is absent from `table`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvenAbsence {
    pub table: TableId,
    pub key: Vec<u8>,
    pub table_root: Hash,
    /// Proves `key`'s slot is empty under `table_root`.
    pub row_proof: SmtProof,
    pub store_proof: MerkleProof,
}

impl ProvenAbsence {
    pub fn verify(&self, store_root: &Hash) -> bool {
        if !self.row_proof.verify(&self.table_root, None) {
            return false;
        }
        let store_leaf = store_leaf_bytes(&self.table, &self.table_root);
        self.store_proof.verify(store_root, &store_leaf)
    }
}

/// A **basic** range proof: every row it lists is present, in `[lo, hi]`, and
/// in strictly ascending key order, all under one verified `table_root`.
///
/// Scope note: this proves *membership* of the listed rows, not
/// *completeness* of the range. Proving "no other key exists in `[lo, hi]`"
/// needs a key-ordered accumulator (adjacency / boundary non-inclusion); the
/// hash-keyed sparse tree deliberately does not order by key, so completeness
/// is a tracked follow-up. The [`RangeProof::verify`] contract is stable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeProof {
    pub table: TableId,
    pub lo: Vec<u8>,
    pub hi: Vec<u8>,
    pub table_root: Hash,
    pub store_proof: MerkleProof,
    /// `(key, value, inclusion_proof)` for each row in range.
    pub rows: Vec<(Vec<u8>, Vec<u8>, SmtProof)>,
}

impl RangeProof {
    pub fn verify(&self, store_root: &Hash) -> bool {
        // The table root must be bound into the store root.
        let store_leaf = store_leaf_bytes(&self.table, &self.table_root);
        if !self.store_proof.verify(store_root, &store_leaf) {
            return false;
        }
        // Each row: in range, strictly ascending, key-bound, and included.
        let mut prev: Option<&[u8]> = None;
        for (k, v, proof) in &self.rows {
            if k.as_slice() < self.lo.as_slice() || k.as_slice() > self.hi.as_slice() {
                return false;
            }
            if let Some(p) = prev {
                if k.as_slice() <= p {
                    return false;
                }
            }
            if proof.key != *k || !proof.verify(&self.table_root, Some(v)) {
                return false;
            }
            prev = Some(k.as_slice());
        }
        true
    }
}

/// The multi-table store owned by a validator's state machine.
pub struct TableStore {
    tables: BTreeMap<TableId, Table>,
    /// Store-level caches. Per-table roots are always current (the trees are
    /// incremental); only the store root — a function of those roots — needs
    /// invalidation, and it recomputes over just one leaf per table.
    store_dirty: bool,
    cached_table_roots: BTreeMap<TableId, Hash>,
    cached_store_root: Hash,
}

impl TableStore {
    pub fn new() -> Self {
        Self {
            tables: BTreeMap::new(),
            store_dirty: true,
            cached_table_roots: BTreeMap::new(),
            cached_store_root: Hash::ZERO,
        }
    }

    /// Create a table if absent.
    pub fn create_table(&mut self, id: TableId) {
        self.tables.entry(id).or_default();
        self.store_dirty = true;
    }

    /// Upsert a row (incrementally updates that table's sparse Merkle root).
    pub fn insert(&mut self, id: TableId, key: Vec<u8>, value: Vec<u8>) {
        self.tables.entry(id).or_default().insert(key, value);
        self.store_dirty = true;
    }

    /// Unverified local read (validator-internal fast path).
    pub fn get(&self, id: &TableId, key: &[u8]) -> Option<&[u8]> {
        self.tables.get(id)?.rows.get(key).map(|v| v.as_slice())
    }

    pub fn row_count(&self, id: &TableId) -> usize {
        self.tables.get(id).map(|t| t.rows.len()).unwrap_or(0)
    }

    /// The 32-byte commitment to the entire store. Light clients pin this.
    pub fn store_root(&mut self) -> Hash {
        self.refresh_store();
        self.cached_store_root
    }

    /// Recompute the store-level tree from the (already-current) per-table
    /// roots. Cheap: one leaf per table.
    fn refresh_store(&mut self) {
        if !self.store_dirty {
            return;
        }
        self.cached_table_roots.clear();
        for (id, table) in &self.tables {
            self.cached_table_roots.insert(*id, table.root());
        }
        let store_leaves: Vec<Vec<u8>> = self
            .cached_table_roots
            .iter()
            .map(|(id, root)| store_leaf_bytes(id, root))
            .collect();
        let store_tree = MerkleTree::from_leaves(store_leaves.iter().map(|l| l.as_slice()));
        self.cached_store_root = store_tree.root();
        self.store_dirty = false;
    }

    /// The store-level inclusion proof for `id` (proves `table_root` is bound
    /// into the store root). Shared by every proof kind below.
    fn store_proof_for(&mut self, id: &TableId) -> Option<(Hash, MerkleProof)> {
        self.refresh_store();
        let table_root = *self.cached_table_roots.get(id)?;
        let store_index = self.cached_table_roots.keys().position(|t| t == id)?;
        let store_leaves: Vec<Vec<u8>> = self
            .cached_table_roots
            .iter()
            .map(|(tid, root)| store_leaf_bytes(tid, root))
            .collect();
        let store_tree = MerkleTree::from_leaves(store_leaves.iter().map(|l| l.as_slice()));
        let store_proof = store_tree.prove(store_index)?;
        Some((table_root, store_proof))
    }

    /// Produce a verifiable read for `(table, key)`, or `None` if absent.
    pub fn prove_read(&mut self, id: TableId, key: &[u8]) -> Option<ProvenRead> {
        let value = self.tables.get(&id)?.rows.get(key)?.clone();
        let row_proof = self.tables.get(&id)?.tree.prove(key);
        let (table_root, store_proof) = self.store_proof_for(&id)?;
        Some(ProvenRead {
            table: id,
            key: key.to_vec(),
            value,
            table_root,
            row_proof,
            store_proof,
        })
    }

    /// Produce a verifiable **non-inclusion** proof for `(table, key)`, or
    /// `None` if the key is in fact present (prove a read instead).
    pub fn prove_non_inclusion(&mut self, id: TableId, key: &[u8]) -> Option<ProvenAbsence> {
        let table = self.tables.get(&id)?;
        if table.rows.contains_key(key) {
            return None;
        }
        let row_proof = table.tree.prove(key);
        let (table_root, store_proof) = self.store_proof_for(&id)?;
        Some(ProvenAbsence {
            table: id,
            key: key.to_vec(),
            table_root,
            row_proof,
            store_proof,
        })
    }

    /// Export every table's rows as plain `(id, [(key, value)])` data — the
    /// canonical, tree-free form a node persists. Empty tables are included so
    /// [`restore_from_rows`](Self::restore_from_rows) recreates them exactly,
    /// keeping the store root stable across a save/reload cycle.
    ///
    /// The sparse Merkle trees are deliberately *not* serialized: they are a
    /// pure function of the rows and are cheaply rebuilt on load, so rows are
    /// the only ground truth we durably keep.
    pub fn snapshot_rows(&self) -> TableRows {
        self.tables
            .iter()
            .map(|(id, table)| {
                let rows = table
                    .rows
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                (*id, rows)
            })
            .collect()
    }

    /// Rebuild a store from exported rows, reconstructing each table's sparse
    /// Merkle tree incrementally via [`insert`](Self::insert). The resulting
    /// store root is identical to the original's (roots are a pure function of
    /// the rows), which is the invariant the persistence round-trip relies on.
    pub fn restore_from_rows(rows: TableRows) -> Self {
        let mut store = Self::new();
        for (id, table_rows) in rows {
            store.create_table(id); // recreate even empty tables
            for (k, v) in table_rows {
                store.insert(id, k, v);
            }
        }
        store
    }

    /// Produce a **basic** range proof over the inclusive key range `[lo, hi]`
    /// (membership of the rows present in range — see [`RangeProof`]).
    pub fn prove_range(&mut self, id: TableId, lo: &[u8], hi: &[u8]) -> Option<RangeProof> {
        let table = self.tables.get(&id)?;
        let rows: Vec<(Vec<u8>, Vec<u8>, SmtProof)> = table
            .rows
            .range(lo.to_vec()..=hi.to_vec())
            .map(|(k, v)| (k.clone(), v.clone(), table.tree.prove(k)))
            .collect();
        let (table_root, store_proof) = self.store_proof_for(&id)?;
        Some(RangeProof {
            table: id,
            lo: lo.to_vec(),
            hi: hi.to_vec(),
            table_root,
            store_proof,
            rows,
        })
    }
}

impl Default for TableStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proven_read_roundtrip() {
        let mut store = TableStore::new();
        let prices = TableId::named("prices");
        let agents = TableId::named("agents");
        for i in 0..50u32 {
            store.insert(
                prices,
                format!("asset-{i}").into_bytes(),
                i.to_le_bytes().to_vec(),
            );
            store.insert(agents, format!("agent-{i}").into_bytes(), vec![i as u8]);
        }
        let root = store.store_root();
        let read = store.prove_read(prices, b"asset-7").expect("row exists");
        assert!(read.verify(&root));
        assert!(!read.verify(&Hash::ZERO)); // wrong root fails
        let mut bad = read.clone();
        bad.value = vec![9, 9, 9];
        assert!(!bad.verify(&root)); // tampered value fails
        store.insert(prices, b"asset-7".to_vec(), vec![42]);
        assert_ne!(store.store_root(), root); // root moves with state
    }

    #[test]
    fn non_inclusion_proof() {
        let mut store = TableStore::new();
        let prices = TableId::named("prices");
        for i in 0..30u32 {
            store.insert(
                prices,
                format!("asset-{i}").into_bytes(),
                i.to_le_bytes().to_vec(),
            );
        }
        let root = store.store_root();
        // Absent key: provable non-inclusion; present key: cannot.
        let absent = store
            .prove_non_inclusion(prices, b"asset-999")
            .expect("absent");
        assert!(absent.verify(&root));
        assert!(store.prove_non_inclusion(prices, b"asset-3").is_none());
        // A non-inclusion proof must not verify once the key is inserted.
        store.insert(prices, b"asset-999".to_vec(), vec![1]);
        assert!(!absent.verify(&store.store_root()));
    }

    #[test]
    fn snapshot_rows_roundtrip_preserves_root() {
        let mut store = TableStore::new();
        let prices = TableId::named("prices");
        let agents = TableId::named("agents");
        let empty = TableId::named("empty"); // created but never written
        store.create_table(empty);
        for i in 0..40u32 {
            store.insert(
                prices,
                format!("asset-{i:03}").into_bytes(),
                i.to_le_bytes().to_vec(),
            );
            store.insert(agents, format!("agent-{i:03}").into_bytes(), vec![i as u8]);
        }
        let root = store.store_root();

        // Export → import (tree-free) must reproduce the identical root and a
        // still-verifiable proof against it.
        let rows = store.snapshot_rows();
        let mut reloaded = TableStore::restore_from_rows(rows);
        assert_eq!(reloaded.store_root(), root, "root must survive save/reload");
        let read = reloaded
            .prove_read(prices, b"asset-007")
            .expect("row exists");
        assert!(
            read.verify(&root),
            "proof from reloaded store verifies against original root"
        );
        assert_eq!(reloaded.row_count(&empty), 0, "empty table is recreated");
    }

    #[test]
    fn range_proof_membership() {
        let mut store = TableStore::new();
        let prices = TableId::named("prices");
        for i in 0..100u32 {
            // zero-padded keys so lexical order == numeric order
            store.insert(
                prices,
                format!("asset-{i:03}").into_bytes(),
                i.to_le_bytes().to_vec(),
            );
        }
        let root = store.store_root();
        let proof = store
            .prove_range(prices, b"asset-010", b"asset-019")
            .expect("range");
        assert!(proof.verify(&root));
        assert_eq!(proof.rows.len(), 10);
        // Tampering a value in the range breaks the proof.
        let mut bad = proof.clone();
        bad.rows[0].1 = vec![7, 7, 7];
        assert!(!bad.verify(&root));
        // A row smuggled outside the stated range is rejected.
        let mut oob = proof.clone();
        let sneak = store.prove_read(prices, b"asset-050").unwrap();
        oob.rows.push((sneak.key, sneak.value, sneak.row_proof));
        assert!(!oob.verify(&root));
    }
}
